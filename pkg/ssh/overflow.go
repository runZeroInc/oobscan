package ssh

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// SSHResult is the outcome of ProbeSSHOverflow.
type SSHResult int

const (
	// SSHError means the probe could not be completed (connect failed, no
	// banner, server KEXINIT could not be drained). No conclusion.
	SSHError SSHResult = iota
	// SSHVulnerable means the server accepts an SSH packet length in the
	// signed-overflow window (0x7FFFFFFC..0x7FFFFFFF) that it should reject,
	// while still enforcing the 0x800 upper bound for a merely-too-large
	// length. This is the HPE iLO4 SSH signed-length-check signature.
	SSHVulnerable
	// SSHNotVulnerable means the server rejects the signed-overflow-window
	// length (patched iLO4, a different SSH stack, or not iLO4 at all).
	SSHNotVulnerable
	// SSHInconclusive means the connection behaviour was ambiguous (for
	// example the server holds every connection open regardless of length, so
	// "held open" carries no signal).
	SSHInconclusive
)

func (r SSHResult) String() string {
	switch r {
	case SSHVulnerable:
		return "vulnerable"
	case SSHNotVulnerable:
		return "not-vulnerable"
	case SSHInconclusive:
		return "inconclusive"
	default:
		return "error"
	}
}

// SSHProbe is the detailed result of the differential probe, including the
// per-length observations that produced the verdict (kept for evidence).
type SSHProbe struct {
	Result SSHResult
	Banner string
	// Held is true when the server kept the connection open (blocked awaiting
	// the packet body) rather than rejecting the length and closing.
	WindowHeld bool // A: length 0x7FFFFFFC (signed-overflow window)
	LegalHeld  bool // B: length 0x00000100 (legal, incomplete body)
	OverHeld   bool // C: length 0x00000FFF (> 0x800, must be rejected)
	Detail     string
}

// probe lengths.
const (
	sshWindowLen uint32 = 0x7FFFFFFC // wraps (int)(len+4) negative -> defeats the signed check
	sshLegalLen  uint32 = 0x00000100 // <= 0x800: accepted by any iLO4, blocks on incomplete body
	sshOverLen   uint32 = 0x00000FFF // > 0x800: rejected by both vulnerable and patched iLO4
	// sshBodyBytes is deliberately far below the 2044-byte auStack_824 buffer
	// so the probe never writes past it: no stack is corrupted.
	sshBodyBytes = 16
)

// ProbeSSHOverflow is a limited-body differential test for the iLO4 SSH
// server's pre-auth stack overflow (signed packet-length check). It never sends
// enough body to overflow the target's buffer.
//
// Three short connections distinguish a server that accepts a length in the
// signed-overflow window from one that rejects it: A offers the overflow length, B a
// legal one to confirm the host is a blocking framer, and C an over-bound one to
// confirm it enforces the upper limit and is not a tarpit. A held plus B held plus C
// closed is vulnerable; A closed is not vulnerable; anything else is inconclusive.
func ProbeSSHOverflow(host string, port int, timeout time.Duration) SSHProbe {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	a, bannerA, errA := probeLen(host, port, timeout, sshWindowLen)
	if errA != nil {
		return SSHProbe{Result: SSHError, Detail: "window probe: " + errA.Error()}
	}
	b, _, errB := probeLen(host, port, timeout, sshLegalLen)
	if errB != nil {
		return SSHProbe{Result: SSHError, Banner: bannerA, Detail: "legal probe: " + errB.Error()}
	}
	c, _, errC := probeLen(host, port, timeout, sshOverLen)
	if errC != nil {
		return SSHProbe{Result: SSHError, Banner: bannerA, Detail: "over probe: " + errC.Error()}
	}

	p := SSHProbe{Banner: bannerA, WindowHeld: a, LegalHeld: b, OverHeld: c}
	switch {
	case !a:
		// The overflow-window length was rejected: patched, different stack, or
		// not iLO4.
		p.Result = SSHNotVulnerable
		p.Detail = "rejected 0x7FFFFFFC"
	case a && c:
		// Held the giant length open but also held a merely-too-large length
		// open: the server does not enforce the 0x800 cap, so "held" is not the
		// signed-check signal (possible tarpit or unrelated framer).
		p.Result = SSHInconclusive
		p.Detail = "accepted/held 0x7FFFFFFC/0x00000FFF"
	case a && !c && b:
		// Enforces the 0x800 cap (rejected 0xFFF) yet accepted 0x7FFFFFFC, and
		// blocks on an incomplete legal body: the signed-check signature.
		p.Result = SSHVulnerable
		p.Detail = "accepted 0x7FFFFFFC / rejected 0x00000FFF / wait 0x800"
	case a && !c && !b:
		// Accepted the window length and rejected 0xFFF, but did not block on a
		// legal incomplete body: unusual; report but do not over-claim.
		p.Result = SSHInconclusive
		p.Detail = "accepted 0x7FFFFFFC / rejected 0x00000FFF / no-wait 0x800"
	default:
		p.Result = SSHInconclusive
		p.Detail = "ambiguous framer behaviour"
	}
	return p
}

// probeLen runs one connection: version exchange, drain the server KEXINIT,
// send a packet whose 4-byte length field is `length` followed by a tiny body,
// and report whether the server held the connection open (true) or rejected the
// length and closed / responded (false).
func probeLen(host string, port int, timeout time.Duration, length uint32) (held bool, banner string, err error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()

	// Version exchange: read the server identification string (first "SSH-"
	// line), then send ours.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(conn)
	for range 50 {
		line, rerr := br.ReadString('\n')
		if rerr != nil {
			return false, "", fmt.Errorf("reading banner: %w", rerr)
		}
		if line = strings.TrimRight(line, "\r\n"); strings.HasPrefix(line, "SSH-") {
			banner = line
			break
		}
	}
	if banner == "" {
		return false, "", errors.New("no SSH identification string")
	}
	if _, werr := conn.Write([]byte(SSHClientVersion + "\r\n")); werr != nil {
		return false, banner, fmt.Errorf("writing banner: %w", werr)
	}

	// Drain the server's KEXINIT packet (uint32 len | body) so it does not sit
	// in our RX buffer and get mistaken for a rejection response later. iLO4
	// sends its KEXINIT immediately after the banner exchange.
	if derr := drainOnePacket(br); derr != nil {
		return false, banner, fmt.Errorf("draining server KEXINIT: %w", derr)
	}

	// Send the crafted packet framing: a 4-byte big-endian length followed by a
	// small body. The body is far below the target's 2044-byte buffer, so no
	// overflow occurs regardless of the length field.
	var lenb [4]byte
	binary.BigEndian.PutUint32(lenb[:], length)
	if _, werr := conn.Write(lenb[:]); werr != nil {
		return false, banner, fmt.Errorf("writing length: %w", werr)
	}
	body := make([]byte, sshBodyBytes)
	if _, werr := conn.Write(body); werr != nil {
		// A write error here can mean the server already rejected and closed
		// (patched): treat as "not held".
		return false, banner, nil
	}

	// Observe: a vulnerable/blocking server sits in its read loop awaiting the
	// declared body and sends nothing; our read times out with the connection
	// still open (held). A server that rejected the length sends a disconnect
	// and/or closes; our read returns data or EOF/reset promptly (not held).
	observe := min(timeout, 4*time.Second)
	_ = conn.SetReadDeadline(time.Now().Add(observe))
	rb := make([]byte, 64)
	n, rerr := br.Read(rb)
	if rerr == nil && n > 0 {
		// Server sent something after we sent the crafted length: a rejection /
		// disconnect, not a blocked read.
		return false, banner, nil
	}
	var ne net.Error
	if errors.As(rerr, &ne) && ne.Timeout() {
		// No data, connection still open: the server is blocked awaiting the
		// body it will never receive.
		return true, banner, nil
	}
	// io.EOF or a reset: the server closed the connection (rejected).
	return false, banner, nil
}

// drainOnePacket reads and discards one unencrypted SSH binary packet
// (uint32 length | body) from br. It bounds the body so a hostile/huge length
// cannot cause an unbounded allocation.
func drainOnePacket(br *bufio.Reader) error {
	var lenb [4]byte
	if _, err := io.ReadFull(br, lenb[:]); err != nil {
		return err
	}
	plen := binary.BigEndian.Uint32(lenb[:])
	if plen < 2 || plen > 1<<20 {
		return fmt.Errorf("implausible packet length %d", plen)
	}
	// Discard the body without a large allocation.
	if _, err := io.CopyN(io.Discard, br, int64(plen)); err != nil {
		return err
	}
	return nil
}
