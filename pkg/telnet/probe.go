package telnet

import (
	"io"
	"net"
	"strings"
	"time"
)

// EmptyReadRetryDelay is the pause between an empty first read and the "\r\n"
// wake-up write, chosen to be short enough to stay inside a single check's
// budget on serial console targets that answer promptly (Perle, Lantronix,
// Moxa serial-over-IP).
const EmptyReadRetryDelay = 100 * time.Millisecond

// maxNegotiationRounds bounds the read/negotiate loop so a chatty peer that
// keeps sending fresh IAC options can't stall the probe forever.
const maxNegotiationRounds = 8

// BannerResult is the output of ReadBannerWithNegotiate.
type BannerResult struct {
	// Raw contains every byte read from the peer, in order. Callers should
	// hex-encode this into the finding's `raw` field so forensic reviewers
	// can inspect the exact bytes on the wire.
	Raw []byte
	// Visible is the non-IAC byte stream (i.e. what the peer's banner would
	// have been if we simply dropped negotiation bytes).
	Visible []byte
	// Annotated renders the same stream with IAC negotiation commands
	// interleaved as tokens (e.g. "<DO Echo>Perle IOLAN diag>"). This is what
	// checks should surface as the readable `banner` field.
	Annotated string
	// HasIAC records whether IAC negotiation was observed at any point.
	HasIAC bool
	// SentEnter records whether we injected a "\r\n" wake-up write because
	// the peer never volunteered a visible banner.
	SentEnter bool
	// Will/Wont/Do/Dont accumulate every option the peer offered/refused
	// across the whole read.
	Will []byte
	Wont []byte
	Do   []byte
	Dont []byte
}

// ReadBannerWithNegotiate reads a telnet-style banner from an already-dialled
// connection. Behaviour:
//
//  1. It reads chunks from conn, parses any IAC negotiation, and writes reject
//     responses (WILL->DONT, DO->WONT), which coaxes a negotiation-first server
//     into emitting its real banner.
//  2. If the visible banner is still empty after the initial read, it writes a
//     "\r\n" wake-up, sleeps EmptyReadRetryDelay, and reads once more. Many serial
//     console front-ends emit no prompt until they see input.
//
// The exchange is bounded by `timeout`. This function manages the connection
// deadline, so a caller must not set its own read deadline after handing over the
// socket.
func ReadBannerWithNegotiate(conn net.Conn, timeout time.Duration) BannerResult {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	var res BannerResult
	buf := make([]byte, 4096)
	var visible []byte
	var annotated strings.Builder

	// Per-read budget: give each chunk half of the remaining time so we can
	// perform a couple of rounds and still leave room for the wake-up retry.
	perRead := func() time.Duration {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 100 * time.Millisecond
		}
		if remaining/2 < 200*time.Millisecond {
			return remaining
		}
		return remaining / 2
	}

	readOnce := func(budget time.Duration) (int, error) {
		_ = conn.SetReadDeadline(time.Now().Add(budget))
		return conn.Read(buf)
	}

	for range maxNegotiationRounds {
		if time.Now().After(deadline) {
			break
		}
		n, err := readOnce(perRead())
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			res.Raw = append(res.Raw, chunk...)
			ir := ParseIAC(chunk)
			visible = append(visible, ir.Visible...)
			annotated.WriteString(ir.Annotated)
			if ir.HasIAC {
				res.HasIAC = true
			}
			res.Will = mergeOptions(res.Will, ir.Will)
			res.Wont = mergeOptions(res.Wont, ir.Wont)
			res.Do = mergeOptions(res.Do, ir.Do)
			res.Dont = mergeOptions(res.Dont, ir.Dont)
			if len(ir.Responses) > 0 {
				_ = conn.SetWriteDeadline(time.Now().Add(perRead()))
				_, werr := conn.Write(ir.Responses)
				if werr != nil {
					break
				}
				// Give the peer a beat to answer the negotiation before we
				// call the read loop again.
				continue
			}
			// No IAC to reply to and we already have visible text; a second
			// read may drain a trailing prompt but we can bail once the
			// deadline is close.
			if len(visible) > 0 {
				break
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			break
		}
	}

	// Wake-up retry: if we never got a visible banner, poke the peer with
	// "\r\n" and read one more chunk. This is the pattern operators use with
	// `telnet` / `nc` when a serial console stays silent on connect.
	if len(visible) == 0 {
		remaining := time.Until(deadline)
		if remaining > EmptyReadRetryDelay+100*time.Millisecond {
			_ = conn.SetWriteDeadline(time.Now().Add(perRead()))
			if _, werr := conn.Write([]byte("\r\n")); werr == nil {
				res.SentEnter = true
				time.Sleep(EmptyReadRetryDelay)
				n, _ := readOnce(perRead())
				if n > 0 {
					chunk := append([]byte(nil), buf[:n]...)
					res.Raw = append(res.Raw, chunk...)
					ir := ParseIAC(chunk)
					visible = append(visible, ir.Visible...)
					annotated.WriteString(ir.Annotated)
					if ir.HasIAC {
						res.HasIAC = true
					}
					res.Will = mergeOptions(res.Will, ir.Will)
					res.Wont = mergeOptions(res.Wont, ir.Wont)
					res.Do = mergeOptions(res.Do, ir.Do)
					res.Dont = mergeOptions(res.Dont, ir.Dont)
					if len(ir.Responses) > 0 {
						_ = conn.SetWriteDeadline(time.Now().Add(perRead()))
						_, _ = conn.Write(ir.Responses)
					}
				}
			}
		}
	}

	res.Visible = visible
	res.Annotated = annotated.String()
	return res
}

// ReadBannerPassive reads a banner without writing anything to conn. Use it for
// raw serial-over-IP passthrough ports (Lantronix 10001-10003, Moxa NPort 4001+)
// whose bytes are transparent to the attached device console: an IAC reject
// response or a "\r\n" wake-up would be injected straight into that downstream
// console -- able to wake a pager or confirm a pending [y/N] on the attached
// router/switch/PLC/UPS. It parses IAC only to annotate/strip it for the result;
// it never sends negotiation replies or a wake-up. Bounded by `timeout`.
func ReadBannerPassive(conn net.Conn, timeout time.Duration) BannerResult {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	var res BannerResult
	buf := make([]byte, 4096)
	var visible []byte
	var annotated strings.Builder

	for range maxNegotiationRounds {
		budget := time.Until(deadline)
		if budget <= 0 {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(budget))
		n, err := conn.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			res.Raw = append(res.Raw, chunk...)
			ir := ParseIAC(chunk)
			visible = append(visible, ir.Visible...)
			annotated.WriteString(ir.Annotated)
			if ir.HasIAC {
				res.HasIAC = true
			}
			res.Will = mergeOptions(res.Will, ir.Will)
			res.Wont = mergeOptions(res.Wont, ir.Wont)
			res.Do = mergeOptions(res.Do, ir.Do)
			res.Dont = mergeOptions(res.Dont, ir.Dont)
			if len(visible) > 0 {
				break // got something printable; do not poke a silent line
			}
		}
		if err != nil {
			break
		}
	}

	res.Visible = visible
	res.Annotated = annotated.String()
	return res
}

// SendEnterAndRead writes "\r\n" to conn, waits EmptyReadRetryDelay for the
// peer to react, and returns any bytes it produces within the supplied
// deadline. Used by raw serial-over-IP probes (Moxa NPort TCP/4001+) that
// don't speak telnet framing but do need a poke before the terminal prints.
func SendEnterAndRead(conn net.Conn, timeout time.Duration) []byte {
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("\r\n")); err != nil {
		return nil
	}
	time.Sleep(EmptyReadRetryDelay)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return nil
	}
	return append([]byte(nil), buf[:n]...)
}

func mergeOptions(dst, src []byte) []byte {
	if len(src) == 0 {
		return dst
	}
	for _, v := range src {
		dst = appendUnique(dst, v)
	}
	return dst
}
