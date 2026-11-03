// Package redlion implements a read-only probe for the Sixnet UDR (Universal
// Data Register) station protocol on TCP/UDP 1594, served by Red Lion / Sixnet
// SixTRAK and VersaTRAK RTUs.
//
// Safety: UDR is the RTU's primary control channel, and a CRC-checked frame can
// carry filesystem operations and direct I/O-register writes that change physical
// outputs. This probe sends only the state-free version/identify command, which
// carries no filesystem or I/O operands, and validates that any reply is itself a
// CRC-checked UDR frame. A CRC-validated reply is what distinguishes a real station
// from an ACK-all or UDP-reflector false positive.
//
// The frame CRC (CRC-16/CCITT-FALSE with xorout, little-endian on the wire) was
// recovered from static analysis of the libudr append routine; see kb/redlion/.
package redlion

import (
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/runZeroInc/oobscan/pkg/wire"
)

// Port is the UDR station-protocol port (both TCP and UDP), service "sixtrak".
const Port = 1594

// UDR frame constants recovered from static analysis of libudr, described in
// the package documentation above.
const (
	udrStart      = 0x29 // binary CRC-checked frame start byte
	cmdUDRVersion = 0x03 // read-only version/identify command (no operands)
)

// Response records UDR reachability and any volunteered banner.
type Response struct {
	From      string
	TCPOpen   bool
	UDPState  string // "open", "closed", or "open|filtered"
	Banner    []byte
	Validated bool // reply was a 0x29-framed, CCITT-CRC-valid UDR frame
}

// crcUDR computes the UDR wire CRC as recovered from libudr appendCRC:
// CRC-16/CCITT-FALSE (init 0xFFFF, poly 0x1021, no bit reflection) with a final
// xorout of 0xFFFF. This is the CRC-16/GENIBUS variant. The 16-bit result is
// emitted on the wire little-endian (low byte first) by the frame builders.
func crcUDR(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc ^ 0xFFFF
}

// versionFrame builds the version/identify probe
// frame (command 0x03). It carries no filesystem or I/O operands and cannot
// create, delete, rename, or write anything, and appends the UDR wire CRC
// trailer (CCITT-FALSE, xorout 0xFFFF, little-endian). The recovered
// verified-good reference frame is the 9 bytes 29 07 FF FF 00 00 03 25 A2, whose
// trailing 25 A2 this builder reproduces.
func versionFrame() []byte {
	frame := []byte{udrStart, 0x07, 0xFF, 0xFF, 0x00, 0x00, cmdUDRVersion}
	c := crcUDR(frame)
	return append(frame, byte(c&0xff), byte(c>>8))
}

// validUDRReply reports whether raw is a plausible UDR station reply: it must
// begin with the 0x29 start byte and carry a correct trailing UDR wire CRC
// (little-endian) over the preceding bytes.
func validUDRReply(raw []byte) bool {
	if len(raw) < 4 || raw[0] != udrStart {
		return false
	}
	got := uint16(raw[len(raw)-1])<<8 | uint16(raw[len(raw)-2])
	return crcUDR(raw[:len(raw)-2]) == got
}

// Query establishes UDR reachability and, using the recovered state-free
// version/identify frame, attempts to elicit a CRC-validated station reply.
func Query(host string, timeout time.Duration) *Response {
	r := &Response{From: host}
	frame := versionFrame()

	// TCP: a successful connect proves the listener is up. Send the read-only
	// version/identify frame and capture any reply, then close.
	if open, banner, err := wire.TCPQuery(host, Port, frame, timeout); err == nil && open {
		r.TCPOpen = true
		r.Banner = banner
		if validUDRReply(banner) {
			r.Validated = true
		}
	}

	// UDP: a connected socket surfaces closed ports as ECONNREFUSED. Send the
	// same read-only version/identify frame and classify / validate the reply.
	if raw, err := wire.UDPQuery(host, Port, frame, timeout); err == nil {
		r.UDPState = "open"
		if len(raw) > 0 {
			if len(r.Banner) == 0 {
				r.Banner = raw
			}
			if validUDRReply(raw) {
				r.Validated = true
			}
		}
	} else if isConnRefused(err) {
		r.UDPState = "closed"
	} else {
		r.UDPState = "open|filtered"
	}

	if !r.TCPOpen && r.UDPState != "open" {
		return nil
	}
	return r
}

func isConnRefused(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

// Fields renders the decoded response as engine field key/value pairs.
func (r *Response) Fields() []string {
	f := []string{
		"service", "sixtrak",
		"port", strconv.Itoa(Port),
		"tcpOpen", strconv.FormatBool(r.TCPOpen),
		"udpState", r.UDPState,
		"udrReplyValidated", strconv.FormatBool(r.Validated),
	}
	if len(r.Banner) > 0 {
		f = append(f,
			"bannerStrings", wire.Join(wire.Printable(r.Banner)),
			"bannerIPv4", wire.Join(wire.IPv4s(r.Banner)),
		)
	}
	return f
}
