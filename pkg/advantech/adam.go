// Package advantech implements the Advantech "ADAM" / EKI device
// configuration protocol (UDP and TCP port 5058), the wire protocol spoken by
// the Advantech EKI/ADAM device-configuration utility and served by the
// on-device bin/edgserver.
//
// The request validator is fixed: a 4-byte magic "ADAM" (0x4144414D) at
// offset 0, a 2-byte product code at 0x0A (0xC524 for the EKI-1524), a 6-byte
// target MAC at 0x0C (all-0xFF is a broadcast wildcard matching any device),
// and a 2-byte opcode at 0x34 read with ntohs. The 0x40xx read/discovery
// opcode block is dispatched before any token check, so a read is
// unauthenticated: 0x4102 returns IPv4/IPv6 address, netmask and gateway;
// 0x4022 returns the serial configuration; and the replies also carry MAC,
// model and firmware version. This probe issues only those read opcodes with
// an empty token; it never sends a write/apply opcode.
package advantech

import (
	"encoding/binary"
	"regexp"
	"time"

	"github.com/runZeroInc/oobscan/pkg/wire"
)

// ConfigPort is the ADAM/EKI configuration port (both UDP and TCP).
const ConfigPort = 5058

const (
	magic         = 0x4144414D // "ADAM"
	prodEKI1524   = 0xC524
	opNetworkRead = 0x4102 // returns IPv4/IPv6, netmask, gateway (pre-auth)
	opSerialRead  = 0x4022 // returns baud/data/stop/parity (pre-auth)
	offMagic      = 0x00
	offProd       = 0x0A
	offMAC        = 0x0C
	offOpcode     = 0x34
	reqLen        = 0x40
)

// fwRE matches an Advantech firmware/version token such as "v6.15" or "1.35".
var fwRE = regexp.MustCompile(`(?i)\b[vV]?\d+\.\d+(?:\.\d+)?[A-Za-z0-9.]*\b`)

// modelRE matches an Advantech model token such as "EKI-1524" or "ADAM-6017".
var modelRE = regexp.MustCompile(`(?i)\b(?:EKI|ADAM|EKI-)\-?[0-9][0-9A-Za-z-]*\b`)

// buildRequest constructs a read-only ADAM request with a broadcast target
// MAC and an empty config token.
func buildRequest(opcode uint16, prod uint16) []byte {
	b := make([]byte, reqLen)
	binary.BigEndian.PutUint32(b[offMagic:], magic)
	binary.BigEndian.PutUint16(b[offProd:], prod)
	for i := range 6 {
		b[offMAC+i] = 0xFF // broadcast wildcard: match any device
	}
	binary.BigEndian.PutUint16(b[offOpcode:], opcode) // ntohs on the device
	return b
}

// Response is one device's decoded ADAM reply.
type Response struct {
	From      string
	Transport string // "udp" or "tcp"
	Opcode    uint16
	MagicOK   bool
	MAC       string
	Model     string
	Firmware  string
	IPv4      []string
	Strings   []string
	Raw       []byte
}

// Query sends the network-read (0x4102) and serial-read (0x4022) opcodes over
// UDP, then TCP, and returns the first decoded reply. Read-only.
func Query(host string, timeout time.Duration) *Response {
	for _, op := range []uint16{opNetworkRead, opSerialRead} {
		req := buildRequest(op, prodEKI1524)
		if raw, err := wire.UDPQuery(host, ConfigPort, req, timeout); err == nil && len(raw) > 0 {
			if r := decode(raw); r != nil {
				r.From, r.Transport, r.Opcode = host, "udp", op
				return r
			}
		}
	}
	for _, op := range []uint16{opNetworkRead, opSerialRead} {
		req := buildRequest(op, prodEKI1524)
		if open, raw, err := wire.TCPQuery(host, ConfigPort, req, timeout); err == nil && open && len(raw) > 0 {
			if r := decode(raw); r != nil {
				r.From, r.Transport, r.Opcode = host, "tcp", op
				return r
			}
		}
	}
	return nil
}

// decode validates the echoed "ADAM" magic and extracts every reportable
// field from the reply. Reply field offsets beyond the echoed header were not
// reverse-engineered, so model/firmware/IP are recovered by pattern from the
// full datagram and the raw hex is always retained.
func decode(raw []byte) *Response {
	r := &Response{Raw: append([]byte(nil), raw...)}
	if len(raw) >= offMagic+4 && binary.BigEndian.Uint32(raw[offMagic:]) == magic {
		r.MagicOK = true
		if len(raw) >= offMAC+6 {
			r.MAC = wire.MACFromBytes(raw[offMAC : offMAC+6])
		}
	}
	r.Strings = wire.Printable(raw)
	r.IPv4 = wire.IPv4s(raw)
	if r.MAC == "" {
		if m := wire.MACs(raw); len(m) > 0 {
			r.MAC = m[0]
		}
	}
	for _, s := range r.Strings {
		if r.Model == "" {
			if m := modelRE.FindString(s); m != "" {
				r.Model = m
			}
		}
		if r.Firmware == "" && r.Model != "" && s != r.Model {
			if v := fwRE.FindString(s); v != "" {
				r.Firmware = v
			}
		}
	}
	// Require the echoed "ADAM" magic. Without it a reply is not the ADAM
	// protocol: UDP reflectors and SIP scanners answer any datagram with
	// printable junk (IPv4s/strings), which would otherwise false-positive.
	if !r.MagicOK {
		return nil
	}
	return r
}
