package advantech

import (
	"encoding/binary"
	"regexp"
	"time"

	"github.com/runZeroInc/oobscan/pkg/wire"
)

const ConfigPort = 5058

const (
	magic         = 0x4144414D
	prodEKI1524   = 0xC524
	opNetworkRead = 0x4102
	opSerialRead  = 0x4022
	offMagic      = 0x00
	offProd       = 0x0A
	offMAC        = 0x0C
	offOpcode     = 0x34
	reqLen        = 0x40
)

var fwRE = regexp.MustCompile(`(?i)\b[vV]?\d+\.\d+(?:\.\d+)?[A-Za-z0-9.]*\b`)

var modelRE = regexp.MustCompile(`(?i)\b(?:EKI|ADAM|EKI-)\-?[0-9][0-9A-Za-z-]*\b`)

func buildRequest(opcode uint16, prod uint16) []byte {
	b := make([]byte, reqLen)
	binary.BigEndian.PutUint32(b[offMagic:], magic)
	binary.BigEndian.PutUint16(b[offProd:], prod)
	for i := range 6 {
		b[offMAC+i] = 0xFF
	}
	binary.BigEndian.PutUint16(b[offOpcode:], opcode)
	return b
}

type Response struct {
	From      string
	Transport string
	Opcode    uint16
	MagicOK   bool
	MAC       string
	Model     string
	Firmware  string
	IPv4      []string
	Strings   []string
	Raw       []byte
}

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

	if !r.MagicOK {
		return nil
	}
	return r
}
