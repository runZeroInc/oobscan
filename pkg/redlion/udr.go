package redlion

import (
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/runZeroInc/oobscan/pkg/wire"
)

const Port = 1594

const (
	udrStart      = 0x29
	cmdUDRVersion = 0x03
)

type Response struct {
	From      string
	TCPOpen   bool
	UDPState  string
	Banner    []byte
	Validated bool
}

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

func versionFrame() []byte {
	frame := []byte{udrStart, 0x07, 0xFF, 0xFF, 0x00, 0x00, cmdUDRVersion}
	c := crcUDR(frame)
	return append(frame, byte(c&0xff), byte(c>>8))
}

func validUDRReply(raw []byte) bool {
	if len(raw) < 4 || raw[0] != udrStart {
		return false
	}
	got := uint16(raw[len(raw)-1])<<8 | uint16(raw[len(raw)-2])
	return crcUDR(raw[:len(raw)-2]) == got
}

func Query(host string, timeout time.Duration) *Response {
	r := &Response{From: host}
	frame := versionFrame()

	if open, banner, err := wire.TCPQuery(host, Port, frame, timeout); err == nil && open {
		r.TCPOpen = true
		r.Banner = banner
		if validUDRReply(banner) {
			r.Validated = true
		}
	}

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
