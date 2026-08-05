package slp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	FuncSrvRqst byte = 1
	FuncSrvRply byte = 2
)

func Request(serviceType string) []byte {
	if serviceType == "" {
		serviceType = "service:service-agent"
	}
	var pdu bytes.Buffer

	writeStr(&pdu, "")

	writeStr(&pdu, serviceType)

	writeStr(&pdu, "DEFAULT")

	writeStr(&pdu, "")

	writeStr(&pdu, "")

	var hdr bytes.Buffer
	hdr.WriteByte(2)
	hdr.WriteByte(FuncSrvRqst)

	hdr.Write([]byte{0, 0, 0})
	hdr.Write([]byte{0, 0})
	hdr.Write([]byte{0, 0, 0})
	hdr.Write([]byte{0x12, 0x34})
	hdr.Write([]byte{0, 2})
	hdr.WriteString("en")
	out := append(hdr.Bytes(), pdu.Bytes()...)

	n := len(out)
	out[2] = byte(n >> 16)
	out[3] = byte(n >> 8)
	out[4] = byte(n)
	return out
}

type Reply struct {
	From    string
	ErrCode uint16
	URLs    []string
	Raw     []byte
}

func Probe(host, serviceType string, timeout time.Duration) (*Reply, error) {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:427", host), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(Request(serviceType)); err != nil {
		return nil, err
	}
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	r, err := parseSrvRply(buf[:n])
	if err != nil {
		return nil, err
	}
	r.From = host
	return r, nil
}

func parseSrvRply(pkt []byte) (*Reply, error) {
	if len(pkt) < 14 {
		return nil, errors.New("short slp packet")
	}
	if pkt[1] != FuncSrvRply {
		return nil, fmt.Errorf("not a SrvRply (func=%d)", pkt[1])
	}

	langLen := int(binary.BigEndian.Uint16(pkt[12:14]))
	off := 14 + langLen
	if off+4 > len(pkt) {
		return nil, errors.New("truncated after header")
	}
	r := &Reply{Raw: pkt}
	r.ErrCode = binary.BigEndian.Uint16(pkt[off : off+2])
	off += 2
	urlCount := int(binary.BigEndian.Uint16(pkt[off : off+2]))
	off += 2
	for range urlCount {

		if off+6 > len(pkt) {
			return nil, errors.New("truncated SLP URL entry")
		}
		off++
		off += 2
		ulen := int(binary.BigEndian.Uint16(pkt[off : off+2]))
		off += 2
		if off+ulen > len(pkt) {
			return nil, errors.New("truncated SLP URL")
		}
		r.URLs = append(r.URLs, string(pkt[off:off+ulen]))
		off += ulen
		if off >= len(pkt) {
			return nil, errors.New("missing SLP authentication-block count")
		}
		authBlocks := int(pkt[off])
		off++
		for range authBlocks {
			if off+4 > len(pkt) {
				return nil, errors.New("truncated SLP authentication block")
			}
			blockLen := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
			if blockLen < 10 || off+blockLen > len(pkt) {
				return nil, errors.New("invalid SLP authentication block length")
			}
			off += blockLen
		}
	}
	return r, nil
}

func VendorFromURLs(urls []string) string {
	for _, u := range urls {
		low := strings.ToLower(u)
		switch {
		case strings.Contains(low, "ilo"):
			return "hpe"
		case strings.Contains(low, "idrac"):
			return "dell"
		case strings.Contains(low, "aten") || strings.Contains(low, "supermicro"):
			return "supermicro"
		case strings.Contains(low, "megarac") || strings.Contains(low, "ami"):
			return "ami"
		case strings.Contains(low, "xclarity"):
			return "lenovo"
		}
	}
	return ""
}

func writeStr(b *bytes.Buffer, s string) {
	b.WriteByte(byte(len(s) >> 8))
	b.WriteByte(byte(len(s)))
	b.WriteString(s)
}
