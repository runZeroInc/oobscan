// Package slp implements just enough of SLPv2 (RFC 2608) to discover WBEM
// and redfish-rest service URLs advertised by BMCs.
//
// Only the unicast Service Request + Service Reply flow is implemented.
// Multicast is left to the caller (send the same packet to 239.255.255.253).
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

// Request builds a SrvRqst for the given service type string. Examples:
//
//	"service:wbem"
//	"service:management-hardware.intel-dcim"
//	"service:ldap"
//	"service:service-agent"
func Request(serviceType string) []byte {
	if serviceType == "" {
		serviceType = "service:service-agent"
	}
	var pdu bytes.Buffer
	// <prev-respondant-list>
	writeStr(&pdu, "")
	// <service-type>
	writeStr(&pdu, serviceType)
	// <scope-list>
	writeStr(&pdu, "DEFAULT")
	// <predicate>
	writeStr(&pdu, "")
	// <slp-spi>
	writeStr(&pdu, "")

	// Header: version(1)=2, function, length(3), flags(2), ext-offset(3), xid(2), lang-len(2), lang(en)
	var hdr bytes.Buffer
	hdr.WriteByte(2)
	hdr.WriteByte(FuncSrvRqst)
	// The 24-bit length is patched after assembly.
	hdr.Write([]byte{0, 0, 0})    // length
	hdr.Write([]byte{0, 0})       // flags
	hdr.Write([]byte{0, 0, 0})    // ext offset
	hdr.Write([]byte{0x12, 0x34}) // xid
	hdr.Write([]byte{0, 2})
	hdr.WriteString("en")
	out := append(hdr.Bytes(), pdu.Bytes()...)
	// Patch 24-bit length field at offset 2.
	n := len(out)
	out[2] = byte(n >> 16)
	out[3] = byte(n >> 8)
	out[4] = byte(n)
	return out
}

// Reply lists the service URLs returned in a SrvRply.
type Reply struct {
	From    string
	ErrCode uint16
	URLs    []string
	Raw     []byte
}

// Probe performs a unicast SrvRqst to host:427.
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
	// skip header: we need to walk past lang-tag-len/lang-tag.
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
		// URL entry: reserved(1) | lifetime(2) | url-len(2) | url | #authblocks(1)
		if off+6 > len(pkt) {
			return nil, errors.New("truncated SLP URL entry")
		}
		off++    // reserved
		off += 2 // lifetime
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

// VendorFromURLs tries to guess the BMC vendor from a SrvRply URL list.
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
