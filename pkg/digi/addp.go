// Package digi implements Digi's ADDP (Advanced Device Discovery Protocol)
// discovery over UDP/2362. Digi devices answer one of three supported magic
// prefixes (DIGI, DVKT, DGDP), so discovery sends all three probes.
package digi

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

// ADDPPort is Digi ADDP UDP discovery port.
const ADDPPort = 2362

// addpMagics are the three known request/response prefixes observed in Digi
// firmware and supported by Metasploit's Rex::Proto::ADDP implementation.
var addpMagics = [][4]byte{{'D', 'I', 'G', 'I'}, {'D', 'V', 'K', 'T'}, {'D', 'G', 'D', 'P'}}

const addpCmdConfigReq = 1

// maxADDPReads bounds how many datagrams either read loop will consume before
// returning, so a host (or spoofer) that floods the socket with ADDP-shaped or
// junk packets cannot keep the loop busy right up to the deadline. Discovery
// realistically yields at most a handful of replies per appliance.
const maxADDPReads = 64

// ADDPResponse is the parsed Digi discovery response.
type ADDPResponse struct {
	From              string
	Raw               []byte
	Magic             string
	Command           uint16
	MAC               string
	IP                string
	Mask              string
	Gateway           string
	DNS               string
	Hostname          string
	Domain            string
	HWName            string
	HWType            byte
	HWRev             byte
	Firmware          string
	Ports             int
	RealPort          int
	RealPortEncrypted bool
	DHCP              bool
}

// Discover broadcasts ADDP probes and returns responses received before
// timeout. broadcast defaults to 255.255.255.255 when blank.
func Discover(broadcast string, timeout time.Duration) ([]ADDPResponse, error) {
	if broadcast == "" {
		broadcast = "255.255.255.255"
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	raddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", broadcast, ADDPPort))
	if err != nil {
		return nil, err
	}
	for _, m := range addpMagics {
		if _, err := conn.WriteToUDP(buildConfigRequest(m), raddr); err != nil {
			return nil, err
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	var out []ADDPResponse
	for range maxADDPReads {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		r, ok := parseADDPReply(buf[:n])
		if !ok {
			continue
		}
		r.From = src.IP.String()
		out = append(out, r)
	}
	return dedupeByHost(out), nil
}

// Query sends the three magic ADDP probes directly to one host and returns the
// best parsed response.
func Query(host string, timeout time.Duration) (*ADDPResponse, error) {
	conn, err := net.DialTimeout("udp", netaddr.DialHostPort(host, ADDPPort), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	for _, m := range addpMagics {
		if _, err := conn.Write(buildConfigRequest(m)); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, 2048)
	var best *ADDPResponse
	for range maxADDPReads {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		r, ok := parseADDPReply(buf[:n])
		if !ok {
			continue
		}
		r.From = host
		if betterADDP(r, best) {
			cp := r
			best = &cp
		}
	}
	if best == nil {
		return nil, fmt.Errorf("not a digi addp reply")
	}
	return best, nil
}

func buildConfigRequest(magic [4]byte) []byte {
	p := make([]byte, 14)
	copy(p[:4], magic[:])
	binary.BigEndian.PutUint16(p[4:6], addpCmdConfigReq)
	binary.BigEndian.PutUint16(p[6:8], 6)
	for i := 8; i < 14; i++ {
		p[i] = 0xff
	}
	return p
}

func parseADDPReply(b []byte) (ADDPResponse, bool) {
	r := ADDPResponse{Raw: append([]byte(nil), b...)}
	if len(b) < 8 {
		return r, false
	}
	if !isADDPMagic(b[:4]) {
		return r, false
	}
	r.Magic = string(b[:4])
	r.Command = binary.BigEndian.Uint16(b[4:6])
	plen := int(binary.BigEndian.Uint16(b[6:8]))
	if 8+plen > len(b) {
		return r, false
	}
	payload := b[8 : 8+plen]
	for i := 0; i+2 <= len(payload); {
		t := payload[i]
		l := int(payload[i+1])
		i += 2
		if i+l > len(payload) {
			break
		}
		v := payload[i : i+l]
		i += l
		switch t {
		case 0x01:
			if len(v) == 6 {
				r.MAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", v[0], v[1], v[2], v[3], v[4], v[5])
			}
		case 0x02:
			if len(v) == 4 {
				r.IP = net.IP(v).String()
			}
		case 0x03:
			if len(v) == 4 {
				r.Mask = net.IP(v).String()
			}
		case 0x04:
			r.Hostname = cleanASCII(v)
		case 0x05:
			r.Domain = cleanASCII(v)
		case 0x06:
			if len(v) == 1 {
				r.HWType = v[0]
			}
		case 0x07:
			if len(v) == 1 {
				r.HWRev = v[0]
			}
		case 0x08:
			r.Firmware = cleanASCII(v)
		case 0x0b:
			if len(v) == 4 {
				r.Gateway = net.IP(v).String()
			}
		case 0x0d:
			r.HWName = cleanASCII(v)
		case 0x0e:
			if len(v) == 4 {
				port := binary.BigEndian.Uint32(v)
				if port > 0 && port <= 65535 {
					r.RealPort = int(port)
				}
			}
		case 0x0f:
			if len(v) == 4 {
				r.DNS = net.IP(v).String()
			}
		case 0x10:
			if len(v) == 1 {
				r.DHCP = v[0] != 0
			}
		case 0x12:
			if len(v) == 1 {
				r.Ports = int(v[0])
			}
		case 0x13:
			if len(v) == 1 {
				r.RealPortEncrypted = v[0] != 0
			}
		}
	}
	if r.Hostname == "" && r.HWName == "" && r.MAC == "" && r.IP == "" {
		return r, false
	}
	return r, true
}

func betterADDP(cur ADDPResponse, best *ADDPResponse) bool {
	if best == nil {
		return true
	}
	sc := addpScore(cur)
	bs := addpScore(*best)
	if sc != bs {
		return sc > bs
	}
	return strings.Compare(cur.Magic, best.Magic) < 0
}

func addpScore(r ADDPResponse) int {
	s := 0
	if r.HWName != "" {
		s += 3
	}
	if r.Firmware != "" {
		s += 2
	}
	if r.MAC != "" {
		s += 2
	}
	if r.Hostname != "" {
		s += 1
	}
	if r.RealPort != 0 {
		s += 1
	}
	if r.Ports != 0 {
		s += 1
	}
	return s
}

func cleanASCII(b []byte) string {
	s := strings.TrimSpace(string(b))
	return strings.Trim(s, "\x00")
}

func isADDPMagic(b []byte) bool {
	if len(b) != 4 {
		return false
	}
	for _, m := range addpMagics {
		if b[0] == m[0] && b[1] == m[1] && b[2] == m[2] && b[3] == m[3] {
			return true
		}
	}
	return false
}

func dedupeByHost(in []ADDPResponse) []ADDPResponse {
	best := make(map[string]ADDPResponse)
	for _, r := range in {
		k := r.From
		if k == "" {
			if r.IP != "" {
				k = r.IP
			} else if r.MAC != "" {
				k = r.MAC
			} else {
				k = r.Magic + ":" + strconv.Itoa(addpScore(r))
			}
		}
		if cur, ok := best[k]; !ok || addpScore(r) > addpScore(cur) {
			best[k] = r
		}
	}
	out := make([]ADDPResponse, 0, len(best))
	for _, r := range best {
		out = append(out, r)
	}
	return out
}
