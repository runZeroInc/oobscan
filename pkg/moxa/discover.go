// Package moxa implements the Moxa NPort / ioLogik "DeviceSearch" discovery
// protocol (UDP/4800). Unauthenticated; returns model, firmware version,
// MAC, and IP of every NPort on the management LAN.
//
// Packet format (from Moxa's DeviceSearch v1.x documented source):
//
//	type(1) | opcode(1) | length(2 BE) | data...
//
// Opcode 0x01 + type 0x00 = query; reply opcode 0x81.
package moxa

import (
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

// fwVersionRE matches a Moxa firmware version token such as "V1.15" or
// "V3.4.2". Anchoring on a strict V<major>.<minor> shape avoids matching the
// stray capital V inside a model/hostname string (e.g. the "V"-free "NPort").
var fwVersionRE = regexp.MustCompile(`(?i)V(?:er\.?\s*)?\d+\.\d+(?:\.\d+)?[0-9A-Za-z.]*`)

// extractFirmware pulls a Moxa firmware version from the reply data using the
// strict V<major>.<minor> shape, or returns "" when none is present.
func extractFirmware(data []byte) string {
	if m := fwVersionRE.Find(data); m != nil {
		s := string(m)
		if len(s) > 0 && (s[0] == 'v' || s[0] == 'V') {
			return "V" + strings.TrimLeft(strings.TrimPrefix(strings.TrimPrefix(s, "V"), "v"), "erER. ")
		}
		return s
	}
	return ""
}

// DiscoveryPort is the DeviceSearch UDP port.
const DiscoveryPort = 4800

// maxDiscoverReads bounds the broadcast read loop so a host flooding the
// socket with DeviceSearch-shaped or junk datagrams cannot keep it busy until
// the deadline. A real LAN yields a bounded set of appliance replies.
const maxDiscoverReads = 128

// MagicQuery is the canonical DeviceSearch identify query.
//
// Verified against Metasploit's Moxa modules:
//
//	\x01\x00\x00\x08\x00\x00\x00\x00
//
// where byte 0 is function code 0x01 and byte 3 is payload length.
var MagicQuery = []byte{0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00}

// Response is one device's reply.
type Response struct {
	From     string
	Raw      []byte
	Model    string
	Firmware string
	Auth     string
	MAC      string
	Hostname string
	IP       string
	Serial   string
	Ports    int
}

// Discover broadcasts a DeviceSearch query. Broadcast defaults to
// 255.255.255.255 if blank.
func Discover(broadcast string, timeout time.Duration) ([]Response, error) {
	if broadcast == "" {
		broadcast = "255.255.255.255"
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	raddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", broadcast, DiscoveryPort))
	if err != nil {
		return nil, err
	}
	if _, err := conn.WriteToUDP(MagicQuery, raddr); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	var out []Response
	for range maxDiscoverReads {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if r, ok := parse(buf[:n]); ok {
			r.From = src.String()
			out = append(out, r)
		}
	}
	return out, nil
}

// Query hits a specific host on UDP/4800.
func Query(host string, timeout time.Duration) (*Response, error) {
	conn, err := net.DialTimeout("udp", netaddr.DialHostPort(host, DiscoveryPort), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(MagicQuery); err != nil {
		return nil, err
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	r, ok := parse(buf[:n])
	if !ok {
		return nil, fmt.Errorf("not a moxa reply")
	}
	r.From = host
	return &r, nil
}

func parse(b []byte) (Response, bool) {
	r := Response{Raw: append([]byte(nil), b...)}
	if rr, ok := parseCanonicalReply(r, b); ok {
		return rr, true
	}
	if rr, ok := parseLegacyReply(r, b); ok {
		return rr, true
	}
	return parseASCIIStatus(r, b)
}

func parseCanonicalReply(r Response, b []byte) (Response, bool) {
	if len(b) < 24 || b[0] != 0x81 {
		return r, false
	}
	// Metasploit and Talos docs describe a fixed 24-byte identify response.
	// Some devices may append bytes, so require a minimum length only.
	mac := b[14:20]
	ip := b[20:24]
	if slicesEqual(mac, []byte{0, 0, 0, 0, 0, 0}) || slicesEqual(mac, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		return r, false
	}
	r.MAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	r.IP = net.IP(ip).String()
	modelNum := int(binary.LittleEndian.Uint16(b[12:14]))
	if modelNum > 0 {
		r.Model = fmt.Sprintf("NPort %d", modelNum)
	}
	return r, true
}

func parseLegacyReply(r Response, b []byte) (Response, bool) {
	if len(b) < 4 {
		return r, false
	}
	if b[0] != 0x01 || b[1] != 0x81 {
		return r, false
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length+4 > len(b) {
		return r, false
	}
	data := b[4 : 4+length]
	r.Model, r.Serial = parseModelSerial(data)
	r.Ports = parsePortCount(data)
	macOff, mac := parseMAC(data)
	if mac != "" {
		r.MAC = mac
	}
	if macOff >= 0 && macOff+10 <= len(data) {
		ip := net.IP(data[macOff+6 : macOff+10]).String()
		if ip != "" && ip != "0.0.0.0" {
			r.IP = ip
		}
	}
	if r.IP == "" {
		r.IP = parseIPv4(data)
	}
	r.Firmware = extractFirmware(data)
	return r, true
}

func parseASCIIStatus(r Response, b []byte) (Response, bool) {
	text := strings.TrimSpace(string(b))
	if text == "" {
		return r, false
	}
	low := strings.ToLower(text)
	if !strings.Contains(low, "moxa") && !strings.Contains(low, "nport") && !strings.Contains(low, "oncell") {
		return r, false
	}
	var model string
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(strings.Trim(line, "\r"))
		if line == "" {
			continue
		}
		if model == "" && strings.Contains(strings.ToLower(line), "moxa") {
			model = line
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(parts[0]))
		v := strings.TrimSpace(parts[1])
		switch k {
		case "name", "hostname":
			if r.Hostname == "" {
				r.Hostname = v
			}
		case "status":
			if r.Auth == "" {
				r.Auth = v
			}
		case "mac", "mac address":
			if m := parseTextMAC(v); m != "" {
				r.MAC = m
			}
		case "ip", "ip address":
			if ip := net.ParseIP(v); ip != nil {
				r.IP = ip.String()
			}
		case "firmware", "software version", "version":
			if r.Firmware == "" {
				r.Firmware = extractFirmware([]byte(v))
			}
		}
	}
	if r.Model == "" {
		r.Model = model
	}
	if r.Firmware == "" {
		r.Firmware = extractFirmware([]byte(text))
	}
	if r.Model == "" && r.MAC == "" && r.Firmware == "" && r.Hostname == "" && r.IP == "" {
		return r, false
	}
	return r, true
}

func parseTextMAC(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.Contains(s, ":") {
		parts := strings.Split(s, ":")
		if len(parts) != 6 {
			return ""
		}
		for _, p := range parts {
			if len(p) != 2 {
				return ""
			}
		}
		return s
	}
	if len(s) != 12 {
		return ""
	}
	for i := range 12 {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s", s[0:2], s[2:4], s[4:6], s[6:8], s[8:10], s[10:12])
}

func parseMAC(data []byte) (int, string) {
	for _, off := range []int{8, 6} {
		if off+6 <= len(data) {
			if mac := moxaMAC(data[off : off+6]); mac != "" {
				return off, mac
			}
		}
	}
	// Fallback for variant layouts: first plausible OUI-bearing 6-byte run.
	for i := 0; i+6 <= len(data); i++ {
		if mac := moxaMAC(data[i : i+6]); mac != "" {
			return i, mac
		}
	}
	return -1, ""
}

func parseModelSerial(data []byte) (model, serial string) {
	runs := printableRuns(data)
	for _, s := range runs {
		if isLikelyModel(s) {
			model = s
			break
		}
	}
	if model == "" && len(runs) > 0 {
		model = runs[0]
	}
	for _, s := range runs {
		if s == model {
			continue
		}
		if isLikelySerial(s) {
			serial = s
			break
		}
	}
	return strings.TrimSpace(model), strings.TrimSpace(serial)
}

func printableRuns(b []byte) []string {
	var out []string
	start := -1
	for i, c := range b {
		if c >= 0x20 && c <= 0x7E {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			s := strings.Trim(string(b[start:i]), " \t\r\n\x00,;:")
			if len(s) >= 3 {
				out = append(out, s)
			}
			start = -1
		}
	}
	if start >= 0 {
		s := strings.Trim(string(b[start:]), " \t\r\n\x00,;:")
		if len(s) >= 3 {
			out = append(out, s)
		}
	}
	return out
}

func isLikelyModel(s string) bool {
	ls := strings.ToLower(s)
	for _, tok := range []string{"moxa", "nport", "mgate", "iologik", "eds", "oncell", "uc-", "ia"} {
		if strings.Contains(ls, tok) {
			return true
		}
	}
	return false
}

func isLikelySerial(s string) bool {
	if len(s) < 6 || len(s) > 32 {
		return false
	}
	ls := strings.ToLower(s)
	if isLikelyModel(ls) || strings.Contains(ls, "build") || strings.HasPrefix(ls, "v") {
		return false
	}
	hasDigit := false
	hasAlpha := false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			hasDigit = true
		}
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasAlpha = true
		}
		if !(r == '-' || r == '_' || r == '.' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return hasDigit && hasAlpha
}

func parsePortCount(data []byte) int {
	for _, off := range []int{4, 5} {
		if off < len(data) {
			v := int(data[off])
			if v >= 1 && v <= 32 {
				return v
			}
		}
	}
	return 0
}

func parseIPv4(data []byte) string {
	for i := 0; i+4 <= len(data); i++ {
		b := data[i : i+4]
		if b[0] == 0 || b[0] >= 224 {
			continue
		}
		if b[0] == 255 || b[1] == 255 || b[2] == 255 || b[3] == 255 {
			continue
		}
		if b[0] == 127 {
			continue
		}
		return net.IP(b).String()
	}
	return ""
}

var moxaOUIs = [][3]byte{
	{0x00, 0x90, 0xE8},
	{0x00, 0x0D, 0x22},
	{0x00, 0x0F, 0xC4},
	{0x00, 0x22, 0x5D},
	{0x00, 0x12, 0x77},
	{0x00, 0x1E, 0xC0},
	{0x00, 0x60, 0xE9},
	{0xE8, 0xE8, 0x75},
	{0x70, 0x82, 0x0E},
	{0xEC, 0xF0, 0x0E},
	{0xF4, 0xCB, 0x52},
}

func moxaMAC(mac []byte) string {
	if len(mac) != 6 {
		return ""
	}
	if slicesEqual(mac, []byte{0, 0, 0, 0, 0, 0}) || slicesEqual(mac, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		return ""
	}
	for _, oui := range moxaOUIs {
		if mac[0] == oui[0] && mac[1] == oui[1] && mac[2] == oui[2] {
			return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
		}
	}
	return ""
}

func slicesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (r Response) String() string {
	parts := []string{r.Model, r.Firmware, r.MAC, r.IP, r.Serial}
	if r.Ports > 0 {
		parts = append(parts, "ports="+strconv.Itoa(r.Ports))
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}
