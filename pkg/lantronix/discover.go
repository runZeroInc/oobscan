package lantronix

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/netaddr"
	"github.com/runZeroInc/oobscan/pkg/telnet"
)

const DiscoveryPort = 30718

const SetupTelnetPort = 9999

const maxDiscoverReads = 128

var MagicQuery = []byte{0x00, 0x00, 0x00, 0xF6}

type Response struct {
	From     string
	Raw      []byte
	MAC      string
	Type     byte
	Firmware string
	Model    string
}

var modelByType = map[byte]string{
	0x01: "LAN50",
	0x02: "LAN5000",
	0x0A: "XPort",
	0x0B: "MatchPort",
	0x0C: "xPico",
	0x0D: "WiPort",
	0x0E: "XPress-DR",
	0x0F: "SecureBox",
	0x10: "UDS1100",
	0x12: "UDS2100",
	0x14: "EDS",
	0x1A: "SLC",
}

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
	buf := make([]byte, 1500)
	var out []Response
	for range maxDiscoverReads {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		out = append(out, parse(buf[:n], src.String()))
	}
	return out, nil
}

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
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	r := parse(buf[:n], host)
	return &r, nil
}

func ProbeSetupTelnet(host string, timeout time.Duration) (banner, iacSummary string, looksLantronix bool, err error) {
	c, err := net.DialTimeout("tcp", netaddr.DialHostPort(host, SetupTelnetPort), timeout)
	if err != nil {
		return "", "", false, err
	}
	defer c.Close()

	res := telnet.ReadBannerWithNegotiate(c, timeout)
	clean := strings.TrimSpace(string(res.Visible))
	if clean == "" {
		return "", res.IACString(), false, nil
	}
	low := strings.ToLower(clean)
	return clean, res.IACString(),
		strings.Contains(low, "lantronix") || strings.Contains(low, "xport") || strings.Contains(low, "uds") || strings.Contains(low, "setup mode"), nil
}

func stripTelnetIAC(b []byte) string {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == 0xff && i+2 < len(b) {
			i += 2
			continue
		}
		if b[i] >= 0x20 || b[i] == '\n' || b[i] == '\r' || b[i] == '\t' {
			out = append(out, b[i])
		}
	}
	return string(out)
}

func parse(b []byte, from string) Response {
	r := Response{From: from, Raw: append([]byte(nil), b...)}

	if len(b) >= 6 {
		r.Type = b[4]
		if m, ok := modelByType[r.Type]; ok {
			r.Model = m
		}
	}
	if bytes.Contains(b, []byte("Lantronix")) {
		if r.Model == "" {
			r.Model = "Lantronix"
		}
	}
	if len(b) >= 30 {

		if mac := lantronixMAC(b[len(b)-6:]); mac != "" {
			r.MAC = mac
		}
	}
	if idx := bytes.Index(b, []byte{0x56, 0x65, 0x72}); idx >= 0 && idx+12 <= len(b) {

		r.Firmware = string(bytes.TrimRight(b[idx+3:idx+12], "\x00 "))
	}
	_ = hex.EncodeToString
	return r
}

var lantronixOUIs = [][3]byte{
	{0x00, 0x20, 0x4A},
	{0x00, 0x80, 0xA3},
}

func lantronixMAC(mac []byte) string {
	if len(mac) != 6 {
		return ""
	}
	for _, oui := range lantronixOUIs {
		if mac[0] == oui[0] && mac[1] == oui[1] && mac[2] == oui[2] {
			return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
		}
	}
	return ""
}
