// Package lantronix speaks just enough of Lantronix's UDP/30718 "Setup
// Protocol" to discover XPort/UDS/SLC devices and pull the device banner
// pre-auth. The protocol is proprietary but documented in
// "Lantronix Protocols Application Note" (2007) -- it's an unauthenticated
// broadcast discovery that still works on most mgmt LANs today.
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

// DiscoveryPort is the Lantronix Setup Protocol port.
const DiscoveryPort = 30718

// SetupTelnetPort is the legacy Lantronix setup telnet/serial config service.
const SetupTelnetPort = 9999

// maxDiscoverReads bounds the broadcast read loop so a host flooding the
// socket with reply-shaped or junk datagrams cannot keep it busy until the
// deadline. A real LAN yields a bounded set of appliance replies.
const maxDiscoverReads = 128

// MagicQuery is the well-known 4-byte "are you a Lantronix?" probe
// (00 00 00 F6 -- the "Query" command in Setup Protocol v1).
var MagicQuery = []byte{0x00, 0x00, 0x00, 0xF6}

// Response is the parsed reply.
type Response struct {
	From     string
	Raw      []byte
	MAC      string
	Type     byte // product type byte
	Firmware string
	Model    string // derived from Type code
}

// typeCode -> human model, from Lantronix public docs.
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

// Discover sends a broadcast query and returns all devices that reply
// within timeout. Requires the caller to have broadcast permission on the
// outbound interface.
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

// Query hits a single host directly.
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

// ProbeSetupTelnet attempts a lightweight read of Lantronix setup service on
// TCP/9999 and returns a cleaned banner (if any), the IAC negotiation summary
// (e.g. "will-echo,will-suppress-go-ahead"), and a heuristic match bool.
// The setup service speaks telnet on connect: it sends an IAC option offer
// (WILL Echo / DO Suppress-GA on most models) and then waits for the client
// to either answer or press Enter before it prints the "MAC address: ..."
// setup menu. We use the shared telnet helper to answer negotiation and
// coax out the real visible banner; IAC sequences are reported separately
// in the iacSummary return value rather than interleaved in the banner.
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

// stripTelnetIAC removes RFC 854 telnet command sequences from a banner. It is
// retained for legacy call sites and tests; new probes should prefer the
// shared `pkg/telnet` helper, which annotates IAC exchanges as
// `<VERB Option>` tokens instead of dropping them.
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
	// Typical reply: 4-byte header echoing magic reply + product string +
	// MAC address near the end. Layouts vary per model, so we do best-effort
	// extraction rather than demand a single format.
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
		// MAC is often the last 6 bytes of the reply, but layouts vary per
		// model, so only trust it when the OUI is one Lantronix actually owns.
		// This avoids fabricating a MAC from padding on longer/variant replies.
		if mac := lantronixMAC(b[len(b)-6:]); mac != "" {
			r.MAC = mac
		}
	}
	if idx := bytes.Index(b, []byte{0x56, 0x65, 0x72}); idx >= 0 && idx+12 <= len(b) { // "Ver"
		// idx+12 <= len(b): b[idx+3:idx+12] is valid when the "Ver..." field ends
		// exactly at the last byte.
		r.Firmware = string(bytes.TrimRight(b[idx+3:idx+12], "\x00 "))
	}
	_ = hex.EncodeToString // keep import for future debugging
	return r
}

// lantronixOUIs are MAC OUI prefixes registered to Lantronix (IEEE). Only a
// candidate whose first three bytes match one of these is trusted as a real
// MAC, so variant/longer replies don't fabricate a MAC from trailing padding.
var lantronixOUIs = [][3]byte{
	{0x00, 0x20, 0x4A}, // Lantronix
	{0x00, 0x80, 0xA3}, // Lantronix
}

// lantronixMAC formats a 6-byte candidate as a MAC string only when its OUI is
// a registered Lantronix prefix; otherwise it returns "".
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
