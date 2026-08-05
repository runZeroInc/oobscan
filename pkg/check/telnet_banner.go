package check

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/telnet"
)

var telnetBannerPorts = []int{23, 10001, 10002, 10003, 2323, 992}

var lantronixRawSerialPorts = map[int]struct{}{10001: {}, 10002: {}, 10003: {}}

type telnetFingerprint struct {
	re      *regexp.Regexp
	vendor  string
	product string
	note    string
}

var telnetFingerprints = []telnetFingerprint{

	{regexp.MustCompile(`(?m)^\s*(?:Welcome to the SLC|SLC(?:8000|48|8|B48|B882)?)\s+(?:login:|console)`), "lantronix", "SLC", "SLC console manager login prompt"},
	{regexp.MustCompile(`(?m)^EMG(?:8500)?\s+login:`), "lantronix", "EMG", "EMG edge gateway login prompt"},
	{regexp.MustCompile(`(?m)^Spider(?:DUO)?\s+login:`), "lantronix", "Spider", "Spider KVM login prompt"},
	{regexp.MustCompile(`(?i)Press\s+Enter\s+(?:for\s+)?Setup\s+Mode`), "lantronix", "XPort", "Setup mode prompt (XPort/UDS/EDS)"},
	{regexp.MustCompile(`(?i)Lantronix\s+(?:UDS|EDS)`), "lantronix", "UDS/EDS", "Lantronix UDS/EDS device server"},
	{regexp.MustCompile(`(?i)MatchPort\s+(?:AR|SL|b/g)?`), "lantronix", "MatchPort", "MatchPort wireless serial server"},

	{regexp.MustCompile(`(?m)^IOLAN[-\w]*\s+(?:login:|#\s?)|Perle\s+IOLAN`), "perle", "IOLAN", "Perle IOLAN console prompt"},

	{regexp.MustCompile(`(?m)Model name\s*:\s*NPort|NPort\s+(?:5|6)\d{3}\b|MOXA\s+Console`), "moxa", "NPort", "NPort text-menu console"},
	{regexp.MustCompile(`(?m)NPort\s+IA(?:-)?5\d{3}`), "moxa", "NPort IA", "Industrial NPort"},

	{regexp.MustCompile(`(?i)PortServer\s+TS|Digi\s+PortServer`), "digi", "PortServer", "Digi PortServer TS/II/III"},
	{regexp.MustCompile(`(?i)Digi\s+Connect(?:Port)?|TransPort`), "digi", "Connect", "Digi ConnectPort / TransPort"},

	{regexp.MustCompile(`(?im)^(?:CM7\d{3}|IM7\d{3}|OM2\d{3}|ACM7\d{3}|Opengear)\b|pmshell>`), "opengear", "Console Manager", "Opengear CM/IM/OM/ACM"},

	{regexp.MustCompile(`User Access Verification`), "cisco", "IOS", "Cisco IOS EXEC/line prompt"},
	{regexp.MustCompile(`(?m)^(?:Trying\s+\S+ \.\.\. Open|\[Resuming connection \d+)`), "cisco", "IOS reverse-telnet", "Cisco IOS reverse-telnet line"},

	{regexp.MustCompile(`(?m)American Power Conversion|Network Management Card AOS|Access Control X\.\d|User Name\s*:\s*$`), "apc", "NMC", "APC AOS NMC/PDU login"},
	{regexp.MustCompile(`(?m)^\s*Rack PDU\s+\d|AP7\d{3}|AP8[69]\d{2}`), "apc", "Rack PDU", "APC Rack PDU chassis"},

	{regexp.MustCompile(`(?im)CyberPower(?: Systems)?|RMCARD\s?(?:20[35]|10[35])|Login Name\s*:\s*$`), "cyberpower", "RMCARD", "CyberPower RMCARD login"},

	{regexp.MustCompile(`(?i)Sentry\s+Switched\s+CDU|Switched CDU Version|Sentry:\s*$`), "servertech", "Sentry Switched CDU", "Sentry Switched CDU prompt"},
	{regexp.MustCompile(`(?i)Sentry\s+PRO\d?|PRO2 PDU`), "servertech", "Sentry PRO", "Sentry PRO2 PDU"},

	{regexp.MustCompile(`(?i)Sixnet|Six[- ]?TRAK|VersaTRAK|Red Lion|R-TRAK`), "redlion", "Sixnet SixTRAK/VersaTRAK", "Red Lion/Sixnet RTU telnet prompt"},

	{regexp.MustCompile(`MikroTik\s+v?\d|RouterOS\s+\d+\.\d|MikroTik Router`), "mikrotik", "RouterOS", "MikroTik RouterOS login"},
}

var telnetHoneypotHints = []*regexp.Regexp{

	regexp.MustCompile(`Ubuntu \d\d\.\d\d\.\d+ LTS`),

	regexp.MustCompile(`(?m)^BusyBox v\d+\.\d+`),

	regexp.MustCompile(`Siemens Simatic|Runtime Version`),
}

func init() {
	Register(Check{
		Name:        "tcp.telnetBanner",
		Description: "TCP telnet (23/10001/10002/10003/2323/992) banner capture with IAC-annotated negotiation and vendor fingerprint",
		Category:    "exposure",

		Enabled: true,
		Run:     runTelnetBanner,
	})
	RegisterExplain("tcp.telnetBanner", explainTelnetBanner)
}

func runTelnetBanner(ctx context.Context, t *engine.Target) []engine.Finding {
	if t.DisableLogins {

		return nil
	}
	var out []engine.Finding
	for _, p := range telnetBannerPorts {
		if !portInScan(t, p) {
			continue
		}
		timeout := min(t.Timeout, 5*time.Second)
		res, ok := telnetBannerDial(ctx, t.Host, p, timeout)
		if !ok {
			continue
		}
		f, ok := telnetBannerFinding(t, p, res)
		if !ok {
			continue
		}
		out = append(out, f)
	}
	return out
}

func telnetBannerFinding(t *engine.Target, port int, res telnet.BannerResult) (engine.Finding, bool) {
	lantronixRawPort := isLantronixRawSerialPort(port)

	proto := "telnet"
	if lantronixRawPort {
		proto = "raw-serial"
	}
	t.MarkOpen(port, "tcp", proto)
	visible := string(res.Visible)

	if lantronixRawPort && looksLikeObviousNonSerialBanner(visible) {
		return engine.Finding{}, false
	}
	clean := sanitizeBanner(visible)
	printable := countPrintableRunes(visible)

	if printable < 2 {
		if lantronixRawPort {
			return engine.Finding{}, false
		}
		fields := []string{
			"port", strconv.Itoa(port),
			"noBannerReason", "empty_read",
			"proof", telnetBannerProof(port, res, printable),
		}
		if iac := res.IACString(); iac != "" {
			fields = append(fields, "telnetIAC", iac)
		}
		if len(res.Raw) > 0 {
			fields = append(fields, "raw", hex.EncodeToString(res.Raw))
		}
		return engine.Finding{
			Check: "tcp.telnetBanner", Category: "exposure", Risk: "info",
			Port: port, Transport: "tcp", Protocol: "telnet",
			Fields: engine.F(fields...),
		}, true
	}

	honeypot := matchTelnetHoneypot(visible)
	fp := matchTelnetFingerprint(visible)
	lantronixRawExposure := isLantronixRawSerialExposure(t, port, res.Visible)

	risk := "info"
	if lantronixRawExposure {
		risk = "high"
	}

	fields := []string{
		"port", strconv.Itoa(port),
		"banner", cleanSnippet(clean),
		"proof", telnetBannerProof(port, res, printable),
	}
	if iac := res.IACString(); iac != "" {
		fields = append(fields, "telnetIAC", iac)
	}
	if fp != nil {
		fields = append(fields, "vendor", fp.vendor, "product", fp.product)
		if fp.note != "" {
			fields = append(fields, "detection", fp.note)
		}
	}
	if honeypot {
		fields = append(fields, "honeypot", "true")
	}
	if lantronixRawExposure {
		fields = append(fields, "detection", "lantronix raw serial passthrough banner")
	}
	if res.SentEnter {
		fields = append(fields, "sentEnter", "true")
	}
	if len(res.Raw) > 0 {
		fields = append(fields, "raw", hex.EncodeToString(res.Raw))
	}
	return engine.Finding{
		Check: "tcp.telnetBanner", Category: "exposure", Risk: risk,
		Port: port, Transport: "tcp", Protocol: "telnet",
		Fields: engine.F(fields...),
	}, true
}

func telnetBannerProof(port int, res telnet.BannerResult, printable int) string {
	return proofKV(
		"tcpPort", strconv.Itoa(port),
		"bytesRead", strconv.Itoa(len(res.Raw)),
		"printableRunes", strconv.Itoa(printable),
		"telnetIAC", res.IACString(),
		"sentEnter", strconv.FormatBool(res.SentEnter),
	)
}

func isLantronixRawSerialExposure(t *engine.Target, port int, banner []byte) bool {
	if len(banner) == 0 {
		return false
	}
	if !isLantronixRawSerialPort(port) {
		return false
	}
	if t == nil || t.Identity == nil || t.Identity.Vendor != "lantronix" {
		return false
	}
	clean := sanitizeBanner(string(banner))
	return !looksLikeObviousNonSerialBanner(clean) && rawSerialBannerEvidence(banner)
}

func rawSerialBannerEvidence(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	terminalSafe := 0
	longestRun := 0
	currentRun := 0
	for _, value := range raw {
		switch {
		case value >= 0x20 && value < 0x7f:
			terminalSafe++
			currentRun++
			longestRun = max(longestRun, currentRun)
		case value == '\r' || value == '\n' || value == '\t' || value == '\b' || value == 0x1b:
			terminalSafe++
			currentRun = 0
		default:
			currentRun = 0
		}
	}
	if terminalSafe*100 < len(raw)*85 || longestRun < 8 {
		return false
	}

	text := sanitizeBanner(string(raw))
	if rawSerialConsoleMarkerRE.MatchString(text) {
		return true
	}
	return len(rawSerialWordRE.FindAllString(text, 2)) >= 2
}

var (
	rawSerialConsoleMarkerRE = regexp.MustCompile(`(?i)\b(?:login|user\s*name|password|sign\s+on|console|ready|welcome|command|controller|corporation|version|press\s+enter|error)\b`)
	rawSerialWordRE          = regexp.MustCompile(`[A-Za-z]{3,}`)
)

func isLantronixRawSerialPort(port int) bool {
	_, ok := lantronixRawSerialPorts[port]
	return ok
}

func looksLikeObviousNonSerialBanner(banner string) bool {
	trim := strings.TrimSpace(strings.ToLower(banner))
	if trim == "" {
		return false
	}
	for _, prefix := range []string{
		"http/1.",
		"http/2",
		"<html",
		"<!doctype",
		"ssh-",
		"220 ",
		"220-",
		"smtp",
		"ftp",
	} {
		if strings.HasPrefix(trim, prefix) {
			return true
		}
	}
	return strings.Contains(trim, "server:") && strings.Contains(trim, "content-")
}

func telnetBannerDial(ctx context.Context, host string, port int, timeout time.Duration) (telnet.BannerResult, bool) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return telnet.BannerResult{}, false
	}
	defer conn.Close()

	if isLantronixRawSerialPort(port) {
		return telnet.ReadBannerPassive(conn, timeout), true
	}
	return telnet.ReadBannerWithNegotiate(conn, timeout), true
}

func matchTelnetFingerprint(banner string) *telnetFingerprint {
	if banner == "" {
		return nil
	}
	for i := range telnetFingerprints {
		if telnetFingerprints[i].re.MatchString(banner) {
			return &telnetFingerprints[i]
		}
	}
	return nil
}

func matchTelnetHoneypot(banner string) bool {
	if banner == "" {
		return false
	}
	for _, re := range telnetHoneypotHints {
		if re.MatchString(banner) {
			return true
		}
	}
	return false
}

func explainTelnetBanner(host string, f engine.Finding) string {
	banner := explainField(f, "banner")
	vendor := explainField(f, "vendor")
	product := explainField(f, "product")
	honeypot := explainField(f, "honeypot") == "true"
	port := explainField(f, "port")
	if port == "" {
		port = "23"
	}
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	if honeypot {
		fmt.Fprintf(&b, "\nThe TCP/%s responder produced a banner that matches a known **honeypot**\n", port)
		b.WriteString("profile (Cowrie / Telnet-IoT-honeypot / Conpot). The service is unlikely to be a\n")
		b.WriteString("real console; treat the host with suspicion but do not raise vendor confidence.\n")
	} else if vendor != "" {
		fmt.Fprintf(&b, "\nTCP/%s answers with a **%s %s** telnet banner. Telnet is a cleartext\n", port, vendor, product)
		b.WriteString("protocol; any credentials sent to this port travel unencrypted and are\n")
		b.WriteString("visible to on-path observers. Prefer SSH where the device supports it.\n")
	} else {
		fmt.Fprintf(&b, "\nTCP/%s answers with a telnet banner. Telnet is a cleartext protocol;\n", port)
		b.WriteString("credentials sent to this port travel unencrypted.\n")
	}
	if banner != "" {
		b.WriteString("\n**Captured banner:**\n")
		b.WriteString(explainSh(banner))
	}
	b.WriteString("\n**Reproduce the connection (banner only, no login):**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("nc -w 3 %s %s", host, port),
	))
	return b.String()
}
