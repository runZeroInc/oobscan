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

// tcp.telnetBanner captures the telnet banner from TCP/23 (or the alternates
// 2323/992 and the common serial-console passthrough listeners), classifies
// the vendor where it can, and surfaces the negotiated banner as evidence; it
// fires only when one of those ports is in the scan's candidate set. IAC
// negotiation is answered rather than stripped so negotiation-first servers
// emit their banner, and a silent listener gets one CRLF wake-up before the
// retry read; no login or other write is sent. The fingerprint table is
// deliberately conservative -- honeypots mimic several of these, so it never
// keys on a generic prompt like `login:` or `BusyBox v` alone -- and findings
// are info by default, escalating to medium only on a vendor-specific prompt
// together with an authentication prompt.

// telnetBannerPorts is the ordered list of ports we consider for the check.
// The default candidate set in cmd/scan.go includes 23/tcp plus Lantronix's
// common raw serial passthrough ports 10001/tcp, 10002/tcp, and 10003/tcp; 2323/tcp and
// 992/tcp are only probed when the user explicitly asks for them.
var telnetBannerPorts = []int{23, 10001, 10002, 10003, 2323, 992}

var lantronixRawSerialPorts = map[int]struct{}{10001: {}, 10002: {}, 10003: {}}

// telnetFingerprint pairs a compiled regex with the vendor/product slugs
// used elsewhere in oobscan. The regex is matched against the visible
// (non-IAC) portion of the banner; the annotated form is preserved in the
// finding.
type telnetFingerprint struct {
	re      *regexp.Regexp
	vendor  string
	product string
	note    string
}

// telnetFingerprints is the vendor detection table. Ordered so the most
// distinctive matches win first; the runner stops on the first hit.
var telnetFingerprints = []telnetFingerprint{
	// Lantronix SLC/SLB console managers -- literal hostname prefix in the login prompt.
	{regexp.MustCompile(`(?m)^\s*(?:Welcome to the SLC|SLC(?:8000|48|8|B48|B882)?)\s+(?:login:|console)`), "lantronix", "SLC", "SLC console manager login prompt"},
	{regexp.MustCompile(`(?m)^EMG(?:8500)?\s+login:`), "lantronix", "EMG", "EMG edge gateway login prompt"},
	{regexp.MustCompile(`(?m)^Spider(?:DUO)?\s+login:`), "lantronix", "Spider", "Spider KVM login prompt"},
	{regexp.MustCompile(`(?i)Press\s+Enter\s+(?:for\s+)?Setup\s+Mode`), "lantronix", "XPort", "Setup mode prompt (XPort/UDS/EDS)"},
	{regexp.MustCompile(`(?i)Lantronix\s+(?:UDS|EDS)`), "lantronix", "UDS/EDS", "Lantronix UDS/EDS device server"},
	{regexp.MustCompile(`(?i)MatchPort\s+(?:AR|SL|b/g)?`), "lantronix", "MatchPort", "MatchPort wireless serial server"},
	// Perle IOLAN -- hostname prefix and post-auth `#` prompt.
	{regexp.MustCompile(`(?m)^IOLAN[-\w]*\s+(?:login:|#\s?)|Perle\s+IOLAN`), "perle", "IOLAN", "Perle IOLAN console prompt"},
	// Moxa NPort -- highly distinctive text-menu console.
	{regexp.MustCompile(`(?m)Model name\s*:\s*NPort|NPort\s+(?:5|6)\d{3}\b|MOXA\s+Console`), "moxa", "NPort", "NPort text-menu console"},
	{regexp.MustCompile(`(?m)NPort\s+IA(?:-)?5\d{3}`), "moxa", "NPort IA", "Industrial NPort"},
	// Digi PortServer / Connect ES.
	{regexp.MustCompile(`(?i)PortServer\s+TS|Digi\s+PortServer`), "digi", "PortServer", "Digi PortServer TS/II/III"},
	{regexp.MustCompile(`(?i)Digi\s+Connect(?:Port)?|TransPort`), "digi", "Connect", "Digi ConnectPort / TransPort"},
	// Opengear console managers (rarely have telnet on by default).
	{regexp.MustCompile(`(?im)^(?:CM7\d{3}|IM7\d{3}|OM2\d{3}|ACM7\d{3}|Opengear)\b|pmshell>`), "opengear", "Console Manager", "Opengear CM/IM/OM/ACM"},
	// Cisco IOS reverse-telnet / EXEC.
	{regexp.MustCompile(`User Access Verification`), "cisco", "IOS", "Cisco IOS EXEC/line prompt"},
	{regexp.MustCompile(`(?m)^(?:Trying\s+\S+ \.\.\. Open|\[Resuming connection \d+)`), "cisco", "IOS reverse-telnet", "Cisco IOS reverse-telnet line"},
	// APC AOS / Rack PDU / NMC.
	{regexp.MustCompile(`(?m)American Power Conversion|Network Management Card AOS|Access Control X\.\d|User Name\s*:\s*$`), "apc", "NMC", "APC AOS NMC/PDU login"},
	{regexp.MustCompile(`(?m)^\s*Rack PDU\s+\d|AP7\d{3}|AP8[69]\d{2}`), "apc", "Rack PDU", "APC Rack PDU chassis"},
	// CyberPower RMCARD.
	{regexp.MustCompile(`(?im)CyberPower(?: Systems)?|RMCARD\s?(?:20[35]|10[35])|Login Name\s*:\s*$`), "cyberpower", "RMCARD", "CyberPower RMCARD login"},
	// Servertech Sentry Switched CDU.
	{regexp.MustCompile(`(?i)Sentry\s+Switched\s+CDU|Switched CDU Version|Sentry:\s*$`), "servertech", "Sentry Switched CDU", "Sentry Switched CDU prompt"},
	{regexp.MustCompile(`(?i)Sentry\s+PRO\d?|PRO2 PDU`), "servertech", "Sentry PRO", "Sentry PRO2 PDU"},
	// Red Lion / Sixnet SixTRAK / VersaTRAK industrial RTU / gateway.
	{regexp.MustCompile(`(?i)Sixnet|Six[- ]?TRAK|VersaTRAK|Red Lion|R-TRAK`), "redlion", "Sixnet SixTRAK/VersaTRAK", "Red Lion/Sixnet RTU telnet prompt"},
	// MikroTik RouterOS (also frequently seen on honeypots -- see honeypot pattern below).
	{regexp.MustCompile(`MikroTik\s+v?\d|RouterOS\s+\d+\.\d|MikroTik Router`), "mikrotik", "RouterOS", "MikroTik RouterOS login"},
}

// telnetHoneypotHints are regex fragments strongly associated with Cowrie /
// Telnet-IoT-honeypot / Conpot profiles. A match downgrades confidence and
// caps the finding at info even if a vendor pattern also matched.
var telnetHoneypotHints = []*regexp.Regexp{
	// Cowrie's stock Ubuntu-issue banner is a highly reliable honeypot signal.
	regexp.MustCompile(`Ubuntu \d\d\.\d\d\.\d+ LTS`),
	// BusyBox banner alone (post-auth) -- Cowrie fakes this; do not treat as vendor evidence.
	regexp.MustCompile(`(?m)^BusyBox v\d+\.\d+`),
	// Conpot's stock IEC-104 / Siemens honeypot banner (rare on 23 but seen).
	regexp.MustCompile(`Siemens Simatic|Runtime Version`),
}

func init() {
	Register(Check{
		Name:        "tcp.telnetBanner",
		Description: "TCP telnet (23/10001/10002/10003/2323/992) banner capture with IAC-annotated negotiation and vendor fingerprint",
		Category:    "exposure",
		// No Applies filter: this fires whenever a listed telnet port is in
		// the scan set. Vendor gating happens after the banner comes back.
		Enabled: true,
		Run:     runTelnetBanner,
	})
	RegisterExplain("tcp.telnetBanner", explainTelnetBanner)
}

func runTelnetBanner(ctx context.Context, t *engine.Target) []engine.Finding {
	if t.DisableLogins {
		// tcp.telnetBanner never submits credentials, but the DisableLogins
		// switch is the "no active writes" master toggle; SendEnter (\r\n)
		// is arguably a probe write, so honour the flag.
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
	// Raw serial-over-IP passthrough ports (10001-3) are read passively precisely
	// because they are not telnet; label the service/protocol truthfully rather
	// than stamping them "telnet".
	proto := "telnet"
	if lantronixRawPort {
		proto = "raw-serial"
	}
	t.MarkOpen(port, "tcp", proto)
	visible := string(res.Visible)
	// An SSH/HTTP responder sitting on a reused raw-serial port is not a serial or
	// telnet banner (6k+ SSH daemons on 10001-3 were mislabeled telnet). Keep the
	// port marked (above) but do not emit a telnet-banner finding for it.
	if lantronixRawPort && looksLikeObviousNonSerialBanner(visible) {
		return engine.Finding{}, false
	}
	clean := sanitizeBanner(visible)
	printable := countPrintableRunes(visible)

	// Empty or non-printable read: still emit an info finding recording the
	// listener is reachable (useful in the exposure matrix), but do not try
	// to fingerprint.
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

	// Risk gating:
	//   - structured, predominantly printable Lantronix raw-serial console text: high
	//   - everything else (vendor match, auth prompt, honeypot, plain banner): info
	// A captured telnet banner is an exposure/reachability indicator, not a finding
	// in itself - the vendor/product/detection fields carry the value. Only the
	// Lantronix raw-serial case with readable prompt/text evidence leaks actual
	// console content and stays high; opaque device bytes remain info for triage.
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

// telnetBannerProof records the read as it happened: which port answered, how
// many bytes came back, how much of that was printable, whether the server
// negotiated telnet options and whether the CRLF wake-up was sent. It is built
// on both the banner and the empty-read arm, because a silent listener is a
// measurement too and a proof present on only one arm is the same value on
// every host that reaches it.
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
	// Raw serial-over-IP passthrough ports are transparent to the attached device
	// console, so read passively (no IAC replies, no "\r\n" wake-up) to avoid
	// injecting keystrokes downstream. Real telnet ports get full negotiation.
	if isLantronixRawSerialPort(port) {
		return telnet.ReadBannerPassive(conn, timeout), true
	}
	return telnet.ReadBannerWithNegotiate(conn, timeout), true
}

// matchTelnetFingerprint runs the vendor regex table against the visible
// banner and returns the first hit, or nil.
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

// matchTelnetHoneypot returns true if the banner carries a signal strongly
// associated with a known honeypot profile.
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
