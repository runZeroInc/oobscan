package check

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/telnet"
)

// Perle IOLAN serial console servers answer on TCP/10064, the diagnostic slot
// in their raw-serial port map (10000 + line number); a reachable pre-auth
// serial line is unauthenticated console access. The check only connects and
// reads what the service volunteers (no bytes sent, so it cannot drive a
// shell or change state), asserting critical only on a positive Perle match
// (diag slot, telnet-negotiating raw line, or IOLAN banner) since 10001 is a
// commonly reused port; it never asserts whether diag mode actually drops to
// a privileged shell. perleRawLinePorts also probes line 1 (10001/tcp) when
// already in the scan set, catching units with diag disabled but line 1 exposed.
const perleDiagPort = 10064

var perleRawLinePorts = []int{perleDiagPort, 10001}

func init() {
	Register(Check{
		Name:        "telnet.perleDiag",
		Description: "Perle IOLAN diagnostic / raw-line listener reachable on TCP/10064 or TCP/10001 (connect + banner only)",
		Category:    "exposure",
		Applies: Applicability{
			Vendors: []string{"perle"},
			Classes: []engine.DeviceClass{engine.ClassSerialConsole},
		},
		Enabled: true,
		Run:     runPerleDiagTelnet,
	})
	Register(Check{
		Name:        "http.perle.iolan.cgiUnauthLeak",
		Description: "Perle IOLAN unauthenticated CGI config leak (/manage.cgi, /tp-main.cgi, /tp-siab.cgi)",
		Category:    "exposure",
		Applies: Applicability{
			Vendors: []string{"perle"},
			Classes: []engine.DeviceClass{engine.ClassSerialConsole},
		},
		Enabled: true,
		Run:     runPerleCGIUnauthLeak,
	})
}

func runPerleCGIUnauthLeak(ctx context.Context, t *engine.Target) []engine.Finding {
	port := webPort(t)
	proto := webProto(t)
	if !webPortMaybeOpen(t, port) {
		return nil
	}
	client := insecureWebClient(min(t.Timeout, 6*time.Second))
	for _, p := range []string{"/manage.cgi", "/tp-main.cgi", "/tp-siab.cgi"} {
		st, _, body := httpProbe(ctx, client, hostPortURL(proto, t.Host, port, p), "")
		if st < 200 || st >= 300 {
			continue
		}
		bl := strings.ToLower(string(body))
		if strings.Contains(bl, "login") || strings.Contains(bl, "<form") {
			continue
		}
		if !strings.Contains(bl, "iolan") && !strings.Contains(bl, "trueport") && !strings.Contains(bl, "perle") {
			continue
		}
		return []engine.Finding{{
			Check: "http.perle.iolan.cgiUnauthLeak", Category: "exposure", Risk: "medium",
			Port: port, Transport: "tcp", Protocol: proto,
			Fields: engine.F(
				"url", p,
				"status", fmt.Sprintf("%d", st),
				"response", cleanSnippet(string(body))),
		}}
	}
	return nil
}

func runPerleDiagTelnet(ctx context.Context, t *engine.Target) []engine.Finding {
	// Zero-network-cost gate: only probe listeners that are in the scan set
	// (either an explicit --ports candidate or an already-discovered open
	// port). This keeps the check from adding a connect to every
	// serialConsole host.
	var out []engine.Finding
	for _, port := range perleRawLinePorts {
		if port != perleDiagPort && !isPerleRawLineTarget(t) {
			continue
		}
		if !portInScan(t, port) {
			continue
		}
		open, res := probePerlePort(ctx, t.Host, port, min(t.Timeout, 5*time.Second))
		if !open {
			continue
		}
		banner := string(res.Visible)
		iac := res.IACString()
		// False-positive guard: a Perle raw serial line / diag slot speaks telnet
		// framing (IAC negotiation) and, if anything, an IOLAN serial-console
		// banner. An SSH/HTTP/TLS banner means this port is not a Perle serial
		// listener (10001 is a commonly reused port), so do not report an
		// unrelated service as a Perle diagnostic exposure.
		if looksLikeObviousNonSerialBanner(banner) {
			continue
		}
		// Require a positive Perle identification before asserting the exposure: the
		// diag slot (10064 is Perle-specific), a telnet-negotiating raw line, or an
		// IOLAN/Perle banner. A silent, non-telnet port yields no assertion.
		matchedOn := ""
		switch {
		case port == perleDiagPort && isPerleRawLineTarget(t):
			// The diag slot is Perle-specific only when the device is already
			// identified as Perle: port 10064 alone (= 10000+line 64) is a generic
			// raw-TCP serial slot other console servers (Opengear/Lantronix/Digi)
			// also expose, so a bare-port match would misattribute them as a
			// critical Perle exposure. Non-Perle hosts fall through to the evidence
			// branches.
			matchedOn = "diag-port"
		case iac != "":
			matchedOn = "telnet-negotiation"
		case perleSerialBanner(banner):
			matchedOn = "iolan-banner"
		default:
			continue
		}
		proto := "perle-diag"
		if port != perleDiagPort {
			proto = "perle-line"
		}
		t.MarkOpen(port, "tcp", proto)
		fields := []string{
			"port", strconv.Itoa(port),
			"matchedOn", matchedOn,
			"banner", cleanSnippet(banner),
		}
		if line := perleLineForPort(port); line != "" {
			fields = append(fields, "line", line)
		}
		if iac != "" {
			fields = append(fields, "telnetIAC", iac)
		}
		// A pre-auth-reachable Perle serial line / diag slot is unauthenticated
		// access to the attached console (or, in diag mode, the device shell) - a
		// critical exposure, gated on the positive match above.
		out = append(out, engine.Finding{
			Check: "telnet.perleDiag", Category: "exposure", Risk: "critical",
			Port: port, Transport: "tcp", Protocol: "telnet",
			Fields: engine.F(fields...),
		})
	}
	return out
}

// perleSerialBanner reports whether a banner positively identifies a Perle IOLAN
// serial / diagnostic listener (rather than some unrelated service on a reused
// port).
func perleSerialBanner(banner string) bool {
	b := strings.ToLower(banner)
	return strings.Contains(b, "iolan") || strings.Contains(b, "perle") || strings.Contains(b, "trueport")
}

func isPerleRawLineTarget(t *engine.Target) bool {
	return t != nil && t.Identity != nil && strings.EqualFold(t.Identity.Vendor, "perle")
}

// perleLineForPort returns the Perle IOLAN "line N" label for a given raw-TCP
// port, or the empty string for the diag slot (which is not a serial line).
func perleLineForPort(port int) string {
	if port == perleDiagPort {
		return ""
	}
	if port > 10000 && port < 10100 {
		return "line-" + strconv.Itoa(port-10000)
	}
	return ""
}

// probePerlePort dials one Perle raw-TCP port and returns whether it accepted
// plus the full BannerResult. Both the diagnostic port (10064) and raw-line
// ports (10000+N) speak telnet-style IAC negotiation before printing
// anything, so the shared telnet helper answers it (WILL->DONT, DO->WONT),
// tracks which options were negotiated (via IACString), and -- if the banner
// is still empty after negotiation -- sends `\r\n` and waits 100ms for one
// more read, all bounded by the supplied timeout.
func probePerlePort(ctx context.Context, host string, port int, timeout time.Duration) (open bool, res telnet.BannerResult) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false, telnet.BannerResult{}
	}
	defer conn.Close()
	return true, telnet.ReadBannerWithNegotiate(conn, timeout)
}

func init() {
	RegisterExplain("telnet.perleDiag", explainPerleDiag)
	RegisterExplain("http.perle.iolan.cgiUnauthLeak", explainPerleCGIUnauthLeak)
}

func explainPerleDiag(host string, f engine.Finding) string {
	banner := explainField(f, "banner")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nPerle IOLAN diagnostic listener reachable on TCP/10064. When the device's\n")
	b.WriteString("diag mode is enabled this port may expose a privileged shell without auth.\n")
	if banner != "" {
		b.WriteString(fmt.Sprintf("\n**Banner:** `%s`\n", banner))
	}
	b.WriteString("\n**Connect and inspect:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("nc -w5 %s 10064", host),
		fmt.Sprintf("telnet %s 10064", host),
	))
	b.WriteString("\n\n**Impact:** If diag mode is enabled, TCP/10064 may provide unauthenticated\n")
	b.WriteString("shell access to the device OS.\n")
	return b.String()
}

func explainPerleCGIUnauthLeak(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nPerle IOLAN served a CGI configuration endpoint without authentication.\n")
	b.WriteString("\n**Validate unauth CGI exposure:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk %s/manage.cgi", baseURL),
		fmt.Sprintf("curl -sk %s/tp-main.cgi", baseURL),
		fmt.Sprintf("curl -sk %s/tp-siab.cgi", baseURL),
	))
	return b.String()
}
