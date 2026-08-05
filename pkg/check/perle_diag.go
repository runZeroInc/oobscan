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

		if looksLikeObviousNonSerialBanner(banner) {
			continue
		}

		matchedOn := ""
		switch {
		case port == perleDiagPort && isPerleRawLineTarget(t):

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

		out = append(out, engine.Finding{
			Check: "telnet.perleDiag", Category: "exposure", Risk: "critical",
			Port: port, Transport: "tcp", Protocol: "telnet",
			Fields: engine.F(fields...),
		})
	}
	return out
}

func perleSerialBanner(banner string) bool {
	b := strings.ToLower(banner)
	return strings.Contains(b, "iolan") || strings.Contains(b, "perle") || strings.Contains(b, "trueport")
}

func isPerleRawLineTarget(t *engine.Target) bool {
	return t != nil && t.Identity != nil && strings.EqualFold(t.Identity.Vendor, "perle")
}

func perleLineForPort(port int) string {
	if port == perleDiagPort {
		return ""
	}
	if port > 10000 && port < 10100 {
		return "line-" + strconv.Itoa(port-10000)
	}
	return ""
}

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
