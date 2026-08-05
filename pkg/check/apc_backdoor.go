package check

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/apc"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

func init() {
	Register(Check{
		Name:        "http.apc.demoBackdoor",
		Description: "APC/Schneider NMC hidden jmm627 demo/service credential + PCNS control-endpoint exposure",
		Category:    "creds",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runAPCDemoBackdoor,
	})
	Register(Check{
		Name:        "http.apc.testDriveMarker",
		Description: "APC/Schneider NMC testdrive522.ini demo marker exposed",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runAPCTestDriveMarker,
	})
}

func runAPCTestDriveMarker(ctx context.Context, t *engine.Target) []engine.Finding {
	port := webPort(t)
	proto := webProto(t)
	if !webPortMaybeOpen(t, port) {
		return nil
	}
	url := hostPortURL(proto, t.Host, port, "/testdrive522.ini")
	st, ct, body := httpProbe(ctx, insecureWebClient(min(t.Timeout, 6*time.Second)), url, "")
	if st < 200 || st >= 300 {
		return nil
	}
	bl := strings.ToLower(strings.TrimSpace(string(body)))
	if bl == "" || strings.Contains(bl, "<html") {
		return nil
	}
	if !strings.Contains(bl, "testdrive") && !strings.Contains(bl, "jmm627") && !strings.Contains(bl, "demo") {
		return nil
	}
	if !strings.Contains(ct, "text") && !strings.Contains(ct, "octet-stream") && !looksLikeINI(bl) {
		return nil
	}
	return []engine.Finding{{
		Check: "http.apc.testDriveMarker", Category: "exposure", Risk: "medium",
		Port: port, Transport: "tcp", Protocol: proto,
		Fields: engine.F(
			"url", "/testdrive522.ini",
			"status", fmt.Sprintf("%d", st),
			"response", cleanSnippet(string(body))),
	}}
}

func looksLikeINI(s string) bool {
	return strings.Contains(s, "=") || (strings.Contains(s, "[") && strings.Contains(s, "]"))
}

func runAPCDemoBackdoor(ctx context.Context, t *engine.Target) []engine.Finding {
	port := webPort(t)
	proto := webProto(t)
	if !webPortMaybeOpen(t, port) {
		return nil
	}
	cl := apc.NewWithScheme(proto, t.Host, port, min(t.Timeout, 6*time.Second))
	var out []engine.Finding
	macontrol, snip, _ := cl.MacontrolExempt(ctx)
	present := macontrol != nil
	vendor := identityVendor(t)
	apcLike := vendor == "apc" || vendor == "schneiderpm" || present

	if !t.DisableLogins && apcLike {

		if ok, proof, err := cl.DemoLogin(ctx); err == nil && ok {
			f := engine.F("user", apc.DemoUser, "pass", apc.DemoPassword)
			if proof != "" {
				f = append(f, engine.Field{Key: "proof", Val: proof})
			}
			out = append(out, engine.Finding{
				Check: "http.apc.demoBackdoor", Category: "creds", Risk: "critical",
				Port: port, Transport: "tcp", Protocol: proto,
				Fields: f,
			})
		}

	} else if t.DisableLogins && apcLike {

		out = append(out, engine.Finding{
			Check: "http.apc.demoBackdoor", Category: "creds", Risk: "info",
			Port: port, Transport: "tcp", Protocol: proto,
			Fields: engine.F(
				"user", apc.DemoUser,
				"pass", apc.DemoPassword),
		})
	}

	if present {
		exempt, pst, psnip, _ := cl.MacontrolPostAuthExempt(ctx)
		risk := "info"
		fields := engine.F(
			"url", "/macontrol.htm",
			"response", cleanSnippet(snip),
			"MV", macontrol.MV,
			"PC", macontrol.PC,
			"DT", macontrol.DT,
			"TM", macontrol.TM,
			"SR", macontrol.SR,
			"SU", macontrol.SU,
			"RD", macontrol.RD,
			"CI", macontrol.CI,
			"CS", macontrol.CS,
			"MD", macontrol.MD,
		)
		if exempt {
			risk = "low"
			fields = append(fields,
				engine.Field{Key: "handler_path", Val: "/Forms/macontrol1"},
				engine.Field{Key: "handler_status", Val: fmt.Sprintf("%d", pst)},
				engine.Field{Key: "handlerReachable", Val: "true"},
				engine.Field{Key: "handler_response", Val: cleanSnippet(psnip)},
			)
		}
		out = append(out, engine.Finding{
			Check: "http.apc.pcnsControl", Category: "exposure", Risk: risk,
			Port: port, Transport: "tcp", Protocol: proto,
			Fields: fields,
		})
	}

	return out
}

func init() {
	RegisterExplain("http.apc.demoBackdoor", explainAPCDemoBackdoor)
	RegisterExplain("http.apc.pcnsControl", explainAPCPCNSControl)
	RegisterExplain("http.apc.testDriveMarker", explainAPCTestDriveMarker)
}

func explainAPCDemoBackdoor(host string, f engine.Finding) string {
	user := explainField(f, "user")
	pass := explainField(f, "pass")
	proof := explainField(f, "proof")
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nAPC NMC3 ships a hidden demo/service credential (`%s / %s`) accepted when\n", user, pass))
	b.WriteString("the `/testdrive522.ini` marker is present. This credential is fleet-wide and\n")
	b.WriteString("**survives normal password changes**.\n")
	if proof != "" {
		b.WriteString(fmt.Sprintf("\n**Proof:** `%s`\n", proof))
	}
	b.WriteString("\n**Validate the demo credential:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf(`curl -sk -c /tmp/apc.jar -X POST %s/Forms/login1 \`, baseURL),
		fmt.Sprintf(`  -d 'login_username=%s&login_password=%s&submit=Log+On' \`, user, pass),
		`  -o /dev/null -w '%{http_code} %{redirect_url}\n'`,
		"",
		"# Check for the demo marker:",
		fmt.Sprintf("curl -sk %s/testdrive522.ini", baseURL),
	))
	b.WriteString("\n\n**Impact:** Full NMC web access via a shared hardcoded credential not\n")
	b.WriteString("removable by changing the normal admin password.\n")
	return b.String()
}

func explainAPCPCNSControl(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe APC PCNS/PowerChute control endpoint `/macontrol.htm` is reachable without\n")
	b.WriteString("authentication. oobscan also sends a safe HEAD to `/Forms/macontrol1` to\n")
	b.WriteString("confirm the handler is pre-session reachable without sending a shutdown action.\n")
	b.WriteString("\n**Read the control page (read-only):**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk %s/macontrol.htm", baseURL),
		fmt.Sprintf("curl -skI %s/Forms/macontrol1 | head -n 12", baseURL),
	))
	return b.String()
}

func explainAPCTestDriveMarker(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nAPC NMC serves `/testdrive522.ini` pre-auth. This file is the marker that gates\n")
	b.WriteString("the hidden demo/service login path (`apc/jmm627`).\n")
	b.WriteString("\n**Validate marker exposure:**\n")
	b.WriteString(explainSh(fmt.Sprintf("curl -sk %s/testdrive522.ini", baseURL)))
	return b.String()
}
