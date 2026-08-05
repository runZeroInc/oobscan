package check

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func init() {
	Register(Check{
		Name:        "http.ami.preAuthRouteRead",
		Description: "AMI MegaRAC pre-auth admin route exposure differential (/api/settings/users, flash-progress)",
		Category:    "http",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runAMIPreAuthRouteRead,
	})
}

func runAMIPreAuthRouteRead(ctx context.Context, t *engine.Target) []engine.Finding {
	if !isAMIRedfish(t) {
		return nil
	}
	port := webPort(t)
	proto := webProto(t)
	if !webPortMaybeOpen(t, port) {
		return nil
	}
	client := insecureWebClient(min(t.Timeout, 5*time.Second))
	baselineStatus, _, _ := httpProbe(ctx, client, hostPortURL(proto, t.Host, port, "/api/session"), "")
	if baselineStatus == 0 {
		return nil
	}
	unauthBaseline := baselineStatus == http.StatusUnauthorized || baselineStatus == http.StatusForbidden || baselineStatus == http.StatusSeeOther
	if !unauthBaseline {
		return nil
	}
	checks := []struct {
		path   string
		marker []string
		risk   string
	}{
		{path: "/api/settings/users", marker: []string{"username", "userid", "role"}, risk: "high"},
		{path: "/api/maintenance/firmware/flash-progress", marker: []string{"progress", "cc", "status"}, risk: "medium"},
		{path: "/api/asrr/maintenance/BMC/flash-progress", marker: []string{"progress", "cc", "status"}, risk: "medium"},
	}
	for _, c := range checks {
		st, ct, body := httpProbe(ctx, client, hostPortURL(proto, t.Host, port, c.path), "")
		if st != http.StatusOK {
			continue
		}
		low := strings.ToLower(string(body))
		if strings.Contains(low, "<html") || strings.Contains(low, "login") {
			continue
		}
		if !strings.Contains(strings.ToLower(ct), "json") && !looksLikeJSON(body) {
			continue
		}
		matched := ""
		for _, m := range c.marker {
			if strings.Contains(low, m) {
				matched = m
				break
			}
		}
		if matched == "" {
			continue
		}
		proof := proofKV(
			"baselinePath", "/api/session",
			"baselineStatus", fmt.Sprintf("%d", baselineStatus),
			"path", c.path,
			"status", fmt.Sprintf("%d", st),
			"marker", matched)
		return []engine.Finding{{
			Check: "http.ami.preAuthRouteRead", Category: "http", Risk: c.risk,
			Port: port, Transport: "tcp", Protocol: proto,
			Fields: engine.F(
				"path", c.path,
				"baseline", "/api/session",
				"baseline_status", fmt.Sprintf("%d", baselineStatus),
				"status", fmt.Sprintf("%d", st),
				"marker", matched,
				"proof", proof,
				"response", cleanSnippet(string(body)),
			),
		}}
	}
	return nil
}

func init() {
	RegisterExplain("http.ami.preAuthRouteRead", explainAMIPreAuthRouteRead)
}

func explainAMIPreAuthRouteRead(host string, f engine.Finding) string {
	path := explainField(f, "path")
	if path == "" {
		path = "/api/settings/users"
	}
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nAMI MegaRAC exposed an admin API route pre-auth while /api/session remained\n")
	b.WriteString("unauthorized, confirming route-level auth bypass exposure.\n")
	b.WriteString("\n**Validate differential:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk -i %s/api/session | head -n 8", baseURL),
		fmt.Sprintf("curl -sk %s%s | python3 -m json.tool | head -n 30", baseURL, path),
	))
	return b.String()
}
