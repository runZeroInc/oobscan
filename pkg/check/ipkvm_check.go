package check

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/httpscan"
)

func init() {
	Register(Check{
		Name:        "ipkvm.posture",
		Description: "IP-KVM appliance unauthenticated-access posture (PiKVM/JetKVM/NanoKVM/TinyPilot/ES3)",
		Category:    "creds",
		Applies:     Applicability{Classes: []engine.DeviceClass{engine.ClassKVM}},
		Enabled:     true,
		Run:         runIPKVMPosture,
	})
}

func runIPKVMPosture(ctx context.Context, t *engine.Target) []engine.Finding {

	port := webPort(t)
	proto := webProto(t)

	per := max(t.Timeout, httpSurfaceMinPerRequest)

	sweepCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	rep, err := httpscan.ProbeHostCtxForVendorsScheme(sweepCtx, t.Host, port, proto, per)
	if err == nil && rep != nil {
		t.SetEvidence("http", rep)
	}

	var out []engine.Finding

	if rep != nil {
		for _, ef := range rep.HTTPFindings {
			if !isIPKVMEndpoint(ef.Path) {
				continue
			}
			rr := pickHTTPRequest(ef)
			if rr.Status < 200 || rr.Status >= 300 || strings.TrimSpace(rr.Snippet) == "" {
				continue
			}

			evidence, ok := ipkvmUnauthData(rr.Snippet)
			if !ok {
				continue
			}
			low := strings.ToLower(rr.Snippet)
			risk := "medium"
			if strings.Contains(low, "nopassword") || strings.Contains(low, "\"password\":false") || strings.Contains(low, "auth\":\"none") {
				risk = "high"
			}
			out = append(out, engine.Finding{
				Check: "ipkvm.noAuth", Category: "creds", Risk: risk,

				Port: port, Transport: "tcp", Protocol: proto,
				Fields: engine.F(
					"url", rr.URL,
					"httpStatus", fmt.Sprintf("%d", rr.Status),
					"bodyEvidence", evidence,
					"response", cleanSnippet(rr.Snippet)),
			})
			break
		}
	}

	return out
}

var ipkvmApplianceMarkers = []string{
	"kvmd", "pikvm", "jetkvm", "nanokvm", "tinypilot", "blikvm",
	"gl-inet", "glinet", "comet", "yeeso", "openterface",
	"streamer", "hid", "atx", "msd", "vnc_enabled", "ustreamer",
}

func ipkvmUnauthData(snippet string) (string, bool) {
	s := strings.TrimSpace(snippet)
	if s == "" {
		return "", false
	}
	low := strings.ToLower(s)

	if strings.HasPrefix(low, "<!doctype") || strings.HasPrefix(low, "<html") || strings.HasPrefix(low, "<?xml") {
		for _, m := range ipkvmApplianceMarkers {
			if strings.Contains(low, m) {
				return "html naming " + m, true
			}
		}
		return "", false
	}

	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		return "json body", true
	}

	if strings.Contains(low, "=") && (strings.Contains(low, "var ") || strings.Contains(low, "window.") || strings.Contains(low, "const ")) {
		return "js config object", true
	}

	for _, m := range ipkvmApplianceMarkers {
		if strings.Contains(low, m) {
			return "body naming " + m, true
		}
	}
	return "", false
}

func isIPKVMEndpoint(path string) bool {
	switch path {
	case "/device/ui-config.js", "/device/status",
		"/api/vm/info", "/api/network/wifi",
		"/api/info", "/api/status", "/api/version":
		return true
	}
	return false
}

func init() {
	RegisterExplain("ipkvm.noAuth", explainIPKVMNoAuth)
}

func explainIPKVMNoAuth(host string, f engine.Finding) string {
	url := explainField(f, "url")
	response := explainField(f, "response")
	baseURL := explainBaseURL(host, f, 443, "https")
	if url == "" {
		url = "/api/status"
	}
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nAn IP-KVM info/status endpoint returned live data without authentication.\n")
	if response != "" {
		b.WriteString(fmt.Sprintf("\n**Response snippet:** `%s`\n", response))
	}
	b.WriteString("\n**Confirm unauthenticated access:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk %s%s | python3 -m json.tool", baseURL, url),
		fmt.Sprintf("curl -sk %s/api/version | python3 -m json.tool", baseURL),
	))
	b.WriteString("\n\n**Impact:** Confirms no-auth posture for the KVM session and virtual media interfaces.\n")
	return b.String()
}
