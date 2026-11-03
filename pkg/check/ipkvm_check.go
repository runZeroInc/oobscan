package check

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/httpscan"
)

// The IP-KVM check covers modern KVM-over-IP appliances (PiKVM, JetKVM, Sipeed
// NanoKVM, TinyPilot, GL.iNet Comet, Angeet/Yeeso ES3) against ClassKVM
// targets: it sweeps unauth info endpoints already in the httpscan list
// (/device/ui-config.js, /device/status, /api/*) to fingerprint the stack and
// firmware version, and flags a no-auth posture when a login-gated endpoint
// returns live data pre-auth (JetKVM noPassword mode, TinyPilot community
// edition default). Detection only -- no login or state-changing request is
// ever submitted.
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
	// Use the observed web port/scheme rather than assuming HTTPS: these appliances
	// (PiKVM/JetKVM/NanoKVM/TinyPilot) routinely serve plain HTTP.
	port := webPort(t)
	proto := webProto(t)
	// Same floor as the BMC surface sweep: a 1s cap manufactures transport failures
	// against a slow embedded TLS stack (see httpSurfaceMinPerRequest).
	per := max(t.Timeout, httpSurfaceMinPerRequest)

	sweepCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	rep, err := httpscan.ProbeHostCtxForVendorsScheme(sweepCtx, t.Host, port, proto, per)
	if err == nil && rep != nil {
		t.SetEvidence("http", rep)
	}

	var out []engine.Finding

	// 1. No-auth posture: an unauthenticated GET to an IP-KVM info/status endpoint
	// returned live data. On these devices those endpoints are supposed to be
	// login-gated, so a 2xx body pre-auth is a real exposure (medium), and a
	// JetKVM "noPassword" flag makes it explicit (high).
	if rep != nil {
		for _, ef := range rep.HTTPFindings {
			if !isIPKVMEndpoint(ef.Path) {
				continue
			}
			rr := pickHTTPRequest(ef)
			if rr.Status < 200 || rr.Status >= 300 || strings.TrimSpace(rr.Snippet) == "" {
				continue
			}
			// A 2xx with a body is not evidence of unauthenticated access: several of these
			// appliances -- and the Lantronix SecureLinx Spider, which serves the same
			// /device/status route -- answer an unauthenticated request with 200 and the
			// login page. Require the body to look like device data first.
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
				// Label the scheme actually observed: hardcoding https while url and port
				// come from the identified web tier makes the three fields disagree on an
				// HTTP-only appliance.
				Port: port, Transport: "tcp", Protocol: proto,
				Fields: engine.F(
					"url", rr.URL,
					"httpStatus", fmt.Sprintf("%d", rr.Status),
					"bodyEvidence", evidence,
					"response", cleanSnippet(rr.Snippet)),
			})
			break // one no-auth finding per host is enough
		}
	}

	return out
}

// ipkvmApplianceMarkers are tokens that only an actual IP-KVM appliance's
// info/status payload carries. A login page for the same route carries none of
// them, which is what separates real unauthenticated data from a 200-wrapped
// login form.
var ipkvmApplianceMarkers = []string{
	"kvmd", "pikvm", "jetkvm", "nanokvm", "tinypilot", "blikvm",
	"gl-inet", "glinet", "comet", "yeeso", "openterface",
	"streamer", "hid", "atx", "msd", "vnc_enabled", "ustreamer",
}

// ipkvmUnauthData reports whether a 2xx body is genuine device data rather than a
// login page, and returns the reason it qualified so the finding records why it
// was accepted. Structured payloads (JSON object/array, or the JS config object
// /device/ui-config.js serves) qualify outright; an HTML body only qualifies if it
// names a known appliance, since these endpoints answer pre-auth with the login
// page on several stacks.
func ipkvmUnauthData(snippet string) (string, bool) {
	s := strings.TrimSpace(snippet)
	if s == "" {
		return "", false
	}
	low := strings.ToLower(s)

	// HTML is presumptively the login/landing page. Only a named appliance rescues it.
	if strings.HasPrefix(low, "<!doctype") || strings.HasPrefix(low, "<html") || strings.HasPrefix(low, "<?xml") {
		for _, m := range ipkvmApplianceMarkers {
			if strings.Contains(low, m) {
				return "html naming " + m, true
			}
		}
		return "", false
	}
	// A JSON object/array from one of these info routes is device data; a login form
	// is not served as JSON.
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		return "json body", true
	}
	// /device/ui-config.js serves a JS assignment rather than bare JSON.
	if strings.Contains(low, "=") && (strings.Contains(low, "var ") || strings.Contains(low, "window.") || strings.Contains(low, "const ")) {
		return "js config object", true
	}
	// Anything else must name an appliance to count.
	for _, m := range ipkvmApplianceMarkers {
		if strings.Contains(low, m) {
			return "body naming " + m, true
		}
	}
	return "", false
}

// isIPKVMEndpoint reports whether a swept path is one of the IP-KVM unauth
// info/status endpoints in the endpoint list.
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
