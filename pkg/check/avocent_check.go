package check

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// Avocent (Vertiv) ACS8000/ACS800 console servers serve a small, non-standard
// Redfish service root as a static file at GET /redfish/v1/index.json,
// reachable pre-auth. The distinctive {Vendor:"Avocent",Product:"ACS"} pair
// (a mini root, not the full ServiceRoot schema) both attributes the
// appliance and confirms the pre-auth web surface tied to the unauthenticated
// cleartext handler POST /appliance/avtrans (no auth, no SSL), the pre-auth
// stack-overflow sink in root uicontrold. This check only performs the
// static read; it never touches /appliance/avtrans.
func init() {
	Register(Check{
		Name:        "http.avocent.acsRedfishRoot",
		Description: "Avocent ACS console server pre-auth Redfish service-root disclosure (avtrans overflow surface)",
		Category:    "exposure",
		Applies: Applicability{
			Vendors: []string{"avocent"},
			Classes: []engine.DeviceClass{engine.ClassSerialConsole, engine.ClassKVM},
		},
		Enabled: true,
		Run:     runAvocentACSRedfishRoot,
	})
	RegisterExplain("http.avocent.acsRedfishRoot", explainAvocentACSRedfishRoot)
}

func runAvocentACSRedfishRoot(ctx context.Context, t *engine.Target) []engine.Finding {
	port := webPort(t)
	proto := webProto(t)
	if !webPortMaybeOpen(t, port) {
		return nil
	}
	client := insecureWebClient(min(t.Timeout, 6*time.Second))

	for _, path := range []string{"/redfish/v1/index.json", "/redfish/v1/", "/redfish/v1"} {
		st, ct, body := httpProbe(ctx, client, hostPortURL(proto, t.Host, port, path), "")
		if st < 200 || st >= 300 {
			continue
		}
		if !strings.Contains(ct, "json") && !looksLikeJSON(body) {
			continue
		}
		var root struct {
			Product string `json:"Product"`
			Vendor  string `json:"Vendor"`
		}
		if json.Unmarshal(body, &root) != nil {
			continue
		}
		if !strings.EqualFold(root.Vendor, "Avocent") || !strings.Contains(strings.ToUpper(root.Product), "ACS") {
			continue
		}
		return []engine.Finding{{
			Check: "http.avocent.acsRedfishRoot", Category: "exposure", Risk: "medium",
			Port: port, Transport: "tcp", Protocol: proto,
			Fields: engine.F(
				"url", path,
				"vendor", cleanSnippet(root.Vendor),
				"product", cleanSnippet(root.Product),
				"relatedPath", "/appliance/avtrans"),
		}}
	}
	return nil
}

func explainAvocentACSRedfishRoot(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nAn Avocent (Vertiv) ACS console server serves its Redfish service root\n")
	b.WriteString("without authentication, confirming the appliance and its live pre-auth web tier.\n")
	b.WriteString("\n**Read the pre-auth service root (SAFE):**\n")
	b.WriteString(explainSh(fmt.Sprintf("curl -sk %s/redfish/v1/index.json", baseURL)))
	b.WriteString("\n\n**Why it matters:** ACS8000/ACS800 firmware exposes the unauthenticated,\n")
	b.WriteString("cleartext handler `POST /appliance/avtrans` (no auth, no TLS) -- the pre-auth\n")
	b.WriteString("stack-overflow sink in the root `uicontrold` process. Confirm the appliance is\n")
	b.WriteString("patched and restrict the management network; do not expose port 80/443 publicly.\n")
	return b.String()
}
