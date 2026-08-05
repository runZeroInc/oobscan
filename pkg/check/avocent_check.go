package check

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func init() {
	Register(Check{
		Name:        "http.avocent.acsRedfishRoot",
		Description: "Avocent ACS console server pre-auth Redfish service-root disclosure",
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
	return b.String()
}
