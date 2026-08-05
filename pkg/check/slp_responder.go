package check

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/slp"
)

func init() {
	Register(Check{
		Name:        "udp.slp.responder",
		Description: "Unauthenticated SLP responder on UDP/427 (OpenSLP CVE-2019-5544 candidate surface)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runSLPResponder,
	})
	RegisterExplain("udp.slp.responder", explainSLPResponder)
}

func runSLPResponder(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	var urls []string
	if v, ok := t.Evidenced("slp"); ok {
		if uu, ok := v.([]string); ok {
			urls = uu
		}
	}
	responded := len(urls) > 0
	if !responded {

		r, err := slp.Probe(t.Host, "service:service-agent", t.Timeout)
		if err == nil && r != nil {
			responded = true
			urls = r.URLs
			if len(urls) > 0 {
				t.SetEvidence("slp", urls)
			}
		}
	}
	if !responded {
		return nil
	}
	t.MarkOpen(427, "udp", "slp")

	vendor := ""
	if t.Identity != nil {
		vendor = strings.ToLower(t.Identity.Vendor)
	}

	risk, note := "info", "unauth-slp-responder-version-not-observable"
	if vendor == "h3c" {
		risk = "medium"
		note = "unauth-slp-responder-h3c-openslp-cve-2019-5544-candidate"
	}

	fields := engine.F(
		"serviceUrls", strconv.Itoa(len(urls)),
		"note", note,
	)
	if len(urls) > 0 {
		shown := urls
		if len(shown) > 4 {
			shown = shown[:4]
		}
		fields = append(fields, engine.Field{Key: "urls", Val: cleanSnippet(strings.Join(shown, " "))})
	}
	fields = append(fields, engine.Field{Key: "proof", Val: proofKV(
		"request", "SrvRqst service:service-agent",
		"scope", "DEFAULT",
		"replies", strconv.Itoa(len(urls)))})

	return []engine.Finding{{
		Check: "udp.slp.responder", Category: "exposure", Risk: risk,
		Port: 427, Transport: "udp", Protocol: "slp",
		Fields: fields,
	}}
}

func explainSLPResponder(host string, f engine.Finding) string {
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe device answers Service Location Protocol requests on UDP/427 with no\n")
	b.WriteString("authentication, advertising its service URLs to any host that asks.\n")
	if u := explainField(f, "urls"); u != "" {
		b.WriteString(fmt.Sprintf("\n**Advertised service URLs:** `%s`\n", u))
	}
	if note := explainField(f, "note"); note != "" {
		b.WriteString(fmt.Sprintf("\n**Assessment:** %s\n", note))
	}
	b.WriteString("\n**Reproduce (read-only discovery request):**\n")
	b.WriteString(explainSh(fmt.Sprintf("slptool --unicast %s findsrvtypes", host)))
	b.WriteString("\n\n**Why this matters beyond the disclosure:** OpenSLP's last upstream release is\n")
	b.WriteString("1.2.1 (2005), the version affected by CVE-2019-5544 - an unauthenticated heap\n")
	b.WriteString("overflow exploited in the wild against VMware ESXi. SLP exposes no version on the\n")
	b.WriteString("wire, so a responder is a candidate to triage, not a confirmed vulnerable host.\n")
	b.WriteString("\n**Mitigation:** SLP is not required for normal BMC operation. Disable it in the\n")
	b.WriteString("service configuration or block inbound UDP/427 at the network boundary.\n")
	return b.String()
}
