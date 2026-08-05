package check

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

var (
	reCiscoKVMPort    = regexp.MustCompile(`(?i)kvm_port"?\s*[:=]\s*"?(\d{1,5})`)
	reCiscoRedfishVer = regexp.MustCompile(`(?i)"redfishversion"\s*:\s*"([^"]{1,16})"`)
	reHTMLTitle       = regexp.MustCompile(`(?is)<title>\s*(.{1,80}?)\s*</title>`)
)

func init() {
	Register(Check{
		Name:        "http.cisco.webPresence",
		Description: "Cisco CIMC web/Redfish presence (pre-auth exposure fingerprint)",
		Category:    "exposure",
		Applies:     Applicability{Classes: []engine.DeviceClass{engine.ClassBMC}},
		Enabled:     true,
		Run:         runCiscoWebPresence,
	})
}

func runCiscoWebPresence(ctx context.Context, t *engine.Target) []engine.Finding {

	client := insecureWebClient(t.Timeout)
	var hitPath, proof string
	for _, path := range []string{"/redfish/v1/", "/kvm/gimme_dat_port", "/kvm/kvm.html"} {
		url := hostPortURL("https", t.Host, 443, path)
		st, _, body := httpProbe(ctx, client, url, "")
		if st == 0 {
			continue
		}
		s := string(body)
		low := strings.ToLower(s)
		switch path {
		case "/redfish/v1/":

			isRedfish := strings.Contains(low, "@odata") || strings.Contains(low, "redfishversion") || strings.Contains(low, "serviceroot")
			if name := firstSubstr(low, "cisco", "cimc", "ucs"); st == http.StatusOK && isRedfish && name != "" {
				version := ""
				if m := reCiscoRedfishVer.FindStringSubmatch(s); m != nil {
					version = m[1]
				}
				proof = proofKV("status", fmt.Sprintf("%d", st), "name", name, "redfishVersion", version)
			}
		case "/kvm/gimme_dat_port":

			if m := reCiscoKVMPort.FindStringSubmatch(s); m != nil {
				proof = proofKV("status", fmt.Sprintf("%d", st), "kvmPort", m[1])
			}
		case "/kvm/kvm.html":

			if m := reHTMLTitle.FindStringSubmatch(s); m != nil && strings.Contains(strings.ToLower(m[1]), "vkvm") {
				proof = proofKV("status", fmt.Sprintf("%d", st), "title", cleanSnippet(m[1]))
			} else if strings.Contains(low, "<kvm-ui") {
				proof = proofKV("status", fmt.Sprintf("%d", st), "kvmUi", "true")
			}
		}
		if proof != "" {
			hitPath = path
			break
		}
	}

	if proof == "" {
		return nil
	}
	return []engine.Finding{{
		Check: "http.cisco.webPresence", Category: "exposure", Risk: "info",
		Port: 443, Transport: "tcp", Protocol: "https",
		Fields: engine.F(
			"url", hitPath,
			"vendor", "cisco",
			"product", "CIMC",
			"proof", proof),
	}}
}

func firstSubstr(s string, needles ...string) string {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return n
		}
	}
	return ""
}

func init() {
	RegisterExplain("http.cisco.webPresence", explainCiscoWebPresence)
}

func explainCiscoWebPresence(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nCisco CIMC/UCS web management interface detected.\n")
	b.WriteString("\n**Enumerate the management surface:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk %s/api/cimcInfo.json | python3 -m json.tool", baseURL),
		fmt.Sprintf("curl -sk %s/redfish/v1/ | python3 -m json.tool", baseURL),
	))
	return b.String()
}
