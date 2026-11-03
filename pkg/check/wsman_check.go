package check

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/creds"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/wsman"
)

func init() {
	Register(Check{
		Name:        "http.wsman.detected",
		Description: "WS-Man service detected and fingerprinted via Identify",
		Category:    "discovery",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runWSMANDetected,
	})
	Register(Check{
		Name:        "http.wsman.defaultCreds",
		Description: "Active WS-Man credential login test (default + supplied creds) with authenticated system-info proof",
		Category:    "creds",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runWSMANDefaultCreds,
	})
	Register(Check{
		Name:          "http.wsman.postAuthEnum",
		Description:   "Collect post-auth WS-Man identity details using supplied credentials",
		Category:      "creds",
		Applies:       Applicability{CrossVendor: true},
		Authenticated: true,
		Enabled:       false,
		Run:           runWSMANPostAuthEnum,
	})
}

const (
	maxWSMANDefaultAttempts  = 8
	maxWSMANPostAuthAttempts = 6
	maxWSMANAuthPorts        = 8
)

func runWSMANDetected(_ context.Context, t *engine.Target) []engine.Finding {
	id := cachedWSMAN(t)
	if id == nil {
		return nil
	}

	scheme, _, port := wsman.ParseURL(id.URL)
	transport := "tcp"
	if port > 0 {
		t.MarkOpen(port, transport, "wsman")
	}
	fields := wsmanFields(id, engine.F("url", id.URL))

	return []engine.Finding{{
		Check: "http.wsman.detected", Category: "discovery", Risk: "info",
		Port: port, Transport: transport, Protocol: "wsman",
		Fields: append(fields, engine.Field{Key: "scheme", Val: scheme}),
	}}
}

func runWSMANDefaultCreds(ctx context.Context, t *engine.Target) []engine.Finding {
	if t.DisableLogins || cachedWSMAN(t) == nil {
		return nil
	}
	vendor := identityVendor(t)
	ports := wsmanAuthPorts(t)
	to := wsmanTimeout(t)
	deadline := time.Now().Add(wsmanAuthBudget(to))
	credsToTry := wsmanAuthCreds(t, vendor)
	if len(credsToTry) == 0 {
		return nil
	}

	attempts := 0
	for _, c := range credsToTry {
		if ctx.Err() != nil || time.Now().After(deadline) {
			break
		}
		if c.User == "" {
			continue
		}
		if attempts >= maxWSMANDefaultAttempts {
			break
		}
		attempts++

		attemptTO := wsmanAttemptTimeout(to, time.Until(deadline))
		if attemptTO <= 0 {
			break
		}
		res, err := wsman.AuthenticateIdentify(t.Host, ports, attemptTO, c.User, c.Pass)
		if err != nil || res == nil || !res.Authenticated || res.Identity == nil || res.SystemInfo == nil || !res.SystemInfo.HasProof() {
			continue
		}
		t.SetEvidence("wsman.postAuth", res)
		scheme, _, port := wsman.ParseURL(res.URL)
		if port > 0 {
			t.MarkOpen(port, "tcp", "wsman")
		}
		fields := append(wsmanFields(res.Identity, nil),
			engine.Field{Key: "username", Val: c.User},
			engine.Field{Key: "password", Val: wsmanPasswordField(c.Pass)},
			engine.Field{Key: "source", Val: c.Source},
			engine.Field{Key: "loginVia", Val: res.Auth},
			engine.Field{Key: "scheme", Val: scheme},
			engine.Field{Key: "systemInfoEndpoint", Val: res.SystemInfo.Endpoint},
			engine.Field{Key: "manufacturer", Val: res.SystemInfo.Manufacturer},
			engine.Field{Key: "model", Val: res.SystemInfo.Model},
			engine.Field{Key: "name", Val: res.SystemInfo.Name},
			engine.Field{Key: "elementName", Val: res.SystemInfo.ElementName},
			engine.Field{Key: "systemName", Val: wsmanFirstNonEmpty(res.SystemInfo.Name, res.SystemInfo.ElementName)},
			engine.Field{Key: "uuid", Val: res.SystemInfo.UUID},
			engine.Field{Key: "resourceUri", Val: "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ComputerSystem"},
			engine.Field{Key: "evidenceEndpoint", Val: "/wsman (CIM_ComputerSystem Enumerate/Pull)"},
			engine.Field{Key: "proof", Val: wsmanProof(res)},
		)
		return []engine.Finding{{
			Check: "http.wsman.defaultCreds", Category: "creds", Risk: "critical",
			Port: port, Transport: "tcp", Protocol: "wsman",
			Fields: compactFields(fields), CVE: c.CVE,
		}}
	}
	return nil
}

func runWSMANPostAuthEnum(ctx context.Context, t *engine.Target) []engine.Finding {
	return nil
}

func cachedWSMAN(t *engine.Target) *wsman.Identity {
	v, ok := t.Evidenced("wsman")
	if !ok {
		return nil
	}
	id, _ := v.(*wsman.Identity)
	if id == nil || !id.HasFingerprint() {
		return nil
	}
	return id
}

type wsmanAuthCred struct {
	User   string
	Pass   string
	Source string
	CVE    []string
}

func wsmanAuthCreds(t *engine.Target, vendor string) []wsmanAuthCred {
	seen := map[string]struct{}{}
	var out []wsmanAuthCred
	add := func(c wsmanAuthCred) {
		if c.User == "" {
			return
		}
		key := c.User + "\x00" + c.Pass
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	for _, c := range suppliedCreds(t) {
		add(wsmanAuthCred{User: c.User, Pass: c.Pass, Source: "cli"})
	}
	for _, c := range creds.CredsFor(vendor, creds.ClassHTTP) {
		add(wsmanAuthCred{User: c.Username, Pass: c.Password, Source: c.Source, CVE: cveOrNil(c.CVE)})
	}
	return out
}

func wsmanPasswordField(pass string) string {
	if pass == "" {
		return "(blank)"
	}
	return pass
}

func wsmanProof(res *wsman.LoginResult) string {
	if res == nil || res.SystemInfo == nil {
		return ""
	}
	return proofKV(
		"endpoint", res.SystemInfo.Endpoint,
		"manufacturer", res.SystemInfo.Manufacturer,
		"model", res.SystemInfo.Model,
		"name", res.SystemInfo.Name,
		"elementName", res.SystemInfo.ElementName,
		"uuid", res.SystemInfo.UUID)
}

func compactFields(in engine.Fields) engine.Fields {
	out := make(engine.Fields, 0, len(in))
	for _, f := range in {
		if strings.TrimSpace(f.Val) == "" {
			continue
		}
		out = append(out, f)
	}
	return out
}

func wsmanFirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func wsmanTimeout(t *engine.Target) time.Duration {
	if t.Timeout > 0 {
		return t.Timeout
	}
	return 4 * time.Second
}

func wsmanAuthBudget(perAttempt time.Duration) time.Duration {
	if perAttempt <= 0 {
		return 12 * time.Second
	}
	b := min(max(perAttempt*3, 8*time.Second), 20*time.Second)
	return b
}

func wsmanAttemptTimeout(base, remaining time.Duration) time.Duration {
	if base <= 0 {
		base = 4 * time.Second
	}
	if remaining <= 0 {
		return 0
	}
	if remaining < base {
		return remaining
	}
	return base
}

func wsmanAuthPorts(t *engine.Target) []int {
	if v, ok := t.Evidenced("wsman"); ok {
		if id, ok := v.(*wsman.Identity); ok && id != nil {
			_, _, p := wsman.ParseURL(id.URL)
			if p > 0 {
				return []int{p}
			}
		}
	}
	ports := wsmanCandidatePorts(t)
	if len(ports) > maxWSMANAuthPorts {
		ports = ports[:maxWSMANAuthPorts]
	}
	return ports
}

func wsmanCandidatePorts(t *engine.Target) []int {
	seen := map[int]struct{}{}
	out := []int{5986, 5985, 16993, 16992, 443}
	for _, p := range out {
		seen[p] = struct{}{}
	}
	for _, p := range t.Ports {
		if p.Proto != engine.ProtoTCP || p.Num <= 0 {
			continue
		}
		if _, ok := seen[p.Num]; ok {
			continue
		}
		seen[p.Num] = struct{}{}
		out = append(out, p.Num)
	}
	if wp := webPort(t); wp > 0 {
		if _, ok := seen[wp]; !ok {
			out = append(out, wp)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return wsmanPortWeight(out[i]) < wsmanPortWeight(out[j])
	})
	return out
}

func wsmanPortWeight(p int) int {
	switch p {
	case 5986:
		return 0
	case 5985:
		return 1
	case 16993:
		return 2
	case 16992:
		return 3
	case 443:
		return 4
	default:
		return 100 + p
	}
}

func wsmanFields(id *wsman.Identity, base engine.Fields) engine.Fields {
	if id == nil {
		return base
	}
	out := append(engine.Fields{}, base...)
	if id.ProductVendor != "" {
		out = append(out, engine.Field{Key: "vendor", Val: id.ProductVendor})
	}
	if id.ProductVersion != "" {
		out = append(out, engine.Field{Key: "product", Val: id.ProductVersion})
	}
	if id.ProtocolVersion != "" {
		out = append(out, engine.Field{Key: "protocolVersion", Val: id.ProtocolVersion})
	}
	if len(id.SecurityProfile) > 0 {
		out = append(out, engine.Field{Key: "securityProfiles", Val: strings.Join(id.SecurityProfile, ",")})
	}
	if slug := id.VendorSlug(); slug != "" {
		out = append(out, engine.Field{Key: "vendorSlug", Val: slug})
	}
	return out
}

func init() {
	RegisterExplain("http.wsman.detected", explainWSMANDetected)
	RegisterExplain("http.wsman.defaultCreds", explainWSMANDefaultCreds)
	RegisterExplain("http.wsman.postAuthEnum", explainWSMANPostAuthEnum)
}

func explainWSMANDetected(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 5986)
	scheme := explainField(f, "scheme")
	if scheme == "" {
		scheme = "https"
	}
	baseURL := explainBaseURL(host, f, port, scheme)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nWS-Man Identify endpoint responded with product metadata.\n")
	b.WriteString("\n**Probe Identify manually:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf(`curl -sk -X POST %s/wsman \\`, baseURL),
		`  -H 'Content-Type: application/soap+xml;charset=UTF-8' \\`,
		`  -d '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>'`,
	))
	return b.String()
}

func explainWSMANDefaultCreds(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 5986)
	user := explainField(f, "username")
	pass := explainField(f, "password")
	scheme := explainField(f, "scheme")
	if scheme == "" {
		scheme = "https"
	}
	baseURL := explainBaseURL(host, f, port, scheme)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nWS-Man accepted the default credential **%s / %s**.\n", user, pass))
	b.WriteString("\n**Validate with curl (Basic shown):**\n")
	b.WriteString(explainSh(
		fmt.Sprintf(`curl -sk -u '%s:%s' -X POST %s/wsman \\`, user, pass, baseURL),
		`  -H 'Content-Type: application/soap+xml;charset=UTF-8' \\`,
		`  -d '<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><s:Header><wsa:To>/wsman</wsa:To><wsman:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ComputerSystem</wsman:ResourceURI><wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo><wsa:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</wsa:Action><wsman:MaxEnvelopeSize s:mustUnderstand="true">153600</wsman:MaxEnvelopeSize><wsman:OperationTimeout>PT5S</wsman:OperationTimeout></s:Header><s:Body><wsen:Enumerate/></s:Body></s:Envelope>'`,
	))
	b.WriteString("\n\n**Impact:** Remote management access with known credentials.\n")
	return b.String()
}

func explainWSMANPostAuthEnum(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 5986)
	user := explainField(f, "username")
	scheme := explainField(f, "scheme")
	if scheme == "" {
		scheme = "https"
	}
	baseURL := explainBaseURL(host, f, port, scheme)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nSupplied credential authenticated to WS-Man as **%s** and post-auth identity data was collected.\n", user))
	b.WriteString("\n**Re-run with known creds:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf(`curl -sk -u '%s:<password>' -X POST %s/wsman \\`, user, baseURL),
		`  -H 'Content-Type: application/soap+xml;charset=UTF-8' \\`,
		`  -d '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>'`,
	))
	return b.String()
}
