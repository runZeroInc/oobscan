package check

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/creds"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/httpx"
)

func init() {
	Register(Check{
		Name:        "http.web.defaultCreds",
		Description: "Active web default-credential login for web-only OOB devices (PDU/console/KVM): self-scoping HTTP Basic + vendor form/JSON-RPC adapters (Moxa/Raritan/...), vendor-targeted, online only",
		Category:    "creds",
		Applies: Applicability{Classes: []engine.DeviceClass{
			engine.ClassPDU, engine.ClassSerialConsole, engine.ClassKVM,
		}},
		Enabled: true,
		Run:     runWebBasicDefaultCreds,
	})
}

const maxWebBasicAttempts = 4

var webBasicSkipVendors = map[string]bool{
	"apc":  true,
	"gude": true,
}

func runWebBasicDefaultCreds(ctx context.Context, t *engine.Target) []engine.Finding {
	if t.DisableLogins {
		return nil
	}
	vendor := identityVendor(t)
	if vendor == "" || webBasicSkipVendors[vendor] {
		return nil
	}

	cands := webBasicCandidates(t, vendor)
	if len(cands) == 0 {
		return nil
	}

	port := webPort(t)
	proto := webProto(t)
	if port <= 0 {
		return nil
	}
	base := hostPortURL(proto, t.Host, port, "")

	client, rec := httpx.NewRecordingClient(insecureWebClient(webBasicPerRequestTimeout(t.Timeout)))

	var findings []engine.Finding
	mechanism := "httpBasic"
	if adapter, ok := webLoginAdapters[vendor]; ok {
		mechanism = adapter.mechanism()
		findings = runWebAdapterLogin(ctx, t, adapter, cands, base, port, proto, vendor, client)
	} else {
		findings = runWebBasicLogin(ctx, t, cands, base, port, proto, vendor, client)
	}
	stashWebLoginTranscript(t, rec, vendor, port, proto, mechanism, findings)
	return findings
}

func stashWebLoginTranscript(t *engine.Target, rec *httpx.Recorder, vendor string, port int, proto, mechanism string, findings []engine.Finding) {
	ex := rec.Exchanges()
	if len(ex) == 0 {
		return
	}
	result, user := "no-match", ""
	if len(findings) > 0 {
		result = "success"
		user = findingField(findings[0], "username")
	}
	t.SetEvidence("web.login.transcript", &httpx.Transcript{
		Vendor:    vendor,
		Port:      port,
		Scheme:    proto,
		Mechanism: mechanism,
		Result:    result,
		Username:  user,
		Exchanges: ex,
	})
}

func runWebBasicLogin(ctx context.Context, t *engine.Target, cands []webBasicCred, base string, port int, proto, vendor string, client *http.Client) []engine.Finding {
	root := base + "/"
	p := probeWebRoot(ctx, client, root)
	if !p.ok {
		return nil
	}

	if !confirmVendorWeb(p.server, p.title, vendor) {
		return nil
	}

	if !p.basicChallenge() {
		return nil
	}
	realm := basicRealm(p.wwwAuth)
	attempts := 0
	for _, c := range cands {
		if ctx.Err() != nil {
			return nil
		}
		if attempts >= maxWebBasicAttempts {
			break
		}
		attempts++
		okAuth, proof := tryBasicLogin(ctx, client, root, c.User, c.Pass)
		if !okAuth {
			continue
		}
		return webCredFinding(t, port, proto, vendor, c, "httpBasic", realm, "/", proof)
	}
	return nil
}

func runWebAdapterLogin(ctx context.Context, t *engine.Target, adapter webLoginAdapter, cands []webBasicCred, base string, port int, proto, vendor string, client *http.Client) []engine.Finding {
	if p := probeWebRoot(ctx, client, base+"/"); p.ok && (p.server != "" || p.title != "") {
		if !confirmVendorWeb(p.server, p.title, vendor) {
			return nil
		}
	}
	attempts := 0
	for _, c := range cands {
		if ctx.Err() != nil {
			return nil
		}
		if attempts >= maxWebBasicAttempts {
			break
		}
		attempts++
		okAuth, proof, err := adapter.login(ctx, client, base, c.User, c.Pass)
		if err != nil {
			return nil
		}
		if !okAuth {
			continue
		}
		return webCredFinding(t, port, proto, vendor, c, adapter.mechanism(), "", "", proof)
	}
	return nil
}

func httpCredCheckName(vendor string) string {
	v := strings.TrimSpace(strings.ToLower(vendor))
	if v == "" {
		v = "web"
	}
	return "http." + v + ".defaultCreds"
}

func webCredFinding(t *engine.Target, port int, proto, vendor string, c webBasicCred, loginVia, realm, endpoint, proof string) []engine.Finding {
	t.MarkOpen(port, "tcp", proto)
	passField := c.Pass
	if passField == "" {
		passField = "(blank)"
	}
	fields := engine.F(
		"vendor", vendor,
		"username", c.User,
		"password", passField,
		"loginVia", loginVia,
		"source", c.Source,
		"proof", proof,
	)
	if realm != "" {
		fields = append(fields, engine.Field{Key: "realm", Val: realm})
	}
	if endpoint != "" {
		fields = append(fields, engine.Field{Key: "evidenceEndpoint", Val: endpoint})
	}
	return []engine.Finding{{
		Check: httpCredCheckName(vendor), Category: "creds", Risk: "critical",
		Port: port, Transport: "tcp", Protocol: proto,
		Fields: fields,
		CVE:    cveOrNil(c.CVE),
	}}
}

type webBasicCred struct {
	User   string
	Pass   string
	Source string
	CVE    string
}

func webBasicCandidates(t *engine.Target, vendor string) []webBasicCred {
	seen := map[[2]string]struct{}{}
	var out []webBasicCred
	add := func(u, p, src, cve string) {
		if u == "" {
			return
		}
		k := [2]string{u, p}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, webBasicCred{User: u, Pass: p, Source: src, CVE: cve})
	}
	for _, c := range suppliedCreds(t) {
		add(c.User, c.Pass, "cli", "")
	}
	for _, c := range creds.VendorCredsFor(vendor, creds.ClassHTTP) {
		add(c.Username, c.Password, c.Source, c.CVE)
	}
	return out
}

type webRootProbe struct {
	ok      bool
	status  int
	wwwAuth string
	server  string
	title   string
}

func (p webRootProbe) basicChallenge() bool {
	return p.status == http.StatusUnauthorized &&
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(p.wwwAuth)), "basic")
}

func probeWebRoot(ctx context.Context, client *http.Client, url string) webRootProbe {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return webRootProbe{}
	}
	resp, err := client.Do(req)
	if err != nil {
		return webRootProbe{}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	return webRootProbe{
		ok:      true,
		status:  resp.StatusCode,
		wwwAuth: resp.Header.Get("Www-Authenticate"),
		server:  resp.Header.Get("Server"),
		title:   htmlTitle(body),
	}
}

func tryBasicLogin(ctx context.Context, client *http.Client, url, user, pass string) (ok bool, proof string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, ""
	}
	req.SetBasicAuth(user, pass)
	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, ""
	}
	return true, basicLoginProof(resp, body)
}

func basicLoginProof(resp *http.Response, body []byte) string {
	if title := htmlTitle(body); title != "" {
		return proofKV("status", strconv.Itoa(resp.StatusCode), "title", title)
	}
	if s := resp.Header.Get("Server"); s != "" {
		return proofKV("status", strconv.Itoa(resp.StatusCode), "server", s)
	}
	return proofKV("status", strconv.Itoa(resp.StatusCode))
}

func basicRealm(h string) string {
	low := strings.ToLower(h)
	i := strings.Index(low, "realm=")
	if i < 0 {
		return ""
	}
	v := strings.TrimSpace(h[i+len("realm="):])
	v = strings.TrimPrefix(v, `"`)
	if j := strings.IndexByte(v, '"'); j >= 0 {
		v = v[:j]
	} else if j := strings.IndexByte(v, ','); j >= 0 {
		v = v[:j]
	}
	return strings.TrimSpace(v)
}

func htmlTitle(body []byte) string {
	s := string(body)
	low := strings.ToLower(s)
	i := strings.Index(low, "<title")
	if i < 0 {
		return ""
	}
	gt := strings.IndexByte(s[i:], '>')
	if gt < 0 {
		return ""
	}
	start := i + gt + 1
	end := strings.Index(strings.ToLower(s[start:]), "</title>")
	if end < 0 {
		return ""
	}
	title := strings.TrimSpace(s[start : start+end])
	title = strings.Join(strings.Fields(title), " ")
	if len(title) > 80 {
		title = title[:80]
	}
	return title
}

func webBasicPerRequestTimeout(scanTimeout time.Duration) time.Duration {
	if scanTimeout <= 0 {
		return 3 * time.Second
	}
	if scanTimeout > 4*time.Second {
		return 4 * time.Second
	}
	if scanTimeout < time.Second {
		return time.Second
	}
	return scanTimeout
}

func init() {
	RegisterExplain("http.web.defaultCreds", explainWebBasicDefaultCreds)
}

func explainWebBasicDefaultCreds(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 443)
	user := explainField(f, "username")
	pass := explainField(f, "password")
	vendor := explainField(f, "vendor")
	realm := explainField(f, "realm")
	baseURL := explainBaseURL(host, f, port, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nThe %s web interface accepted the default credential **%s / %s** over HTTP Basic auth", vendor, user, pass))
	if realm != "" {
		b.WriteString(fmt.Sprintf(" (realm %q)", realm))
	}
	b.WriteString(".\n")
	b.WriteString("\n**Validate:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk -u '%s:%s' %s/ -o /dev/null -w '%%{http_code}\\n'", user, pass, baseURL),
		fmt.Sprintf("curl -sk -u '%s:%s' %s/", user, pass, baseURL),
	))
	b.WriteString("\n\n**Impact:** Authenticated management access to the device with a known shipped default credential.\n")
	return b.String()
}
