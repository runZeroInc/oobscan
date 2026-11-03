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

// The web Basic-auth default-credential check targets web-only OOB devices
// (PDUs, serial console servers, rack KVMs) that authenticate with HTTP Basic.
// It self-scopes on a 401 `WWW-Authenticate: Basic` challenge, so it no-ops on
// form-login/JSON-RPC devices, and follows the standard active-login discipline
// (identified vendor's defaults only, capped attempts, stop at first success).
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

// maxWebBasicAttempts caps Basic-auth login attempts per host on top of the
// vendor-targeting, keeping the check well under any device lockout threshold.
const maxWebBasicAttempts = 4

// webBasicSkipVendors have a bespoke active web-login check already, so the
// generic Basic path must not double-attempt (and risk a second lockout counter)
// against them.
var webBasicSkipVendors = map[string]bool{
	"apc":  true, // pdu.confirm -> http.apc.defaultCreds (form login)
	"gude": true, // http.gude.defaultCreds (Basic on /ov.html)
}

func runWebBasicDefaultCreds(ctx context.Context, t *engine.Target) []engine.Finding {
	if t.DisableLogins {
		return nil // active login; skipped under --disable-logins
	}
	vendor := identityVendor(t)
	if vendor == "" || webBasicSkipVendors[vendor] {
		return nil
	}
	// Only the identified vendor's documented defaults (never the broad spray).
	// ClassHTTP pulls the vendor's HTTP rows plus the ClassAny rows that most
	// account-level defaults use.
	cands := webBasicCandidates(t, vendor)
	if len(cands) == 0 {
		return nil
	}

	port := webPort(t)
	proto := webProto(t)
	if port <= 0 {
		return nil
	}
	base := hostPortURL(proto, t.Host, port, "") // scheme://host:port (no path)

	// Retain the request/response transcript for false-positive analysis.
	client, rec := httpx.NewRecordingClient(insecureWebClient(webBasicPerRequestTimeout(t.Timeout)))

	// A vendor with a bespoke web-login flow (Moxa form / Opengear CGI / Raritan
	// JSON-RPC) is driven by its adapter; every other vendor uses the generic,
	// self-scoping HTTP Basic path. Both are vendor-targeted, capped, and stop at
	// the first success.
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

// stashWebLoginTranscript records the captured login exchanges on the target so
// resultFrom can emit them in the scan record. It only stores when a
// credentialed request was actually sent (the self-scoping Basic gate that
// no-ops before any login yields no useful transcript).
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

// runWebBasicLogin is the self-scoping HTTP Basic path: it proceeds only against
// a genuine `WWW-Authenticate: Basic` challenge whose Server/title also confirm
// the identified vendor, so it cleanly no-ops on form-login / JSON-RPC devices
// and never sprays a wrong-vendor default at a UDP-discovery false positive.
func runWebBasicLogin(ctx context.Context, t *engine.Target, cands []webBasicCred, base string, port int, proto, vendor string, client *http.Client) []engine.Finding {
	root := base + "/"
	p := probeWebRoot(ctx, client, root)
	if !p.ok {
		return nil
	}
	// Vendor-fingerprint gate: the live Server/title must corroborate the vendor.
	if !confirmVendorWeb(p.server, p.title, vendor) {
		return nil
	}
	// Basic gate: proceed only against a real Basic challenge.
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

// runWebAdapterLogin drives a vendor-specific adapter (form / JSON-RPC) over the
// candidate list, capped and stopping at the first success; a transport error
// aborts the loop (login flow unavailable / not this device). It applies the
// same vendor-fingerprint gate as the Basic path when the root page yields a
// Server/title (skipping a fingerprint mismatch); otherwise the adapter's own
// handshake confirms the device.
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
			return nil // login flow unavailable / not this device
		}
		if !okAuth {
			continue
		}
		return webCredFinding(t, port, proto, vendor, c, adapter.mechanism(), "", "", proof)
	}
	return nil
}

// httpCredCheckName is the standardized per-vendor default-cred finding name,
// protocol.vendor.defaultCreds (e.g. "http.supermicro.defaultCreds",
// "http.moxa.defaultCreds"), matching the existing http.apc/idrac/cim/gude
// convention so every confirmed web default-cred hit keys the same way. They all
// share the http.web.defaultCreds explainer via GetExplainer's family fallback.
func httpCredCheckName(vendor string) string {
	v := strings.TrimSpace(strings.ToLower(vendor))
	if v == "" {
		v = "web"
	}
	return "http." + v + ".defaultCreds"
}

// webCredFinding builds the shared critical finding for a confirmed web default
// credential. realm/endpoint are optional (Basic-only) fields.
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

// webBasicCred is a candidate credential with provenance for the finding.
type webBasicCred struct {
	User   string
	Pass   string
	Source string
	CVE    string
}

// webBasicCandidates builds the ordered candidate list: operator-supplied creds
// first (so a rotated unit is still confirmed), then the identified vendor's
// documented HTTP/any defaults, de-duplicated by (user, pass). Blank-username
// rows are dropped (Basic auth needs a username).
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

// webRootProbe is the result of one unauthenticated GET of the device root: the
// status, the WWW-Authenticate header, the Server header, and the page <title>.
// It drives both the vendor-fingerprint gate and the Basic-challenge gate from a
// single round-trip.
type webRootProbe struct {
	ok      bool // the request completed (a response was received)
	status  int
	wwwAuth string
	server  string
	title   string
}

// basicChallenge reports whether the probe is a genuine HTTP Basic challenge
// (401 with a `WWW-Authenticate: Basic ...` header).
func (p webRootProbe) basicChallenge() bool {
	return p.status == http.StatusUnauthorized &&
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(p.wwwAuth)), "basic")
}

// probeWebRoot issues one unauthenticated GET and captures the signals the
// targeting gates need. It never sends a credential.
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

// tryBasicLogin sends one Basic-auth GET and reports success. Success is a 2xx
// response (the 401 challenge cleared and the server returned content); a
// repeated 401 is a rejected credential, and a 3xx/4xx/5xx is treated as
// non-success to avoid false positives. The proof is a compact page marker.
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

// basicLoginProof builds a short proof line from an authenticated response: the
// page <title>, else the Server header, else a generic marker.
func basicLoginProof(resp *http.Response, body []byte) string {
	if title := htmlTitle(body); title != "" {
		return proofKV("status", strconv.Itoa(resp.StatusCode), "title", title)
	}
	if s := resp.Header.Get("Server"); s != "" {
		return proofKV("status", strconv.Itoa(resp.StatusCode), "server", s)
	}
	return proofKV("status", strconv.Itoa(resp.StatusCode))
}

// basicRealm extracts the realm token from a WWW-Authenticate: Basic header.
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

// htmlTitle returns the trimmed <title> text of an HTML body, or "".
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
