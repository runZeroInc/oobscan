package check

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/creds"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

// AMI MegaRAC SP-X web-login check. SP-X is shared by several BMC vendors
// (Fujitsu iRMC, ASUS ASMB, ASRock Rack, Tyan, Gigabyte, Inspur, H3C HDM, AMI
// reference builds); two login conventions are supported: the classic POST
// /rpc/WEBSES/create.asp form RPC, and the REST POST /api/session. Acceptance
// requires both a server-minted session token and an explicit success code;
// cookie-based results are strengthened by replay against an authenticated
// route. See kb/ami/ for the request/response shapes.
type megaracAdapter struct{ ep megaracEndpoint }

func (megaracAdapter) mechanism() string { return "httpRpc" }

// megaracMaxAttempts caps MegaRAC login attempts per host (well under lockout).
const megaracMaxAttempts = 6

// megaracEndpoint pairs a MegaRAC RPC login path with its request field names.
// The response is parsed uniformly by megaracParseLogin.
type megaracEndpoint struct {
	path      string // "/rpc/WEBSES/create.asp" | "/api/session"
	userField string // "WEBVAR_USERNAME"        | "username"
	passField string // "WEBVAR_PASSWORD"        | "password"
}

func (e megaracEndpoint) zero() bool { return e.path == "" }

// megaracEndpoints are the login endpoints probed, classic ".asp" RPC first
// (the confirmed Fujitsu iRMC path) then the newer REST session endpoint.
var megaracEndpoints = []megaracEndpoint{
	{path: "/rpc/WEBSES/create.asp", userField: "WEBVAR_USERNAME", passField: "WEBVAR_PASSWORD"},
	{path: "/api/session", userField: "username", passField: "password"},
}

// megaracVendors is the AMI MegaRAC SP-X OEM family this check gates on.
var megaracVendors = map[string]struct{}{
	"ami": {}, "fujitsu": {}, "asus": {}, "asrockrack": {},
	"tyan": {}, "gigabyte": {}, "inspur": {}, "h3c": {},
}

var (
	// SESSION_TOKEN / SessionToken value, e.g. 'SESSION_TOKEN' : 'ab12cd34...'
	megaracSessionTokenRe = regexp.MustCompile(`(?i)session[_ ]?token['":=\s]+['"]?([0-9a-zA-Z]{6,})`)
	// CSRFTOKEN / CSRFToken value.
	megaracCSRFTokenRe = regexp.MustCompile(`(?i)csrf[_ ]?token['":=\s]+['"]?([0-9a-zA-Z]{6,})`)
	// WEBVAR_ERROR_WEB_SESSION:<n> -- 0 is success, non-zero is a rejected login.
	megaracWebErrRe = regexp.MustCompile(`(?i)WEBVAR_ERROR_WEB_SESSION\s*:\s*(-?\d+)`)
	// "ok":<n> in the /api/session JSON -- 0 is success, non-zero is rejected.
	megaracOkRe = regexp.MustCompile(`(?i)"ok"\s*:\s*(-?\d+)`)
)

func (a megaracAdapter) login(ctx context.Context, client *http.Client, base, user, pass string) (ok bool, proof string, err error) {
	form := url.Values{
		a.ep.userField: {user},
		a.ep.passField: {pass},
	}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+a.ep.path, strings.NewReader(form))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))

	sess, accepted := megaracParseLogin(resp, body)
	if !accepted {
		return false, "", nil
	}
	proof = proofKV(
		"loginPath", a.ep.path,
		"token", sess.tokenKind,
		"tokenLen", strconv.Itoa(sess.tokenLen),
		"code", sess.successCode,
	)
	// Strengthen (best-effort): replay the minted QSESSIONID (+ X-CSRFTOKEN) against
	// an authenticated-only route to prove the session actually authorizes access.
	if okA, epA, stA, marker := megaracVerifySession(ctx, client, base, sess); okA {
		proof += " " + proofKV(
			"authedPath", epA,
			"authedStatus", strconv.Itoa(stA),
			"marker", marker,
		)
	}
	return true, proof, nil
}

// megaracSession is the server-minted session evidence extracted from a login
// response: the session token a rejected credential does not receive, plus the
// CSRF token needed to replay it against an authenticated-only route.
type megaracSession struct {
	tokenKind   string       // "QSESSIONID cookie" | "SESSION_TOKEN"
	tokenLen    int          // server-returned token length (this run)
	successCode string       // `"ok":0` | "WEBVAR_ERROR_WEB_SESSION:0"
	cookie      *http.Cookie // replayable QSESSIONID cookie (nil for a .asp body token)
	csrf        string       // CSRFTOKEN for the X-CSRFTOKEN header on the authed GET
}

// megaracParseLogin decides a MegaRAC login from the response and, on success,
// returns the session evidence. A rejected credential (401/403, or a non-zero
// WEBVAR_ERROR_WEB_SESSION / "ok" code) is a clean not-accepted. Success
// requires both a validated, non-trivial session token (QSESSIONID cookie or
// SESSION_TOKEN body value) and an explicit zero success code -- never bare
// cookie presence or a CSRF token alone.
func megaracParseLogin(resp *http.Response, body []byte) (megaracSession, bool) {
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return megaracSession{}, false // rejected credential
	}
	low := string(body)

	// Explicit result code: reject any non-zero, else record the zero success code
	// (its presence is required below, alongside a real token).
	successCode := ""
	if m := megaracWebErrRe.FindStringSubmatch(low); m != nil {
		if m[1] != "0" {
			return megaracSession{}, false // WEBVAR_ERROR_WEB_SESSION:<non-zero>
		}
		successCode = "WEBVAR_ERROR_WEB_SESSION:0"
	}
	if m := megaracOkRe.FindStringSubmatch(low); m != nil {
		if m[1] != "0" {
			return megaracSession{}, false // "ok":<non-zero>
		}
		successCode = `"ok":0`
	}
	if successCode == "" {
		return megaracSession{}, false // no explicit success code -> not a proven login
	}

	// A validated, server-minted session token -- the signal a rejected credential
	// does not get. QSESSIONID cookie (REST path) is replayable; the SESSION_TOKEN
	// body value (classic .asp path) is not, but still proves a minted session.
	sess := megaracSession{successCode: successCode}
	if m := megaracCSRFTokenRe.FindStringSubmatch(low); m != nil {
		sess.csrf = m[1]
	}
	for _, c := range resp.Cookies() {
		if strings.EqualFold(c.Name, "QSESSIONID") && megaracValidToken(c.Value) {
			sess.cookie = c
			sess.tokenKind = "QSESSIONID cookie"
			sess.tokenLen = len(c.Value)
			return sess, true
		}
	}
	if m := megaracSessionTokenRe.FindStringSubmatch(low); m != nil && megaracValidToken(m[1]) {
		sess.tokenKind = "SESSION_TOKEN"
		sess.tokenLen = len(m[1])
		return sess, true
	}
	return megaracSession{}, false // success code but no real session token
}

// megaracValidToken rejects empty / placeholder session-token values. A real
// MegaRAC token is a non-trivial string (a 36-char QSESSIONID UUID, or a long
// hex SESSION_TOKEN); the logged-out / rejected sentinels are empty, "0", an
// all-zero blob, or a "deleted"/"null" placeholder.
func megaracValidToken(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < 8 {
		return false
	}
	switch strings.ToLower(v) {
	case "null", "none", "deleted", "undefined":
		return false
	}
	return strings.Trim(v, "0") != ""
}

// megaracAuthedEndpoints are authenticated-only MegaRAC REST routes: without a
// valid session they return 401/403 (or redirect to the login SPA), so a 200 with
// a distinctive JSON marker under a freshly minted session proves the session
// authorizes access. (/api/settings/users is the authed-only route the
// http.ami.preAuthRouteRead differential also keys on.)
var megaracAuthedEndpoints = []struct {
	path    string
	markers []string
}{
	{path: "/api/settings/users", markers: []string{"username", "userid", "role", "privilege"}},
	{path: "/api/status", markers: []string{"power_status", "host_power", "status"}},
}

// megaracVerifySession replays the minted QSESSIONID cookie (with the X-CSRFTOKEN
// header) against an authenticated-only route and reports whether it returns real
// authenticated JSON (HTTP 200 with a marker, not a 401/403/redirect or the login
// SPA). Best-effort: a classic .asp body token has no replayable cookie, and a
// network error / unknown firmware layout leaves the token+success-code proof
// standing on its own.
func megaracVerifySession(ctx context.Context, client *http.Client, base string, sess megaracSession) (bool, string, int, string) {
	if sess.cookie == nil {
		return false, "", 0, "" // no replayable session cookie (classic .asp body token)
	}
	for _, ep := range megaracAuthedEndpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+ep.path, nil)
		if err != nil {
			continue
		}
		req.AddCookie(sess.cookie)
		if sess.csrf != "" {
			req.Header.Set("X-CSRFTOKEN", sess.csrf)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue // 401/403/303 -> session not honored here
		}
		low := strings.ToLower(string(body))
		if strings.Contains(low, "<html") || strings.Contains(low, "url_name=login") {
			continue // bounced to the login SPA -> not authenticated
		}
		for _, m := range ep.markers {
			if strings.Contains(low, m) {
				return true, ep.path, resp.StatusCode, m
			}
		}
	}
	return false, "", 0, ""
}

func init() {
	Register(Check{
		Name:        "http.megarac.webDefaultCreds",
		Description: "Active AMI MegaRAC SP-X web-UI default-credential login (POST /rpc/WEBSES/create.asp | /api/session) -- vendor-targeted, online only",
		Category:    "creds",
		Applies:     Applicability{CrossVendor: true}, // MegaRAC is BMC-class; the generic web check excludes BMC
		Enabled:     true,
		Run:         runMegaRACWebDefaultCreds,
	})
	RegisterExplain("http.megarac.webDefaultCreds", explainMegaRACWebDefaultCreds)
}

func runMegaRACWebDefaultCreds(ctx context.Context, t *engine.Target) []engine.Finding {
	if t.DisableLogins { // active login; online-gated
		return nil
	}
	vendor := identityVendor(t)
	if !megaracVendor(t, vendor) {
		return nil
	}
	cands := megaracWebCandidates(t, vendor)
	if len(cands) == 0 {
		return nil
	}
	port := webPort(t)
	proto := webProto(t)
	if port <= 0 {
		return nil
	}
	base := hostPortURL(proto, t.Host, port, "") // scheme://host:port
	per := megaracPerRequestTimeout(t.Timeout)
	client := insecureWebClient(per)

	// Fingerprint gate: only proceed against a genuine MegaRAC web UI with a live
	// RPC login endpoint, so an AMI-family host that is pure-Redfish/OpenBMC (or
	// otherwise not the MegaRAC RPC form) is left untouched -- no login POST.
	ep := megaracWebLoginEndpoint(ctx, client, base)
	if ep.zero() {
		return nil
	}

	adapter := megaracAdapter{ep: ep}
	attempts := 0
	for _, c := range cands {
		if ctx.Err() != nil {
			return nil
		}
		if attempts >= megaracMaxAttempts {
			break
		}
		attempts++
		okAuth, proof, err := adapter.login(ctx, client, base, c.user, c.pass)
		if err != nil {
			return nil
		}
		if !okAuth {
			continue
		}
		t.MarkOpen(port, "tcp", proto)
		passField := c.pass
		if passField == "" {
			passField = "(blank)"
		}
		return []engine.Finding{{
			Check: httpCredCheckName(vendor), Category: "creds", Risk: "critical",
			Port: port, Transport: "tcp", Protocol: proto,
			Fields: engine.F(
				"vendor", vendor,
				"username", c.user,
				"password", passField,
				"loginVia", adapter.mechanism(),
				"source", c.source,
				"evidenceEndpoint", ep.path,
				"proof", proof),
			CVE: cveOrNil(c.cve),
		}}
	}
	return nil
}

// megaracVendor reports whether the identified vendor is an AMI MegaRAC SP-X OEM
// (the family this check is scoped to), or the product string names MegaRAC.
func megaracVendor(t *engine.Target, vendor string) bool {
	if _, ok := megaracVendors[vendor]; ok {
		return true
	}
	if t.Identity != nil && strings.Contains(strings.ToLower(t.Identity.Product), "megarac") {
		return true
	}
	return false
}

type megaracCred struct{ user, pass, source, cve string }

// megaracWebCandidates returns operator-supplied creds first, then the identified
// vendor's documented MegaRAC defaults (creds.VendorCredsFor -- vendor-only, never
// the generic spray), de-duplicated, username required.
func megaracWebCandidates(t *engine.Target, vendor string) []megaracCred {
	seen := map[[2]string]struct{}{}
	var out []megaracCred
	add := func(u, p, src, cve string) {
		if u == "" {
			return
		}
		k := [2]string{u, p}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, megaracCred{u, p, src, cve})
	}
	// suppliedCreds folds this scan's own IPMI-recovered passwords in behind the
	// operator's, so the provenance has to be resolved per pair: labelling a
	// RAKP-cracked password "cli" claims the operator handed it over and hides that
	// the web login was reached from a credential the scan itself broke.
	credSource := credSourceFunc(t)
	for _, c := range suppliedCreds(t) {
		add(c.User, c.Pass, credSource(c), "")
	}
	for _, c := range creds.VendorCredsFor(vendor, creds.ClassHTTP) {
		add(c.Username, c.Password, c.Source, c.CVE)
	}
	return out
}

// megaracWebLoginEndpoint confirms a MegaRAC-family web UI at the root and then
// returns the live RPC login endpoint (classic /rpc/WEBSES/create.asp or REST
// /api/session), or a zero endpoint when the host is not a MegaRAC web-login
// surface (so we never POST credentials to a non-MegaRAC page).
func megaracWebLoginEndpoint(ctx context.Context, client *http.Client, base string) megaracEndpoint {
	if !megaracRootFingerprint(ctx, client, base) {
		return megaracEndpoint{}
	}
	for _, ep := range megaracEndpoints {
		if megaracEndpointLive(ctx, client, base+ep.path) {
			return ep
		}
	}
	return megaracEndpoint{}
}

// megaracRootFingerprint reports whether the web root looks like a MegaRAC-family
// web UI: the Angular SPA shell (<app-root>) or an explicit MegaRAC/AMI marker.
// It requires an HTML/SPA surface so a bare JSON API is not mistaken for one.
func megaracRootFingerprint(ctx context.Context, client *http.Client, base string) bool {
	for _, path := range []string{"/", "/index.html"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		low := strings.ToLower(string(body))
		if strings.Contains(low, "<app-root") ||
			strings.Contains(low, "megarac") ||
			strings.Contains(low, "american megatrends") ||
			strings.Contains(low, "webses") ||
			strings.Contains(low, "qsessionid") {
			return true
		}
	}
	return false
}

// megaracEndpointLive reports whether a GET of a candidate login endpoint looks
// like a live MegaRAC RPC/REST endpoint: reachable, not a 404, and not the SPA
// HTML catch-all (which would serve index.html for unknown routes). GET carries
// no credentials, so it neither creates a session nor counts toward lockout.
func megaracEndpointLive(ctx context.Context, client *http.Client, u string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	resp.Body.Close()
	if resp.StatusCode == 0 || resp.StatusCode == http.StatusNotFound {
		return false
	}
	// A login endpoint is POST-only, so the routed answer to this GET is often
	// "method not allowed" carrying the web server's own HTML error page. That page
	// is a document, and rejecting it below discards the one status code that proves
	// the route exists. The SPA catch-all cannot produce it: an unknown route is
	// served as 200 index.html.
	if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented {
		return true
	}
	low := strings.ToLower(string(body))
	// The SPA catch-all returns the Angular index document; that is not the real
	// login endpoint.
	if strings.Contains(low, "<app-root") || strings.Contains(low, "<!doctype html") {
		return false
	}
	return true
}

func megaracPerRequestTimeout(scanTimeout time.Duration) time.Duration {
	if scanTimeout <= 0 || scanTimeout > 4*time.Second {
		return 4 * time.Second
	}
	if scanTimeout < time.Second {
		return time.Second
	}
	return scanTimeout
}

func explainMegaRACWebDefaultCreds(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 443)
	user := explainField(f, "username")
	pass := explainField(f, "password")
	endpoint := explainField(f, "evidenceEndpoint")
	if endpoint == "" {
		endpoint = "/rpc/WEBSES/create.asp"
	}
	baseURL := explainBaseURL(host, f, port, "https")
	uField, pField := "WEBVAR_USERNAME", "WEBVAR_PASSWORD"
	if endpoint == "/api/session" {
		uField, pField = "username", "password"
	}
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nThe AMI MegaRAC SP-X web UI accepted the default credential **%s / %s** via %s.\n", user, pass, endpoint))
	b.WriteString("\n**Validate (POST the creds to the MegaRAC RPC login):**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk -c - -X POST %s%s \\", baseURL, endpoint),
		fmt.Sprintf("  --data-urlencode '%s=%s' --data-urlencode '%s=%s'", uField, user, pField, pass),
	))
	b.WriteString("\n\n**Impact:** Full MegaRAC BMC web access -- KVM/vMedia, power control, user management, firmware.\n")
	return b.String()
}
