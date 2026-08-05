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

type megaracAdapter struct{ ep megaracEndpoint }

func (megaracAdapter) mechanism() string { return "httpRpc" }

const megaracMaxAttempts = 6

type megaracEndpoint struct {
	path      string
	userField string
	passField string
}

func (e megaracEndpoint) zero() bool { return e.path == "" }

var megaracEndpoints = []megaracEndpoint{
	{path: "/rpc/WEBSES/create.asp", userField: "WEBVAR_USERNAME", passField: "WEBVAR_PASSWORD"},
	{path: "/api/session", userField: "username", passField: "password"},
}

var megaracVendors = map[string]struct{}{
	"ami": {}, "fujitsu": {}, "asus": {}, "asrockrack": {},
	"tyan": {}, "gigabyte": {}, "inspur": {}, "h3c": {},
}

var (
	megaracSessionTokenRe = regexp.MustCompile(`(?i)session[_ ]?token['":=\s]+['"]?([0-9a-zA-Z]{6,})`)

	megaracCSRFTokenRe = regexp.MustCompile(`(?i)csrf[_ ]?token['":=\s]+['"]?([0-9a-zA-Z]{6,})`)

	megaracWebErrRe = regexp.MustCompile(`(?i)WEBVAR_ERROR_WEB_SESSION\s*:\s*(-?\d+)`)

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

	if okA, epA, stA, marker := megaracVerifySession(ctx, client, base, sess); okA {
		proof += " " + proofKV(
			"authedPath", epA,
			"authedStatus", strconv.Itoa(stA),
			"marker", marker,
		)
	}
	return true, proof, nil
}

type megaracSession struct {
	tokenKind   string
	tokenLen    int
	successCode string
	cookie      *http.Cookie
	csrf        string
}

func megaracParseLogin(resp *http.Response, body []byte) (megaracSession, bool) {
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return megaracSession{}, false
	}
	low := string(body)

	successCode := ""
	if m := megaracWebErrRe.FindStringSubmatch(low); m != nil {
		if m[1] != "0" {
			return megaracSession{}, false
		}
		successCode = "WEBVAR_ERROR_WEB_SESSION:0"
	}
	if m := megaracOkRe.FindStringSubmatch(low); m != nil {
		if m[1] != "0" {
			return megaracSession{}, false
		}
		successCode = `"ok":0`
	}
	if successCode == "" {
		return megaracSession{}, false
	}

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
	return megaracSession{}, false
}

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

var megaracAuthedEndpoints = []struct {
	path    string
	markers []string
}{
	{path: "/api/settings/users", markers: []string{"username", "userid", "role", "privilege"}},
	{path: "/api/status", markers: []string{"power_status", "host_power", "status"}},
}

func megaracVerifySession(ctx context.Context, client *http.Client, base string, sess megaracSession) (bool, string, int, string) {
	if sess.cookie == nil {
		return false, "", 0, ""
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
			continue
		}
		low := strings.ToLower(string(body))
		if strings.Contains(low, "<html") || strings.Contains(low, "url_name=login") {
			continue
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
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runMegaRACWebDefaultCreds,
	})
	RegisterExplain("http.megarac.webDefaultCreds", explainMegaRACWebDefaultCreds)
}

func runMegaRACWebDefaultCreds(ctx context.Context, t *engine.Target) []engine.Finding {
	if t.DisableLogins {
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
	base := hostPortURL(proto, t.Host, port, "")
	per := megaracPerRequestTimeout(t.Timeout)
	client := insecureWebClient(per)

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

	credSource := credSourceFunc(t)
	for _, c := range suppliedCreds(t) {
		add(c.User, c.Pass, credSource(c), "")
	}
	for _, c := range creds.VendorCredsFor(vendor, creds.ClassHTTP) {
		add(c.Username, c.Password, c.Source, c.CVE)
	}
	return out
}

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

	if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented {
		return true
	}
	low := strings.ToLower(string(body))

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
