// Package apc implements active validation probes for the APC /
// Schneider Network Management Card web tier, turning fingerprint-derived candidates
// into confirmed findings: Login verifies a credential without sending any
// state-changing action, LimitedStatusOpen confirms the pre-auth limited-status page
// is serving device status, and MacontrolExempt confirms the PowerChute control
// endpoint is exempt from the session auth gate.
//
// The NMC keys its session off a URL-path token rather than a cookie: a successful
// login redirects to the bare authenticated base while a failure redirects back to
// the logon or password page, and that differential is the confirmation signal.
package apc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

// Client is a bounded, redirect-disabled HTTP client scoped to one NMC.
type Client struct {
	base string
	hc   *http.Client
}

var (
	reNMCPath = regexp.MustCompile(`/NMC/[^/]+/`)   // the /NMC/<token>/ prefix
	reAuthed  = regexp.MustCompile(`^/NMC/[^/]+/$`) // bare authed base (login OK)
)

// New builds a Client for host:port. The scheme is derived from the port so an
// HTTP-only NMC (tcp/80, HTTPS disabled) is probed correctly.
func New(host string, port int, timeout time.Duration) *Client {
	return NewWithScheme(netaddr.DefaultScheme(port), host, port, timeout)
}

// NewWithScheme builds a Client for an explicit scheme (http/https). Callers that
// already know the transport identify observed (via the target's web.scheme
// attribute) should use this so an NMC on a non-standard HTTP port is not
// mis-probed as HTTPS. An unrecognized scheme falls back to https.
func NewWithScheme(scheme, host string, port int, timeout time.Duration) *Client {
	if scheme != "http" && scheme != "https" {
		scheme = "https"
	}
	return newClient(netaddr.URL(scheme, host, port, ""), timeout)
}

// newClient builds a Client for an explicit base URL (used by tests).
func newClient(base string, timeout time.Duration) *Client {
	return &Client{
		base: base,
		// Never follow redirects: the redirect target IS the signal.
		hc: httpx.ClientWithRedirect(timeout, func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }),
	}
}

// resp is a trimmed request outcome.
type resp struct {
	status  int
	locPath string // path component of the Location header
	body    string
}

func (c *Client) do(ctx context.Context, method, path, body string) (resp, error) {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return resp{}, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r, err := c.hc.Do(req)
	if err != nil {
		return resp{}, err
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
	out := resp{status: r.StatusCode, body: string(b)}
	if loc := r.Header.Get("Location"); loc != "" {
		if u, perr := url.Parse(loc); perr == nil {
			out.locPath = u.Path
		}
	}
	return out, nil
}

// tokenPath fetches /home.htm and returns the /NMC/<token>/ prefix the NMC
// hands out for a fresh (unauthenticated) session, or "" if none.
func (c *Client) tokenPath(ctx context.Context) string {
	r, err := c.do(ctx, http.MethodGet, "/home.htm", "")
	if err != nil {
		return ""
	}
	if m := reNMCPath.FindString(r.locPath); m != "" {
		return m
	}
	// Some builds land directly on a page under /NMC/<token>/; check the path.
	return reNMCPath.FindString(r.locPath)
}

// Login actively verifies user:pass against the NMC form login. It returns
// ok=true only when the login POST redirects to the bare authenticated base
// (/NMC/<newtoken>/) rather than back to logon.htm/Password, plus a short proof
// scraped from the authenticated landing page (device model / firmware). It
// sends one login POST without configuration writes. Failed attempts can
// increment the NMC lockout counter; callers should limit attempts and stop
// at the first success.
func (c *Client) Login(ctx context.Context, user, pass string) (ok bool, proof string, err error) {
	tok := c.tokenPath(ctx)
	if tok == "" {
		return false, "", fmt.Errorf("no NMC session token (not an APC NMC login flow)")
	}
	form := url.Values{
		"prefLanguage":   {"00000000"},
		"login_username": {user},
		"login_password": {pass},
		"submit":         {"Log On"},
	}.Encode()
	r, err := c.do(ctx, http.MethodPost, tok+"Forms/login1", form)
	if err != nil {
		return false, "", err
	}
	// The login POST 3xx-redirecting to the bare /NMC/<newtoken>/ base (not
	// .../logon.htm | .../Password, not a re-rendered 200 logon) is necessary but
	// not sufficient -- the redirect target alone is not proof. Confirm the session
	// by GETting an authenticated-only page under the new token and requiring it to
	// return real authenticated content: a rejected credential's token bounces that
	// GET straight back to logon.htm (303) or re-serves the login form.
	if r.status < 300 || r.status >= 400 || !reAuthed.MatchString(r.locPath) {
		return false, "", nil
	}
	h, herr := c.do(ctx, http.MethodGet, r.locPath+"home.htm", "")
	if herr != nil {
		return false, "", nil
	}
	// Release the session slot regardless of the verdict (the NMC caps concurrent
	// sessions; logout.htm is on the no-auth whitelist).
	defer func() { _, _ = c.do(ctx, http.MethodGet, r.locPath+"logout.htm", "") }()
	if h.status < 200 || h.status >= 300 || !looksLikeAuthedNMC(h.body) {
		// The minted token did not read an authenticated page -- redirect back to
		// logon.htm or the login form re-served -- so the login is not confirmed.
		return false, "", nil
	}
	proof = fmt.Sprintf("authedPath=%s status=%d %s", r.locPath+"home.htm", h.status, apcProof(h.body))
	return true, proof, nil
}

// looksLikeAuthedNMC reports whether a page fetched under a post-login /NMC/<tok>/
// token is a genuinely authenticated NMC page rather than the logon/password page
// re-served (or a generic error). The logon page carries the login form; an
// authenticated page carries the device model/firmware string, the NMC nav, or a
// logout affordance. The post-login GET is required because a redirect alone
// does not prove authentication.
func looksLikeAuthedNMC(body string) bool {
	low := strings.ToLower(body)
	if strings.Contains(low, "login_password") || strings.Contains(low, "login_username") {
		return false // the logon form was re-served -> not authenticated
	}
	return reModelFW.MatchString(body) ||
		strings.Contains(low, "logout") ||
		strings.Contains(low, "network management card")
}

// apcProof extracts a compact login-proof from the authenticated NMC home page:
// the model/firmware line if present, else the page <title>.
func apcProof(body string) string {
	if m := reModelFW.FindString(body); m != "" {
		return fmt.Sprintf("modelFw=%q", snippet(m))
	}
	low := strings.ToLower(body)
	if i := strings.Index(low, "<title"); i >= 0 {
		if gt := strings.IndexByte(body[i:], '>'); gt >= 0 {
			start := i + gt + 1
			if end := strings.Index(strings.ToLower(body[start:]), "</title>"); end >= 0 {
				return fmt.Sprintf("title=%q", snippet(body[start:start+end]))
			}
		}
	}
	if strings.Contains(low, "logout") {
		return "logout=true"
	}
	return "nmcMarker=true"
}

var reModelFW = regexp.MustCompile(`(?i)(AP\d{4}[A-Z0-9]*|v\d+\.\d+\.\d+[^"<\r\n]{0,40})`)

// LimitedStatusOpen confirms /limstat.htm serves device status without a login.
// It is "open" only when the page renders (2xx); a redirect to logon.htm means
// the Limited Status Page is disabled (the default).
func (c *Client) LimitedStatusOpen(ctx context.Context) (bool, string, error) {
	r, err := c.do(ctx, http.MethodGet, "/limstat.htm", "")
	if err != nil {
		return false, "", err
	}
	if r.status >= 200 && r.status < 300 && looksLikeLimitedStatus(r.body) {
		return true, snippet(r.body), nil
	}
	return false, "", nil
}

// MacontrolInfo contains the fields returned by an APC MACONTROL status page.
// Field names follow the page's wire format because several are undocumented.
type MacontrolInfo struct {
	MV string
	PC string
	DT string
	TM string
	SR string
	SU string
	RD string
	CI string
	CS string
	MD string
}

// MacontrolExempt confirms the PowerChute/PCNS control endpoint /macontrol.htm is
// present and exempt from the web-session auth gate. It is a read-only GET: the
// endpoint sits on the NMC's no-auth whitelist, so a fresh unauthenticated client
// that is not redirected to logon.htm proves the exemption. It must never POST
// /Forms/macontrol1, which is the state-changing PCNS action. A valid result requires
// the MACONTROL title and protocol fields; generic 2xx pages and 403/405 denial pages
// are not evidence of exposure.
func (c *Client) MacontrolExempt(ctx context.Context) (info *MacontrolInfo, snip string, err error) {
	r, err := c.do(ctx, http.MethodGet, "/macontrol.htm", "")
	if err != nil {
		return nil, "", err
	}
	if r.status < 200 || r.status >= 300 {
		return nil, "", nil
	}
	info, ok := parseMacontrol(r.body)
	if !ok {
		return nil, "", nil
	}
	return info, snippet(r.body), nil
}

// MacontrolPostAuthExempt confirms the PCNS control handler /Forms/macontrol1
// sits outside the web-session auth gate without touching device state. It sends
// an HTTP HEAD -- never a POST -- so no shutdown/register/unregister action can be
// driven: a HEAD carries no form body and, per HTTP semantics, must have no side
// effects. If the endpoint redirects to logon it is gated; a 401/403/404 means it
// is not reachable/exempt; any other status (including 405 Method Not Allowed on
// the POST-only handler) proves the handler exists outside the login.
func (c *Client) MacontrolPostAuthExempt(ctx context.Context) (exempt bool, status int, snip string, err error) {
	r, err := c.do(ctx, http.MethodHead, "/Forms/macontrol1", "")
	if err != nil {
		return false, 0, "", err
	}
	if strings.Contains(strings.ToLower(r.locPath), "logon") {
		return false, r.status, snippet(r.body), nil
	}
	if r.status == http.StatusUnauthorized || r.status == http.StatusForbidden || r.status == http.StatusNotFound {
		return false, r.status, snippet(r.body), nil
	}
	return true, r.status, snippet(r.body), nil
}

func looksLikeLimitedStatus(body string) bool {
	low := strings.ToLower(body)
	if bodyStart := strings.Index(low, "<body"); bodyStart >= 0 {
		if bodyOpenEnd := strings.IndexByte(low[bodyStart:], '>'); bodyOpenEnd >= 0 {
			low = low[bodyStart+bodyOpenEnd+1:]
			if end := strings.Index(low, "</body>"); end >= 0 {
				low = low[:end]
			}
		}
	}
	tokens := make(map[string]struct{})
	for _, token := range reLimitedStatusToken.FindAllString(low, -1) {
		tokens[token] = struct{}{}
	}
	branded := strings.Contains(low, "apc") || strings.Contains(low, "schneider")
	return len(tokens) >= 2 || branded && len(tokens) >= 1
}

var reLimitedStatusToken = regexp.MustCompile(`\b(?:ups|pdu|battery|runtime|outlets?|load|voltage|current|phase)\b`)

var (
	reMacontrolTitle = regexp.MustCompile(`(?is)<title[^>]*>\s*macontrol\s*</title>`)
	reMacontrolField = regexp.MustCompile(`(?m)(?:^|[\s>])([A-Z]{2})=([^\s<]+)`)
)

func parseMacontrol(body string) (*MacontrolInfo, bool) {
	if !reMacontrolTitle.MatchString(body) {
		return nil, false
	}
	values := make(map[string]string)
	for _, match := range reMacontrolField.FindAllStringSubmatch(body, -1) {
		values[match[1]] = match[2]
	}
	if values["MV"] == "" || values["PC"] == "" || len(values) < 4 {
		return nil, false
	}
	return &MacontrolInfo{
		MV: values["MV"], PC: values["PC"], DT: values["DT"], TM: values["TM"],
		SR: values["SR"], SU: values["SU"], RD: values["RD"], CI: values["CI"],
		CS: values["CS"], MD: values["MD"],
	}, true
}

// DemoLogin actively tests the hidden APC "Test Drive" demo/service credential,
// reusing the NMC form-login flow from Login: one POST /Forms/login1,
// without configuration writes. On a production unit the credential should not authenticate,
// since it is gated behind the uploadable demo marker file, so ok=true means either a
// demo unit or a planted marker acting as a password-change-surviving backdoor.
func (c *Client) DemoLogin(ctx context.Context) (ok bool, proof string, err error) {
	return c.Login(ctx, DemoUser, DemoPassword)
}

// DemoUser / DemoPassword are the hidden APC NMC "Test Drive" demo/service
// credential (literal apc\0jmm627\0 in the shared NMC3 AOS auth core). Gated by
// the uploadable /testdrive522.ini marker.
const (
	DemoUser     = "apc"
	DemoPassword = "jmm627"
)

// snippet renders a short one-line printable-ASCII preview of a response body.
func snippet(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\n' || c == '\r' || c == '\t':
			b = append(b, ' ')
		case c >= 0x20 && c < 0x7f:
			b = append(b, c)
		}
	}
	out := strings.Join(strings.Fields(string(b)), " ")
	if len(out) > 120 {
		out = out[:120]
	}
	return out
}
