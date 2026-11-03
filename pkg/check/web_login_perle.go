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
)

// Perle IOLAN console/device-server web-login adapter.
//
//	GET  /manage.cgi/login   -> login page (form action="?submit", fields
//	                            username/password/login). Modern Apache-fronted
//	                            units set no CSRF/session cookie; older direct
//	                            mini_httpd builds embed a hidden csrf_id.
//	POST /manage.cgi/login?submit  application/x-www-form-urlencoded
//	  username=<u>&password=<p>&login=Login[&csrf_id=<tok>]
//
// Both outcomes redirect. Rejection targets `login_failed=1` and clears only
// housekeeping cookies; success mints a non-empty session cookie, verified
// against `/manage.cgi/home` or `/manage.cgi/`.
type perleAdapter struct{}

func (perleAdapter) mechanism() string { return "httpForm" }

func (perleAdapter) login(ctx context.Context, client *http.Client, base, user, pass string) (ok bool, proof string, err error) {
	// Preflight: fetch the login page to obtain the CSRF token (older units) and
	// any initial cookies the POST must carry. A transport error aborts the
	// attempt loop (device unreachable / not this device).
	csrf, cookies, perr := perleLoginPreflight(ctx, client, base)
	if perr != nil {
		return false, "", perr
	}

	form := url.Values{
		"username": {user},
		"password": {pass},
		"login":    {"Login"},
	}
	if csrf != "" {
		form.Set("csrf_id", csrf)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/manage.cgi/login?submit", strings.NewReader(form.Encode()))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies { // bind the CSRF token to its session
		req.AddCookie(c)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer func() { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192)); resp.Body.Close() }()

	// The login POST always answers 302 on this firmware; a 200 is the login-page
	// re-render (or not this flow) -- never a success.
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return false, "", nil
	}
	loc := resp.Header.Get("Location")
	if perleRedirectToLogin(loc) {
		return false, "", nil // explicit rejected-credential / login-page redirect
	}
	// Success mints a real session-token cookie; a reject mints none (only cleared
	// housekeeping cookies, which have an empty value and are filtered here).
	sc := perleSessionCookie(resp.Cookies())
	if sc == nil {
		return false, "", nil // 302 without a session token: ambiguous, not success
	}

	// Verify the token against an authenticated management page.
	authed, gated, ep, marker := perleVerifySession(ctx, client, base, perleMergeCookies(cookies, sc))
	locTrim := webLoginTrimLoc(loc)
	switch {
	case authed:
		return true, proofKV(
			"loginStatus", strconv.Itoa(resp.StatusCode), "location", locTrim,
			"cookie", sc.Name, "cookieLen", strconv.Itoa(len(sc.Value)),
			"authedPath", ep, "marker", marker), nil
	case gated:
		return false, "", nil
	default:
		// The success-only session token remains evidence when verification is unavailable.
		return true, proofKV(
			"loginStatus", strconv.Itoa(resp.StatusCode), "location", locTrim,
			"cookie", sc.Name, "cookieLen", strconv.Itoa(len(sc.Value)),
			"verify", "inconclusive"), nil
	}
}

// perleReCSRF* match the hidden csrf_id form token in either attribute order.
var (
	perleReCSRFNameFirst = regexp.MustCompile(`(?i)name=["']?csrf_id["']?[^>]*?\bvalue=["']?([^"'\s>]+)`)
	perleReCSRFValFirst  = regexp.MustCompile(`(?i)value=["']?([^"'\s>]+)["']?[^>]*?\bname=["']?csrf_id`)
)

// perleLoginPreflight GETs the IOLAN login page and returns the CSRF token (may
// be "" -- the Apache-fronted units render no token) and the cookies the login
// POST must echo. A transport error is returned as err so the caller stops the
// attempt loop.
func perleLoginPreflight(ctx context.Context, client *http.Client, base string) (csrf string, cookies []*http.Cookie, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/manage.cgi/login", nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	cookies = resp.Cookies()
	if m := perleReCSRFNameFirst.FindSubmatch(body); m != nil {
		csrf = string(m[1])
	} else if m := perleReCSRFValFirst.FindSubmatch(body); m != nil {
		csrf = string(m[1])
	}
	return csrf, cookies, nil
}

// perleSessionCookie returns the minted session-token cookie from a login-POST
// response, or nil. The IOLAN names it `session` (firmware Cookie.session); some
// proxied units prefix it (perle_session), so the match is name-contains-session
// with a non-empty, non-placeholder value. The cleared housekeeping cookies
// (simpleHtml/simpleHtmlTmp/motd) carry an empty value and never match.
func perleSessionCookie(cookies []*http.Cookie) *http.Cookie {
	for _, c := range cookies {
		if !strings.Contains(strings.ToLower(c.Name), "session") {
			continue
		}
		v := strings.TrimSpace(c.Value)
		if v == "" || v == "0" || v == "deleted" || len(v) < 4 {
			continue
		}
		return c
	}
	return nil
}

// perleMergeCookies returns the preflight cookies with the freshly minted session
// cookie overriding any same-name preflight cookie, so the authenticated GET
// carries exactly one `session` value (the new one). Without this, a unit that
// sets a session cookie on the login-page GET would send two same-name cookies
// and the server would read the stale preflight value.
func perleMergeCookies(base []*http.Cookie, override *http.Cookie) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(base)+1)
	for _, c := range base {
		if c.Name == override.Name {
			continue
		}
		out = append(out, c)
	}
	return append(out, override)
}

// perleRedirectToLogin reports whether a 302 Location points back at the login
// page -- the rejected-credential signal (`login_failed`) or a bare redirect to
// the login page (`/login.html`, `/manage.cgi/login`). A successful login
// redirects to a management page, which matches none of these.
func perleRedirectToLogin(loc string) bool {
	l := strings.ToLower(loc)
	return strings.Contains(l, "login_failed") ||
		strings.Contains(l, "login.html") ||
		strings.Contains(l, "manage.cgi/login")
}

// perleVerifySession GETs a session-gated management page with the freshly
// minted cookies to confirm it returns authenticated content (unauthenticated
// pages 302 to /login.html; a valid session returns HTTP 200 content):
//
//	authed - authenticated content returned (confirmed session)
//	gated  - redirected back to / served the login page (cookie did not
//	         authorize -- a definitive rejection)
//	ep     - the endpoint that answered
//	marker - a distinctive marker from its response (title or status+len)
//
// Otherwise inconclusive (transport error / unexpected status like 404): the
// caller falls back to trusting the success-only session cookie.
func perleVerifySession(ctx context.Context, client *http.Client, base string, cookies []*http.Cookie) (authed, gated bool, ep, marker string) {
	loginBody := func(low string) bool {
		return strings.Contains(low, "webmgr_session_expired") ||
			strings.Contains(low, "not logged into") ||
			strings.Contains(low, "url=/manage.cgi/login") ||
			strings.Contains(low, `action="?submit"`)
	}
	for _, path := range []string{"/manage.cgi/home", "/manage.cgi/"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue // transport error on this endpoint; try the next
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		resp.Body.Close()
		low := strings.ToLower(string(body))
		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			if perleRedirectToLogin(resp.Header.Get("Location")) {
				return false, true, path, "" // gated back to login: cookie invalid
			}
			// A redirect elsewhere is inconclusive; try the next endpoint.
		case resp.StatusCode == http.StatusOK:
			if loginBody(low) {
				return false, true, path, "" // served the login page, not authed content
			}
			m := htmlTitle(body)
			if m == "" {
				m = fmt.Sprintf("HTTP 200, %dB", len(body))
			}
			return true, false, path, m
			// Any other status (404/5xx) is inconclusive; try the next endpoint.
		}
	}
	return false, false, "", ""
}

// webLoginTrimLoc shortens a redirect Location to its path (+query) for the proof
// line, dropping the scheme://host the IOLAN emits as an absolute redirect.
func webLoginTrimLoc(loc string) string {
	if loc == "" {
		return "(none)"
	}
	if u, err := url.Parse(loc); err == nil && u.Path != "" {
		if u.RawQuery != "" {
			return u.Path + "?" + u.RawQuery
		}
		return u.Path
	}
	return loc
}

func init() { registerWebLoginAdapter("perle", perleAdapter{}) }
