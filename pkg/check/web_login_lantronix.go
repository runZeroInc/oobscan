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

// Lantronix SLC/SLB console-manager web-login adapter. The SLC `xwsd` web tier
// accepts `slclogin`/`slcpassword` at `/`: success sets an `SLM_` session
// cookie and redirects to `/`; rejection returns the login page and clears the
// cookie. The adapter verifies the cookie against `/home.htm` or
// `/websessions.htm`.
type lantronixAdapter struct{}

func (lantronixAdapter) mechanism() string { return "httpForm" }

func (lantronixAdapter) login(ctx context.Context, client *http.Client, base, user, pass string) (ok bool, proof string, err error) {
	form := url.Values{"slclogin": {user}, "slcpassword": {pass}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/", strings.NewReader(form))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer func() { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192)); resp.Body.Close() }()

	// Success is a 302 to `/`; a rejected credential re-renders login.htm at HTTP
	// 200 (with "Invalid login.") and mints no session token.
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return false, "", nil
	}
	// A reject clears the cookie (session=""); only a non-empty SLM token counts.
	sc := lantronixSessionCookie(resp.Cookies())
	if sc == nil {
		return false, "", nil // 302 without a real SLC session token: not success
	}

	// Prove the token authorizes access: GET an authenticated-only page with it.
	authed, gated, ep, marker := lantronixVerifySession(ctx, client, base, sc)
	locTrim := webLoginTrimLoc(resp.Header.Get("Location"))
	switch {
	case authed:
		return true, proofKV(
			"loginStatus", strconv.Itoa(resp.StatusCode), "location", locTrim,
			"cookie", sc.Name, "cookieLen", strconv.Itoa(len(sc.Value)),
			"authedPath", ep, "marker", marker), nil
	case gated:
		return false, "", nil
	default:
		// The success-only SLM token remains evidence when verification is unavailable.
		return true, proofKV(
			"loginStatus", strconv.Itoa(resp.StatusCode), "location", locTrim,
			"cookie", sc.Name, "cookieLen", strconv.Itoa(len(sc.Value)),
			"verify", "inconclusive"), nil
	}
}

// lantronixSLMSuffix matches the xwsd session-token timestamp suffix
// (`-DDMMYYhhmmss`) so a bare/placeholder value is not mistaken for a token.
var lantronixSLMSuffix = regexp.MustCompile(`-\d{10,}$`)

// lantronixSessionCookie returns the minted SLC session-token cookie, or nil. The
// token is `session=SLM_<...>` or `session=<...>-<timestamp>`; a rejected/logged-
// off unit clears it to session="" (empty value), which never matches here.
func lantronixSessionCookie(cookies []*http.Cookie) *http.Cookie {
	for _, c := range cookies {
		if !strings.EqualFold(c.Name, "session") {
			continue
		}
		v := strings.TrimSpace(c.Value)
		if v == "" || v == `""` || len(v) < 4 {
			continue
		}
		if strings.HasPrefix(v, "SLM_") || lantronixSLMSuffix.MatchString(v) {
			return c
		}
	}
	return nil
}

// lantronixVerifySession GETs a session-gated SLC page with the minted cookie
// to confirm it grants real authenticated content (xwsd bounces an
// unauthenticated request to the login page):
//
//	authed - authenticated content returned (no login form)
//	gated  - bounced to the login page -- cookie did not authorize (reject)
//	ep     - the endpoint that answered
//	marker - a distinctive marker from its response (title + size)
//
// Otherwise inconclusive (transport error / unexpected status): the caller
// falls back to trusting the success-only SLM session cookie.
func lantronixVerifySession(ctx context.Context, client *http.Client, base string, sc *http.Cookie) (authed, gated bool, ep, marker string) {
	loginPage := func(low string) bool {
		return strings.Contains(low, "name=slclogin") ||
			strings.Contains(low, "slcpassword") ||
			strings.Contains(low, "invalid login") ||
			strings.Contains(low, "logintitle") ||
			strings.Contains(low, "login to") ||
			(strings.Contains(low, "refresh") && strings.Contains(low, "login.htm"))
	}
	for _, path := range []string{"/home.htm", "/websessions.htm"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		req.AddCookie(sc)
		resp, err := client.Do(req)
		if err != nil {
			continue // transport error on this endpoint; try the next
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		resp.Body.Close()
		low := strings.ToLower(string(body))
		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			if l := strings.ToLower(resp.Header.Get("Location")); strings.Contains(l, "login") {
				return false, true, path, "" // bounced to login: cookie invalid
			}
			// A redirect elsewhere is inconclusive; try the next endpoint.
		case resp.StatusCode == http.StatusOK:
			if loginPage(low) {
				return false, true, path, "" // served the login page, not authed content
			}
			m := htmlTitle(body)
			if m != "" {
				m = fmt.Sprintf("title=%s, %dB", m, len(body))
			} else {
				m = fmt.Sprintf("HTTP 200, %dB", len(body))
			}
			return true, false, path, m
			// Any other status is inconclusive; try the next endpoint.
		}
	}
	return false, false, "", ""
}

func init() { registerWebLoginAdapter("lantronix", lantronixAdapter{}) }
