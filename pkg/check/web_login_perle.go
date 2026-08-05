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

type perleAdapter struct{}

func (perleAdapter) mechanism() string { return "httpForm" }

func (perleAdapter) login(ctx context.Context, client *http.Client, base, user, pass string) (ok bool, proof string, err error) {

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
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer func() { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192)); resp.Body.Close() }()

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return false, "", nil
	}
	loc := resp.Header.Get("Location")
	if perleRedirectToLogin(loc) {
		return false, "", nil
	}

	sc := perleSessionCookie(resp.Cookies())
	if sc == nil {
		return false, "", nil
	}

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

		return true, proofKV(
			"loginStatus", strconv.Itoa(resp.StatusCode), "location", locTrim,
			"cookie", sc.Name, "cookieLen", strconv.Itoa(len(sc.Value)),
			"verify", "inconclusive"), nil
	}
}

var (
	perleReCSRFNameFirst = regexp.MustCompile(`(?i)name=["']?csrf_id["']?[^>]*?\bvalue=["']?([^"'\s>]+)`)
	perleReCSRFValFirst  = regexp.MustCompile(`(?i)value=["']?([^"'\s>]+)["']?[^>]*?\bname=["']?csrf_id`)
)

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

func perleRedirectToLogin(loc string) bool {
	l := strings.ToLower(loc)
	return strings.Contains(l, "login_failed") ||
		strings.Contains(l, "login.html") ||
		strings.Contains(l, "manage.cgi/login")
}

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
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		resp.Body.Close()
		low := strings.ToLower(string(body))
		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			if perleRedirectToLogin(resp.Header.Get("Location")) {
				return false, true, path, ""
			}

		case resp.StatusCode == http.StatusOK:
			if loginBody(low) {
				return false, true, path, ""
			}
			m := htmlTitle(body)
			if m == "" {
				m = fmt.Sprintf("HTTP 200, %dB", len(body))
			}
			return true, false, path, m

		}
	}
	return false, false, "", ""
}

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
