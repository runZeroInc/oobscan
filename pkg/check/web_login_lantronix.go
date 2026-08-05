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

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return false, "", nil
	}

	sc := lantronixSessionCookie(resp.Cookies())
	if sc == nil {
		return false, "", nil
	}

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

		return true, proofKV(
			"loginStatus", strconv.Itoa(resp.StatusCode), "location", locTrim,
			"cookie", sc.Name, "cookieLen", strconv.Itoa(len(sc.Value)),
			"verify", "inconclusive"), nil
	}
}

var lantronixSLMSuffix = regexp.MustCompile(`-\d{10,}$`)

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
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		resp.Body.Close()
		low := strings.ToLower(string(body))
		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			if l := strings.ToLower(resp.Header.Get("Location")); strings.Contains(l, "login") {
				return false, true, path, ""
			}

		case resp.StatusCode == http.StatusOK:
			if loginPage(low) {
				return false, true, path, ""
			}
			m := htmlTitle(body)
			if m != "" {
				m = fmt.Sprintf("title=%s, %dB", m, len(body))
			} else {
				m = fmt.Sprintf("HTTP 200, %dB", len(body))
			}
			return true, false, path, m

		}
	}
	return false, false, "", ""
}

func init() { registerWebLoginAdapter("lantronix", lantronixAdapter{}) }
