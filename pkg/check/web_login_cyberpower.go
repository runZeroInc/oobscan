package check

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var cyberpowerResultOK = regexp.MustCompile(`"result"\s*:\s*"ok"`)

var cyberpowerRedirect = regexp.MustCompile(`"redirect"\s*:\s*"([^"]+)"`)

type cyberpowerAdapter struct{}

func (cyberpowerAdapter) mechanism() string { return "httpForm" }

func (cyberpowerAdapter) login(ctx context.Context, client *http.Client, base, user, pass string) (ok bool, proof string, err error) {
	form := url.Values{"username": {user}, "password": {pass}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/login.cgi", strings.NewReader(form))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	for _, c := range resp.Cookies() {
		if c.Name == "cocp" && c.Value != "" {
			return true, proofKV("loginPath", "/login.cgi", "status", strconv.Itoa(resp.StatusCode), "cookie", c.Name, "cookieLen", strconv.Itoa(len(c.Value))), nil
		}
	}
	if cyberpowerResultOK.Match(body) {
		if m := cyberpowerRedirect.FindSubmatch(body); m != nil {
			return true, proofKV("loginPath", "/login.cgi", "status", strconv.Itoa(resp.StatusCode), "result", "ok", "redirect", string(m[1])), nil
		}
	}
	return false, "", nil
}

func init() { registerWebLoginAdapter("cyberpower", cyberpowerAdapter{}) }
