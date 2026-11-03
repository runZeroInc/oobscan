package redfish

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

// NoXFFResult reports the AMI / ASRock MegaRAC ":9080 no-X-Forwarded-For" pre-auth
// admin bypass check.
//
// On affected MegaRAC builds the Lua Redfish backend binds 0.0.0.0:9080 in the
// clear and only enforces credentials when an X-Forwarded-For header is present
// (lighttpd injects XFF on the fronted :443 path). A request sent directly to
// :9080 without that header falls into the else-branch that assigns
// user_id=0 / role Administrator (firmware: redfish-handler.lua.dec:1044-1167).
// So an unauthenticated GET of an admin-scoped Redfish resource on :9080 that
// returns a real resource body (not a login page) indicates the bypass.
type NoXFFResult struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Scheme    string `json:"scheme"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	XFFStatus int    `json:"xff_status"`
	Bypassed  bool   `json:"bypassed"`
	IsRedfish bool   `json:"isRedfish"`
	IsLogin   bool   `json:"isLogin"`
	Snippet   string `json:"snippet,omitempty"`
	Error     string `json:"error,omitempty"`
}

// CheckNoXFFBypass probes host:port (default 9080) for the no-XFF admin bypass
// by comparing two unauthenticated GETs for each admin-scoped path: one with no
// X-Forwarded-For and one with X-Forwarded-For: 1.2.3.4. A bypass is asserted
// only on a differential where the no-XFF request returns real Redfish data and
// the XFF control is denied/non-Redfish.
func CheckNoXFFBypass(host string, port int, scheme string, timeout time.Duration) ([]NoXFFResult, error) {
	if port == 0 {
		port = 9080
	}
	if scheme == "" {
		scheme = "http"
	}
	client := httpx.ClientWithRedirect(timeout, func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	})
	paths := []string{
		"/redfish/v1/Systems/Self",
		"/redfish/v1/Managers/Self",
		"/redfish/v1/AccountService/Accounts",
	}
	var out []NoXFFResult
	var lastErr error
	for _, p := range paths {
		url := netaddr.URL(scheme, host, port, p)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		// Deliberately send no X-Forwarded-For and no Authorization.
		resp, err := client.Do(req)
		cancel()
		r := NoXFFResult{Host: host, Port: port, Scheme: scheme, Path: p}
		if err != nil {
			r.Error = err.Error()
			lastErr = err
			out = append(out, r)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		low := strings.ToLower(string(body))
		r.Status = resp.StatusCode
		r.IsRedfish = strings.Contains(low, "@odata")
		r.IsLogin = strings.Contains(low, "loginname") || strings.Contains(low, "<html") ||
			strings.Contains(low, "login.html") || strings.Contains(low, "sessionservice/sessions")

		ctx2, cancel2 := context.WithTimeout(context.Background(), timeout)
		req2, err := http.NewRequestWithContext(ctx2, http.MethodGet, url, nil)
		if err != nil {
			cancel2()
			r.Error = err.Error()
			lastErr = err
			out = append(out, r)
			continue
		}
		req2.Header.Set("X-Forwarded-For", "1.2.3.4")
		resp2, err := client.Do(req2)
		cancel2()
		if err != nil {
			r.Error = err.Error()
			lastErr = err
			out = append(out, r)
			continue
		}
		body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 4096))
		resp2.Body.Close()
		r.XFFStatus = resp2.StatusCode
		low2 := strings.ToLower(string(body2))
		xffRedfish := strings.Contains(low2, "@odata")
		// Bypass: no-XFF request got real Redfish; XFF control got denied/non-Redfish.
		r.Bypassed = r.Status == http.StatusOK && r.IsRedfish && !r.IsLogin &&
			((r.XFFStatus == http.StatusUnauthorized || r.XFFStatus == http.StatusForbidden) ||
				((r.XFFStatus == http.StatusBadRequest || r.XFFStatus == http.StatusNotFound || r.XFFStatus >= 500) && !xffRedfish))
		r.Snippet = bypassSnippet(body)
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, lastErr
	}
	return out, nil
}

func bypassSnippet(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 160 {
		return s[:160]
	}
	return s
}
