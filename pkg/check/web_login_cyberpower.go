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

// cyberpowerResultOK matches the RMCARD success JSON `{"result": "ok", ...}`
// tolerant of the whitespace the firmware emits after the colon (the old exact
// `"result":"ok"` substring never matched the real `"result": "ok"`).
var cyberpowerResultOK = regexp.MustCompile(`"result"\s*:\s*"ok"`)

// cyberpowerRedirect captures the success JSON's `redirect` target so the proof
// carries server-returned evidence gathered this run (not a static sentence).
var cyberpowerRedirect = regexp.MustCompile(`"redirect"\s*:\s*"([^"]+)"`)

// CyberPower RMCARD (RMCARD205/305) web-login adapter. The modern login
// (login_pass.cgi) wraps the credential in X25519+AES-GCM, but the card also
// accepts a legacy plaintext form login at `login.cgi` with the same success
// shape (a `cocp` cookie + JSON `redirect`), so this adapter drives that path
// instead of adding an unnecessary ECDH handshake. Accepts the documented
// default cyber/cyber.
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

	// Proof of authentication is the server-minted `cocp` session token. The JSON
	// `{"result":"ok"}` body is an explicit application-level success assertion and
	// is accepted only when it also carries a non-empty redirect target (the login
	// handler's success shape) - never a bare status/redirect. Both proofs are
	// dynamic: they report a value the server returned on this attempt (the cocp
	// cookie length, or the redirect destination).
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
