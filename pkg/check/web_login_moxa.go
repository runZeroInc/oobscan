package check

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Moxa NPort 6000 web-login adapter. `Login.htm` posts `EncUser`/`EncPasswd`
// to `/`, each obfuscating the credential against a server nonce
// (`FakeChallenge`). Transform, verified byte-for-byte against the shipped
// `nport.js`/`sha256.js` (whose lookup-table step is an identity map, so it is
// omitted here):
//
//	key    = SHA256(FakeChallenge)                        // 32 raw digest bytes
//	out[i] = key[i] XOR secret[i]  for i < len(secret)
//	out[i] = key[i]                for i >= len(secret)   // tail = raw digest
//	Enc    = hex(out[0..31])                              // 64 lowercase hex
//
// A rejected login returns the challenge form; success returns a frameset,
// confirmed by a GET of an authenticated frame -- redirects/cookies alone are
// not sufficient evidence.
type moxaAdapter struct{}

func (moxaAdapter) mechanism() string { return "httpForm" }

var (
	reMoxaFakeChallenge = regexp.MustCompile(`(?i)name=["']?FakeChallenge["']?\s+value=["']?([^"'>\s]+)`)
	// reMoxaFrameSrc extracts the `src=` of each `<frame ...>` child of the
	// authenticated frameset landing page. The trailing `\s` after `frame`
	// excludes the enclosing `<frameset>` tag (which carries no `src`).
	reMoxaFrameSrc = regexp.MustCompile(`(?i)<frame\s[^>]*\bsrc\s*=\s*["']?([^"'>\s]+)`)
)

func (moxaAdapter) login(ctx context.Context, client *http.Client, base, user, pass string) (ok bool, proof string, err error) {
	// Fetch the server nonce.
	nonce, ok := moxaFetchChallenge(ctx, client, base+"/")
	if !ok {
		// No challenge means this is not the NPort login flow.
		return false, "", errNotThisDevice
	}
	form := url.Values{
		"EncUser":       {moxaEncode(user, nonce)},
		"EncPasswd":     {moxaEncode(pass, nonce)},
		"FakeChallenge": {nonce},
		"Submit.x":      {"1"},
		"Submit.y":      {"1"},
	}
	postURL := base + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	resp.Body.Close()

	// A failed login returns the challenge form.
	if moxaIsLoginPage(body) {
		return false, "", nil
	}
	// Require the authenticated console frameset.
	frames := moxaFramesetSources(body)
	if len(frames) == 0 {
		return false, "", nil
	}
	// Verify one authenticated frame with the same source-IP session.
	authEP, authMarker, okAuth := moxaVerifyAuthedFrame(ctx, client, postURL, frames)
	if !okAuth {
		return false, "", nil
	}
	proof = proofKV(
		"loginPath", "/",
		"loginStatus", strconv.Itoa(resp.StatusCode),
		"frames", strings.Join(frames, ","),
		"authedPath", authEP,
		"marker", authMarker,
	)
	return true, proof, nil
}

// moxaFetchChallenge GETs the login page and returns the FakeChallenge nonce.
func moxaFetchChallenge(ctx context.Context, client *http.Client, loginURL string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
	if err != nil {
		return "", false
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	m := reMoxaFakeChallenge.FindSubmatch(body)
	if m == nil {
		return "", false
	}
	return string(m[1]), true
}

// moxaIsLoginPage reports whether a body is the NPort login page -- i.e. a
// rejected login re-render or a page that bounced back to the login form. It
// keys on the unambiguous login-form markers: the FakeChallenge nonce field, the
// `InputPassword` form, or the `EncPasswd` hidden field.
func moxaIsLoginPage(body []byte) bool {
	if reMoxaFakeChallenge.Match(body) {
		return true
	}
	low := strings.ToLower(string(body))
	return strings.Contains(low, "name=inputpassword") ||
		strings.Contains(low, "name=encpasswd")
}

// moxaFramesetSources returns the `src=` of every `<frame>` child when the body
// is the authenticated frameset landing page, else nil. The presence of a real
// `<frameset>` with named child pages is the authenticated-console marker a
// rejected credential never receives.
func moxaFramesetSources(body []byte) []string {
	if !strings.Contains(strings.ToLower(string(body)), "<frameset") {
		return nil
	}
	var out []string
	for _, m := range reMoxaFrameSrc.FindAllSubmatch(body, -1) {
		if s := strings.TrimSpace(string(m[1])); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// moxaVerifyAuthedFrame GETs up to a few of the frameset's child pages (resolved
// against the POST URL) and returns the first that answers with authenticated
// content: HTTP 200, not a redirect to the login page, and not a re-rendered
// login form. It returns the resolved endpoint path and a compact marker built
// from the server's own response (status, length, and <title> when present) so
// the finding's proof is dynamic server-returned evidence gathered this run.
func moxaVerifyAuthedFrame(ctx context.Context, client *http.Client, postURL string, srcs []string) (endpoint, marker string, ok bool) {
	baseRef, err := url.Parse(postURL)
	if err != nil {
		return "", "", false
	}
	tried := 0
	for _, s := range srcs {
		if tried >= 3 {
			break
		}
		ref, err := url.Parse(s)
		if err != nil {
			continue
		}
		u := baseRef.ResolveReference(ref)
		tried++
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", "", false // transport failure: do not claim success
		}
		fbody, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK { // 3xx bounce to login / any non-200 => not authed
			continue
		}
		if moxaIsLoginPage(fbody) || len(fbody) < 32 { // re-rendered login / empty stub => not authed
			continue
		}
		m := fmt.Sprintf("HTTP 200 len=%d", len(fbody))
		if title := htmlTitle(fbody); title != "" {
			m += " title=" + title
		}
		return u.EscapedPath(), m, true
	}
	return "", "", false
}

// moxaEncode implements the NPort `encodePassword(secret, SHA256(nonce))`
// transform: per-byte XOR of the secret against the SHA-256 digest of the nonce,
// hex-encoded, with the untouched digest tail padding out to 32 bytes.
func moxaEncode(secret, nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	out := make([]byte, 32)
	copy(out, sum[:])
	for i := 0; i < len(secret) && i < 32; i++ {
		out[i] = sum[i] ^ secret[i]
	}
	return hex.EncodeToString(out)
}

func init() { registerWebLoginAdapter("moxa", moxaAdapter{}) }
