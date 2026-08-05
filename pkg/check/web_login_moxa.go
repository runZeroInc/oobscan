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

type moxaAdapter struct{}

func (moxaAdapter) mechanism() string { return "httpForm" }

var (
	reMoxaFakeChallenge = regexp.MustCompile(`(?i)name=["']?FakeChallenge["']?\s+value=["']?([^"'>\s]+)`)

	reMoxaFrameSrc = regexp.MustCompile(`(?i)<frame\s[^>]*\bsrc\s*=\s*["']?([^"'>\s]+)`)
)

func (moxaAdapter) login(ctx context.Context, client *http.Client, base, user, pass string) (ok bool, proof string, err error) {

	nonce, ok := moxaFetchChallenge(ctx, client, base+"/")
	if !ok {

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

	if moxaIsLoginPage(body) {
		return false, "", nil
	}

	frames := moxaFramesetSources(body)
	if len(frames) == 0 {
		return false, "", nil
	}

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

func moxaIsLoginPage(body []byte) bool {
	if reMoxaFakeChallenge.Match(body) {
		return true
	}
	low := strings.ToLower(string(body))
	return strings.Contains(low, "name=inputpassword") ||
		strings.Contains(low, "name=encpasswd")
}

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
			return "", "", false
		}
		fbody, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		if moxaIsLoginPage(fbody) || len(fbody) < 32 {
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
