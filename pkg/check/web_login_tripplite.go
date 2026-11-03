package check

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Tripp Lite PowerAlert Device Manager (PADM) web-login adapter. The shipped
// client uses an OAuth2 password grant: POST
// /api/oauth/token?grant_type=password, returning an access_token on
// acceptance and 401 without one. The token is confirmed live (not just
// well-formed) via a read-only GET /api/devices with the Bearer, which 401s
// without a token. Older SNMPWEBCARD/WEBCARDLX generations expose a different
// backend and 404 the PADM paths; the adapter returns errNotThisDevice rather
// than guess a login shape it cannot confirm sessionlessly.
type trippliteAdapter struct{}

// trippliteLoginPath is the PADM OAuth2 password-grant token endpoint. The SPA's
// auth service composes exactly this URL (API_PREFIX "/api" + "oauth/token" +
// "?grant_type=password").
const trippliteLoginPath = "/api/oauth/token?grant_type=password"

// trippliteAuthedPath is a read-only, JWT-gated resource used to prove the minted
// token is a live session. Unauthenticated it returns HTTP 401.
const trippliteAuthedPath = "/api/devices"

func (trippliteAdapter) mechanism() string { return "httpRest" }

func (trippliteAdapter) login(ctx context.Context, client *http.Client, base, user, pass string) (ok bool, proof string, err error) {
	reqBody, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+trippliteLoginPath, strings.NewReader(string(reqBody)))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))

	switch {
	case resp.StatusCode == http.StatusNotFound:
		// Non-PADM/legacy backend: the OAuth token endpoint is absent. Abort the
		// attempt loop rather than spray a login shape we cannot confirm.
		return false, "", errNotThisDevice
	case resp.StatusCode != http.StatusOK:
		// Rejected credential (HTTP 401 {"msg":"Unauthorized"}) or any other
		// non-success: no token is minted, so this is not an authenticated session.
		return false, "", nil
	}

	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if json.Unmarshal(raw, &tok) != nil || tok.AccessToken == "" || tok.RefreshToken == "" {
		// HTTP 200 without the OAuth token envelope is not the login handler's
		// success shape (a rejected login never carries an access_token).
		return false, "", nil
	}

	// The token is minted (rejection can never produce one). Confirm it opens a
	// JWT-gated resource so the proof is a live authenticated GET, not just a body.
	authStatus, marker := trippliteConfirm(ctx, client, base, tok.AccessToken)
	if authStatus == http.StatusUnauthorized || authStatus == http.StatusForbidden {
		// A minted token that the same firmware immediately rejects is
		// contradictory; do not claim success (keeps a malformed 200 from firing).
		return false, "", nil
	}
	proof = proofKV(
		"endpoint", trippliteLoginPath,
		"status", "200",
		"accessTokenLen", strconv.Itoa(len(tok.AccessToken)),
		"refreshToken", "true",
	)
	if authStatus == http.StatusOK {
		proof += " " + proofKV("authedPath", trippliteAuthedPath, "authedStatus", "200", "marker", marker)
	}
	return true, proof, nil
}

// trippliteConfirm issues the read-only Bearer GET of the JWT-gated resource and
// returns its HTTP status plus a compact marker of the authenticated body (a
// distinctive field name and its length) for the dynamic proof. Best-effort: a
// transport error yields status 0, which is treated as inconclusive (the minted
// token alone still proves the credential).
func trippliteConfirm(ctx context.Context, client *http.Client, base, accessToken string) (status int, marker string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+trippliteAuthedPath, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	// The unauthenticated response is {"errors":[{"detail":"Missed JWT token"}]};
	// an authenticated one is a JSON:API {"data":...} envelope. Report whichever
	// top-level key is present plus the body length as server-returned evidence.
	key := "body"
	if strings.Contains(string(body), `"data"`) {
		key = "data"
	} else if strings.Contains(string(body), `"errors"`) {
		key = "errors"
	}
	return resp.StatusCode, fmt.Sprintf("%s len=%d", key, len(body))
}

func init() { registerWebLoginAdapter("tripplite", trippliteAdapter{}) }
