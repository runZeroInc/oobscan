package check

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Opengear console-server web-login adapter (modern OM2200 and legacy 5.5.0 --
// one og-rest-api codebase, two vintages). Login is a JSON POST to
// /api/v{N}/sessions; the `sid` in the 303 body is carried as `Authorization:
// Token <sid>`. The 303+sid is necessary but not sufficient: real units answer
// `GET /api/v{N}/sessions/self` with HTTP 200 even for a bogus token
// (`state=challenge-in-progress`), so success is gated on that resource
// returning `state=Authenticated`. See kb/opengear/. v2 is tried first,
// falling through to v1 only on 404; a 401 is definitive and is not retried on
// the other version.
type opengearAdapter struct{}

func (opengearAdapter) mechanism() string { return "httpRest" }

func (opengearAdapter) login(ctx context.Context, client *http.Client, base, user, pass string) (ok bool, proof string, err error) {
	var neither = true
	for _, ver := range []string{"v2", "v1"} {
		st, sid, e := opengearPostSession(ctx, client, base, ver, user, pass)
		if e != nil {
			return false, "", e // transport error: stop
		}
		switch {
		case st == http.StatusSeeOther || st == http.StatusFound:
			if sid == "" {
				return false, "", nil // redirect without a session id: not a clean success
			}
			// Gate on the authenticated-only self-session resource: the token must
			// resolve to state=Authenticated. Always tear the minted session down.
			authed, p := opengearConfirmSession(ctx, client, base, ver, sid, user)
			opengearLogout(ctx, client, base, ver, sid)
			if !authed {
				return false, "", nil // 303+sid but the session is not authenticated
			}
			return true, p, nil
		case st == http.StatusUnauthorized || st == http.StatusForbidden:
			return false, "", nil // definitive rejection; do not probe the other version
		case st == http.StatusNotFound:
			continue // endpoint not on this API version; try the other
		default:
			neither = false
			continue
		}
	}
	if neither {
		return false, "", errNotThisDevice // no /api/v{1,2}/sessions endpoint here
	}
	return false, "", nil
}

// opengearPostSession posts the credential to /api/<ver>/sessions and returns the
// status and any session id parsed from the JSON body.
func opengearPostSession(ctx context.Context, client *http.Client, base, ver, user, pass string) (status int, sid string, err error) {
	reqBody, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/"+ver+"/sessions", strings.NewReader(string(reqBody)))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	var env struct {
		Sid string `json:"sid"`
	}
	_ = json.Unmarshal(body, &env)
	return resp.StatusCode, env.Sid, nil
}

// opengearConfirmSession issues the read-only self-session GET with the minted
// token and reports whether it resolves to an authenticated session. It returns
// authed=true only when the body reports state=Authenticated; the HTTP status is
// not trusted on its own because real firmware answers this endpoint 200 even for
// an invalid token (reporting state=challenge-in-progress). The proof carries the
// evidence gathered this run -- the sid token length, the endpoint GET'd, its HTTP
// status, the returned state marker, and the authenticated user.
func opengearConfirmSession(ctx context.Context, client *http.Client, base, ver, sid, user string) (authed bool, proof string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/"+ver+"/sessions/self", nil)
	if err != nil {
		return false, ""
	}
	req.Header.Set("Authorization", "Token "+sid)
	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	var s struct {
		State string `json:"state"`
		User  string `json:"user"`
	}
	_ = json.Unmarshal(body, &s)
	if !strings.EqualFold(strings.TrimSpace(s.State), "Authenticated") {
		return false, ""
	}
	u := s.User
	if u == "" {
		u = user
	}
	return true, proofKV(
		"apiVersion", ver,
		"loginStatus", "303",
		"sidLen", strconv.Itoa(len(sid)),
		"authedPath", "/api/"+ver+"/sessions/self",
		"authedStatus", strconv.Itoa(resp.StatusCode),
		"state", s.State,
		"user", u,
	)
}

// opengearLogout attempts to release the session token created by the check.
func opengearLogout(ctx context.Context, client *http.Client, base, ver, sid string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, base+"/api/"+ver+"/sessions/self", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Token "+sid)
	if resp, err := client.Do(req); err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
	}
}

func init() { registerWebLoginAdapter("opengear", opengearAdapter{}) }
