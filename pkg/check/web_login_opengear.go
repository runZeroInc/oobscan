package check

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type opengearAdapter struct{}

func (opengearAdapter) mechanism() string { return "httpRest" }

func (opengearAdapter) login(ctx context.Context, client *http.Client, base, user, pass string) (ok bool, proof string, err error) {
	var neither = true
	for _, ver := range []string{"v2", "v1"} {
		st, sid, e := opengearPostSession(ctx, client, base, ver, user, pass)
		if e != nil {
			return false, "", e
		}
		switch {
		case st == http.StatusSeeOther || st == http.StatusFound:
			if sid == "" {
				return false, "", nil
			}

			authed, p := opengearConfirmSession(ctx, client, base, ver, sid, user)
			opengearLogout(ctx, client, base, ver, sid)
			if !authed {
				return false, "", nil
			}
			return true, p, nil
		case st == http.StatusUnauthorized || st == http.StatusForbidden:
			return false, "", nil
		case st == http.StatusNotFound:
			continue
		default:
			neither = false
			continue
		}
	}
	if neither {
		return false, "", errNotThisDevice
	}
	return false, "", nil
}

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
