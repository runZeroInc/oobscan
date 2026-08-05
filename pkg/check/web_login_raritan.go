package check

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type raritanAdapter struct{}

func (raritanAdapter) mechanism() string { return "httpJsonRpc" }

const raritanNewSession = `{"jsonrpc":"2.0","method":"newSession","params":null,"id":1}`

func (raritanAdapter) login(ctx context.Context, client *http.Client, base, user, pass string) (ok bool, proof string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/session", strings.NewReader(raritanNewSession))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("RpcAuthorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	req.Header.Set("X-Client-Type", "Web GUI")
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))

	switch resp.StatusCode {
	case http.StatusOK:

		var env struct {
			Result struct {
				Ret     int    `json:"_ret_"`
				Token   string `json:"token"`
				Session struct {
					Username string `json:"username"`
					ID       int    `json:"sessionId"`
				} `json:"session"`
			} `json:"result"`
		}
		if json.Unmarshal(body, &env) != nil || env.Result.Token == "" {
			return false, "", errNotThisDevice
		}
		u := env.Result.Session.Username
		if u == "" {
			u = user
		}
		return true, proofKV(
			"endpoint", "/session", "status", "200",
			"tokenLen", strconv.Itoa(len(env.Result.Token)),
			"user", u,
			"sessionId", strconv.Itoa(env.Result.Session.ID),
			"ret", strconv.Itoa(env.Result.Ret)), nil
	case 451:

		var e struct {
			Error struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &e) != nil {
			return false, "", errNotThisDevice
		}
		msg := strings.TrimSpace(e.Error.Message)
		if msg == "" {
			msg = "forced password change"
		}
		return true, proofKV("endpoint", "/session", "status", "451", "jsonrpcError", msg), nil
	case http.StatusUnauthorized, http.StatusForbidden:

		return false, "", nil
	default:

		return false, "", errNotThisDevice
	}
}

func init() { registerWebLoginAdapter("raritan", raritanAdapter{}) }
