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

// Raritan Xerus (PX3 / SX2 / KX3) web-login adapter. Xerus authenticates over
// JSON-RPC 2.0: POST /session calling newSession, with the credential in a
// custom RpcAuthorization header (not standard Authorization), so the
// browser's native Basic dialog never appears. A minted result.token proves
// acceptance; rejection returns 401/403 without one. HTTP 451 means the
// credential is valid but a forced default-password change is pending;
// jsonrpcd always sends a JSON-RPC error envelope with it, so a generic proxy
// 451 (no envelope) is never mistaken for a Xerus forced change. See
// kb/raritan/.
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
		// Require the JSON-RPC session token; a generic 200 is not sufficient.
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
		// "Unavailable for legal reasons": credential valid, forced default-password
		// change pending. Firmware routes this on status 451, but require the
		// JSON-RPC error envelope (jsonrpcd always sends one) so a generic 451 is
		// not a false positive. This turns a bare-status guess into status + the
		// server-returned error message gathered this run.
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
		// Rejected credentials return 401/403 without a token.
		return false, "", nil
	default:
		// 404 / 405 / non-JSON: not the Xerus /session endpoint on this host.
		return false, "", errNotThisDevice
	}
}

func init() { registerWebLoginAdapter("raritan", raritanAdapter{}) }
