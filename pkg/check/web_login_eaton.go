package check

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type eatonAdapter struct{}

func (eatonAdapter) mechanism() string { return "httpOauth2" }

const eatonTokenEndpoint = "/rest/mbdetnrs/1.0/oauth2/token"

func (eatonAdapter) login(ctx context.Context, client *http.Client, base, user, pass string) (ok bool, proof string, err error) {
	reqBody, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+eatonTokenEndpoint, strings.NewReader(string(reqBody)))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	switch resp.StatusCode {
	case http.StatusOK:
		var env struct {
			AccessToken string `json:"access_token"`
		}
		_ = json.Unmarshal(body, &env)
		if env.AccessToken == "" {
			return false, "", nil
		}
		return true, proofKV("endpoint", eatonTokenEndpoint, "status", "200", "accessTokenLen", strconv.Itoa(len(env.AccessToken))), nil
	case http.StatusForbidden:

		marker, isJSON := eatonErrEnvelope(body)
		if !isJSON {
			return false, "", nil
		}
		return true, proofKV("endpoint", eatonTokenEndpoint, "status", "403") + " " + marker, nil
	case http.StatusUnauthorized:
		return false, "", nil
	default:
		return false, "", errNotThisDevice
	}
}

func eatonErrEnvelope(body []byte) (marker string, isJSON bool) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(body, &obj) != nil || len(obj) == 0 {
		return "", false
	}
	var env struct {
		Error struct {
			ErrorCode json.Number `json:"errorCode"`
			Message   string      `json:"message"`
		} `json:"error"`
		ErrorCode json.Number `json:"errorCode"`
		Message   string      `json:"message"`
	}
	_ = json.Unmarshal(body, &env)
	switch {
	case env.Error.ErrorCode != "":
		return "errorCode=" + env.Error.ErrorCode.String(), true
	case env.ErrorCode != "":
		return "errorCode=" + env.ErrorCode.String(), true
	case strings.TrimSpace(env.Error.Message) != "":
		return "message=" + strings.TrimSpace(env.Error.Message), true
	case strings.TrimSpace(env.Message) != "":
		return "message=" + strings.TrimSpace(env.Message), true
	default:
		return "json envelope", true
	}
}

func init() { registerWebLoginAdapter("eaton", eatonAdapter{}) }
