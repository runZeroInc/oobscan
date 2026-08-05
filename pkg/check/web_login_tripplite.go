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

type trippliteAdapter struct{}

const trippliteLoginPath = "/api/oauth/token?grant_type=password"

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

		return false, "", errNotThisDevice
	case resp.StatusCode != http.StatusOK:

		return false, "", nil
	}

	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if json.Unmarshal(raw, &tok) != nil || tok.AccessToken == "" || tok.RefreshToken == "" {

		return false, "", nil
	}

	authStatus, marker := trippliteConfirm(ctx, client, base, tok.AccessToken)
	if authStatus == http.StatusUnauthorized || authStatus == http.StatusForbidden {

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

	key := "body"
	if strings.Contains(string(body), `"data"`) {
		key = "data"
	} else if strings.Contains(string(body), `"errors"`) {
		key = "errors"
	}
	return resp.StatusCode, fmt.Sprintf("%s len=%d", key, len(body))
}

func init() { registerWebLoginAdapter("tripplite", trippliteAdapter{}) }
