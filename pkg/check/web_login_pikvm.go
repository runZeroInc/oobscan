package check

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
)

type pikvmAdapter struct{}

func (pikvmAdapter) mechanism() string { return "kvmdApi" }

type pikvmEnv struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
}

func (pikvmAdapter) login(ctx context.Context, client *http.Client, base, user, pass string) (ok bool, proof string, err error) {
	st, env, err := pikvmAPIGet(ctx, client, base+"/api/auth/check", user, pass)
	if err != nil {
		return false, "", err
	}
	switch st {
	case http.StatusOK:

		if !env.OK {
			return false, "", errNotThisDevice
		}
	case http.StatusForbidden, http.StatusUnauthorized:
		return false, "", nil
	default:
		return false, "", errNotThisDevice
	}

	proof = proofKV("authPath", "/api/auth/check", "authStatus", "200", "authOk", "true")

	if ist, ienv, ierr := pikvmAPIGet(ctx, client, base+"/api/info?fields=system", user, pass); ierr == nil && ist == http.StatusOK && ienv.OK {
		if ver := pikvmKvmdVersion(ienv.Result); ver != "" {
			proof += " " + proofKV("authedPath", "/api/info", "authedStatus", "200", "infoOk", "true", "kvmdVersion", ver)
		} else {
			proof += " " + proofKV("authedPath", "/api/info", "authedStatus", "200", "infoOk", "true", "resultBytes", strconv.Itoa(len(ienv.Result)))
		}
	}
	return true, proof, nil
}

func pikvmAPIGet(ctx context.Context, client *http.Client, url, user, pass string) (int, pikvmEnv, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, pikvmEnv{}, err
	}
	req.Header.Set("X-KVMD-User", user)
	req.Header.Set("X-KVMD-Passwd", pass)
	resp, err := client.Do(req)
	if err != nil {
		return 0, pikvmEnv{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	var env pikvmEnv
	_ = json.Unmarshal(body, &env)
	return resp.StatusCode, env, nil
}

func pikvmKvmdVersion(result json.RawMessage) string {
	var sys struct {
		System struct {
			Kvmd struct {
				Version string `json:"version"`
			} `json:"kvmd"`
		} `json:"system"`
	}
	if json.Unmarshal(result, &sys) != nil {
		return ""
	}
	return sys.System.Kvmd.Version
}

func init() {
	registerWebLoginAdapter("pikvm", pikvmAdapter{})
	registerWebLoginAdapter("blikvm", pikvmAdapter{})
}
