package check

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
)

// PiKVM / kvmd web-login adapter (also covers BliKVM and other kvmd forks).
// kvmd exposes a read-only credential check -- GET /api/auth/check with the
// user/password in X-KVMD-* headers -- answering 200 for a valid credential,
// 403 for a rejected one, 401 when none is presented. The HTTP 200 alone is
// not trusted (a non-kvmd device could answer 200 on that path): success
// requires the kvmd JSON envelope with ok:true. On success the credential is
// re-sent to the authenticated-only /api/info to prove it unlocks real
// content and to mint a per-host proof (the running kvmd version).
type pikvmAdapter struct{}

func (pikvmAdapter) mechanism() string { return "kvmdApi" }

// pikvmEnv is the kvmd JSON envelope shared by every /api/* response.
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
		// Do not key on the status code alone: require the kvmd envelope with
		// ok:true. A 200 without it is not a kvmd auth-check endpoint.
		if !env.OK {
			return false, "", errNotThisDevice
		}
	case http.StatusForbidden, http.StatusUnauthorized:
		return false, "", nil // rejected / no credential accepted
	default:
		return false, "", errNotThisDevice // not a kvmd endpoint
	}

	proof = proofKV("authPath", "/api/auth/check", "authStatus", "200", "authOk", "true")
	// Prove the credential unlocks an authenticated-only resource: /api/info is
	// auth_required and returns the running kvmd version only for a valid
	// credential. This yields a distinctive, per-host dynamic marker.
	if ist, ienv, ierr := pikvmAPIGet(ctx, client, base+"/api/info?fields=system", user, pass); ierr == nil && ist == http.StatusOK && ienv.OK {
		if ver := pikvmKvmdVersion(ienv.Result); ver != "" {
			proof += " " + proofKV("authedPath", "/api/info", "authedStatus", "200", "infoOk", "true", "kvmdVersion", ver)
		} else {
			proof += " " + proofKV("authedPath", "/api/info", "authedStatus", "200", "infoOk", "true", "resultBytes", strconv.Itoa(len(ienv.Result)))
		}
	}
	return true, proof, nil
}

// pikvmAPIGet issues one credentialed read-only GET with the kvmd header
// credential and returns the status plus the parsed kvmd envelope. A body that is
// not the kvmd envelope leaves env.OK false.
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

// pikvmKvmdVersion pulls result.system.kvmd.version from an /api/info response.
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
	registerWebLoginAdapter("blikvm", pikvmAdapter{}) // BliKVM is a kvmd fork, same API
}
