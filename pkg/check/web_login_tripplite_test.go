package check

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// trippliteEmulator emulates the real PADM auth (Angular SPA + openresty tier):
//
//	GET  /                                     -> SPA index (PowerAlert title)
//	POST /api/oauth/token?grant_type=password  (JSON {username,password})
//	       accepted -> 200 {"access_token","refresh_token","msg"}
//	       rejected -> 401 {"msg":"Unauthorized"}       (no token)
//	GET  /api/devices  (Authorization: Bearer <token>)
//	       with the minted token -> 200 {"data":[...]}
//	       without a token        -> 401 {"errors":[{"detail":"Missed JWT token"}]}
//
// When legacy is true, the PADM REST paths 404 (older SNMPWEBCARD backend) so
// the adapter must decline (errNotThisDevice), not guess.
func trippliteEmulator(t *testing.T, okUser, okPass string, legacy bool) *httptest.Server {
	t.Helper()
	const token = "eyJ.mock-access.jwt"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "openresty/1.15.8.3")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			_, _ = w.Write([]byte(`<!doctype html><html><head><title>PowerAlert Device Manager</title></head><body><app-root></app-root></body></html>`))
		case legacy:
			// Older backend: none of the PADM REST paths exist.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"status":404,"message":"There is no method to handle"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/oauth/token":
			body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			var creds struct{ Username, Password string }
			_ = json.Unmarshal(body, &creds)
			if creds.Username == okUser && creds.Password == okPass {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token":"` + token + `","refresh_token":"eyJ.mock-refresh.jwt","msg":"OK"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"msg":"Unauthorized"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/devices":
			if r.Header.Get("Authorization") == "Bearer "+token {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":[{"id":"0","type":"devices","attributes":{"name":"UPS"}}]}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"errors":[{"detail":"Missed JWT token","code":401}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestTrippliteAdapterLogin_OAuthSuccess proves the documented default
// localadmin/localadmin mints an OAuth access_token and opens the JWT-gated
// /api/devices, and that the proof carries that live evidence.
func TestTrippliteAdapterLogin_OAuthSuccess(t *testing.T) {
	srv := trippliteEmulator(t, "localadmin", "localadmin", false)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "tripplite", "PowerAlert Device Manager", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runWebBasicDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.tripplite.defaultCreds")
	if f == nil {
		t.Fatalf("expected finding via tripplite adapter for localadmin/localadmin, got %+v", got)
	}
	if via := fieldVal(f.Fields, "loginVia"); via != "httpRest" {
		t.Errorf("loginVia = %q, want httpRest", via)
	}
	if u := fieldVal(f.Fields, "username"); u != "localadmin" {
		t.Errorf("username = %q, want localadmin", u)
	}
	proof := fieldVal(f.Fields, "proof")
	if !strings.Contains(proof, "accessTokenLen=") || !strings.Contains(proof, "authedPath=/api/devices") || !strings.Contains(proof, "authedStatus=200") {
		t.Errorf("proof must carry the minted token + the authed GET evidence, got %q", proof)
	}
}

// TestTrippliteAdapterLogin_WrongCredsNoToken is the false-positive guard: a
// rejected credential is HTTP 401 {"msg":"Unauthorized"} with no token, so the
// adapter must not report a finding (this is the shape observed live on real
// units where the default was already rotated).
func TestTrippliteAdapterLogin_WrongCredsNoToken(t *testing.T) {
	// okPass differs from every candidate default -> both localadmin/localadmin and
	// admin/admin are rejected with 401 and no token.
	srv := trippliteEmulator(t, "localadmin", "rotated-secret", false)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "tripplite", "PowerAlert Device Manager", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("rejected default (401 no token) must not yield a finding, got %+v", got)
	}
}

// TestTrippliteAdapterLogin_LegacyBackendDeclines proves that on an older,
// non-PADM backend (the OAuth token endpoint 404s) the adapter declines rather
// than guessing a login shape, so no false positive is emitted.
func TestTrippliteAdapterLogin_LegacyBackendDeclines(t *testing.T) {
	srv := trippliteEmulator(t, "localadmin", "localadmin", true) // legacy: REST 404s
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "tripplite", "PowerAlert Device Manager", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("legacy backend (oauth/token 404) must not yield a finding, got %+v", got)
	}
}
