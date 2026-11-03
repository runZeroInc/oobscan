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

// eatonEmulator emulates the real Network-M2 tntnet + mbdetnrs OAuth2 login:
// GET / serves "Server: Tntnet/3.0" with an empty <title> (the Angular SPA
// fills it client-side); the OAuth2 token endpoint is reachable only at the
// /rest/mbdetnrs/1.0 prefix (the bare /oauth2/token 401s). The mode string
// selects the accepted-credential response:
//
//	"forced403"  the pre-expired default admin/admin returns HTTP 403 +
//	             mbdetnrs JSON error envelope (credential valid, forced change).
//	"token200"   the (post-change) credential returns HTTP 200 + access_token.
//	"html403"    the accepted pair returns HTTP 403 with an HTML body (a generic
//	             proxy/WAF 403 that must not be reported).
//
// A non-matching credential always returns 401 + JSON error.
func eatonEmulator(t *testing.T, okUser, okPass, mode string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Tntnet/3.0")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head><title></title></head><body></body></html>`))
		case r.Method == http.MethodPost && r.URL.Path == "/rest/mbdetnrs/1.0/oauth2/token":
			body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			var creds struct{ Username, Password string }
			_ = json.Unmarshal(body, &creds)
			if creds.Username != okUser || creds.Password != okPass {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":{"errorCode":100}}`))
				return
			}
			switch mode {
			case "token200":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token":"eyJ0b2tlbiI6ImFiYzEyMzQ1Njc4OTAifQ","token_type":"Bearer","expires_in":3600}`))
			case "html403":
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`<html><body>403 Forbidden</body></html>`))
			default: // forced403
				w.WriteHeader(http.StatusForbidden) // valid-but-pre-expired default
				_, _ = w.Write([]byte(`{"error":{"errorCode":112}}`))
			}
		case r.Method == http.MethodPost && r.URL.Path == "/oauth2/token":
			// The bare path (the old, wrong adapter target) must never authenticate.
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"errorCode":100}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestEatonAdapterLogin_PrefixedEndpointAnd403 locks: the login uses the
// /rest/mbdetnrs/1.0 prefix (the bare path 401s), HTTP 403 + the mbdetnrs JSON
// error envelope on the pre-expired default counts as success, and the
// empty-title + Tntnet gate does not block the adapter.
func TestEatonAdapterLogin_PrefixedEndpointAnd403(t *testing.T) {
	srv := eatonEmulator(t, "admin", "admin", "forced403")
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "eaton", "Network-M2", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runWebBasicDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.eaton.defaultCreds")
	if f == nil {
		t.Fatalf("expected finding (prefixed endpoint + 403-valid + Tntnet gate), got %+v", got)
	}
	if via := fieldVal(f.Fields, "loginVia"); via != "httpOauth2" {
		t.Errorf("loginVia = %q, want httpOauth2", via)
	}
	if u, p := fieldVal(f.Fields, "username"), fieldVal(f.Fields, "password"); u != "admin" || p != "admin" {
		t.Errorf("recovered %q/%q, want admin/admin", u, p)
	}
	// Proof must embed the exact status+endpoint and the server-returned marker.
	if pr := fieldVal(f.Fields, "proof"); !strings.Contains(pr, "status=403") ||
		!strings.Contains(pr, eatonTokenEndpoint) || !strings.Contains(pr, "errorCode=112") {
		t.Errorf("proof = %q, want status+endpoint+error-code marker", pr)
	}
}

// TestEatonAdapterLogin_Token200 locks the strong signal: a 200 + access_token
// is confirmed and the proof embeds the token length gathered this run. (Here the
// vendor-default admin/admin is answered on the 200 path to exercise that branch.)
func TestEatonAdapterLogin_Token200(t *testing.T) {
	srv := eatonEmulator(t, "admin", "admin", "token200")
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "eaton", "Network-M2", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runWebBasicDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.eaton.defaultCreds")
	if f == nil {
		t.Fatalf("expected finding on 200 + access_token, got %+v", got)
	}
	if pr := fieldVal(f.Fields, "proof"); !strings.Contains(pr, "status=200") || !strings.Contains(pr, "accessTokenLen=") {
		t.Errorf("proof = %q, want 200 + access_token length marker", pr)
	}
}

func TestEatonAdapterLogin_WrongCreds(t *testing.T) {
	srv := eatonEmulator(t, "admin", "rotated", "forced403") // default admin/admin now rejected
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "eaton", "Network-M2", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("expected no finding when default rejected (401), got %+v", got)
	}
}

// TestEatonAdapterLogin_Generic403NoFalsePositive locks the tightening: a 403
// with an HTML body (a generic proxy/WAF forbidden, not the mbdetnrs JSON error
// envelope) must not be reported as a valid credential.
func TestEatonAdapterLogin_Generic403NoFalsePositive(t *testing.T) {
	srv := eatonEmulator(t, "admin", "admin", "html403")
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "eaton", "Network-M2", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("generic HTML 403 (no JSON envelope) must not be a false positive, got %+v", got)
	}
}
