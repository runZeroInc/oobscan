package check

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// pikvmEmulator emulates kvmd's read-only credential check and the
// authenticated-only /api/info endpoint:
//   - GET /                -> the PiKVM fingerprint page
//   - GET /api/auth/check  -> 200 {"ok":true} for the accepted X-KVMD-User/
//     Passwd pair; 403 for a wrong pair; 401 when no credential is sent.
//   - GET /api/info        -> 200 with result.system.kvmd.version for a valid
//     credential; 403/401 otherwise.
func pikvmEmulator(t *testing.T, okUser, okPass string) *httptest.Server {
	t.Helper()
	authed := func(w http.ResponseWriter, r *http.Request, onOK func()) {
		u, p := r.Header.Get("X-KVMD-User"), r.Header.Get("X-KVMD-Passwd")
		switch {
		case u == "" && p == "":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"ok":false,"result":{"error":"UnauthorizedError","error_msg":"Unauthorized"}}`))
		case u == okUser && p == okPass:
			onOK()
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"ok":false,"result":{"error":"ForbiddenError","error_msg":"Forbidden"}}`))
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.29.4")
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<title>PiKVM Login</title>"))
		case "/api/auth/check":
			authed(w, r, func() {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
			})
		case "/api/info":
			authed(w, r, func() {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"ok":true,"result":{"system":{"kvmd":{"version":"4.98"}}}}`))
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPikvmAdapterLogin_Success(t *testing.T) {
	srv := pikvmEmulator(t, "admin", "admin")
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "pikvm", "PiKVM v4", map[string]string{"web.port": port, "web.scheme": "http"})
	tgt.Identity.Class = engine.ClassKVM

	got := runWebBasicDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.pikvm.defaultCreds")
	if f == nil {
		t.Fatalf("expected http.pikvm.defaultCreds via pikvm adapter, got %+v", got)
	}
	if via := fieldVal(f.Fields, "loginVia"); via != "kvmdApi" {
		t.Errorf("loginVia = %q, want kvmdApi", via)
	}
	if u, p := fieldVal(f.Fields, "username"), fieldVal(f.Fields, "password"); u != "admin" || p != "admin" {
		t.Errorf("recovered %q/%q, want admin/admin", u, p)
	}
	proof := fieldVal(f.Fields, "proof")
	if !strings.Contains(proof, "authedPath=/api/info") || !strings.Contains(proof, "kvmdVersion=4.98") {
		t.Errorf("proof missing dynamic authed-endpoint evidence: %q", proof)
	}
}

func TestPikvmAdapterLogin_WrongCreds(t *testing.T) {
	srv := pikvmEmulator(t, "admin", "rotated")
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "pikvm", "PiKVM v4", map[string]string{"web.port": port, "web.scheme": "http"})
	tgt.Identity.Class = engine.ClassKVM

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("expected no finding for rejected default (403 ok=false), got %+v", got)
	}
}

// TestPikvmAdapterLogin_NotKvmd200 is the false-positive guard: a device that
// answers HTTP 200 to /api/auth/check but without the kvmd {"ok":true} envelope
// must not be reported. This is the "status code alone is not proof" rule.
func TestPikvmAdapterLogin_NotKvmd200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.29.4")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte("<title>PiKVM Login</title>"))
		case "/api/auth/check":
			// 200 but a non-kvmd body (no "ok":true).
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"welcome"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "pikvm", "PiKVM v4", map[string]string{"web.port": port, "web.scheme": "http"})
	tgt.Identity.Class = engine.ClassKVM

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("expected no finding for a 200 without the kvmd ok:true envelope, got %+v", got)
	}
}

// TestBlikvmUsesKvmdAdapter confirms BliKVM (a kvmd fork) is covered by the same
// adapter and now has a creds.Table entry so candidates are produced.
func TestBlikvmUsesKvmdAdapter(t *testing.T) {
	srv := pikvmEmulator(t, "admin", "admin")
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "blikvm", "BliKVM", map[string]string{"web.port": port, "web.scheme": "http"})
	tgt.Identity.Class = engine.ClassKVM

	if f := hasFinding(runWebBasicDefaultCreds(context.Background(), tgt), "http.blikvm.defaultCreds"); f == nil {
		t.Fatalf("BliKVM should be covered by the kvmd adapter, got no finding")
	}
}
