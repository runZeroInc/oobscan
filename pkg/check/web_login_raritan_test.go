package check

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// raritanEmulator emulates the Xerus JSON-RPC login. GET / answers a bare 401
// (as real units do); POST /session decodes the RpcAuthorization Basic header and
// returns 200+token for the accepted pair, 451 for the forced-change pair, or 401
// otherwise. The mode string selects false-positive-guard variants:
//
//	"plain200"  /session returns a non-Xerus 200 body (random device answering
//	            200 to POST /session must not be reported).
//	"reject403" the rejected branch answers HTTP 403 + `AuthFailReason: 1` + an
//	            HTML body -- the live-observed wrong/rotated-password shape.
//	"html451"   the forced-change branch answers HTTP 451 with an HTML body (no
//	            JSON-RPC envelope) -- a generic proxy 451 that must not be reported.
//
// The success and forced-change branches otherwise emit the firmware-grounded
// JSON-RPC envelopes (result.token, and the {error:{...}} carried on 451).
func raritanEmulator(t *testing.T, okUser, okPass, forcedUser, forcedPass, mode string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "lighttpd/1.4.39")
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("<title>401 - Unauthorized</title>"))
			return
		}
		if r.URL.Path != "/session" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if mode == "plain200" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>not a raritan</html>"))
			return
		}
		reject := func() {
			if mode == "reject403" {
				// Live-observed wrong/rotated-password shape.
				w.Header().Set("AuthFailReason", "1")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("<HTML><HEAD><TITLE>403 Forbidden</TITLE></HEAD><BODY>Authentication failed.</BODY></HTML>"))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}
		u, p := decodeRPCAuth(r.Header.Get("RpcAuthorization"))
		switch {
		case u == okUser && p == okPass:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"_ret_":0,"session":{"sessionId":7,"username":"` + u + `"},"token":"tok-abc123def456"},"id":1}`))
		case forcedUser != "" && u == forcedUser && p == forcedPass:
			if mode == "html451" {
				// Generic proxy 451 (no JSON-RPC envelope) -> must not be reported.
				w.WriteHeader(451)
				_, _ = w.Write([]byte("<html><body>451 Unavailable For Legal Reasons</body></html>"))
				return
			}
			// Firmware-grounded jsonrpcd forced-change envelope.
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			w.WriteHeader(451)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"needDefaultPasswordChange"}}`))
		default:
			reject()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func decodeRPCAuth(h string) (user, pass string) {
	h = strings.TrimSpace(strings.TrimPrefix(h, "Basic "))
	raw, err := base64.StdEncoding.DecodeString(h)
	if err != nil {
		return "", ""
	}
	u, p, _ := strings.Cut(string(raw), ":")
	return u, p
}

func TestRaritanAdapterLogin_Success(t *testing.T) {
	srv := raritanEmulator(t, "admin", "raritan", "", "", "")
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "raritan", "PX3", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runWebBasicDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.raritan.defaultCreds")
	if f == nil {
		t.Fatalf("expected http.raritan.defaultCreds via raritan adapter, got %+v", got)
	}
	if via := fieldVal(f.Fields, "loginVia"); via != "httpJsonRpc" {
		t.Errorf("loginVia = %q, want httpJsonRpc", via)
	}
	if u, p := fieldVal(f.Fields, "username"), fieldVal(f.Fields, "password"); u != "admin" || p != "raritan" {
		t.Errorf("recovered %q/%q, want admin/raritan", u, p)
	}
	if pr := fieldVal(f.Fields, "proof"); !strings.Contains(pr, "tokenLen=") || !strings.Contains(pr, "username=admin") {
		t.Errorf("proof = %q, want dynamic token-length + session-user marker", pr)
	}
}

func TestRaritanAdapterLogin_ForcedChangeStillCounts(t *testing.T) {
	// HTTP 451 + the jsonrpcd error envelope = credential valid, forced change.
	srv := raritanEmulator(t, "nope", "nope", "admin", "raritan", "")
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "raritan", "PX3", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runWebBasicDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.raritan.defaultCreds")
	if f == nil {
		t.Fatalf("HTTP 451 + JSON envelope must still confirm the default credential, got %+v", got)
	}
	pr := fieldVal(f.Fields, "proof")
	if !strings.Contains(pr, "451") || !strings.Contains(pr, "needDefaultPasswordChange") {
		t.Errorf("proof = %q, want 451 marker + server-returned error message", pr)
	}
}

func TestRaritanAdapterLogin_WrongCreds(t *testing.T) {
	srv := raritanEmulator(t, "admin", "rotated-pw", "", "", "")
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "raritan", "PX3", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("expected no finding for rejected default (401), got %+v", got)
	}
}

func TestRaritanAdapterLogin_Reject403NoFalsePositive(t *testing.T) {
	// Live-observed shape: a rotated/wrong password answers HTTP 403 +
	// AuthFailReason:1 + HTML. It must be treated as rejected, not confirmed.
	srv := raritanEmulator(t, "nomatch", "nomatch", "", "", "reject403")
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "raritan", "PX3", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("HTTP 403 (AuthFailReason) is a rejected credential, got %+v", got)
	}
}

func TestRaritanAdapterLogin_Generic451NoFalsePositive(t *testing.T) {
	// A generic proxy 451 (no JSON-RPC envelope) must not be mistaken for a Xerus
	// forced-change; the adapter requires the jsonrpcd {error:{...}} body.
	srv := raritanEmulator(t, "nope", "nope", "admin", "raritan", "html451")
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "raritan", "PX3", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("generic 451 (HTML, no JSON envelope) must not be a false positive, got %+v", got)
	}
}

func TestRaritanAdapterLogin_NotRaritanNoFalsePositive(t *testing.T) {
	// A non-Xerus device answering 200 to POST /session must not be reported.
	srv := raritanEmulator(t, "admin", "raritan", "", "", "plain200")
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "raritan", "PX3", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("non-Xerus 200 must not be a false positive, got %+v", got)
	}
}
