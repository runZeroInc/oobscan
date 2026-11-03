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

// opengearEmulator emulates the og-rest-api login. apiVer is "v1" (legacy
// Cherokee) or "v2" (modern nginx). GET / serves an Opengear-titled page (the
// vendor fingerprint); POST /api/<ver>/sessions returns 303 + {"sid":...} for
// the accepted pair, 401 otherwise, and 404 for the other version (to
// exercise the fall-through). GET /api/<ver>/sessions/self models the live
// firmware quirk that makes the authenticated-resource gate necessary: it
// answers HTTP 200 for any request, but only the minted token reports the
// configured selfState; every other token reports state=challenge-in-progress.
// A success emulator sets selfState="Authenticated"; a soft-token emulator
// sets a non-authenticated state to prove the adapter refuses to score the
// 303 alone.
func opengearEmulator(t *testing.T, apiVer, server, okUser, okPass, selfState string, credPosts *int) *httptest.Server {
	t.Helper()
	const sid = "0123456789abcdef0123456789abcdef"
	sessionsPath := "/api/" + apiVer + "/sessions"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if server != "" {
			w.Header().Set("Server", server)
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<title>lab01 - Opengear Management Console</title>"))
		case r.Method == http.MethodPost && r.URL.Path == sessionsPath:
			if credPosts != nil {
				*credPosts++
			}
			var body struct{ Username, Password string }
			raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			_ = json.Unmarshal(raw, &body)
			if body.Username == okUser && body.Password == okPass {
				http.SetCookie(w, &http.Cookie{Name: "session_id", Value: sid, HttpOnly: true})
				w.Header().Set("Location", sessionsPath+"/self")
				w.WriteHeader(http.StatusSeeOther)
				_, _ = w.Write([]byte(`{"sid":"` + sid + `","message":"Redirecting to new session"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":[{"type":"invalid_credentials"}]}`))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/") && strings.HasSuffix(r.URL.Path, "/sessions"):
			// A different API version than this emulator speaks.
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodGet && r.URL.Path == sessionsPath+"/self":
			// Always HTTP 200 (as real firmware does), but only the minted token
			// reports the configured state; any other token is unauthenticated.
			state := "challenge-in-progress"
			if r.Header.Get("Authorization") == "Token "+sid {
				state = selfState
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"session":"self","state":"` + state + `","user":"` + okUser + `"}`))
		case r.Method == http.MethodDelete && r.URL.Path == sessionsPath+"/self":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOpengearAdapterLogin_ModernV2(t *testing.T) {
	srv := opengearEmulator(t, "v2", "", "root", "default", "Authenticated", nil) // modern: no Server header
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "opengear", "OM2200", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runWebBasicDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.opengear.defaultCreds")
	if f == nil {
		t.Fatalf("expected http.web.defaultCreds via opengear adapter, got %+v", got)
	}
	if via := fieldVal(f.Fields, "loginVia"); via != "httpRest" {
		t.Errorf("loginVia = %q, want http.rest.opengear", via)
	}
	if u, p := fieldVal(f.Fields, "username"), fieldVal(f.Fields, "password"); u != "root" || p != "default" {
		t.Errorf("recovered %q/%q, want root/default", u, p)
	}
	proof := fieldVal(f.Fields, "proof")
	if !strings.Contains(proof, "state=Authenticated") {
		t.Errorf("proof should confirm the authenticated session: %q", proof)
	}
	// Proof must carry evidence gathered this run: the authed endpoint GET'd.
	if !strings.Contains(proof, "authedPath=/api/v2/sessions/self") {
		t.Errorf("proof should name the authed-resource GET: %q", proof)
	}
}

func TestOpengearAdapterLogin_LegacyV1FallThrough(t *testing.T) {
	// Legacy speaks only v1; the adapter must try v2 (404) then v1 (303).
	srv := opengearEmulator(t, "v1", "Cherokee/1.2.104 (UNIX)", "root", "default", "Authenticated", nil)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "opengear", "CM7148", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runWebBasicDefaultCreds(context.Background(), tgt)
	if f := hasFinding(got, "http.opengear.defaultCreds"); f == nil {
		t.Fatalf("expected finding via v1 fall-through, got %+v", got)
	}
}

func TestOpengearAdapterLogin_WrongCreds(t *testing.T) {
	credPosts := 0
	srv := opengearEmulator(t, "v2", "", "root", "rotated", "Authenticated", &credPosts)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "opengear", "OM2200", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("expected no finding for rejected default, got %+v", got)
	}
	// A 401 on v2 is definitive: it must not be retried on v1 (no second failed login).
	if credPosts != 1 {
		t.Errorf("credentialed POSTs = %d, want 1 (401 must not fall through to v1)", credPosts)
	}
}

// TestOpengearAdapterLogin_SoftTokenNotAuthenticated is the FP guard for the real
// firmware behavior: the POST is accepted (303 + a valid-looking sid), but the
// authenticated-only sessions/self resource reports a non-authenticated state
// (challenge-in-progress). The adapter must not score this as a success -- ok is
// gated on state=Authenticated, not on the redirect or the minted token.
func TestOpengearAdapterLogin_SoftTokenNotAuthenticated(t *testing.T) {
	srv := opengearEmulator(t, "v2", "", "root", "default", "challenge-in-progress", nil)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "opengear", "OM2200", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("expected no finding when sessions/self is not Authenticated, got %+v", got)
	}
}
