package check

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// cyberpowerEmulator emulates the real RMCARD login (recovered from rmcard-1.6.0):
// GET / serves "Server: HTTPsrv" + the brandless runtime-composed title
// "UPS Remote Management | Login"; POST /login.cgi with username/password sets the
// `cocp` cookie (and returns the success JSON with a space after the colon) for the
// accepted pair, else returns an error JSON with no cookie.
func cyberpowerEmulator(t *testing.T, okUser, okPass string, jsonOnly bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "HTTPsrv")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head><title>UPS Remote Management | Login</title></head></html>`))
		case r.Method == http.MethodPost && r.URL.Path == "/login.cgi":
			body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			vals, _ := url.ParseQuery(string(body))
			if vals.Get("username") == okUser && vals.Get("password") == okPass {
				if !jsonOnly {
					http.SetCookie(w, &http.Cookie{Name: "cocp", Value: "sess123", HttpOnly: true})
				}
				w.WriteHeader(http.StatusOK)
				// Note the space after the colon -- the real firmware emits this.
				_, _ = w.Write([]byte(`{"result": "ok", "redirect": "/home.html"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"result": "fail"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestCyberpowerAdapterLogin_BrandlessTitleGate proves the vendor gate accepts a
// real RMCARD (Server: HTTPsrv, brandless title) so the adapter is not blocked,
// and that the `cocp` cookie confirms the default cyber/cyber.
func TestCyberpowerAdapterLogin_BrandlessTitleGate(t *testing.T) {
	srv := cyberpowerEmulator(t, "cyber", "cyber", false)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "cyberpower", "RMCARD", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runWebBasicDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.cyberpower.defaultCreds")
	if f == nil {
		t.Fatalf("expected finding via cyberpower adapter (brandless-title gate must pass on Server: HTTPsrv), got %+v", got)
	}
	if via := fieldVal(f.Fields, "loginVia"); via != "httpForm" {
		t.Errorf("loginVia = %q, want http.form.cyberpower", via)
	}
	if u, p := fieldVal(f.Fields, "username"), fieldVal(f.Fields, "password"); u != "cyber" || p != "cyber" {
		t.Errorf("recovered %q/%q, want cyber/cyber", u, p)
	}
}

// TestCyberpowerAdapterLogin_JSONResultOKSpace proves the JSON success fallback
// tolerates the whitespace the firmware emits (`"result": "ok"`) -- the old exact
// `"result":"ok"` substring never matched, leaving the fallback dead -- and that
// the accepted proof is dynamic: it carries the redirect target the server
// returned this run (not a static "returned {result:ok}" sentence).
func TestCyberpowerAdapterLogin_JSONResultOKSpace(t *testing.T) {
	srv := cyberpowerEmulator(t, "cyber", "cyber", true) // no cookie: force the JSON branch
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "cyberpower", "RMCARD", map[string]string{"web.port": port, "web.scheme": "http"})

	f := hasFinding(runWebBasicDefaultCreds(context.Background(), tgt), "http.cyberpower.defaultCreds")
	if f == nil {
		t.Fatal("expected finding via the JSON result-ok fallback (space-tolerant match regressed)")
	}
	if proof := fieldVal(f.Fields, "proof"); !strings.Contains(proof, "redirect=") || !strings.Contains(proof, "/home.html") {
		t.Errorf("JSON success proof must carry the server-returned redirect target, got %q", proof)
	}
}

// TestCyberpowerAdapterLogin_JSONResultOKNoRedirect is a false-positive guard: a
// bare {"result":"ok"} with no redirect target is not the login handler's success
// shape (a bare status assertion), so the adapter must not report a finding.
func TestCyberpowerAdapterLogin_JSONResultOKNoRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "HTTPsrv")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			_, _ = w.Write([]byte(`<html><head><title>UPS Remote Management | Login</title></head></html>`))
		case r.Method == http.MethodPost && r.URL.Path == "/login.cgi":
			_, _ = w.Write([]byte(`{"result": "ok"}`)) // no cookie, no redirect target
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "cyberpower", "RMCARD", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("bare {result:ok} with no redirect must not yield a finding, got %+v", got)
	}
}

func TestCyberpowerAdapterLogin_WrongCreds(t *testing.T) {
	srv := cyberpowerEmulator(t, "cyber", "rotated", false)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "cyberpower", "RMCARD", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("expected no finding for rejected default, got %+v", got)
	}
}
