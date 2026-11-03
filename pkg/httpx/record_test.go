package httpx

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecorderCapturesAndRestoresBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/login" && string(body) == "user=admin&pass=admin" {
			w.Header().Set("Set-Cookie", "sid=abc; HttpOnly")
			w.Header().Set("Location", "/home")
			w.WriteHeader(http.StatusSeeOther)
			_, _ = w.Write([]byte("redirecting"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<title>Login</title>"))
	}))
	defer srv.Close()

	// Redirect-disabled, as the web-login checks use it (the redirect target is
	// itself a signal, so the caller inspects the 3xx directly).
	client, rec := NewRecordingClient(&http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	})

	// A GET, then a credentialed POST.
	if _, err := client.Get(srv.URL + "/"); err != nil {
		t.Fatalf("get: %v", err)
	}
	resp, err := client.Post(srv.URL+"/login", "application/x-www-form-urlencoded", strings.NewReader("user=admin&pass=admin"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	// The caller must still be able to read the (restored) body.
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(got) != "redirecting" {
		t.Errorf("caller body = %q, want %q (body must be restored after recording)", got, "redirecting")
	}

	ex := rec.Exchanges()
	if len(ex) != 2 {
		t.Fatalf("recorded %d exchanges, want 2", len(ex))
	}
	// GET exchange
	if ex[0].Method != "GET" || ex[0].Status != 200 || !strings.Contains(ex[0].Body, "Login") {
		t.Errorf("exchange[0] = %+v", ex[0])
	}
	// POST exchange: request body + response status/headers/body captured
	p := ex[1]
	if p.Method != "POST" || p.Status != http.StatusSeeOther {
		t.Errorf("exchange[1] method/status = %s/%d", p.Method, p.Status)
	}
	if p.RequestBody != "user=admin&pass=admin" {
		t.Errorf("captured request body = %q", p.RequestBody)
	}
	if p.ResponseHeaders["Location"] != "/home" {
		t.Errorf("captured Location = %q", p.ResponseHeaders["Location"])
	}
	if !strings.Contains(p.ResponseHeaders["Set-Cookie"], "sid=abc") {
		t.Errorf("captured Set-Cookie = %q", p.ResponseHeaders["Set-Cookie"])
	}
	if p.Body != "redirecting" {
		t.Errorf("captured response body = %q", p.Body)
	}
}

func TestRecorderMaxExchanges(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	client, rec := NewRecordingClient(&http.Client{})
	rec.MaxExchanges = 3
	for range 6 {
		resp, err := client.Get(srv.URL + "/")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}
	if n := len(rec.Exchanges()); n != 3 {
		t.Errorf("recorded %d exchanges, want cap 3", n)
	}
}
