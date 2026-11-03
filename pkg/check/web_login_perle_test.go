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

// perleEmulator emulates the real IOLAN manage.cgi login flow (recovered from
// DS/TS 5.0G4 firmware in lab/perle-iolan/): GET / and GET /manage.cgi/login
// serve a "Perle" WebManager login page (fields username/password/login).
// POST /manage.cgi/login?submit always answers 302: success mints a
// non-empty `session` cookie and redirects to /manage.cgi/home; failure mints
// no session cookie (only clears the housekeeping simpleHtml cookies) and
// redirects to ...?login_failed. The gated management pages
// (/manage.cgi/home, /manage.cgi/) return authenticated content only with the
// valid session cookie, else 302 to /login.html -- the discriminator the
// adapter verifies.
func perleEmulator(t *testing.T, okUser, okPass string, credPosts *int) *httptest.Server {
	t.Helper()
	const issuedCSRF = "csrf-abc123"
	const sessTok = "authenticated-token-9f3a"
	loginPage := `<!DOCTYPE html><html lang="en"><head><!-- Perle --></head><body>` +
		`<form method="post" action="?submit" name="login_form">` +
		`<input type="hidden" name="csrf_id" value="` + issuedCSRF + `">` +
		`<input name="username" id="username"><input name="password" id="password" type="password">` +
		`<input type="submit" name="login" id="login" value="Login"></form></body></html>`
	authedPage := `<!DOCTYPE html><html><head><title>IOLAN - Home</title></head>` +
		`<body><div id="header">IOLAN Console Server</div>` +
		`<h2>Server Configuration</h2><p>Welcome, admin.</p></body></html>`
	validSession := func(r *http.Request) bool {
		c, err := r.Cookie("session")
		return err == nil && c.Value == sessTok
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "mini_httpd/1.23 28Dec2015")
		switch {
		case r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/manage.cgi/login"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(loginPage))
		case r.Method == http.MethodPost && r.URL.Path == "/manage.cgi/login":
			if credPosts != nil {
				*credPosts++
			}
			raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			vals, _ := url.ParseQuery(string(raw))
			if vals.Get("username") == okUser && vals.Get("password") == okPass && vals.Get("login") == "Login" {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: sessTok, Path: "/"})
				w.Header().Set("Location", "/manage.cgi/home")
				w.WriteHeader(http.StatusFound)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "simpleHtml", Value: ""}) // cleared on reject
			http.SetCookie(w, &http.Cookie{Name: "simpleHtmlTmp", Value: ""})
			w.Header().Set("Location", "/manage.cgi/login?login_failed=1&no_redirect=1")
			w.WriteHeader(http.StatusFound)
		case r.URL.Path == "/manage.cgi/home" || r.URL.Path == "/manage.cgi/":
			if validSession(r) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(authedPage))
				return
			}
			w.Header().Set("Location", "/login.html") // gated: bounce to login
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPerleAdapterLogin_Success(t *testing.T) {
	var posts int
	srv := perleEmulator(t, "admin", "superuser", &posts)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "perle", "IOLAN", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runWebBasicDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.perle.defaultCreds")
	if f == nil {
		t.Fatalf("expected http.perle.defaultCreds via perle adapter, got %+v", got)
	}
	if via := fieldVal(f.Fields, "loginVia"); via != "httpForm" {
		t.Errorf("loginVia = %q, want httpForm", via)
	}
	if u, p := fieldVal(f.Fields, "username"), fieldVal(f.Fields, "password"); u != "admin" || p != "superuser" {
		t.Errorf("recovered %q/%q, want admin/superuser", u, p)
	}
	proof := fieldVal(f.Fields, "proof")
	for _, want := range []string{"cookie=", "cookieLen=", "authedPath=/manage.cgi/home", "marker="} {
		if !strings.Contains(proof, want) {
			t.Errorf("proof %q missing %q", proof, want)
		}
	}
	if posts != 1 {
		t.Errorf("credentialed POSTs = %d, want 1 (stop at first success)", posts)
	}
}

func TestPerleAdapterLogin_WrongCreds(t *testing.T) {
	srv := perleEmulator(t, "admin", "rotated-pw", nil)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "perle", "IOLAN", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("expected no finding when default rejected (302 login_failed, no session cookie), got %+v", got)
	}
}

// TestPerleAdapterLogin_RedirectCookieFP is the false-positive guard: a device
// that answers every login POST with a 302 to a non-login page and sets a
// non-empty `session` cookie -- i.e. exactly the "redirect + cookie" shape the old
// heuristic accepted -- but whose gated management page never honors the cookie
// (always bounces to /login.html). The authenticated-resource verification must
// reject it (ok=false), so no finding is emitted.
func TestPerleAdapterLogin_RedirectCookieFP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "mini_httpd/1.23 28Dec2015")
		switch {
		case r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/manage.cgi/login"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head><!-- Perle --></head><body>` +
				`<form action="?submit" method="post" name="login_form">` +
				`<input name="username"><input name="password"><input name="login" value="Login"></form></body></html>`))
		case r.Method == http.MethodPost && r.URL.Path == "/manage.cgi/login":
			// Mints a session cookie and redirects away from login for any password.
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "bogus-not-a-real-session", Path: "/"})
			w.Header().Set("Location", "/manage.cgi/home")
			w.WriteHeader(http.StatusFound)
		case r.URL.Path == "/manage.cgi/home" || r.URL.Path == "/manage.cgi/":
			// The cookie never actually authorizes: always bounce to login.
			w.Header().Set("Location", "/login.html")
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "perle", "IOLAN", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("redirect+cookie without a real authed session must NOT be reported, got %+v", got)
	}
}

func TestPerleAdapterLogin_WrongVendorFingerprintSkips(t *testing.T) {
	// Same login flow, but the root page fingerprint is a non-Perle box (a
	// Cradlepoint-style GoAhead unit). The FP gate must veto before any POST.
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "GoAhead-Webs")
		if r.Method == http.MethodPost {
			posts++
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<title>Cradlepoint</title>"))
	}))
	t.Cleanup(srv.Close)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "perle", "IOLAN", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("wrong-vendor fingerprint must be skipped, got %+v", got)
	}
	if posts != 0 {
		t.Errorf("FP gate must send no login POST, got %d", posts)
	}
}

func TestPerleAdapterLogin_DisableLogins(t *testing.T) {
	var posts int
	srv := perleEmulator(t, "admin", "superuser", &posts)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "perle", "IOLAN", map[string]string{"web.port": port, "web.scheme": "http"})
	tgt.DisableLogins = true

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("--disable-logins must suppress the login, got %+v", got)
	}
	if posts != 0 {
		t.Errorf("no request under --disable-logins, got %d", posts)
	}
}

// TestPerleAdapterLogin_CSRFEchoed proves the adapter fetches the login page and
// forwards the hidden csrf_id token on the POST (older units that embed the token
// would reject a login without it).
func TestPerleAdapterLogin_CSRFEchoed(t *testing.T) {
	var gotCSRF string
	const sessTok = "authenticated-token-1234"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "mini_httpd/1.23 28Dec2015")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/manage.cgi/login", r.Method == http.MethodGet && r.URL.Path == "/":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "preflight-token"})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head><!-- Perle --></head><body>` +
				`<form action="?submit" method="post" name="login_form">` +
				`<input type="hidden" name="csrf_id" value="tok-XYZ-789">` +
				`<input name="username"><input name="password"><input name="login" value="Login"></form></body></html>`))
		case r.Method == http.MethodPost && r.URL.Path == "/manage.cgi/login":
			raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			vals, _ := url.ParseQuery(string(raw))
			gotCSRF = vals.Get("csrf_id")
			http.SetCookie(w, &http.Cookie{Name: "session", Value: sessTok, Path: "/"})
			w.Header().Set("Location", "/manage.cgi/home")
			w.WriteHeader(http.StatusFound)
		case r.URL.Path == "/manage.cgi/home" || r.URL.Path == "/manage.cgi/":
			if c, err := r.Cookie("session"); err == nil && c.Value == sessTok {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<title>IOLAN - Home</title><p>Welcome</p>`))
				return
			}
			w.Header().Set("Location", "/login.html")
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "perle", "IOLAN", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); hasFinding(got, "http.perle.defaultCreds") == nil {
		t.Fatalf("expected finding, got %+v", got)
	}
	if gotCSRF != "tok-XYZ-789" {
		t.Errorf("csrf_id forwarded = %q, want tok-XYZ-789 (preflight token not echoed)", gotCSRF)
	}
}
