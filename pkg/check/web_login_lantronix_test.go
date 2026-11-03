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

// lantronixEmulator emulates the real SLC/SLB xwsd web-login flow (recovered
// from Lantronix SLB882 7.8.0.2RC2 bin/xwsd + www/login.htm): GET / serves the
// "Lantronix SLC48" login page (fields slclogin/slcpassword). POST / is a
// login attempt: success sets a non-empty `session=SLM_<...>` cookie and 302s
// to `/`; a reject re-renders the login page at HTTP 200 with "Invalid
// login." and clears the cookie. The gated pages (/home.htm, /websessions.htm)
// return authenticated content only with a valid session cookie, else the
// login page -- the discriminator the adapter verifies.
func lantronixEmulator(t *testing.T, okUser, okPass string, credPosts *int) *httptest.Server {
	t.Helper()
	const sessTok = "SLM_9f3ac1b2-110724143000"
	loginForm := `<body class="auth"><div class=loginTitle>Login to SLC48</div>` +
		`<form name=theform method=post autocomplete="off">` +
		`<input type=text name=slclogin id="text_login">` +
		`<input type=password name=slcpassword id="text_pass">` +
		`<input type=submit value="Login"></form></body></html>`
	loginPage := `<!DOCTYPE html><html><head><title>Lantronix SLC48</title></head>` + loginForm
	rejectPage := `<!DOCTYPE html><html><head><title>Lantronix SLC48</title></head>` +
		`<div class=loginMsg>Invalid login.</div>` + loginForm
	authedPage := `<!DOCTYPE html><html><head><title>Lantronix SLC48</title></head>` +
		`<body class=main><div id=header>SLC48 Console Manager</div>` +
		`<h2>System Status</h2><table><tr><td>Uptime</td><td>3 days</td></tr></table></body></html>`
	validSession := func(r *http.Request) bool {
		c, err := r.Cookie("session")
		return err == nil && c.Value == sessTok
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "mini_httpd/1.19 xwsd")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(loginPage))
		case r.Method == http.MethodPost && r.URL.Path == "/":
			if credPosts != nil {
				*credPosts++
			}
			raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			vals, _ := url.ParseQuery(string(raw))
			if vals.Get("slclogin") == okUser && vals.Get("slcpassword") == okPass {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: sessTok, Path: "/"})
				w.Header().Set("Location", "https://"+r.Host+"/")
				w.WriteHeader(http.StatusFound)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/"}) // cleared on reject
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(rejectPage))
		case r.URL.Path == "/home.htm" || r.URL.Path == "/websessions.htm":
			if validSession(r) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(authedPage))
				return
			}
			w.WriteHeader(http.StatusOK) // xwsd bounces to login via refresh
			_, _ = w.Write([]byte(`<html><head><META HTTP-EQUIV="refresh" content="0;url=login.htm"></head></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestLantronixAdapterLogin_Success(t *testing.T) {
	var posts int
	srv := lantronixEmulator(t, "sysadmin", "PASS", &posts)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "lantronix", "SLC", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runWebBasicDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.lantronix.defaultCreds")
	if f == nil {
		t.Fatalf("expected http.lantronix.defaultCreds via lantronix adapter, got %+v", got)
	}
	if via := fieldVal(f.Fields, "loginVia"); via != "httpForm" {
		t.Errorf("loginVia = %q, want httpForm", via)
	}
	if u, p := fieldVal(f.Fields, "username"), fieldVal(f.Fields, "password"); u != "sysadmin" || p != "PASS" {
		t.Errorf("recovered %q/%q, want sysadmin/PASS", u, p)
	}
	proof := fieldVal(f.Fields, "proof")
	for _, want := range []string{"cookie=session", "cookieLen=", "authedPath=/home.htm", "marker="} {
		if !strings.Contains(proof, want) {
			t.Errorf("proof %q missing %q", proof, want)
		}
	}
	if posts != 1 {
		t.Errorf("credentialed POSTs = %d, want 1 (stop at first success)", posts)
	}
}

func TestLantronixAdapterLogin_WrongCreds(t *testing.T) {
	srv := lantronixEmulator(t, "sysadmin", "rotated-pw", nil)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "lantronix", "SLC", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("expected no finding when default rejected (HTTP 200 Invalid login., session cleared), got %+v", got)
	}
}

// TestLantronixAdapterLogin_RedirectCookieFP rejects a session cookie that does
// not authorize a gated page.
func TestLantronixAdapterLogin_RedirectCookieFP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "mini_httpd/1.19 xwsd")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head><title>Lantronix SLC48</title></head><body>` +
				`<div class=loginTitle>Login to SLC48</div>` +
				`<form name=theform method=post><input name=slclogin><input name=slcpassword type=password>` +
				`<input type=submit value="Login"></form></body></html>`))
		case r.Method == http.MethodPost && r.URL.Path == "/":
			// Mints an SLM-looking cookie and redirects for any password.
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "SLM_bogus-000000000000", Path: "/"})
			w.Header().Set("Location", "https://"+r.Host+"/")
			w.WriteHeader(http.StatusFound)
		case r.URL.Path == "/home.htm" || r.URL.Path == "/websessions.htm":
			// The cookie never authorizes: always bounce to the login page.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head><META HTTP-EQUIV="refresh" content="0;url=login.htm"></head></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "lantronix", "SLC", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("redirect+SLM cookie without a real authed session must NOT be reported, got %+v", got)
	}
}

func TestLantronixAdapterLogin_WrongVendorFingerprintSkips(t *testing.T) {
	// Same login flow, but the root page fingerprint is a Cradlepoint (a UDP/30718
	// discovery false positive). The FP gate must veto before any POST.
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
	tgt := mkTargetWithIdentity(t, host, port, "lantronix", "SLC", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("wrong-vendor fingerprint must be skipped, got %+v", got)
	}
	if posts != 0 {
		t.Errorf("FP gate must send no login POST, got %d", posts)
	}
}

func TestLantronixAdapterLogin_DisableLogins(t *testing.T) {
	var posts int
	srv := lantronixEmulator(t, "sysadmin", "PASS", &posts)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "lantronix", "SLC", map[string]string{"web.port": port, "web.scheme": "http"})
	tgt.DisableLogins = true

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("--disable-logins must suppress the login, got %+v", got)
	}
	if posts != 0 {
		t.Errorf("no request under --disable-logins, got %d", posts)
	}
}
