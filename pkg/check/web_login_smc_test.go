package check

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// atenEmulator emulates the Supermicro ATEN web login (as recovered from the real
// X13 firmware in lab/smc-x13/): GET / and /page/login.www serve the ATEN login
// page (title "Supermicro BMC Login" + the ATEN META); POST /cgi/login.cgi with
// base64 name/pwd + check=00 returns 200 + Set-Cookie SID for the accepted pair,
// 401 otherwise.
func atenEmulator(t *testing.T, okUser, okPass string, posts *int) *httptest.Server {
	t.Helper()
	loginPage := `<html><head><title>Supermicro BMC Login</title>` +
		`<META NAME="ATEN International Co Ltd."></head><body>login.cgi</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/page/login.www"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(loginPage))
		case r.Method == http.MethodPost && r.URL.Path == "/cgi/login.cgi":
			if posts != nil {
				*posts++
			}
			body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			vals, _ := url.ParseQuery(string(body))
			u, _ := base64.StdEncoding.DecodeString(vals.Get("name"))
			p, _ := base64.StdEncoding.DecodeString(vals.Get("pwd"))
			if vals.Get("check") == "00" && string(u) == okUser && string(p) == okPass {
				http.SetCookie(w, &http.Cookie{Name: "SID", Value: "labsessiontoken"})
				w.Header().Set("Location", "/cgi/url_redirect.cgi?url_name=topmenu")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<html>redirect url_redirect.cgi</html>`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSMCWebDefaultCreds_Success(t *testing.T) {
	var posts int
	srv := atenEmulator(t, "ADMIN", "ADMIN", &posts)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "supermicro", "ATEN", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runSMCWebDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.supermicro.defaultCreds")
	if f == nil {
		t.Fatalf("expected http.web.defaultCreds via smc ATEN adapter, got %+v", got)
	}
	if via := fieldVal(f.Fields, "loginVia"); via != "httpForm" {
		t.Errorf("loginVia = %q, want http.form.smc-aten", via)
	}
	if u, p := fieldVal(f.Fields, "username"), fieldVal(f.Fields, "password"); u != "ADMIN" || p != "ADMIN" {
		t.Errorf("recovered %q/%q, want ADMIN/ADMIN", u, p)
	}
	if posts > smcMaxAttempts {
		t.Errorf("login POSTs = %d, exceeds cap %d", posts, smcMaxAttempts)
	}
}

func TestSMCWebDefaultCreds_WrongCreds(t *testing.T) {
	srv := atenEmulator(t, "ADMIN", "rotated-pw", nil)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "supermicro", "ATEN", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runSMCWebDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("expected no finding when default rejected, got %+v", got)
	}
}

func TestSMCWebDefaultCreds_NotATENNoAttempt(t *testing.T) {
	// A Supermicro host that is not the ATEN web form (e.g. X14 bmcweb/Redfish):
	// the fingerprint gate must skip it -- no login POST at all.
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/cgi/login.cgi" {
			posts++
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","Vendor":"Supermicro"}`)) // bmcweb, not ATEN
	}))
	t.Cleanup(srv.Close)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "supermicro", "X14", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runSMCWebDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("non-ATEN Supermicro must be skipped, got %+v", got)
	}
	if posts != 0 {
		t.Errorf("fingerprint gate must send no login POST, got %d", posts)
	}
}

func TestSMCWebDefaultCreds_DisableLogins(t *testing.T) {
	var posts int
	srv := atenEmulator(t, "ADMIN", "ADMIN", &posts)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "supermicro", "ATEN", map[string]string{"web.port": port, "web.scheme": "http"})
	tgt.DisableLogins = true

	if got := runSMCWebDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("--disable-logins must suppress the login, got %+v", got)
	}
	if posts != 0 {
		t.Errorf("no request under --disable-logins, got %d", posts)
	}
}

func TestSMCWebDefaultCreds_WrongVendorSkipped(t *testing.T) {
	srv := atenEmulator(t, "ADMIN", "ADMIN", nil)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "dell", "iDRAC", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runSMCWebDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("non-supermicro vendor must be skipped, got %+v", got)
	}
}

// atenLegacyEmulator emulates the older X9/X10-era ATEN web login as it behaves on
// fw 3.x: the login page has an empty <title> and the "ATEN International" META (no
// "Supermicro BMC Login" string), and /cgi/login.cgi reads name/pwd verbatim, with no
// base64 and no check field. On success it emits two Set-Cookie SID headers, a
// clearing one then the real token, and /cgi/url_redirect.cgi returns authenticated
// content. base64-encoded creds (the X11+ wire form) must not authenticate here.
func atenLegacyEmulator(t *testing.T, okUser, okPass string, posts *int) *httptest.Server {
	t.Helper()
	loginPage := `<html><head><title></title>` +
		`<META NAME="ATEN International Co Ltd." CONTENT="(c) ATEN International Co Ltd. 2010">` +
		`</head><body><form action="/cgi/login.cgi" method="post"></form></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(loginPage))
		case r.Method == http.MethodPost && r.URL.Path == "/cgi/login.cgi":
			if posts != nil {
				*posts++
			}
			body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			vals, _ := url.ParseQuery(string(body))
			// Legacy firmware: fields are verbatim, not base64-decoded.
			if vals.Get("name") == okUser && vals.Get("pwd") == okPass {
				http.SetCookie(w, &http.Cookie{Name: "SID", Value: ""}) // clearing cookie
				http.SetCookie(w, &http.Cookie{Name: "SID", Value: "legacyx10token"})
				w.WriteHeader(http.StatusOK)
				return
			}
			// Wrong/base64-mangled creds: no SID minted (mirrors the real box).
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/cgi/ipmi.cgi":
			// Authenticated ATEN device-info opcodes (as observed on real fw 3.53).
			c, err := r.Cookie("SID")
			if err != nil || c.Value != "legacyx10token" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<html><META HTTP-EQUIV="refresh" CONTENT="0;URL=/"></html>`))
				return
			}
			body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			w.WriteHeader(http.StatusOK)
			switch {
			case strings.HasPrefix(string(body), "GENERIC_INFO.XML"):
				_, _ = w.Write([]byte(`<?xml version="1.0"?><IPMI><GENERIC_INFO><GENERIC BMC_IP="010.0.0.1" WEB_VERSION="1.1" IPMIFW_VERSION="0353" IPMIFW_BLDTIME="2017-07-21" /></GENERIC_INFO></IPMI>`))
			case strings.HasPrefix(string(body), "Get_PlatformInfo.XML"):
				_, _ = w.Write([]byte(`<?xml version="1.0"?><IPMI><PLATFORM_INFO><HOST_AND_USER HOSTNAME="burn-bmc" SESS_USER_NAME="ADMIN" USER_ACCESS="04"/></PLATFORM_INFO></IPMI>`))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Regression: the legacy X10 ATEN web UI (plaintext name/pwd, empty title) must
// be caught. Before the encoding fix the check only sent base64 creds, so X10
// hosts with default ADMIN/ADMIN over the web UI were silently missed.
func TestSMCWebDefaultCreds_LegacyPlaintextX10(t *testing.T) {
	var posts int
	srv := atenLegacyEmulator(t, "ADMIN", "ADMIN", &posts)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "supermicro", "X10", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runSMCWebDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.supermicro.defaultCreds")
	if f == nil {
		t.Fatalf("expected default-cred finding against legacy X10 ATEN, got %+v", got)
	}
	if enc := fieldVal(f.Fields, "formEncoding"); enc != "plaintext" {
		t.Errorf("formEncoding = %q, want plaintext", enc)
	}
	if u, p := fieldVal(f.Fields, "username"), fieldVal(f.Fields, "password"); u != "ADMIN" || p != "ADMIN" {
		t.Errorf("recovered %q/%q, want ADMIN/ADMIN", u, p)
	}
	// The proof must carry concise session-derived facts, not prose.
	if proof := fieldVal(f.Fields, "proof"); proof != "fw=3.53 build=2017-07-21 user=ADMIN priv=admin host=burn-bmc" {
		t.Errorf("proof = %q, want concise fw/user/priv/host from the session", proof)
	}
	if posts > smcMaxAttempts {
		t.Errorf("login POSTs = %d, exceeds cap %d", posts, smcMaxAttempts)
	}
}
