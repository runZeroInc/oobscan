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

// megaracEmulator emulates an AMI MegaRAC SP-X web login (Fujitsu iRMC S6
// firmware): GET / serves the Angular SPA shell (<app-root>), a GET of the RPC
// login endpoint returns a live non-HTML response (so the endpoint gate
// selects it), and a POST with the right field names + the accepted
// credential returns the session success signal (SESSION_TOKEN/CSRF body for
// /rpc/WEBSES, QSESSIONID cookie for /api/session); everything else 404s/401s.
// On the REST path it also serves the authenticated-only /api/settings/users
// route, gated on the minted QSESSIONID cookie, exercising the post-login GET.
const megaracLabQSession = "labqsession-b0c1d2e3f40516"

func megaracEmulator(t *testing.T, endpoint, okUser, okPass string, posts *int) *httptest.Server {
	t.Helper()
	spa := `<!doctype html><html><head><meta name="version" content="v2.63a-S6M6_M7">` +
		`<title></title></head><body><app-root></app-root></body></html>`
	uField, pField := "WEBVAR_USERNAME", "WEBVAR_PASSWORD"
	if endpoint == "/api/session" {
		uField, pField = "username", "password"
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/index.html"):
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(spa))
		case r.Method == http.MethodGet && r.URL.Path == "/api/settings/users":
			// Authenticated-only route: user list only with a valid session cookie.
			if c, err := r.Cookie("QSESSIONID"); err != nil || c.Value != megaracLabQSession {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":2,"username":"admin","userid":2,"role":"administrator","privilege":4}]`))
		case r.Method == http.MethodGet && r.URL.Path == endpoint:
			// Live login endpoint probed with GET: non-HTML, non-404.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"ok":-1}`))
		case r.Method == http.MethodPost && r.URL.Path == endpoint:
			if posts != nil {
				*posts++
			}
			body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			vals, _ := url.ParseQuery(string(body))
			if vals.Get(uField) != okUser || vals.Get(pField) != okPass {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if endpoint == "/api/session" {
				http.SetCookie(w, &http.Cookie{Name: "QSESSIONID", Value: megaracLabQSession})
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"ok":0,"privilege":4,"CSRFToken":"a1b2c3d4e5f60718"}`))
				return
			}
			// Classic WEBVAR session structure (Fujitsu iRMC scheme).
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("WEBVAR_JSONVAR_WEB_SESSION:\n{\n" +
				"WEBVAR_STRUCTNAME_WEB_SESSION:\n[\n" +
				"{ 'SESSION_COOKIE' : 'lab', 'SESSION_TOKEN' : 'a1b2c3d4e5f60718', 'CSRFTOKEN' : 'ffee0011ddcc2233' }\n],\n" +
				"WEBVAR_STRUCTSIZE_WEB_SESSION:1,\nWEBVAR_ERROR_WEB_SESSION:0\n}\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestMegaRACWebDefaultCreds_Success(t *testing.T) {
	// Fujitsu iRMC S6 classic /rpc/WEBSES/create.asp, default sysadmin/superuser.
	var posts int
	srv := megaracEmulator(t, "/rpc/WEBSES/create.asp", "sysadmin", "superuser", &posts)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "fujitsu", "iRMC S6 (MegaRAC SP-X)", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runMegaRACWebDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.fujitsu.defaultCreds")
	if f == nil {
		t.Fatalf("expected http.web.defaultCreds via megarac adapter, got %+v", got)
	}
	if via := fieldVal(f.Fields, "loginVia"); via != "httpRpc" {
		t.Errorf("loginVia = %q, want http.rpc.megarac", via)
	}
	if u, p := fieldVal(f.Fields, "username"), fieldVal(f.Fields, "password"); u != "sysadmin" || p != "superuser" {
		t.Errorf("recovered %q/%q, want sysadmin/superuser", u, p)
	}
	if ep := fieldVal(f.Fields, "evidenceEndpoint"); ep != "/rpc/WEBSES/create.asp" {
		t.Errorf("evidenceEndpoint = %q, want /rpc/WEBSES/create.asp", ep)
	}
	if f.Risk != "critical" {
		t.Errorf("risk = %q, want critical", f.Risk)
	}
	if posts > megaracMaxAttempts {
		t.Errorf("login POSTs = %d, exceeds cap %d", posts, megaracMaxAttempts)
	}
}

func TestMegaRACWebDefaultCreds_APISessionQSESSIONID(t *testing.T) {
	// A different OEM (ASRock Rack) using the REST /api/session convention: the
	// success marker is the QSESSIONID cookie. admin/admin is the documented default.
	srv := megaracEmulator(t, "/api/session", "admin", "admin", nil)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "asrockrack", "MegaRAC", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runMegaRACWebDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.asrockrack.defaultCreds")
	if f == nil {
		t.Fatalf("expected http.web.defaultCreds via /api/session, got %+v", got)
	}
	if ep := fieldVal(f.Fields, "evidenceEndpoint"); ep != "/api/session" {
		t.Errorf("evidenceEndpoint = %q, want /api/session", ep)
	}
	if u, p := fieldVal(f.Fields, "username"), fieldVal(f.Fields, "password"); u != "admin" || p != "admin" {
		t.Errorf("recovered %q/%q, want admin/admin", u, p)
	}
	proof := fieldVal(f.Fields, "proof")
	for _, want := range []string{"loginPath=/api/session", `token="QSESSIONID cookie"`, "tokenLen=", `code="ok":0`, "authedPath=/api/settings/users", "authedStatus=200"} {
		if !strings.Contains(proof, want) {
			t.Errorf("proof %q missing %q", proof, want)
		}
	}
}

// TestMegaRACParseLogin_FPGuard is the tightened-logic guard: bare cookie
// presence is not proof of an authenticated session. A response that mints a
// QSESSIONID cookie but carries no explicit zero success code (the shape of a
// device that hands out an anonymous/pre-auth session cookie) must be rejected;
// only cookie + "ok":0 is accepted.
func TestMegaRACParseLogin_FPGuard(t *testing.T) {
	mk := func(setCookie, body string) *http.Response {
		h := http.Header{}
		if setCookie != "" {
			h.Add("Set-Cookie", setCookie)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: h}
	}
	cases := []struct {
		name      string
		setCookie string
		body      string
		wantOK    bool
		wantKind  string
	}{
		{
			name:      "bare QSESSIONID cookie, no success code -> reject",
			setCookie: "QSESSIONID=abcdef1234567890; Path=/",
			body:      `<html><body>login</body></html>`,
		},
		{
			name:      "QSESSIONID cookie + ok:0 -> accept",
			setCookie: "QSESSIONID=abcdef1234567890; Path=/",
			body:      `{"ok":0,"CSRFToken":"a1b2c3d4e5f6"}`,
			wantOK:    true,
			wantKind:  "QSESSIONID cookie",
		},
		{
			name:   "SESSION_TOKEN body, no success code -> reject",
			body:   `{ 'SESSION_TOKEN' : 'a1b2c3d4e5f60718' }`,
			wantOK: false,
		},
		{
			name:     "SESSION_TOKEN + WEBVAR_ERROR_WEB_SESSION:0 -> accept",
			body:     `{ 'SESSION_TOKEN' : 'a1b2c3d4e5f60718' } WEBVAR_ERROR_WEB_SESSION:0`,
			wantOK:   true,
			wantKind: "SESSION_TOKEN",
		},
		{
			name:      "ok:0 but trivial cookie value + no body token -> reject",
			setCookie: "QSESSIONID=0; Path=/",
			body:      `{"ok":0}`,
			wantOK:    false,
		},
		{
			name:      "CSRF token + ok:0 but no session token -> reject",
			setCookie: "",
			body:      `{"ok":0,"CSRFToken":"a1b2c3d4e5f60718"}`,
			wantOK:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, ok := megaracParseLogin(mk(tc.setCookie, tc.body), []byte(tc.body))
			if ok != tc.wantOK {
				t.Fatalf("accepted = %v, want %v (sess=%+v)", ok, tc.wantOK, sess)
			}
			if ok && sess.tokenKind != tc.wantKind {
				t.Errorf("tokenKind = %q, want %q", sess.tokenKind, tc.wantKind)
			}
		})
	}
}

// TestMegaRACParseLogin_RejectStatus confirms an explicit 401/403 (the real
// SP-X rejected-credential response) is a clean not-accepted regardless of body.
func TestMegaRACParseLogin_RejectStatus(t *testing.T) {
	for _, st := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		resp := &http.Response{StatusCode: st, Header: http.Header{}}
		if _, ok := megaracParseLogin(resp, []byte(`{"ok":0,"CSRFToken":"deadbeefcafe"}`)); ok {
			t.Errorf("status %d must be rejected even with a success-shaped body", st)
		}
	}
}

func TestMegaRACWebDefaultCreds_WrongCreds(t *testing.T) {
	srv := megaracEmulator(t, "/rpc/WEBSES/create.asp", "sysadmin", "rotated-pw", nil)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "fujitsu", "iRMC S6", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runMegaRACWebDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("expected no finding when default rejected, got %+v", got)
	}
}

func TestMegaRACWebDefaultCreds_NotMegaRACNoAttempt(t *testing.T) {
	// An AMI-family vendor whose web surface is not the MegaRAC RPC form (e.g. a
	// pure-Redfish/OpenBMC box): the fingerprint gate must skip it -- no login POST.
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && (r.URL.Path == "/rpc/WEBSES/create.asp" || r.URL.Path == "/api/session") {
			posts++
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","Vendor":"AMI"}`)) // Redfish, not MegaRAC SPA
	}))
	t.Cleanup(srv.Close)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "ami", "Redfish", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runMegaRACWebDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("non-MegaRAC AMI surface must be skipped, got %+v", got)
	}
	if posts != 0 {
		t.Errorf("fingerprint gate must send no login POST, got %d", posts)
	}
}

func TestMegaRACWebDefaultCreds_DisableLogins(t *testing.T) {
	var posts int
	srv := megaracEmulator(t, "/rpc/WEBSES/create.asp", "sysadmin", "superuser", &posts)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "fujitsu", "iRMC S6", map[string]string{"web.port": port, "web.scheme": "http"})
	tgt.DisableLogins = true

	if got := runMegaRACWebDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("--disable-logins must suppress the login, got %+v", got)
	}
	if posts != 0 {
		t.Errorf("no request under --disable-logins, got %d", posts)
	}
}

func TestMegaRACWebDefaultCreds_WrongVendorSkipped(t *testing.T) {
	var posts int
	srv := megaracEmulator(t, "/rpc/WEBSES/create.asp", "sysadmin", "superuser", &posts)
	host, port := splitHostPort(t, srv.URL)
	// A non-MegaRAC vendor (Dell iDRAC) must be skipped even though the emulated
	// surface would accept the creds.
	tgt := mkTargetWithIdentity(t, host, port, "dell", "iDRAC", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runMegaRACWebDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("non-MegaRAC vendor must be skipped, got %+v", got)
	}
	if posts != 0 {
		t.Errorf("wrong-vendor gate must send no request, got %d", posts)
	}
}

// Guard: the two RPC conventions carry distinct field names; a stray rename would
// silently break login. Keep this in sync with megaracEndpoints.
func TestMegaRACEndpointFields(t *testing.T) {
	want := map[string][2]string{
		"/rpc/WEBSES/create.asp": {"WEBVAR_USERNAME", "WEBVAR_PASSWORD"},
		"/api/session":           {"username", "password"},
	}
	for _, ep := range megaracEndpoints {
		w, ok := want[ep.path]
		if !ok {
			t.Errorf("unexpected megarac endpoint %q", ep.path)
			continue
		}
		if ep.userField != w[0] || ep.passField != w[1] {
			t.Errorf("%s fields = %q/%q, want %q/%q", ep.path, ep.userField, ep.passField, w[0], w[1])
		}
	}
}
