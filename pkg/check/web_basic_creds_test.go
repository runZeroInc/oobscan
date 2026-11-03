package check

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// basicAuthServer emulates an HTTP Basic-auth device: it sets the given Server
// header on every response (the vendor fingerprint a real device carries even on
// its 401 challenge), returns 401 + WWW-Authenticate: Basic to an unauthenticated
// request, 200 + body to a request whose Basic credential is in accept{user:pass},
// and a repeated 401 otherwise. authTries counts credentialed attempts.
func basicAuthServer(t *testing.T, server, realm string, accept map[string]string, body string, authTries *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if server != "" {
			w.Header().Set("Server", server)
		}
		u, p, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("Www-Authenticate", "Basic realm=\""+realm+"\"")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if authTries != nil {
			atomic.AddInt32(authTries, 1)
		}
		if want, has := accept[u]; has && want == p {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
			return
		}
		w.Header().Set("Www-Authenticate", "Basic realm=\""+realm+"\"")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestWebBasicDefaultCreds_Success(t *testing.T) {
	var tries int32
	// Digi PortServer: RomPager Server header (the fingerprint), default root/dbps.
	srv := basicAuthServer(t, "Allegro-Software-RomPager-Digi/3.12", "PortServer",
		map[string]string{"root": "dbps"}, "<title>PortServer TS Configuration</title>", &tries)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "digi", "PortServer TS", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runWebBasicDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.digi.defaultCreds")
	if f == nil {
		t.Fatalf("expected http.web.defaultCreds, got %+v", got)
	}
	if f.Risk != "critical" {
		t.Errorf("risk = %q, want critical", f.Risk)
	}
	if u := fieldVal(f.Fields, "username"); u != "root" {
		t.Errorf("username = %q, want root", u)
	}
	if p := fieldVal(f.Fields, "password"); p != "dbps" {
		t.Errorf("password = %q, want dbps", p)
	}
	if via := fieldVal(f.Fields, "loginVia"); via != "httpBasic" {
		t.Errorf("loginVia = %q, want httpBasic", via)
	}
	if !strings.Contains(fieldVal(f.Fields, "proof"), "PortServer") {
		t.Errorf("proof missing authed title: %q", fieldVal(f.Fields, "proof"))
	}
}

func TestWebBasicDefaultCreds_WrongCreds(t *testing.T) {
	var tries int32
	srv := basicAuthServer(t, "Allegro-Software-RomPager-Digi/3.12", "PortServer",
		map[string]string{"root": "changed-me"}, "ok", &tries)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "digi", "PortServer TS", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("expected no finding for rejected default, got %+v", got)
	}
	if tries == 0 {
		t.Errorf("expected at least one Basic attempt, got 0")
	}
	if tries > maxWebBasicAttempts {
		t.Errorf("attempts = %d, exceeds cap %d", tries, maxWebBasicAttempts)
	}
}

func TestWebBasicDefaultCreds_FormDeviceNoBasic(t *testing.T) {
	// A form-login device returns a 200 login page and never challenges Basic;
	// the self-scoping gate must skip it entirely (0 auth attempts).
	var authTries int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "MoxaHttp/2.2")
		if _, _, ok := r.BasicAuth(); ok {
			atomic.AddInt32(&authTries, 1)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><title>NPort Web Console</title><form id=login></form></html>"))
	}))
	t.Cleanup(srv.Close)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "moxa", "NPort", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("expected no finding for non-Basic device, got %+v", got)
	}
	if authTries != 0 {
		t.Errorf("form device should get no credentialed attempt, got %d", authTries)
	}
}

func TestWebBasicDefaultCreds_DisableLogins(t *testing.T) {
	var tries int32
	srv := basicAuthServer(t, "Allegro-Software-RomPager-Digi/3.12", "PortServer",
		map[string]string{"root": "dbps"}, "ok", &tries)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "digi", "PortServer TS", map[string]string{"web.port": port, "web.scheme": "http"})
	tgt.DisableLogins = true

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("--disable-logins must suppress the login, got %+v", got)
	}
	if tries != 0 {
		t.Errorf("no request should be sent under --disable-logins, got %d", tries)
	}
}

func TestWebBasicDefaultCreds_SkipBespokeVendor(t *testing.T) {
	var tries int32
	srv := basicAuthServer(t, "APC", "APC", map[string]string{"apc": "apc"}, "ok", &tries)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "apc", "NMC", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("apc has a bespoke login check; generic Basic must skip it, got %+v", got)
	}
	if tries != 0 {
		t.Errorf("skip-vendor must send no request, got %d", tries)
	}
}

func TestWebBasicDefaultCreds_StopsAtFirstSuccessWithinCap(t *testing.T) {
	// Server Technology ships admn then cdup (both blank/force-set). Accept only
	// the SECOND account and confirm the check tries both, stops at success, and
	// stays within the cap. Server header "ServerTech-AWS" is the vendor gate.
	var tries int32
	srv := basicAuthServer(t, "ServerTech-AWS/v8.0k", "Protected Object",
		map[string]string{"cdup": ""}, "<title>Sentry Switched CDU</title>", &tries)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "servertech", "Sentry", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runWebBasicDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.servertech.defaultCreds")
	if f == nil {
		t.Fatalf("expected finding when the 2nd default works, got %+v", got)
	}
	if u, p := fieldVal(f.Fields, "username"), fieldVal(f.Fields, "password"); u != "cdup" || p != "(blank)" {
		t.Errorf("recovered %q/%q, want cdup/(blank)", u, p)
	}
	if tries > maxWebBasicAttempts {
		t.Errorf("attempts = %d, exceeds cap %d", tries, maxWebBasicAttempts)
	}
}

func TestWebBasicDefaultCreds_ForbiddenNotSuccess(t *testing.T) {
	// A valid Basic credential that lands on a 403 (authorized but forbidden
	// resource) must not be read as a successful login.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Allegro-Software-RomPager-Digi/3.12")
		if _, _, ok := r.BasicAuth(); !ok {
			w.Header().Set("Www-Authenticate", "Basic realm=\"x\"")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "digi", "PortServer TS", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("403 on auth must not count as success, got %+v", got)
	}
}

// TestWebBasicDefaultCreds_VendorFingerprintRejectsMisID is the regression for
// the mistargeting a replay surfaced: a Cradlepoint box misidentified as
// "lantronix" (via the UDP/30718 discovery collision) that happens to challenge
// Basic must not get Lantronix defaults sprayed at it. The vendor-fingerprint
// gate rejects it on the Server header.
func TestWebBasicDefaultCreds_VendorFingerprintRejectsMisID(t *testing.T) {
	var tries int32
	srv := basicAuthServer(t, "CradlepointHTTPService/1.0.0", "Cradlepoint",
		map[string]string{"sysadmin": "PASS"}, "ok", &tries)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "lantronix", "SLC", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("misidentified Cradlepoint must not get lantronix creds, got %+v", got)
	}
	if tries != 0 {
		t.Errorf("vendor-fingerprint gate must send no credentialed attempt, got %d", tries)
	}
}

func splitHostPort(t *testing.T, srvURL string) (host, port string) {
	t.Helper()
	hp := strings.TrimPrefix(srvURL, "http://")
	i := strings.LastIndexByte(hp, ':')
	if i < 0 {
		t.Fatalf("bad server URL %q", srvURL)
	}
	return hp[:i], hp[i+1:]
}
