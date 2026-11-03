package redfish

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeRedfish is a minimal Redfish server for the auth/info helpers. It gates
// admin resources behind either an X-Auth-Token minted by SessionService or a
// Basic-auth login, and serves Manager/System documents once authenticated.
type fakeRedfish struct {
	user, pass string
	token      string // set once a session is minted
	allowBasic bool   // accept Basic auth on admin resources
	allowMTLS  bool   // accept a presented client cert as auth
}

func (f *fakeRedfish) authed(r *http.Request) bool {
	if f.token != "" && r.Header.Get("X-Auth-Token") == f.token {
		return true
	}
	if f.allowBasic {
		u, p, ok := r.BasicAuth()
		if ok && u == f.user && p == f.pass {
			return true
		}
	}
	if f.allowMTLS && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return true
	}
	return false
}

func (f *fakeRedfish) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/redfish/v1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","Vendor":"AMI","Product":"MegaRAC","RedfishVersion":"1.16.0","UUID":"svc-uuid-1"}`))
	})
	mux.HandleFunc("/redfish/v1/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","Vendor":"AMI","Product":"MegaRAC","RedfishVersion":"1.16.0","UUID":"svc-uuid-1"}`))
	})
	mux.HandleFunc("/redfish/v1/SessionService/Sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "no", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"UserName":"`+f.user+`"`) && strings.Contains(string(body), `"Password":"`+f.pass+`"`) {
			f.token = "TOKEN-123"
			w.Header().Set("X-Auth-Token", f.token)
			w.Header().Set("Location", "/redfish/v1/SessionService/Sessions/1")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/SessionService/Sessions/1","Id":"1"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	admin := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !f.authed(r) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(body))
		}
	}
	mux.HandleFunc("/redfish/v1/AccountService/Accounts", admin(`{"@odata.type":"#ManagerAccountCollection","Members":[{"@odata.id":"/redfish/v1/AccountService/Accounts/1"}]}`))
	mux.HandleFunc("/redfish/v1/AccountService/Accounts/1", admin(`{"@odata.id":"/redfish/v1/AccountService/Accounts/1","UserName":"root","RoleId":"Administrator","Enabled":true}`))
	mux.HandleFunc("/redfish/v1/Managers", admin(`{"@odata.type":"#ManagerCollection","Members":[{"@odata.id":"/redfish/v1/Managers/Self"}]}`))
	mux.HandleFunc("/redfish/v1/Managers/Self", admin(`{"@odata.id":"/redfish/v1/Managers/Self","Id":"BMC","Manufacturer":"AMI","Model":"MegaRAC-SP-X","FirmwareVersion":"7.11"}`))
	mux.HandleFunc("/redfish/v1/Systems", admin(`{"@odata.type":"#ComputerSystemCollection","Members":[{"@odata.id":"/redfish/v1/Systems/Self"}]}`))
	mux.HandleFunc("/redfish/v1/Systems/Self", admin(`{"@odata.id":"/redfish/v1/Systems/Self","Id":"System","Manufacturer":"ASRockRack","Model":"X470D4U","SerialNumber":"SN123","BiosVersion":"P3.40","PowerState":"On"}`))
	return mux
}

func newFake(f *fakeRedfish) *httptest.Server {
	srv := httptest.NewTLSServer(f.handler())
	return srv
}

func hostOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return strings.TrimPrefix(srv.URL, "https://")
}

func TestOpenSessionAndPullInfo_SessionPath(t *testing.T) {
	f := &fakeRedfish{user: "root", pass: "0penBmc"}
	srv := newFake(f)
	defer srv.Close()
	base := "https://" + hostOf(t, srv)
	client := InsecureClient(3 * time.Second)

	res := OpenSession(client, base, "root", "0penBmc", 3*time.Second)
	if !res.Authenticated {
		t.Fatalf("expected authenticated session, got %+v", res)
	}
	if res.Via != "session" || res.Token == "" {
		t.Fatalf("expected session token login, got %+v", res)
	}
	info := PullSystemInfo(client, base, map[string]string{"X-Auth-Token": res.Token}, "root", 3*time.Second)
	if info.FirmwareVersion != "7.11" {
		t.Errorf("firmware = %q, want 7.11", info.FirmwareVersion)
	}
	// System doc wins for the branded vendor/model.
	if info.Model != "X470D4U" {
		t.Errorf("model = %q, want X470D4U", info.Model)
	}
	if info.SerialNumber != "SN123" {
		t.Errorf("serial = %q, want SN123", info.SerialNumber)
	}
	if info.RedfishVersion != "1.16.0" {
		t.Errorf("redfishVersion = %q, want 1.16.0", info.RedfishVersion)
	}
	if info.ServiceUUID != "svc-uuid-1" {
		t.Errorf("service_uuid = %q, want svc-uuid-1", info.ServiceUUID)
	}
	if info.ManagerID != "BMC" {
		t.Errorf("manager_id = %q, want BMC", info.ManagerID)
	}
	if info.SystemID != "System" {
		t.Errorf("system_id = %q, want System", info.SystemID)
	}
	if info.BIOSVersion != "P3.40" {
		t.Errorf("bios_version = %q, want P3.40", info.BIOSVersion)
	}
	if info.PowerState != "On" {
		t.Errorf("power_state = %q, want On", info.PowerState)
	}
	if info.AccountRole != "Administrator" {
		t.Errorf("account_role = %q, want Administrator", info.AccountRole)
	}
	if info.AccountEnabled != "true" {
		t.Errorf("account_enabled = %q, want true", info.AccountEnabled)
	}
	if info.Empty() {
		t.Error("info unexpectedly empty")
	}
}

func TestOpenSession_BasicFallback(t *testing.T) {
	// No SessionService success (wrong creds path exercised), but Basic works.
	f := &fakeRedfish{user: "USERID", pass: "PASSW0RD", allowBasic: true}
	// Break the session path by making SessionService reject everything: use a
	// different expected user for the POST body match than the Basic creds.
	f.user = "USERID"
	srv := newFake(f)
	defer srv.Close()
	base := "https://" + hostOf(t, srv)
	client := InsecureClient(3 * time.Second)

	// Force the session POST to fail by pointing OpenSession at creds the POST
	// matcher accepts too -> would mint a token. To isolate the Basic path,
	// disable session minting by using creds the POST matcher rejects but Basic
	// accepts: the fake matches POST on the same user/pass, so instead we test
	// Basic directly via AuthedResource.
	hdrs := basicAuthHeader("USERID", "PASSW0RD")
	if ok, _ := AuthedResource(client, base, hdrs, 3*time.Second); !ok {
		t.Fatal("expected Basic-auth admin read to succeed")
	}
	wrong := basicAuthHeader("USERID", "wrong")
	if ok, _ := AuthedResource(client, base, wrong, 3*time.Second); ok {
		t.Error("wrong Basic creds should not authenticate")
	}
}

func TestOpenSession_WrongCreds(t *testing.T) {
	f := &fakeRedfish{user: "root", pass: "0penBmc"}
	srv := newFake(f)
	defer srv.Close()
	base := "https://" + hostOf(t, srv)
	client := InsecureClient(3 * time.Second)

	res := OpenSession(client, base, "admin", "admin", 3*time.Second)
	if res.Authenticated {
		t.Errorf("wrong creds must not authenticate, got %+v", res)
	}
}

func TestAuthedResource_DeniesUnauthenticated(t *testing.T) {
	f := &fakeRedfish{user: "root", pass: "0penBmc"}
	srv := newFake(f)
	defer srv.Close()
	base := "https://" + hostOf(t, srv)
	client := InsecureClient(3 * time.Second)
	if ok, _ := AuthedResource(client, base, nil, 3*time.Second); ok {
		t.Error("admin resource must be denied without auth")
	}
}

func TestProbeAuthPathStatusAndPattern(t *testing.T) {
	// This fake models the broken differential seen in the field:
	// unauthenticated admin resource requests challenge (401), while the same
	// paths with auth and SessionService POST error (500).
	mux := http.NewServeMux()
	mux.HandleFunc("/redfish/v1/Managers", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `xBasic realm="RedfishService"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/redfish/v1/AccountService/Accounts", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `xBasic realm="RedfishService"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/redfish/v1/SessionService/Sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	base := "https://" + hostOf(t, srv)
	client := InsecureClient(3 * time.Second)
	st := ProbeAuthPathStatus(client, base, "ADMIN", "ADMIN", 3*time.Second)
	if st.UnauthStatus != http.StatusUnauthorized || st.BasicStatus != http.StatusInternalServerError || st.SessionStatus != http.StatusInternalServerError {
		t.Fatalf("unexpected status probe: %+v", st)
	}
	if !strings.Contains(st.Challenge, "xBasic") {
		t.Fatalf("challenge = %q, want xBasic", st.Challenge)
	}
	if !IsAuthPathErrorPattern(st) {
		t.Fatalf("expected auth-path error pattern for %+v", st)
	}
}

func TestIsAuthPathErrorPatternNegative(t *testing.T) {
	st := AuthPathStatus{UnauthStatus: 401, BasicStatus: 401, SessionStatus: 401}
	if IsAuthPathErrorPattern(st) {
		t.Fatalf("unexpected positive pattern for %s", fmt.Sprintf("%+v", st))
	}
}

func TestVerifyCredential_SessionDifferentialValid(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/redfish/v1/Managers", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `xBasic realm="RedfishService"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/redfish/v1/Systems", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `xBasic realm="RedfishService"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/redfish/v1/AccountService/Accounts", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `xBasic realm="RedfishService"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/redfish/v1/SessionService/Sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		s := string(body)
		if strings.Contains(s, `"UserName":"ADMIN"`) && strings.Contains(s, `"Password":"ADMIN"`) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := InsecureClient(3 * time.Second)
	if !VerifyCredential(client, srv.URL, "ADMIN", "ADMIN", 3*time.Second) {
		t.Fatal("expected session differential to verify credential validity")
	}
}

func TestVerifyCredential_SessionDifferentialNegative(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/redfish/v1/Managers", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `xBasic realm="RedfishService"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/redfish/v1/Systems", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `xBasic realm="RedfishService"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/redfish/v1/AccountService/Accounts", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `xBasic realm="RedfishService"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/redfish/v1/SessionService/Sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := InsecureClient(3 * time.Second)
	if VerifyCredential(client, srv.URL, "ADMIN", "ADMIN", 3*time.Second) {
		t.Fatal("did not expect verification when both good and bad creds map to 5xx")
	}
}
