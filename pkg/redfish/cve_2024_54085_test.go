package redfish

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// vulnHostIfaceServer models a MegaRAC build with CVE-2024-54085: every
// admin-scoped resource is denied anonymously and served when the request
// carries the spoofed host-interface address in X-Server-Addr.
func vulnHostIfaceServer(t *testing.T, wantHeader string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Server-Addr") != wantHeader {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/redfish/v1/AccountService/Accounts":
			_, _ = w.Write([]byte(`{"@odata.type":"#ManagerAccountCollection","Members":[{"@odata.id":"/redfish/v1/AccountService/Accounts/1"}]}`))
		case "/redfish/v1/AccountService/Accounts/1":
			_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/AccountService/Accounts/1","UserName":"admin","RoleId":"Administrator","Enabled":true}`))
		case "/redfish/v1":
			_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","Vendor":"AMI","Product":"MegaRAC","RedfishVersion":"1.11.0"}`))
		case "/redfish/v1/Managers":
			_, _ = w.Write([]byte(`{"@odata.type":"#ManagerCollection","Members":[{"@odata.id":"/redfish/v1/Managers/Self"}]}`))
		case "/redfish/v1/Managers/Self":
			_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/Managers/Self","Id":"Self","Manufacturer":"AMI","Model":"MegaRAC","FirmwareVersion":"12.5"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckHostInterfaceBypass_Confirmed(t *testing.T) {
	srv := vulnHostIfaceServer(t, HostInterfaceAddr+":")
	host, port := splitHostPort(t, srv.URL)

	res := CheckHostInterfaceBypass(host, port, 3*time.Second)
	if !res.Confirmed {
		t.Fatalf("expected confirmed bypass, got %+v", res)
	}
	if res.Path != "/redfish/v1/AccountService/Accounts" {
		t.Errorf("path = %q, want the admin-scoped Accounts resource", res.Path)
	}
	if res.Header() != "X-Server-Addr: 169.254.0.17:" {
		t.Errorf("header = %q, want the published spoof header", res.Header())
	}
	if res.PlainStatus != http.StatusUnauthorized || res.SpoofStatus != http.StatusOK {
		t.Errorf("differential = plain %d / spoof %d, want 401/200", res.PlainStatus, res.SpoofStatus)
	}
	// Inventory must be pulled back over the bypassed path: that is what proves
	// the access is real rather than a status-code artifact.
	if res.Info.FirmwareVersion != "12.5" || res.Info.ManagerID != "Self" {
		t.Errorf("info = %+v, want firmware/manager pulled over the bypass", res.Info)
	}
	if res.Info.AccountRole != "Administrator" {
		t.Errorf("accountRole = %q, want Administrator read from the account list", res.Info.AccountRole)
	}
}

func TestCheckHostInterfaceBypass_BareAddressVariant(t *testing.T) {
	// Builds that compare the bare address rather than "addr:" are still vulnerable.
	srv := vulnHostIfaceServer(t, HostInterfaceAddr)
	host, port := splitHostPort(t, srv.URL)

	res := CheckHostInterfaceBypass(host, port, 3*time.Second)
	if !res.Confirmed {
		t.Fatalf("expected confirmed bypass on the bare-address variant, got %+v", res)
	}
	if res.HeaderValue != HostInterfaceAddr {
		t.Errorf("headerValue = %q, want the bare address", res.HeaderValue)
	}
}

func TestCheckHostInterfaceBypass_PatchedDeniesBoth(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized) // header no longer trusted
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	if res := CheckHostInterfaceBypass(host, port, 3*time.Second); res.Confirmed {
		t.Errorf("patched host must not confirm, got %+v", res)
	}
}

func TestCheckHostInterfaceBypass_UnauthReadableNotAttributed(t *testing.T) {
	// A BMC that serves the admin resources to any anonymous caller is a
	// different (pre-auth exposure) problem; the header proves nothing here, so
	// this must not be reported as CVE-2024-54085.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"@odata.type":"#ManagerAccountCollection","Members":[]}`))
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	if res := CheckHostInterfaceBypass(host, port, 3*time.Second); res.Confirmed {
		t.Errorf("unauth-readable host must not be attributed to the header bypass, got %+v", res)
	}
}

func TestCheckHostInterfaceBypass_LoginPageIsNotAccess(t *testing.T) {
	// A 200 that returns an HTML login page is not authenticated access.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Server-Addr") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>login</body></html>`))
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	if res := CheckHostInterfaceBypass(host, port, 3*time.Second); res.Confirmed {
		t.Errorf("HTML login page must not count as a bypass, got %+v", res)
	}
}

func TestCheckHostInterfaceBypass_NeverWrites(t *testing.T) {
	// The published exploit POSTs a new Administrator account. This check must
	// only ever GET.
	var mu sync.Mutex
	var methods []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	CheckHostInterfaceBypass(host, port, 3*time.Second)
	mu.Lock()
	defer mu.Unlock()
	if len(methods) == 0 {
		t.Fatal("probe issued no requests")
	}
	for _, m := range methods {
		if m != http.MethodGet {
			t.Errorf("probe issued %s; the check must be read-only", m)
		}
	}
}
