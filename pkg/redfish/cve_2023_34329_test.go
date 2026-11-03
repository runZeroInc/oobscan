package redfish

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCVE34329Verdict(t *testing.T) {
	redfishBody := []byte(`{"@odata.type":"#ManagerAccountCollection","Members":[]}`)
	loginBody := []byte(`<!DOCTYPE html><html><head><title>Login</title></head></html>`)
	cases := []struct {
		name        string
		plainStatus int
		spoofStatus int
		spoofBody   []byte
		want        bool
	}{
		{"vulnerable: denied plain, redfish spoofed", 401, 200, redfishBody, true},
		{"vulnerable: 403 plain, redfish spoofed", 403, 200, redfishBody, true},
		{"patched: denied both", 401, 401, nil, false},
		{"unauth already readable (not this bug)", 200, 200, redfishBody, false},
		{"spoof returns login page", 401, 200, loginBody, false},
		{"spoof non-2xx", 401, 500, redfishBody, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cve34329Verdict(tc.plainStatus, tc.spoofStatus, tc.spoofBody); got != tc.want {
				t.Errorf("verdict = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCheckCVE34329_Differential stands up a server that accepts only the exact
// request from Eclypsium's published detector. Extra spoof headers are rejected
// so the test cannot pass if this probe is accidentally combined with 54085.
func TestCheckCVE34329_Differential(t *testing.T) {
	vuln := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redfish/v1/Systems" {
			http.NotFound(w, r)
			return
		}
		if r.Host != cve34329InternalIP {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Server-Addr") != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"@odata.type":"#ManagerAccountCollection","Members":[{"@odata.id":"/redfish/v1/AccountService/Accounts/1"}]}`))
	}))
	defer vuln.Close()

	host, port := splitHostPort(t, vuln.URL)
	res := CheckCVE202334329(host, port, 3*time.Second)
	if !res.Vulnerable {
		t.Fatalf("expected vulnerable verdict, got %+v", res)
	}
	if res.PlainStatus != http.StatusUnauthorized {
		t.Errorf("plain status = %d, want 401", res.PlainStatus)
	}
	if len(res.SpoofHeaders) != 1 || res.SpoofHeaders["Host"] != cve34329InternalIP {
		t.Errorf("spoof headers = %#v, want only Host: %s", res.SpoofHeaders, cve34329InternalIP)
	}

	// Patched server: always denies regardless of spoofed headers.
	patched := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer patched.Close()
	host2, port2 := splitHostPort(t, patched.URL)
	if res := CheckCVE202334329(host2, port2, 3*time.Second); res.Vulnerable {
		t.Errorf("patched server flagged vulnerable: %+v", res)
	}
}

func splitHostPort(t *testing.T, url string) (string, int) {
	t.Helper()
	hp := strings.TrimPrefix(url, "https://")
	h, ps, err := net.SplitHostPort(hp)
	if err != nil {
		t.Fatalf("split %q: %v", hp, err)
	}
	p, _ := strconv.Atoi(ps)
	return h, p
}
