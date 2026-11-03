package ilo

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// iloBypassServer returns a TLS test server that models an iLO4 web endpoint.
//
//	mode "vuln"    : the 29-byte Connection header drops the auth check, so the
//	                 protected REST resource returns 200 + JSON; a plain request
//	                 is denied with 401. This is CVE-2017-12542.
//	mode "patched" : the protected resource always returns 401 (fixed >= 2.53).
//	mode "preauth" : the resource is unauthenticated regardless of the header, so
//	                 the differential cannot attribute a bypass (false-positive
//	                 guard: a genuinely open endpoint must not be flagged).
func iloBypassServer(t *testing.T, mode string) (host string, close func()) {
	t.Helper()
	restBody := `{"Type":"Collection.0","Name":"Accounts","links":{"Member":[]},` +
		`"MemberType":"AccountService.0.10.0","AccountService":true}`
	mux := http.NewServeMux()
	mux.HandleFunc(bypassPath, func(w http.ResponseWriter, r *http.Request) {
		conn := r.Header.Get("Connection")
		switch mode {
		case "vuln":
			if len(conn) == 29 {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(restBody))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		case "patched":
			w.WriteHeader(http.StatusUnauthorized)
		case "preauth":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(restBody))
		}
	})
	srv := httptest.NewTLSServer(mux)
	return strings.TrimPrefix(srv.URL, "https://"), srv.Close
}

func TestVerifyAuthBypass(t *testing.T) {
	cases := []struct {
		mode     string
		wantVuln bool
	}{
		{"vuln", true},
		{"patched", false},
		{"preauth", false}, // open endpoint: no bypass can be attributed
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			host, closeFn := iloBypassServer(t, c.mode)
			defer closeFn()
			ok, evidence, err := VerifyAuthBypass(host, 3*time.Second)
			if err != nil {
				t.Fatalf("VerifyAuthBypass error: %v", err)
			}
			if ok != c.wantVuln {
				t.Fatalf("mode=%s: got vulnerable=%v, want %v (evidence=%q)", c.mode, ok, c.wantVuln, evidence)
			}
			if c.wantVuln && evidence == "" {
				t.Fatalf("mode=%s: vulnerable but no evidence snippet returned", c.mode)
			}
			if c.wantVuln && (!strings.Contains(evidence, "baselineStatus=401") || !strings.Contains(evidence, "bypassStatus=200")) {
				t.Fatalf("mode=%s: malformed evidence %q", c.mode, evidence)
			}
		})
	}
}

// TestVerifyAuthBypassUnreachable confirms a dead host yields (false, no error)
// rather than a false positive.
func TestVerifyAuthBypassUnreachable(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1 (RFC 5737): guaranteed non-routable.
	ok, _, err := VerifyAuthBypass("192.0.2.1:65001", 500*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("unreachable host reported vulnerable")
	}
}
