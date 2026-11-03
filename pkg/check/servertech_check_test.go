package check

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func servertechTarget(t *testing.T, srvURL string) *engine.Target {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srvURL, "http://"))
	if err != nil {
		t.Fatalf("split %q: %v", srvURL, err)
	}
	return &engine.Target{
		Host:    host,
		Timeout: 2 * time.Second,
		Identity: &engine.Identity{
			Vendor:     "servertech",
			Class:      engine.ClassPDU,
			Attributes: map[string]string{"web.port": portStr, "web.scheme": "http"},
		},
	}
}

func TestRunServertechConfigBakLeak(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config.bak" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ldap_bind_secure=abc\nsnmpv3_auth_secure=def\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer vuln.Close()

	got := runServertechConfigBakLeak(context.Background(), servertechTarget(t, vuln.URL))
	f := hasFinding(got, "http.servertech.configBakLeak")
	if f == nil {
		t.Fatalf("expected servertech config leak finding, got %+v", got)
	}
	if f.Risk != "high" {
		t.Errorf("risk = %s, want high", f.Risk)
	}

	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("login required"))
	}))
	defer safe.Close()
	if got := runServertechConfigBakLeak(context.Background(), servertechTarget(t, safe.URL)); len(got) != 0 {
		t.Fatalf("expected no finding for auth-gated backup paths, got %+v", got)
	}
}

func TestRunServertechMgrHandshake(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<init><company>Server Technology</company><cookie>C=7af1</cookie></init>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer vuln.Close()
	got := runServertechMgrHandshake(context.Background(), servertechTarget(t, vuln.URL))
	f := hasFinding(got, "http.servertech.mgrHandshake")
	if f == nil {
		t.Fatalf("expected servertech handshake finding, got %+v", got)
	}

	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("auth required"))
	}))
	defer safe.Close()
	if got := runServertechMgrHandshake(context.Background(), servertechTarget(t, safe.URL)); len(got) != 0 {
		t.Fatalf("expected no finding on auth-gated handshake, got %+v", got)
	}
}
