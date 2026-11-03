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

func amiRouteTarget(t *testing.T, srvURL string) *engine.Target {
	t.Helper()
	host, ps, err := net.SplitHostPort(strings.TrimPrefix(srvURL, "http://"))
	if err != nil {
		t.Fatalf("split %q: %v", srvURL, err)
	}
	return &engine.Target{
		Host:    host,
		Timeout: 2 * time.Second,
		Identity: &engine.Identity{
			Vendor: "ami", Class: engine.ClassBMC,
			Attributes: map[string]string{"web.port": ps, "web.scheme": "http"},
		},
	}
}

func TestRunAMIPreAuthRouteRead_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/session":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"auth required"}`))
		case "/api/settings/users":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Users":[{"UserName":"admin","Role":"Administrator"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	got := runAMIPreAuthRouteRead(context.Background(), amiRouteTarget(t, srv.URL))
	if f := hasFinding(got, "http.ami.preAuthRouteRead"); f == nil {
		t.Fatalf("expected pre-auth route finding, got %+v", got)
	}
}

func TestRunAMIPreAuthRouteRead_Patched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"auth required"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	if got := runAMIPreAuthRouteRead(context.Background(), amiRouteTarget(t, srv.URL)); len(got) != 0 {
		t.Fatalf("expected no finding on auth-gated routes, got %+v", got)
	}
}
