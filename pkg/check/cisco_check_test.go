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

func ciscoTarget(t *testing.T, srvURL string) *engine.Target {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srvURL, "http://"))
	if err != nil {
		t.Fatalf("split %q: %v", srvURL, err)
	}
	return &engine.Target{
		Host:    host,
		Timeout: 2 * time.Second,
		Identity: &engine.Identity{
			Vendor:     "cisco",
			Class:      engine.ClassBMC,
			Attributes: map[string]string{"web.port": portStr, "web.scheme": "http"},
		},
	}
}

func TestRunCiscoXMLAPIPresence(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/nuova" {
			w.Header().Set("Content-Type", "text/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<error errorCode="552" errorDescr="cookie missing"/>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer vuln.Close()

	got := runCiscoXMLAPIPresence(context.Background(), ciscoTarget(t, vuln.URL))
	f := hasFinding(got, "http.cisco.xmlApiPresence")
	if f == nil {
		t.Fatalf("expected cisco XML API presence finding, got %+v", got)
	}
	if f.Risk != "info" {
		t.Errorf("risk = %s, want info", f.Risk)
	}

	patched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer patched.Close()
	if got := runCiscoXMLAPIPresence(context.Background(), ciscoTarget(t, patched.URL)); len(got) != 0 {
		t.Fatalf("expected no finding for disabled /nuova, got %+v", got)
	}
}
