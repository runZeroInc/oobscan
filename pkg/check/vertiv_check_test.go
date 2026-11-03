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

func webTarget(t *testing.T, srvURL, vendor string, class engine.DeviceClass) *engine.Target {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srvURL, "http://"))
	if err != nil {
		t.Fatalf("split %q: %v", srvURL, err)
	}
	return &engine.Target{
		Host:    host,
		Timeout: 2 * time.Second,
		Identity: &engine.Identity{
			Vendor:     vendor,
			Class:      class,
			Attributes: map[string]string{"web.port": portStr, "web.scheme": "http"},
		},
	}
}

func TestRunVertivUnityCardInfo(t *testing.T) {
	// Configured card: the discovery JSON is served unauthenticated.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/web/cardinfo.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"8.5.1.0","sysname":"lab","state":"configured","hostname":"unity-01","macaddr":"00:11:22:33:44:55"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	got := runVertivUnityCardInfo(context.Background(), webTarget(t, srv.URL, "vertiv", engine.ClassPDU))
	f := hasFinding(got, "http.vertiv.unityCardInfo")
	if f == nil {
		t.Fatal("expected http.vertiv.unityCardInfo when cardinfo.json is served unauthenticated")
	}
	if f.Risk != "info" {
		t.Errorf("risk = %s, want info for a configured card", f.Risk)
	}
	if v := fieldVal(f.Fields, "version"); v != "8.5.1.0" {
		t.Errorf("version field = %q, want 8.5.1.0", v)
	}
	if v := fieldVal(f.Fields, "mac"); v != "00:11:22:33:44:55" {
		t.Errorf("mac field = %q", v)
	}

	// Unconfigured is a provisioning signal, not proof of takeover.
	un := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"8.5.1.0","sysname":"","state":"unconfigured","hostname":"","macaddr":"00:11:22:33:44:55"}`))
	}))
	defer un.Close()
	got = runVertivUnityCardInfo(context.Background(), webTarget(t, un.URL, "vertiv", engine.ClassPDU))
	if f := hasFinding(got, "http.vertiv.unityCardInfo"); f == nil || f.Risk != "info" {
		t.Errorf("unconfigured card should yield an info finding, got %+v", got)
	}

	// Auth-gated / unrelated JSON -> no finding.
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer safe.Close()
	if got := runVertivUnityCardInfo(context.Background(), webTarget(t, safe.URL, "vertiv", engine.ClassPDU)); len(got) != 0 {
		t.Errorf("expected no finding for an unrelated JSON body, got %v", got)
	}
}
