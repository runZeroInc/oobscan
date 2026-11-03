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

func TestLooksLikePrometheus(t *testing.T) {
	yes := [][]byte{
		[]byte("# HELP go_goroutines Number of goroutines\n# TYPE go_goroutines gauge\ngo_goroutines 12"),
		[]byte("process_cpu_seconds_total 3.4"),
	}
	for _, b := range yes {
		if !looksLikePrometheus(b) {
			t.Errorf("expected Prometheus body to be recognized: %q", b)
		}
	}
	no := [][]byte{
		[]byte("<html><body>JetKVM</body></html>"),
		[]byte(`{"status":"ok"}`),
		[]byte(""),
	}
	for _, b := range no {
		if looksLikePrometheus(b) {
			t.Errorf("non-metrics body must not be recognized: %q", b)
		}
	}
}

func TestExtractScriptSrcs(t *testing.T) {
	body := []byte(`<html><script src="/assets/index-abc123.js"></script><script type="module" src='/assets/vendor-xyz.js'></script></html>`)
	got := extractScriptSrcs(body)
	if len(got) != 2 {
		t.Fatalf("len(extractScriptSrcs)=%d, want 2", len(got))
	}
	if got[0] != "/assets/index-abc123.js" || got[1] != "/assets/vendor-xyz.js" {
		t.Fatalf("extractScriptSrcs=%v, want hashed assets", got)
	}
}

func TestRunNanoKVMUniversalKeyFromHashedAsset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/index.html":
			_, _ = w.Write([]byte(`<html><script type="module" src="/assets/index-abc123.js"></script></html>`))
		case "/assets/index-abc123.js":
			_, _ = w.Write([]byte(`const k="nanokvm-sipeed-2024";`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	hostPort := strings.TrimPrefix(srv.URL, "http://")
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatalf("split hostport: %v", err)
	}

	tgt := &engine.Target{
		Host:          host,
		Timeout:       2 * time.Second,
		DisableLogins: false,
		Identity: &engine.Identity{
			Class:   engine.ClassKVM,
			Vendor:  "nanokvm",
			Product: "NanoKVM",
			Attributes: map[string]string{
				"web.port":   portStr,
				"web.scheme": "http",
			},
		},
	}

	got := runNanoKVMUniversalKey(context.Background(), tgt)
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %d", len(got))
	}
	if got[0].Check != "http.nanokvm.universalKey" {
		t.Fatalf("check=%q, want http.nanokvm.universalKey", got[0].Check)
	}
	if url := explainField(got[0], "url"); url != "/assets/index-abc123.js" {
		t.Fatalf("url=%q, want /assets/index-abc123.js", url)
	}
}
