package check

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func webTargetAt(host string, port int, scheme string, attrs map[string]string) *engine.Target {
	a := map[string]string{"web.port": strconv.Itoa(port), "web.scheme": scheme}
	for k, v := range attrs {
		a[k] = v
	}
	return &engine.Target{
		Host:    host,
		Timeout: 200 * time.Millisecond,
		Identity: &engine.Identity{
			Class:      engine.ClassBMC,
			Vendor:     "supermicro",
			Confidence: engine.ConfHigh,
			Attributes: a,
		},
	}
}

func findingOnPort(fs []engine.Finding, check string, port int) (engine.Finding, bool) {
	for _, f := range fs {
		if f.Check == check && f.Port == port {
			return f, true
		}
	}
	return engine.Finding{}, false
}

// The primary port's Server header and title are carried over from the fingerprint
// stage rather than re-read, so a web.service finding for it can be produced for a
// port that answers nothing at check time. That reads as a live measurement and is
// then used to contradict other checks; it has to say where it came from.
func TestWebServiceMarksCarriedOverPrimaryPort(t *testing.T) {
	port := closedPort(t)
	tg := webTargetAt("127.0.0.1", port, "http", map[string]string{
		"http.server": "lighttpd/1.4.35",
		"http.title":  "ATEN Remote Console",
	})

	f, ok := findingOnPort(runWebService(context.Background(), tg), "web.service", port)
	if !ok {
		t.Fatalf("no web.service finding for the primary port %d", port)
	}
	if got := findingField(f, "server"); got != "lighttpd/1.4.35" {
		t.Fatalf("server = %q, want the identity the fingerprint stage recorded", got)
	}
	if got := findingField(f, "source"); got != "identify" {
		t.Errorf("source = %q, want \"identify\": nothing on this port answered at check time, "+
			"so the finding must not read as a live measurement", got)
	}
}

// The converse: when the port does answer, the finding is a live read and must not
// be labelled as carried over.
func TestWebServiceLeavesLiveReadUnlabelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write([]byte("\x00\x00\x01\x00icon-bytes"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	tg := webTargetAt(host, port, "http", map[string]string{"http.server": "lighttpd/1.4.35"})

	f, ok := findingOnPort(runWebService(context.Background(), tg), "web.service", port)
	if !ok {
		t.Fatalf("no web.service finding for the primary port %d", port)
	}
	if got := findingField(f, "source"); got != "" {
		t.Errorf("source = %q, want it absent: the port answered at check time", got)
	}
	if findingField(f, "favicon") == "" {
		t.Error("a served favicon should have been hashed")
	}
}
