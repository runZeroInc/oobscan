package httpscan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The sweep used to derive its URL scheme from the port number alone, so a plain
// HTTP web tier on a port outside {80,8080,8000,8888} was swept as HTTPS: every
// request failed the TLS handshake and the sweep returned zero endpoints. That is
// indistinguishable in the output from "swept fine, found nothing", so the loss
// was silent. An explicit scheme from the caller must override the port guess.
func TestProbeHostTargetsHonorsExplicitScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","RedfishVersion":"1.5.0"}`))
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split %s: %v", srv.URL, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %s: %v", portStr, err)
	}
	// httptest ports are ephemeral and effectively never in the http-by-default
	// set, so the port-derived guess here is https against a plaintext listener.
	if defaultScheme(port) != "https" {
		t.Skipf("ephemeral port %d already defaults to http; nothing to prove", port)
	}
	targets := []AggregatedTarget{{
		Path: "/redfish/v1/", Match: MatchExact, Tags: []string{"info", "redfish"},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Port-derived guess (https): the plaintext listener cannot answer.
	guessed, err := probeHostTargets(ctx, host, port, "", 500*time.Millisecond, targets)
	if err == nil && guessed != nil && len(guessed.HTTPFindings) > 0 {
		t.Fatalf("expected the https guess to find nothing against a plaintext listener, got %d finding(s)",
			len(guessed.HTTPFindings))
	}

	// Explicit scheme: the sweep reaches the endpoint.
	rep, err := probeHostTargets(ctx, host, port, "http", 500*time.Millisecond, targets)
	if err != nil {
		t.Fatalf("explicit http scheme: %v", err)
	}
	if rep == nil || len(rep.HTTPFindings) == 0 {
		t.Fatal("explicit http scheme found no endpoints; the caller's scheme was ignored")
	}
	if rep.Scheme != "http" {
		t.Errorf("report scheme = %q, want http", rep.Scheme)
	}
}

func TestProbeHostTargetsRejectsBogusScheme(t *testing.T) {
	// A garbage scheme must fall back to the port guess, not build "gopher://".
	rep, _ := probeHostTargets(context.Background(), "127.0.0.1", 443, "gopher", time.Millisecond, nil)
	if rep == nil {
		t.Fatal("nil report")
	}
	if rep.Scheme != "https" {
		t.Errorf("scheme = %q, want the port-derived https fallback", rep.Scheme)
	}
}
