package check

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func bmcTargetAt(host string, port int, scheme string) *engine.Target {
	return &engine.Target{
		Host:    host,
		Timeout: 500 * time.Millisecond,
		Identity: &engine.Identity{
			Class:      engine.ClassBMC,
			Vendor:     "supermicro",
			Confidence: engine.ConfHigh,
			Attributes: map[string]string{
				"web.port":   strconv.Itoa(port),
				"web.scheme": scheme,
			},
		},
	}
}

// closedPort returns a port with nothing listening on it.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return port
}

// A sweep in which every request failed at the transport layer must say so,
// rather than reporting an empty finding list indistinguishable from a clean host.
func TestHTTPSurfaceReportsUnreachableSweep(t *testing.T) {
	tg := bmcTargetAt("127.0.0.1", closedPort(t), "http")

	fs := runHTTPSurface(context.Background(), tg)
	if len(fs) != 1 {
		t.Fatalf("got %d finding(s), want exactly the unreachable diagnostic", len(fs))
	}
	f := fs[0]
	if f.Check != "http.surfaceUnreachable" {
		t.Fatalf("check = %q, want http.surfaceUnreachable", f.Check)
	}
	fields := map[string]string{}
	for _, kv := range f.Fields {
		fields[kv.Key] = kv.Val
	}
	// requestsFailed is reported as a failed/attempted ratio: inside this branch the
	// two can never disagree, so emitting them as separate fields was redundant.
	ratio := fields["requestsFailed"]
	failed, attempted, ok := strings.Cut(ratio, "/")
	if !ok {
		t.Fatalf("requestsFailed=%q; want a failed/attempted ratio", ratio)
	}
	if failed != attempted {
		t.Errorf("requestsFailed=%q; want the two sides equal", ratio)
	}
	if attempted == "0" || attempted == "" {
		t.Errorf("requestsFailed=%q; the diagnostic must not fire when nothing was tried", ratio)
	}
	if fields["note"] != "" {
		t.Error("the constant `note` field is back; it repeated the check name on every host")
	}
}

// The inverse: a reachable host must produce real endpoint findings and must not
// be labelled unreachable.
func TestHTTPSurfaceReachableHostIsNotFlaggedUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "lighttpd/1.4.35")
		_, _ = w.Write([]byte("serial=ABC1234567\nfirmware=01.09.16\npassword=leaked\n"))
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

	fs := runHTTPSurface(context.Background(), bmcTargetAt(host, port, "http"))
	if len(fs) == 0 {
		t.Fatal("reachable host produced no findings")
	}
	for _, f := range fs {
		if f.Check == "http.surfaceUnreachable" {
			t.Error("reachable host was flagged http.surfaceUnreachable")
		}
	}
}

// The sweep must use the scheme identify recorded, not a guess from the port
// number: an http-only web tier on an unconventional port was previously swept as
// https, failing every request.
func TestHTTPSurfaceUsesIdentifiedScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("serial=ABC1234567\npassword=leaked\n"))
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	// Same plaintext listener, but identify says https: every request must fail,
	// proving the caller's scheme is what the sweep actually uses.
	fs := runHTTPSurface(context.Background(), bmcTargetAt(host, port, "https"))
	sawUnreachable := false
	for _, f := range fs {
		if f.Check == "http.surfaceUnreachable" {
			sawUnreachable = true
		}
	}
	if !sawUnreachable {
		t.Error("https against a plaintext listener should have reported an unreachable sweep")
	}
}

// A concurrent endpoint sweep can fail every path on a slow/saturated embedded
// web tier while direct requests still work. In that case we should suppress the
// unreachable-surface claim.
func TestHTTPSurfaceSuppressesUnreachableWhenCanarySucceeds(t *testing.T) {
	shrinkHTTPSurfaceBudgets(t, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		// Wait for the client deadline instead of sleeping past it. This still
		// exercises the timeout path, but lets httptest.Server.Close return as
		// soon as the probe has cancelled every request.
		<-r.Context().Done()
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

	tg := bmcTargetAt(host, port, "http")
	tg.Timeout = 50 * time.Millisecond
	fs := runHTTPSurface(context.Background(), tg)
	for _, f := range fs {
		if f.Check == "http.surfaceUnreachable" {
			t.Fatalf("reachable host should not be flagged unreachable: %+v", fs)
		}
	}
}

// Probing only "/" is not a reachability test: on an iLO4/iDRAC it serves the heavy SPA
// and frequently stalls while the small static handlers on the same port answer
// instantly. A host whose root is unusable but whose static routes answer must not be
// called unreachable.
func TestHTTPSurfaceCanaryLooksBeyondRoot(t *testing.T) {
	shrinkHTTPSurfaceBudgets(t, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Root is the pathological one: wait until its canary request expires.
		if r.URL.Path == "/" {
			<-r.Context().Done()
			return
		}
		// A cheap static route the canary also knows about answers immediately.
		if r.URL.Path == "/redfish/v1/" {
			_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/"}`))
			return
		}
		// Everything the concurrent sweep asks for times out.
		<-r.Context().Done()
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

	tg := bmcTargetAt(host, port, "http")
	tg.Timeout = 50 * time.Millisecond
	for _, f := range runHTTPSurface(context.Background(), tg) {
		if f.Check == "http.surfaceUnreachable" {
			t.Fatal("a host answering /redfish/v1/ was flagged unreachable because / stalled")
		}
	}
}

// slowHandshakeTLSServer starts an HTTPS listener that stalls inside the TLS
// handshake for delay before serving normally.
func slowHandshakeTLSServer(t *testing.T, delay time.Duration, h http.Handler) (host string, port int) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			time.Sleep(delay)
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	hostStr, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return hostStr, p
}

// The canary must outlast a slow TLS handshake. Every phase of a scanner client is
// derived from its whole-request timeout and then clamped by a per-phase ceiling,
// so a canary budgeted like the sweep hands the handshake the same budget the sweep
// gave it and fails wherever the sweep failed - reporting the port dead with maximum
// apparent confidence on a surface that answers a moment later. Plaintext listeners
// cannot see this: there is no handshake phase to bound.
func TestHTTPSurfaceCanaryOutlastsSlowTLSHandshake(t *testing.T) {
	shrinkHTTPSurfaceBudgets(t, 10)
	// Between the sweep's handshake budget and the fingerprint stage's.
	host, port := slowHandshakeTLSServer(t, 400*time.Millisecond,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/"}`))
		}))

	tg := bmcTargetAt(host, port, "https")
	tg.Timeout = 50 * time.Millisecond
	// Narrow the sweep to one vendor's paths: every request has to burn its full
	// handshake budget here, and the endpoint count only decides how long that takes.
	tg.Identity.Vendor = "intel"

	for _, f := range runHTTPSurface(context.Background(), tg) {
		if f.Check == "http.surfaceUnreachable" {
			t.Fatalf("a host whose TLS handshake is merely slow was reported unreachable: %+v", f.Fields)
		}
	}
}

// An iLO's root page is a heavy single-page app that stalls while /xmldata on the
// same port answers at once, so the fingerprint stage comes away with no Server
// header and no title -- and the guard that only recognises those two let the
// unreachable claim be published on the same port as the /xmldata disclosures the
// iLO checks derive from that very read.
func TestHTTPSurfaceKeepsQuietWhenIdentifyReadXMLDataOnly(t *testing.T) {
	port := closedPort(t)
	tg := bmcTargetAt("127.0.0.1", port, "https")
	tg.Identity.Vendor = "hpe"
	// What collectILO leaves behind: a signal sourced from the /xmldata read, and no
	// HTML-shaped evidence at all.
	delete(tg.Identity.Attributes, "http.server")
	delete(tg.Identity.Attributes, "http.title")
	tg.Identity.Signals = []engine.Signal{{Source: "ilo", Vendor: "hpe", Detail: "iLO4"}}

	for _, f := range runHTTPSurface(context.Background(), tg) {
		if f.Check == "http.surfaceUnreachable" {
			t.Fatalf("port %d was called unreachable although /xmldata was read on it, "+
				"which is what the iLO findings on this port report: %+v", port, f.Fields)
		}
	}
}

// The fingerprint stage does not always establish a web port; when it does not, the
// sweep runs against webPort's fallback. Every other HTTP check on the target stamps
// its findings with that same fallback, so an unreachable claim about it lands on the
// same port as their successes. A read on file therefore still bears on the claim,
// and requiring the attribute to name this exact port is what let those pairs ship.
func TestIdentifyReadWebSurfaceWithNoRecordedWebPort(t *testing.T) {
	iloSignal := []engine.Signal{{Source: "ilo", Vendor: "hpe", Detail: "iLO4"}}
	cases := []struct {
		name string
		id   *engine.Identity
		port int
		want bool
	}{
		{
			name: "no web port recorded, /xmldata read on file",
			id:   &engine.Identity{Signals: iloSignal},
			port: 443,
			want: true,
		},
		{
			name: "no web port recorded, no read on file",
			id:   &engine.Identity{},
			port: 443,
			want: false,
		},
		{
			name: "read recorded against a different port",
			id: &engine.Identity{
				Signals:    iloSignal,
				Attributes: map[string]string{"web.port": "8443", "http.server": "hpe"},
			},
			port: 443,
			want: false,
		},
		{
			name: "read recorded against this port",
			id: &engine.Identity{
				Attributes: map[string]string{"web.port": "443", "http.server": "HP-iLO-Server/1.30"},
			},
			port: 443,
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tg := &engine.Target{Host: "192.0.2.10", Identity: tc.id}
			if got := identifyReadWebSurface(tg, tc.port); got != tc.want {
				t.Fatalf("identifyReadWebSurface(port %d) = %v, want %v", tc.port, got, tc.want)
			}
		})
	}
}

// The fingerprint stage reads the web surface on a budget the check battery does not
// match, so when it recorded a Server header or a title against this exact port it
// has already proved the port answers. A sweep that then failed every request is
// evidence about the sweep's bounds, not about the port, and must not be published
// as a contradiction of every other HTTP finding on it.
func TestHTTPSurfaceKeepsQuietWhenIdentifyAlreadyReadThePort(t *testing.T) {
	port := closedPort(t)
	tg := bmcTargetAt("127.0.0.1", port, "https")
	tg.Identity.Attributes["http.server"] = "lighttpd/1.4.35"

	for _, f := range runHTTPSurface(context.Background(), tg) {
		if f.Check == "http.surfaceUnreachable" {
			t.Fatalf("port %d was called unreachable although the fingerprint stage read it: %+v", port, f.Fields)
		}
	}
}

// The claim that survives must say what was measured and on what budget, so a slow
// surface can be told apart from a dead one without rerunning the scan.
func TestHTTPSurfaceUnreachableRecordsCanaryBudget(t *testing.T) {
	tg := bmcTargetAt("127.0.0.1", closedPort(t), "http")

	fs := runHTTPSurface(context.Background(), tg)
	if len(fs) != 1 || fs[0].Check != "http.surfaceUnreachable" {
		t.Fatalf("got %+v, want exactly the unreachable diagnostic", fs)
	}
	for _, key := range []string{"canaryStatus", "canaryBudget", "sweepBudget"} {
		if findingField(fs[0], key) == "" {
			t.Errorf("missing %s: the record cannot be told apart from a dead port without it", key)
		}
	}
	if got := findingField(fs[0], "canaryBudget"); got != httpSurfaceCanaryTimeout(tg).String() {
		t.Errorf("canaryBudget = %q, want the budget the canary actually used", got)
	}
}

// shrinkHTTPSurfaceBudgets scales the sweep and canary budgets down by the given
// divisor for the duration of one test, preserving their ratios so the behaviour
// under test is unchanged. Production values are restored on cleanup.
func shrinkHTTPSurfaceBudgets(t *testing.T, div time.Duration) {
	t.Helper()
	perReq, minC, maxC, budget :=
		httpSurfaceMinPerRequest, httpSurfaceMinCanary, httpSurfaceMaxCanary, httpSurfaceCanaryBudget
	t.Cleanup(func() {
		httpSurfaceMinPerRequest, httpSurfaceMinCanary, httpSurfaceMaxCanary, httpSurfaceCanaryBudget =
			perReq, minC, maxC, budget
	})
	httpSurfaceMinPerRequest /= div
	httpSurfaceMinCanary /= div
	httpSurfaceMaxCanary /= div
	httpSurfaceCanaryBudget /= div
}
