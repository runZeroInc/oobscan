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

func TestParseXCCNonce(t *testing.T) {
	cases := []struct {
		body string
		want string
		ok   bool
	}{
		{`{"nonce":"11111111-2222-3333-4444-555555555555"}`, "11111111-2222-3333-4444-555555555555", true},
		// The confirmed XCC shape: {"return":0,"nonce":"<uuid5>"}.
		{`{"return":0,"nonce":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}`, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", true},
		{`{"authnonce":"abc"}`, "abc", true},
		{`{"data":{"nonce":"nested"}}`, "nested", true},
		{`<html>login</html>`, "", false},
		{`{"unrelated":1}`, "", false},
		{``, "", false},
	}
	for _, c := range cases {
		got, ok := parseXCCNonce([]byte(c.body))
		if ok != c.ok {
			t.Errorf("parseXCCNonce(%q) ok=%v want %v", c.body, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("parseXCCNonce(%q)=%q want %q", c.body, got, c.want)
		}
	}
}

func TestParseXCCServerString(t *testing.T) {
	sn, fw, mtm, serial, ok := parseXCCServerString("node01:5.30 UPnP/1.1 7X99CTO1WW:J300ABCD")
	if !ok {
		t.Fatal("expected the XCC server string to parse")
	}
	if sn != "node01" || fw != "5.30" || mtm != "7X99CTO1WW" || serial != "J300ABCD" {
		t.Errorf("parsed = %q/%q/%q/%q", sn, fw, mtm, serial)
	}
	// A generic UPnP server string must not be mistaken for the XCC leak.
	if _, _, _, _, ok := parseXCCServerString("Linux/3.14 UPnP/1.0 miniupnpd/1.9"); ok {
		t.Error("generic miniupnpd server string should not parse as an XCC leak")
	}
	if _, _, _, _, ok := parseXCCServerString("no upnp marker here"); ok {
		t.Error("string without UPnP/ marker should not parse")
	}
}

func TestNonceVersion(t *testing.T) {
	if got := nonceVersion("aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee"); got != 5 {
		t.Fatalf("nonceVersion(v5)=%d want 5", got)
	}
	if got := nonceVersion("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"); got != 4 {
		t.Fatalf("nonceVersion(v4)=%d want 4", got)
	}
	if got := nonceVersion("bad"); got != 0 {
		t.Fatalf("nonceVersion(bad)=%d want 0", got)
	}
}

func lenovoTarget(t *testing.T, srvURL string) *engine.Target {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srvURL, "http://"))
	if err != nil {
		t.Fatalf("split %q: %v", srvURL, err)
	}
	return &engine.Target{
		Host:    host,
		Timeout: 2 * time.Second,
		Identity: &engine.Identity{
			Vendor:     "lenovo",
			Class:      engine.ClassBMC,
			Attributes: map[string]string{"web.port": portStr, "web.scheme": "http"},
		},
	}
}

func TestLenovoGetNonce(t *testing.T) {
	// Reachable pre-auth get_nonce -> info finding.
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/providers/get_nonce" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"nonce":"11111111-2222-3333-4444-555555555555"}`))
			return
		}
		http.Error(w, "no", http.StatusNotFound)
	}))
	defer vuln.Close()

	f := lenovoGetNonce(context.Background(), lenovoTarget(t, vuln.URL))
	if f == nil {
		t.Fatal("expected lenovo.xcc_get_nonce on a reachable pre-auth get_nonce")
	}
	if f.Check != "http.lenovo.xcc.nonce" || f.Risk != "info" {
		t.Errorf("finding = %s/%s", f.Check, f.Risk)
	}

	// Guarded (401) -> nothing asserted.
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"auth required"}`))
	}))
	defer safe.Close()
	if f := lenovoGetNonce(context.Background(), lenovoTarget(t, safe.URL)); f != nil {
		t.Errorf("expected no finding when get_nonce is guarded, got %+v", f)
	}
}

func TestRunLenovoXCCNonceReplay(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/providers/get_nonce" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"return":0,"nonce":"aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer vuln.Close()

	f := hasFinding(runLenovoXCCNonceReplay(context.Background(), lenovoTarget(t, vuln.URL)), "http.lenovo.xcc.nonceReplay")
	if f == nil {
		t.Fatal("expected nonce replay finding on deterministic v5 nonce")
	}

	var c int
	patched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/providers/get_nonce" {
			c++
			w.Header().Set("Content-Type", "application/json")
			if c%2 == 0 {
				_, _ = w.Write([]byte(`{"return":0,"nonce":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeee2"}`))
			} else {
				_, _ = w.Write([]byte(`{"return":0,"nonce":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeee1"}`))
			}
			return
		}
		http.NotFound(w, r)
	}))
	defer patched.Close()

	if got := runLenovoXCCNonceReplay(context.Background(), lenovoTarget(t, patched.URL)); len(got) != 0 {
		t.Fatalf("expected no nonce replay finding on rotating nonce, got %+v", got)
	}
}

func TestReadLimited(t *testing.T) {
	r := strings.NewReader("0123456789abcdef")
	got := readLimited(r, 10)
	if string(got) != "0123456789" {
		t.Errorf("readLimited = %q, want first 10 bytes", string(got))
	}
}

func TestParseLenovoDeviceInfo(t *testing.T) {
	body := []byte(`{"device":{"machineTypeAndModel":"7X99CTO1WW","machine_serial_number":"J300ABCD","xccBuildVersion":"5.30","systemName":"node01"}}`)
	v, ok := parseLenovoDeviceInfo(body)
	if !ok {
		t.Fatal("expected device info to parse")
	}
	if v.Model == "" || v.Serial == "" || v.Firmware == "" || v.Hostname == "" {
		t.Fatalf("unexpected parsed values: %+v", v)
	}
}

func TestRunLenovoXCCDeviceInfo(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/DeviceDescription.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"machineTypeAndModel":"7X99CTO1WW","machine_serial_number":"J300ABCD","xccBuildVersion":"5.30","systemName":"node01"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer vuln.Close()

	got := runLenovoXCCDeviceInfo(context.Background(), lenovoTarget(t, vuln.URL))
	f := hasFinding(got, "http.lenovo.xcc.deviceInfo")
	if f == nil {
		t.Fatalf("expected lenovo device info finding, got %+v", got)
	}
	if f.Risk != "info" {
		t.Errorf("risk = %s, want info", f.Risk)
	}

	patched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"auth required"}`))
	}))
	defer patched.Close()
	if got := runLenovoXCCDeviceInfo(context.Background(), lenovoTarget(t, patched.URL)); len(got) != 0 {
		t.Fatalf("expected no finding on auth-gated endpoints, got %+v", got)
	}
}

func TestRunLenovoXCCNonauthEdgeReportsRoutePresenceOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nonauth/lock_down", "/nonauth/secmode":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"return":1,"reason":"network token required"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	got := runLenovoXCCNonauthEdge(context.Background(), lenovoTarget(t, server.URL))
	finding := hasFinding(got, "http.lenovo.xcc.nonauthEdge")
	if finding == nil {
		t.Fatalf("expected route-presence finding, got %+v", got)
	}
	if finding.Risk != "info" {
		t.Errorf("risk = %s, want info", finding.Risk)
	}
	if proof := fieldVal(finding.Fields, "proof"); !strings.Contains(proof, "routes=2") || !strings.Contains(proof, "differs=true") {
		t.Errorf("route proof = %q", proof)
	}
}
