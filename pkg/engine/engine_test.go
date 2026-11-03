package engine

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestExpandTargets(t *testing.T) {
	got, err := ExpandTargets([]string{"10.0.0.0/30", "192.168.1.5", "10.1.1.1-10.1.1.3", "10.2.2.1-2"})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	want := []string{
		"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3",
		"10.1.1.1", "10.1.1.2", "10.1.1.3",
		"10.2.2.1", "10.2.2.2",
		"192.168.1.5",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d hosts %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("host[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestExpandTargetsRejectsOversizedInput(t *testing.T) {
	for _, spec := range []string{"0.0.0.0/0", "0.0.0.0-255.255.255.255"} {
		t.Run(spec, func(t *testing.T) {
			if _, err := ExpandTargets([]string{spec}); err == nil {
				t.Fatalf("ExpandTargets(%q) succeeded, want size-limit error", spec)
			}
		})
	}
}

func TestExpandTargetsRangeEndingAtMaxIPv4(t *testing.T) {
	got, err := ExpandTargets([]string{"255.255.255.254-255.255.255.255"})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	want := []string{"255.255.255.254", "255.255.255.255"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("hosts = %v, want %v", got, want)
	}
}

func TestExpandTargetsKeepsPort(t *testing.T) {
	// A host:port target is kept verbatim so consumers can split off the port
	// (scan turns it into a web-port hint; the IPMI path discards it).
	got, err := ExpandTargets([]string{"10.0.0.5:8443"})
	if err != nil || len(got) != 1 || got[0] != "10.0.0.5:8443" {
		t.Fatalf("got %v err %v, want [10.0.0.5:8443]", got, err)
	}
}

func TestExpandTargetsKeepsIPv6Specs(t *testing.T) {
	// Zoned link-local literals (what link-local discovery produces) and IPv6
	// multicast sweep specs both pass through untouched: expansion is text-only,
	// and pkg/discover resolves the multicast ones into hosts afterwards.
	for _, spec := range []string{
		"fe80::1%en0",
		"[fe80::1%en0]:8443",
		"ff02::1%en0",
		"ff02::1",
	} {
		got, err := ExpandTargets([]string{spec})
		if err != nil || len(got) != 1 || got[0] != spec {
			t.Errorf("ExpandTargets(%q) = %v, err %v; want [%s]", spec, got, err, spec)
		}
	}
}

func TestSplitHostPortHint(t *testing.T) {
	for _, tc := range []struct {
		spec     string
		wantHost string
		wantPort int
	}{
		{"10.0.0.5:8443", "10.0.0.5", 8443},
		{"host.example:80", "host.example", 80},
		{"10.0.0.5", "10.0.0.5", 0},               // bare IPv4: no port
		{"example.com", "example.com", 0},         // bare hostname: no port
		{"[2001:db8::1]:443", "2001:db8::1", 443}, // bracketed IPv6 + port
		{"2001:db8::1", "2001:db8::1", 0},         // unbracketed IPv6: not a port
		{"10.0.0.5:0", "10.0.0.5", 0},             // invalid port -> stripped, no hint
	} {
		gotHost, gotPort := SplitHostPortHint(tc.spec)
		if gotHost != tc.wantHost || gotPort != tc.wantPort {
			t.Errorf("SplitHostPortHint(%q) = %q/%d, want %q/%d", tc.spec, gotHost, gotPort, tc.wantHost, tc.wantPort)
		}
	}
}

// TestRunPropagatesWebPort proves a host:port target reaches the per-target
// pipeline as a bare Host plus a WebPort hint, and that a bare host inherits the
// global --web-port (Config.WebPort) default.
func TestRunPropagatesWebPort(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{} // host -> WebPort
	e := New(Config{Workers: 2, Timeout: time.Second, WebPort: 9000}, &countEmitter{})
	e.Run(context.Background(), []string{"10.0.0.5:8643", "10.0.0.6"}, func(_ context.Context, tg *Target) {
		mu.Lock()
		seen[tg.Host] = tg.WebPort
		mu.Unlock()
	})
	if got, ok := seen["10.0.0.5"]; !ok || got != 8643 {
		t.Errorf("host:port target: Host=10.0.0.5 WebPort=%d (present=%v), want WebPort=8643", got, ok)
	}
	if got, ok := seen["10.0.0.6"]; !ok || got != 9000 {
		t.Errorf("bare host: Host=10.0.0.6 WebPort=%d (present=%v), want --web-port default 9000", got, ok)
	}
}

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("623/udp,443,16992/tcp,80-81")
	if err != nil {
		t.Fatal(err)
	}
	want := map[Port]bool{
		{623, ProtoUDP}: true, {443, ProtoTCP}: true,
		{16992, ProtoTCP}: true, {80, ProtoTCP}: true, {81, ProtoTCP}: true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d ports %v", len(got), got)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected port %v", p)
		}
	}
}

// countEmitter records Start/Emit calls for tests.
type countEmitter struct {
	mu       sync.Mutex
	started  int
	emitted  int
	panicked int
}

func (c *countEmitter) Start(string)            { c.mu.Lock(); c.started++; c.mu.Unlock() }
func (c *countEmitter) Activity(string, string) {}
func (c *countEmitter) Checks(string, int, int) {}
func (c *countEmitter) Emit(t *Target) {
	c.mu.Lock()
	c.emitted++
	if t.Err != "" {
		c.panicked++
	}
	c.mu.Unlock()
}
func (c *countEmitter) Log(string)                  {}
func (c *countEmitter) Status(uint64, uint64, bool) {}
func (c *countEmitter) Close() error                { return nil }

// TestPanicIsolation proves a panic in one target's RunFunc does not abort the
// scan and is recorded as an error result.
func TestPanicIsolation(t *testing.T) {
	hosts := []string{"a", "b", "c", "d", "e"}
	ce := &countEmitter{}
	e := New(Config{Workers: 3, Timeout: time.Second}, ce)
	var ran atomic.Uint64
	e.Run(context.Background(), hosts, func(ctx context.Context, tg *Target) {
		ran.Add(1)
		if tg.Host == "c" {
			panic("boom")
		}
	})
	if ce.started != len(hosts) || ce.emitted != len(hosts) {
		t.Errorf("started=%d emitted=%d, want %d each", ce.started, ce.emitted, len(hosts))
	}
	if ce.panicked != 1 {
		t.Errorf("panicked results = %d, want 1", ce.panicked)
	}
	if ran.Load() != uint64(len(hosts)) {
		t.Errorf("ran %d targets, want %d", ran.Load(), len(hosts))
	}
	if done, total := e.Stats(); done != uint64(len(hosts)) || total != uint64(len(hosts)) {
		t.Errorf("stats done=%d total=%d", done, total)
	}
}

// TestCanonicalCheckIDRenames locks legacy check ids emitted by older scan/
// convert output onto their current spelling, so re-converting an old NDJSON
// file still matches the rule that consumes it. See canonicalCheckIDAliases.
func TestCanonicalCheckIDRenames(t *testing.T) {
	if got := CanonicalCheckID("ssh.hpe.iloRdpktOverflow"); got != "ssh.hpe.iloSSHOverflow" {
		t.Errorf("CanonicalCheckID(retired) = %q, want ssh.hpe.iloSSHOverflow", got)
	}
	if got := CanonicalCheckID("ssh.hpe.iloSSHOverflow"); got != "ssh.hpe.iloSSHOverflow" {
		t.Errorf("CanonicalCheckID(current) = %q, want ssh.hpe.iloSSHOverflow (idempotent)", got)
	}
}

// TestCanonicalFieldKeyUnification locks the unified output vocabulary: every
// synonym field key folds onto one canonical key (applied to both NDJSON and the
// TTY view via CanonicalFieldKey), while semantically-distinct fields stay their
// own key. See canonicalKeyAliases.
func TestCanonicalFieldKeyUnification(t *testing.T) {
	fold := map[string]string{
		// response: raw device response/output
		"raw": "response", "output": "response", "sample": "response", "snippet": "response",
		// credential
		"user": "username", "defaultUsername": "username",
		"pass": "password", "defaultPassword": "password", "default_user": "username", "default_pass": "password",
		// provenance vs mechanism (kept distinct)
		"via": "source",
		// proof (never "evidence")
		"evidence": "proof",
		// http status
		"httpStatus": "status", "http_status": "status",
		// snake -> camel + existing aliases still hold
		"fw": "firmwareVersion", "mfr": "manufacturer", "serial": "serialNumber",
	}
	for in, want := range fold {
		if got := CanonicalFieldKey(in); got != want {
			t.Errorf("CanonicalFieldKey(%q) = %q, want %q", in, got, want)
		}
	}
	// Semantically-specific fields must not be folded away.
	for _, k := range []string{"banner", "sysdescr", "response", "proof", "source", "loginVia", "status", "username", "password", "community", "manufacturer", "vendor", "firmwareVersion", "version", "location", "evidenceEndpoint", "status1", "status2"} {
		if got := CanonicalFieldKey(k); got != k {
			t.Errorf("CanonicalFieldKey(%q) unexpectedly folded to %q", k, got)
		}
	}
	// A finding emitting synonyms renders the canonical keys in NDJSON.
	f := Fields{{Key: "raw", Val: "deadbeef"}, {Key: "via", Val: "common"}, {Key: "defaultUsername", Val: "admin"}}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	for _, want := range []string{`"response"`, `"source"`, `"username"`} {
		if !strings.Contains(js, want) {
			t.Errorf("marshaled fields %s missing %s", js, want)
		}
	}
	for _, bad := range []string{`"raw"`, `"via"`, `"defaultUsername"`} {
		if strings.Contains(js, bad) {
			t.Errorf("marshaled fields %s still contains un-canonical %s", js, bad)
		}
	}
}

// TestTargetTimeoutModes covers the three TargetTimeout states. A negative value
// means "no per-target deadline" -- opt-in long-running checks (the OpenBMC
// default-userKey heap sweep) need to run to completion, and the 4m default
// silently truncated them a few percent in.
func TestTargetTimeoutModes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cfg        time.Duration
		wantCfg    time.Duration
		wantDeadln bool
	}{
		{"unset takes the 4m default", 0, 4 * time.Minute, true},
		{"explicit value is honored", 30 * time.Second, 30 * time.Second, true},
		{"negative disables the deadline", -1 * time.Second, -1 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := New(Config{Workers: 1, Timeout: time.Second, TargetTimeout: tc.cfg}, &countEmitter{})
			if e.cfg.TargetTimeout != tc.wantCfg {
				t.Errorf("cfg.TargetTimeout=%s, want %s", e.cfg.TargetTimeout, tc.wantCfg)
			}
			var gotDeadline bool
			e.Run(context.Background(), []string{"10.0.0.5"}, func(ctx context.Context, _ *Target) {
				_, gotDeadline = ctx.Deadline()
			})
			if gotDeadline != tc.wantDeadln {
				t.Errorf("target ctx has deadline=%v, want %v", gotDeadline, tc.wantDeadln)
			}
		})
	}
}
