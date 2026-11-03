package cmd

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/check"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

// TestIPMILaneOrdersSamplerLast confirms the session-opening SID sampler is
// pushed to the end of the serial IPMI lane while every other check keeps its
// order, so it can never take a session slot an earlier capture/auth check needs.
func TestIPMILaneOrdersSamplerLast(t *testing.T) {
	ipmiChecks := []check.Check{
		{Name: "ipmi.sidEntropy"},
		{Name: "ipmi.v20.rakpHash"},
		{Name: "ipmi.v20.defaultCreds"},
	}
	sort.SliceStable(ipmiChecks, func(i, j int) bool {
		return !ipmiOpensSessionsLast(ipmiChecks[i].Name) && ipmiOpensSessionsLast(ipmiChecks[j].Name)
	})
	got := []string{ipmiChecks[0].Name, ipmiChecks[1].Name, ipmiChecks[2].Name}
	want := []string{"ipmi.v20.rakpHash", "ipmi.v20.defaultCreds", "ipmi.sidEntropy"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("lane order = %v, want %v", got, want)
		}
	}
}

func TestRunCheckReturnsPanicFinding(t *testing.T) {
	target := &engine.Target{Host: "192.0.2.1"}
	findings := runCheck(context.Background(), target, check.Check{
		Name:     "test.panic",
		Category: "test",
		Run: func(context.Context, *engine.Target) []engine.Finding {
			panic("boom")
		},
	})

	if len(findings) != 1 {
		t.Fatalf("runCheck returned %d findings, want 1", len(findings))
	}
	// The panic must not be filed under the check that crashed: it would count toward
	// that check's totals and read as a result.
	f := findings[0]
	if f.Check != "check.panic" {
		t.Errorf("check = %q, want check.panic; a crash must not masquerade as the finding it failed to produce", f.Check)
	}
	if f.Risk != "info" {
		t.Errorf("risk = %q, want info", f.Risk)
	}
	if got := findingFieldVal(f, "check"); got != "test.panic" {
		t.Errorf("the failing check must be recorded in a field, got %q", got)
	}
	if got := findingFieldVal(f, "panic"); got != "boom" {
		t.Errorf("panic value = %q, want boom", got)
	}
	if len(target.Findings) != 1 {
		t.Fatalf("target recorded %d findings, want 1", len(target.Findings))
	}
}

func findingFieldVal(f engine.Finding, key string) string {
	for _, kv := range f.Fields {
		if kv.Key == key {
			return kv.Val
		}
	}
	return ""
}

func TestReclassifyHoneypotByBreadthFlipsIdentityKeepsData(t *testing.T) {
	tgt := &engine.Target{
		Host:     "192.0.2.40",
		Identity: &engine.Identity{Class: engine.ClassUnknown, Confidence: engine.ConfLow},
	}
	tgt.AddFindings(
		engine.Finding{Check: "id", Category: "discovery", Risk: "info",
			Fields: engine.F("class", "unknown", "confidence", "low")},
		engine.Finding{Check: "http.gude.defaultCreds", Category: "creds", Risk: "critical", Port: 80, Transport: "tcp", Protocol: "http"},
		engine.Finding{Check: "tcp.telnetBanner", Risk: "info", Port: 23, Transport: "tcp",
			Fields: engine.F("banner", "WELCOME TO ENTRACOMP SK-ACPE")},
	)
	tgt.SetEvidence("web.login.transcript", "acquired-transcript")
	for _, p := range []int{22, 23, 80, 443, 623, 2068, 3900, 5120, 5900, 7578, 10001, 10002} {
		tgt.MarkOpen(p, "tcp", "svc")
	}

	reclassifyHoneypotByBreadth(context.Background(), tgt)

	if tgt.Identity.Class != engine.ClassHoneypot {
		t.Fatalf("identity class = %s, want honeypot", tgt.Identity.Class)
	}
	byCheck := map[string][]engine.Finding{}
	for _, f := range tgt.FindingsSnapshot() {
		byCheck[f.Check] = append(byCheck[f.Check], f)
	}
	// The id finding is refreshed (exactly one) and now carries the honeypot verdict.
	if n := len(byCheck["id"]); n != 1 {
		t.Fatalf("want exactly one (refreshed) id finding, got %d", n)
	}
	if why := findingField(byCheck["id"][0], "honeypot"); !strings.Contains(why, "open-port breadth") {
		t.Errorf("id finding honeypot reason = %q, want it to mention open-port breadth", why)
	}
	// Everything else the battery acquired is retained.
	if _, ok := byCheck["http.gude.defaultCreds"]; !ok {
		t.Error("severe finding was dropped; findings must be retained (filter by class in analysis)")
	}
	if fs, ok := byCheck["tcp.telnetBanner"]; !ok {
		t.Error("captured telnet banner finding was dropped")
	} else if v := findingField(fs[0], "banner"); v != "WELCOME TO ENTRACOMP SK-ACPE" {
		t.Errorf("telnet banner value lost: %q", v)
	}
	if _, ok := tgt.Evidenced("web.login.transcript"); !ok {
		t.Error("post-auth evidence was dropped; it must be retained")
	}
	if n := len(tgt.OpenSnapshot()); n < 12 {
		t.Errorf("open-port map = %d entries, want the full 12 retained", n)
	}

	// Below the threshold, the helper must be a no-op.
	clean := &engine.Target{
		Host:     "192.0.2.41",
		Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "supermicro", Confidence: engine.ConfHigh},
	}
	clean.AddFindings(engine.Finding{Check: "ipmi.v20.rakpHash", Risk: "critical"})
	for _, p := range []int{22, 80, 443, 623, 5900} {
		clean.MarkOpen(p, "tcp", "svc")
	}
	reclassifyHoneypotByBreadth(context.Background(), clean)
	if clean.Identity.Class != engine.ClassBMC {
		t.Fatalf("real BMC class = %s, want bmc (unchanged)", clean.Identity.Class)
	}
	if len(clean.FindingsSnapshot()) != 1 {
		t.Fatalf("real BMC findings were altered: %+v", clean.FindingsSnapshot())
	}
}

// findingField returns the value of a finding field by (canonical) key.
func findingField(f engine.Finding, key string) string {
	key = engine.CanonicalFieldKey(key)
	for _, fld := range f.Fields {
		if engine.CanonicalFieldKey(fld.Key) == key {
			return fld.Val
		}
	}
	return ""
}

func TestScanDefaultPortsIncludeCoreOOBPorts(t *testing.T) {
	def := scanCmd.Flags().Lookup("ports").DefValue
	for _, want := range []string{"16992/tcp", "16993/tcp", "10001/tcp", "10002/tcp", "10003/tcp"} {
		if !strings.Contains(def, want) {
			t.Fatalf("default scan ports missing %s: %s", want, def)
		}
	}
}
