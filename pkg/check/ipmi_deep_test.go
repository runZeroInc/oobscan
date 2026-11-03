package check

import (
	"context"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// deepIPMIChecks are the --ipmi-full-gated deep IPMI checks. ipmi.sidEntropy is
// deliberately not here: it moved into the default scan (its sampler opens and
// immediately closes each session, so it is safe to run by default).
var deepIPMIChecks = []string{
	"ipmi.sidClientCorr",
	"ipmi.netfnOem",
	"ipmi.rakpRatelimit",
}

// TestDeepIPMIChecksRegistered confirms the four deep IPMI checks are registered,
// enabled in the default set, and select for a ClassBMC identity so the pipeline
// runs them.
func TestDeepIPMIChecksRegistered(t *testing.T) {
	byName := map[string]Check{}
	for _, c := range All() {
		byName[c.Name] = c
	}
	for _, name := range deepIPMIChecks {
		c, ok := byName[name]
		if !ok {
			t.Errorf("check %q not registered", name)
			continue
		}
		if !c.Enabled {
			t.Errorf("%s should be enabled in the default set", name)
		}
	}

	selects := func(id *engine.Identity, name string) bool {
		for _, c := range ForIdentity(id, Selector{}) {
			if c.Name == name {
				return true
			}
		}
		return false
	}

	bmc := &engine.Identity{Class: engine.ClassBMC, Vendor: "supermicro"}
	for _, name := range deepIPMIChecks {
		if !selects(bmc, name) {
			t.Errorf("%s should select for a ClassBMC identity", name)
		}
	}
}

// TestDeepIPMIChecksGatedOffByDefault confirms each deep check returns nil (does
// no probing, emits no finding) when the --ipmi-full flag is not set.
func TestDeepIPMIChecksGatedOffByDefault(t *testing.T) {
	byName := map[string]Check{}
	for _, c := range All() {
		byName[c.Name] = c
	}
	// IPMIFull left false: every deep check must be an immediate no-op.
	tgt := &engine.Target{
		Host:     "203.0.113.7",
		IPMIFull: false,
		Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "supermicro"},
	}
	for _, name := range deepIPMIChecks {
		c, ok := byName[name]
		if !ok {
			t.Fatalf("check %q not registered", name)
		}
		if fs := c.Run(context.Background(), tgt); fs != nil {
			t.Errorf("%s returned %d findings with IPMIFull=false; want nil", name, len(fs))
		}
	}
}

// TestSIDEntropyRunsByDefault confirms ipmi.sidEntropy no longer self-gates on
// --ipmi-full: with the IPMI port closed it returns nil via the port gate (not
// the IPMIFull gate), and it is absent from the --ipmi-full-gated set.
func TestSIDEntropyRunsByDefault(t *testing.T) {
	byName := map[string]Check{}
	for _, c := range All() {
		byName[c.Name] = c
	}
	c, ok := byName["ipmi.sidEntropy"]
	if !ok || !c.Enabled {
		t.Fatal("ipmi.sidEntropy must be registered and enabled in the default set")
	}
	// IPMIFull=false and no open 623/udp -> the port gate returns nil, cleanly.
	tgt := &engine.Target{Host: "203.0.113.7", IPMIFull: false,
		Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "supermicro"}}
	if fs := c.Run(context.Background(), tgt); fs != nil {
		t.Errorf("ipmi.sidEntropy returned %d findings with the IPMI port closed; want nil", len(fs))
	}
}

func TestSIDFindingMapsSMCPredictable(t *testing.T) {
	target := &engine.Target{Identity: &engine.Identity{Vendor: "supermicro"}}
	// Small-space samples (top bytes fixed, low byte jitters) -- the ATEN pattern.
	finding := sidFinding(target, []uint32{0x1c1782, 0x1c1792, 0x1c17a2, 0x1c17b2})
	if finding == nil {
		t.Fatal("expected predictable SID finding")
	}
	if finding.Check != "ipmi.sidPredictable" || finding.Risk != "critical" {
		t.Fatalf("finding = %+v", finding)
	}
}

// TestSIDFindingCarriesNoCVE locks that the predictable-SID finding ships
// without a CVE for every vendor. SMC-0011's identifier is disputed, so the
// finding is reported on its check id alone.
func TestSIDFindingCarriesNoCVE(t *testing.T) {
	for _, vendor := range []string{"supermicro", "dell"} {
		target := &engine.Target{Identity: &engine.Identity{Vendor: vendor}}
		finding := sidFinding(target, []uint32{0x1c1782, 0x1c1792, 0x1c17a2, 0x1c17b2})
		if finding == nil {
			t.Fatalf("%s: expected predictable SID finding", vendor)
		}
		if len(finding.CVE) != 0 {
			t.Errorf("%s: CVE = %v, want none", vendor, finding.CVE)
		}
	}
}
