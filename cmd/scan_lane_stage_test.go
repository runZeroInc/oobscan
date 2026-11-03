package cmd

import (
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/check"
)

// ipmi.postAuthEnum reads the OpenBMC bypass and setup-state evidence that the
// cross-vendor ipmi.openbmc.* checks store. Sharing the serial lane is not enough to
// order it: ForIdentity returns device-specific checks ahead of cross-vendor ones, and
// postAuthEnum is device-specific while its producers are cross-vendor, so without a
// stage rank the consumer runs first and reads nothing.
func TestIPMILaneOrdersConsumersAfterProducers(t *testing.T) {
	// ForIdentity's shape: device-specific first, cross-vendor after.
	in := []check.Check{
		{Name: "ipmi.postAuthEnum"},                     // device-specific consumer
		{Name: "ipmi.sidPredictable"},                   // session sampler, must stay last
		{Name: "ipmi.openbmc.defaultUserKeyAuthBypass"}, // cross-vendor producer
		{Name: "ipmi.defaultCreds"},                     // cross-vendor producer
	}
	got := planCheckLanes(in).ipmi

	pos := map[string]int{}
	for i, c := range got {
		pos[c.Name] = i
	}
	for _, producer := range []string{"ipmi.openbmc.defaultUserKeyAuthBypass", "ipmi.defaultCreds"} {
		if pos[producer] > pos["ipmi.postAuthEnum"] {
			t.Errorf("%s runs at %d, after its consumer ipmi.postAuthEnum at %d",
				producer, pos[producer], pos["ipmi.postAuthEnum"])
		}
	}
	if pos["ipmi.sidPredictable"] != len(got)-1 {
		t.Errorf("session sampler at %d, want last (%d): it must not hold a slot an earlier check needs",
			pos["ipmi.sidPredictable"], len(got)-1)
	}
}

// Within a stage the ForIdentity order is preserved, so an unrelated reordering
// cannot slip in.
func TestIPMILaneStageSortIsStable(t *testing.T) {
	in := []check.Check{
		{Name: "ipmi.rmcpPing"},
		{Name: "ipmi.guid"},
		{Name: "ipmi.versions"},
	}
	got := planCheckLanes(in).ipmi
	for i, want := range []string{"ipmi.rmcpPing", "ipmi.guid", "ipmi.versions"} {
		if got[i].Name != want {
			t.Fatalf("position %d = %q, want %q; same-stage checks must keep ForIdentity order", i, got[i].Name, want)
		}
	}
}

// Every consumer entry must name a real check, and must be an ipmi.* check: a
// non-IPMI name would never reach the serial lane and the entry would be inert.
func TestIPMIEvidenceConsumersAreRegisteredIPMIChecks(t *testing.T) {
	registered := map[string]struct{}{}
	for _, c := range check.All() {
		registered[c.Name] = struct{}{}
	}
	for name := range ipmiEvidenceConsumers {
		if _, ok := registered[name]; !ok {
			t.Errorf("%q is not a registered check; the stage entry is stale", name)
		}
		if !strings.HasPrefix(name, "ipmi.") {
			t.Errorf("%q is not an IPMI check, so it never reaches the serial lane", name)
		}
		if needsIPMIEvidence(name) {
			t.Errorf("%q is in both the deferred lane and the serial-lane consumer stage", name)
		}
	}
}
