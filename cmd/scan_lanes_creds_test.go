package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/check"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

// postCheckSource reads the post-check phase's source. The functions it runs are
// unexported, so naming one is the only way to assert that the later coverage a
// deferral decision rests on still exists. Go runs a test with its package directory
// as the working directory, so the relative path is stable.
func postCheckSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "pkg", "check", "post_checks.go"))
	if err != nil {
		t.Fatalf("read post-check source: %v", err)
	}
	return string(b)
}

// checkByName returns a registered check, failing the test when it has been renamed.
func checkByName(t *testing.T, name string) check.Check {
	t.Helper()
	for _, c := range check.All() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("%q is not a registered check", name)
	return check.Check{}
}

// A check reaching a BMC's web surface with credentials recovered from IPMI has to
// observe ipmi.auth after the serial lane writes it, so it belongs in the deferred
// lane. These are the ones with no later coverage.
func TestCredentialReusingChecksAreDeferred(t *testing.T) {
	for _, name := range []string{
		"http.redfish.postAuthEnum",
		"http.megarac.webDefaultCreds",
		"http.cim.defaultCreds",
	} {
		if !needsIPMIEvidence(name) {
			t.Errorf("%q reuses IPMI-recovered credentials but is not deferred, so it reads ipmi.auth unordered", name)
		}
	}
}

// Deferring costs wall-clock, so each exclusion needs a reason that still holds. These
// assert the reason rather than the absence, so a change to any of them fails here
// instead of silently making the exclusion wrong.
func TestUndeferredCredentialReadersHaveAReason(t *testing.T) {
	// http.web.defaultCreds is scoped to the classes a BMC is not, so a credential
	// recovered over IPMI can never reach it.
	web := checkByName(t, "http.web.defaultCreds")
	if web.Applies.CrossVendor {
		t.Error("http.web.defaultCreds became cross-vendor, so it can now reach a BMC and needs deferring")
	}
	for _, cls := range web.Applies.Classes {
		if cls == engine.ClassBMC {
			t.Error("http.web.defaultCreds now applies to BMCs, so it can see recovered credentials and needs deferring")
		}
	}

	// http.wsman.postAuthEnum cannot fire in a default scan, so deferring it would be
	// inert.
	if wsman := checkByName(t, "http.wsman.postAuthEnum"); wsman.Enabled {
		t.Error("http.wsman.postAuthEnum is enabled now, so its unordered read of ipmi.auth matters")
	}

	// http.smc.webDefaultCreds is retried with recovered credentials by the post-check
	// phase, which runs after every lane. Deferring it as well would put duplicate work
	// on the critical path.
	if !strings.Contains(postCheckSource(t), "runSMCWebWithRecoveredIPMICreds") {
		t.Error("the SMC web post-check is gone, so http.smc.webDefaultCreds no longer has later coverage")
	}
}

// Deferred and serial-lane-consumer are mutually exclusive: the first moves a check out
// of the IPMI lane, the second orders it inside it.
func TestDeferredAndSerialConsumerAreDisjoint(t *testing.T) {
	for name := range ipmiEvidenceDependents {
		if _, ok := ipmiEvidenceConsumers[name]; ok {
			t.Errorf("%q is listed as both deferred and a serial-lane consumer", name)
		}
	}
}

// Every deferred check must be a real, enabled, non-IPMI check: an IPMI name would be
// pulled out of the serial lane it needs, and a disabled one would never run.
func TestDeferredChecksAreEnabledNonIPMI(t *testing.T) {
	for name := range ipmiEvidenceDependents {
		c := checkByName(t, name)
		if strings.HasPrefix(name, "ipmi.") {
			t.Errorf("%q is an IPMI check and must stay in the serial lane", name)
		}
		if !c.Enabled {
			t.Errorf("%q is disabled, so deferring it is inert", name)
		}
	}
}

// The deferred lane has to actually receive them, and the concurrent lane must not.
func TestPlanCheckLanesRoutesDeferredChecks(t *testing.T) {
	in := []check.Check{
		{Name: "http.megarac.webDefaultCreds"},
		{Name: "http.cim.defaultCreds"},
		{Name: "http.redfish.postAuthEnum"},
		{Name: "web.service"},
		{Name: "ipmi.defaultCreds"},
	}
	p := planCheckLanes(in)

	deferred := map[string]bool{}
	for _, c := range p.afterIPMI {
		deferred[c.Name] = true
	}
	for _, want := range []string{"http.megarac.webDefaultCreds", "http.cim.defaultCreds", "http.redfish.postAuthEnum"} {
		if !deferred[want] {
			t.Errorf("%q did not land in the deferred lane", want)
		}
	}
	for _, c := range p.concurrent {
		if needsIPMIEvidence(c.Name) {
			t.Errorf("%q is deferred but was routed to the concurrent lane", c.Name)
		}
	}
	if len(p.ipmi) != 1 || p.ipmi[0].Name != "ipmi.defaultCreds" {
		t.Errorf("serial lane = %+v, want just ipmi.defaultCreds", p.ipmi)
	}
	if len(p.concurrent) != 1 || p.concurrent[0].Name != "web.service" {
		t.Errorf("concurrent lane = %+v, want just web.service", p.concurrent)
	}
}
