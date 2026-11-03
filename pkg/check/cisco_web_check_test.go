package check

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// TestCiscoWebPresenceRegistered confirms the ported cisco.cimc.web-presence
// case is registered as the native http.cisco.webPresence check, is enabled in
// the default set, and selects for a ClassBMC identity.
func TestCiscoWebPresenceRegistered(t *testing.T) {
	byName := map[string]Check{}
	for _, c := range All() {
		byName[c.Name] = c
	}

	c, ok := byName["http.cisco.webPresence"]
	if !ok {
		t.Fatal("check \"http.cisco.webPresence\" not registered")
	}
	if !c.Enabled {
		t.Error("http.cisco.webPresence should be enabled in the default set")
	}
	if c.Authenticated {
		t.Error("http.cisco.webPresence is a pre-auth read; must not be Authenticated")
	}
	if c.Destructive {
		t.Error("http.cisco.webPresence is a safe read; must not be Destructive")
	}

	selects := func(id *engine.Identity, name string) bool {
		for _, sc := range ForIdentity(id, Selector{}) {
			if sc.Name == name {
				return true
			}
		}
		return false
	}

	// Positive: selects for any BMC identity (the case is ClassBMC-scoped).
	if !selects(&engine.Identity{Class: engine.ClassBMC, Vendor: "cisco"}, "http.cisco.webPresence") {
		t.Error("http.cisco.webPresence should select for a Cisco BMC")
	}
	if !selects(&engine.Identity{Class: engine.ClassBMC, Vendor: "dell"}, "http.cisco.webPresence") {
		t.Error("http.cisco.webPresence is BMC-class scoped and should select for any BMC")
	}
}
