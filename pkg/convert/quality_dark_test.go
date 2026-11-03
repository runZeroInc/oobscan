package convert

import (
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/check"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

// A producer check never emits under its own name, so it can only ever be reported as
// dark. If one starts self-emitting it must come off the producer list, or the dark
// list will hide a real regression in it.
func TestProducerChecksNeverEmitOwnName(t *testing.T) {
	registered := map[string]bool{}
	for _, c := range check.All() {
		registered[engine.CanonicalCheckID(c.Name)] = true
	}
	for id, emits := range producerChecks {
		canon := engine.CanonicalCheckID(id)
		if !registered[canon] {
			t.Errorf("producerChecks lists %q, which is not a registered check", id)
		}
		if strings.TrimSpace(emits) == "" {
			t.Errorf("producerChecks[%q] must document what it emits instead", id)
		}
	}
}

// Producers buried among the dark entries hide the genuinely silent checks, so a
// producer must not be listed as dark.
func TestDarkChecksExcludeProducers(t *testing.T) {
	registered := map[string]bool{}
	for id := range producerChecks {
		registered[id] = true
	}
	registered["ipmi.fullWalk"] = true // a real check that self-emits; must stay dark-eligible

	dark := darkChecks(registered, map[string]int{})
	for _, id := range dark {
		if _, producer := producerChecks[id]; producer {
			t.Errorf("producer check %q was reported as dark", id)
		}
	}
	found := false
	for _, id := range dark {
		if id == "ipmi.fullWalk" {
			found = true
		}
	}
	if !found {
		t.Error("a genuinely-silent self-emitting check must still be reported as dark")
	}
}

// A check registered with Enabled:false cannot fire in a default scan, so reporting
// it as dark is noise. http.wsman.postAuthEnum was force-added to the inline-ids list
// and so bypassed the enabled filter.
func TestRegisteredCheckIDsExcludesDisabledChecks(t *testing.T) {
	ids := RegisteredCheckIDs()
	byName := map[string]check.Check{}
	for _, c := range check.All() {
		byName[engine.CanonicalCheckID(c.Name)] = c
	}
	for id := range ids {
		c, ok := byName[id]
		if !ok {
			continue // an inline-emitted finding id with no registry entry; expected
		}
		if !c.Enabled {
			t.Errorf("disabled check %q is in RegisteredCheckIDs, so it will always report as dark", id)
		}
	}
}
