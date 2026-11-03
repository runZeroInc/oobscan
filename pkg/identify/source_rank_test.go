package identify

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// Every source a collector actually emits must be ranked. An unranked source
// falls back to unrankedSourcePriority, which is deliberately the worst rank --
// so forgetting to rank a new source now costs it tie-breaks instead of silently
// winning them all, which is what happened when tls-cn was introduced.
func TestAllEmittedSourcesAreRanked(t *testing.T) {
	// Sources produced by addVendor calls across the collectors, plus the
	// fold/derive paths (fingerprint, ipmi.*, http.vendors).
	emitted := []string{
		"redfish", "wsman", "snmp", "snmp.sysdescr", "lantronix.telnet", "lantronix",
		"ilo", "idrac", "guid", "tls", "tls-cn", "slp", "moxa", "mdns",
		"http", "http.title", "http.apc-nmc", "http.vendors",
		"digi.realport", "digi.addp",
		"fingerprint", "ipmi.deviceId", "ipmi.authCaps", "ipmi.cipherSuites",
	}
	for _, src := range emitted {
		if _, ok := sourcePriority[src]; !ok {
			t.Errorf("source %q is emitted by a collector but has no sourcePriority rank "+
				"(it would default to unranked=%d)", src, unrankedSourcePriority)
		}
	}
}

func TestUnrankedSourceIsLeastTrusted(t *testing.T) {
	for src, rank := range sourcePriority {
		if rank >= unrankedSourcePriority {
			t.Errorf("ranked source %q has rank %d, which is not better than unranked %d",
				src, rank, unrankedSourcePriority)
		}
	}
	if got := rankSource("some-brand-new-source"); got != unrankedSourcePriority {
		t.Errorf("rankSource(unknown) = %d, want %d", got, unrankedSourcePriority)
	}
}

// A dedicated vendor probe must beat a certificate-CN heuristic when the two
// agree on vendor and neither carries a generation. Before rankSource, the
// unranked tls-cn scored 0 and outranked every dedicated probe.
func TestDedicatedProbeBeatsCertCNHeuristic(t *testing.T) {
	for _, order := range []string{"cn-first", "probe-first"} {
		cands := []candidate{
			{"dell", "iDRAC", "", engine.ConfHigh, "tls-cn"},
			{"dell", "iDRAC", "", engine.ConfHigh, "idrac"},
		}
		if order == "probe-first" {
			cands[0], cands[1] = cands[1], cands[0]
		}
		best := pickCandidate(cands)
		if best == nil || best.source != "idrac" {
			t.Errorf("%s: picked %+v, want the idrac-sourced candidate", order, best)
		}
	}
}

// The generation tie-break still outranks source trust: a probe-derived exact
// generation must survive even against a higher-trust source without one.
func TestExactGenerationStillWins(t *testing.T) {
	best := pickCandidate([]candidate{
		{"dell", "iDRAC", "", engine.ConfHigh, "tls-cn"},
		{"dell", "iDRAC9", "9", engine.ConfHigh, "idrac"},
	})
	if best == nil || best.generation != "9" || best.product != "iDRAC9" {
		t.Fatalf("picked %+v, want the iDRAC9/generation-9 candidate", best)
	}
}
