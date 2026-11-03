package convert

import (
	"slices"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// The emitters in pkg/check are tested against engine.FindingNeedsProof /
// engine.FindingHasProof, because pkg/convert imports pkg/check and a check
// test cannot call the audit's own copy. This pins the two definitions to the
// same answers, so widening or narrowing one without the other fails here
// rather than silently letting a family of findings ship with no evidence.
func TestProofPredicateMatchesEngine(t *testing.T) {
	for _, c := range proofParityCases() {
		f := c.f
		if got, want := needsProofField(&f), engine.FindingNeedsProof(&f); got != want {
			t.Errorf("%s: needsProofField=%v but engine.FindingNeedsProof=%v", c.name, got, want)
		}
		if got, want := hasProofField(&f), engine.FindingHasProof(&f); got != want {
			t.Errorf("%s: hasProofField=%v but engine.FindingHasProof=%v", c.name, got, want)
		}
	}
}

type proofParityCase struct {
	name string
	f    engine.Finding
}

func proofParityCases() []proofParityCase {
	return []proofParityCase{
		{"exposure with proof", engine.Finding{Category: "exposure", Risk: "info",
			Fields: engine.F("proof", "tcpPort=623 transport=tcp tlsHandshake=no-reply")}},
		{"exposure with no evidence key", engine.Finding{Category: "exposure", Risk: "info",
			Fields: engine.F("vendor", "supermicro", "channel", "usbanywhere")}},
		{"exposure with an empty proof", engine.Finding{Category: "exposure", Risk: "info",
			Fields: engine.Fields{{Key: "proof", Val: "  "}}}},
		{"exposure carrying only a banner", engine.Finding{Category: "exposure", Risk: "info",
			Fields: engine.F("banner", "NPort login:")}},
		{"exposure carrying only a response", engine.Finding{Category: "exposure", Risk: "info",
			Fields: engine.F("response", `{"systemName":"node01"}`)}},
		{"exposure carrying only evidenceEndpoint", engine.Finding{Category: "exposure", Risk: "info",
			Fields: engine.F("evidenceEndpoint", "/redfish/v1/SessionService")}},
		{"exposure carrying only a hash", engine.Finding{Category: "exposure", Risk: "info",
			Fields: engine.F("hash", "$rakp$a1b2$c3d4")}},
		{"exposure carrying only bodyBytes", engine.Finding{Category: "exposure", Risk: "info",
			Fields: engine.F("bodyBytes", "4096")}},
		// The folded spellings are built as raw Fields, not through engine.F:
		// engine.F canonicalizes at construction, so a case written that way never
		// reaches either predicate with the spelling its name claims. A finding read
		// back off a corpus line does carry the emitter's own spelling, which is the
		// path these pin.
		{"exposure carrying only raw (folds to response)", engine.Finding{Category: "exposure", Risk: "info",
			Fields: engine.Fields{{Key: "raw", Val: "524642"}}}},
		{"exposure carrying only snippet (folds to response)", engine.Finding{Category: "exposure", Risk: "info",
			Fields: engine.Fields{{Key: "snippet", Val: "RFB 003.008"}}}},
		{"exposure carrying only sample (folds to response)", engine.Finding{Category: "exposure", Risk: "info",
			Fields: engine.Fields{{Key: "sample", Val: "RFB 003.008"}}}},
		{"exposure carrying only output (folds to response)", engine.Finding{Category: "exposure", Risk: "info",
			Fields: engine.Fields{{Key: "output", Val: "uid=0(root)"}}}},
		{"exposure carrying only evidence (folds to proof)", engine.Finding{Category: "exposure", Risk: "info",
			Fields: engine.Fields{{Key: "evidence", Val: "cc=0x00"}}}},
		{"high risk, no evidence", engine.Finding{Category: "creds", Risk: "high",
			Fields: engine.F("username", "ADMIN")}},
		{"critical risk, no evidence", engine.Finding{Category: "creds", Risk: "critical",
			Fields: engine.F("username", "ADMIN")}},
		{"low risk, non-exposure, no evidence", engine.Finding{Category: "creds", Risk: "low",
			Fields: engine.F("username", "ADMIN")}},
		{"info, non-exposure, no evidence", engine.Finding{Category: "identity", Risk: "info",
			Fields: engine.F("vendor", "dell")}},
		{"no fields at all", engine.Finding{Category: "exposure", Risk: "info"}},
		{"exposure carrying only the unavailability marker", engine.Finding{Category: "exposure", Risk: "info",
			Fields: engine.Fields{engine.ProofUnavailable("listener sent nothing before the read deadline")}}},
		{"exposure whose proof value mentions the marker", engine.Finding{Category: "exposure", Risk: "info",
			Fields: engine.F("proof", "tcpPort=623 "+engine.ProofUnavailableKey+"=nothing came back")}},
	}
}

// TestProofParityCasesCoverEveryKey keeps the table above honest. A case list
// that exercises four of the eight allowlisted spellings pins parity for four of
// them and silently leaves the rest free to diverge, which is the state this
// test was added to prevent. Every spelling in either list -- and every spelling
// that folds onto one -- must appear as its own case.
func TestProofParityCasesCoverEveryKey(t *testing.T) {
	exercised := map[string]bool{}
	for _, c := range proofParityCases() {
		for _, fd := range c.f.Fields {
			if strings.TrimSpace(fd.Val) == "" {
				continue
			}
			exercised[fd.Key] = true
		}
	}
	// Both allowlists, plus the emitter spellings that fold onto a canonical key
	// and therefore satisfy the contract without being listed anywhere.
	want := append([]string{}, proofFieldKeys...)
	want = append(want, engine.ProofFieldKeys...)
	want = append(want, "sample", "output", "evidence")
	reported := map[string]bool{}
	for _, k := range want {
		if reported[k] {
			continue
		}
		reported[k] = true
		if !exercised[k] {
			t.Errorf("no parity case carries a %q field, so the two predicates are unpinned for it", k)
		}
	}
	// The marker must be pinned as a non-evidence key in both copies, or moving a
	// disclaimer out of the proof value buys nothing.
	if !exercised[engine.ProofUnavailableKey] {
		t.Errorf("no parity case carries a %q field", engine.ProofUnavailableKey)
	}
}

// TestProofUnavailableIsNotEvidence pins the marker's exclusion in both copies
// of the contract. A finding whose only evidence-shaped field says it has no
// evidence must read as unproven.
func TestProofUnavailableIsNotEvidence(t *testing.T) {
	if slices.Contains(proofFieldKeys, engine.ProofUnavailableKey) ||
		slices.Contains(engine.ProofFieldKeys, engine.ProofUnavailableKey) {
		t.Fatalf("%q is listed as evidence; a reason why there is none is not evidence", engine.ProofUnavailableKey)
	}
	if got := engine.CanonicalFieldKey(engine.ProofUnavailableKey); got != engine.ProofUnavailableKey {
		t.Errorf("marker folds to %q, so it can land on an evidence key", got)
	}
	f := engine.Finding{Category: "exposure", Risk: "info",
		Fields: engine.Fields{engine.ProofUnavailable("aten vmedia listener is mute behind stunnel")}}
	if hasProofField(&f) || engine.FindingHasProof(&f) {
		t.Errorf("a finding carrying only the marker reads as proven: %v", f.Fields)
	}
	if !needsProofField(&f) || !engine.FindingNeedsProof(&f) {
		t.Errorf("an exposure finding stopped owing evidence: %v", f.Fields)
	}
}

// TestProofFieldKeyListsAgree fails the moment one list learns an evidence key
// the other does not, rather than waiting for a case above to happen to exercise
// it. The comparison is on the canonical folding of each list, because a folded
// spelling and its canonical key mean the same thing to both predicates.
func TestProofFieldKeyListsAgree(t *testing.T) {
	canonical := func(keys []string) []string {
		out := make([]string, 0, len(keys))
		for _, k := range keys {
			if c := engine.CanonicalFieldKey(k); !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
		slices.Sort(out)
		return out
	}
	got, want := canonical(proofFieldKeys), canonical(engine.ProofFieldKeys)
	if !slices.Equal(got, want) {
		t.Errorf("evidence key lists diverged:\n  pkg/convert: %v\n  pkg/engine:  %v", got, want)
	}
	// Every spelling either list holds must actually count, in both copies --
	// the literal entries, not only the canonical forms they fold to. Checking
	// the folded set alone leaves an entry like "raw" untested as written, which
	// is how a list can hold eight keys while five are pinned.
	spellings := append([]string{}, proofFieldKeys...)
	spellings = append(spellings, engine.ProofFieldKeys...)
	// Emitter spellings that fold onto a canonical key: they satisfy the contract
	// without appearing in either list, so they need pinning too.
	spellings = append(spellings, "raw", "snippet", "sample", "output", "evidence")
	for _, k := range spellings {
		f := engine.Finding{Category: "exposure", Risk: "info", Fields: engine.Fields{{Key: k, Val: "x"}}}
		if !hasProofField(&f) || !engine.FindingHasProof(&f) {
			t.Errorf("evidence key %q does not satisfy the contract (convert=%v engine=%v)",
				k, hasProofField(&f), engine.FindingHasProof(&f))
		}
	}
}
