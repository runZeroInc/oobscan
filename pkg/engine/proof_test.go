package engine

import (
	"slices"
	"testing"
)

// TestProofFieldKeysAreCanonical is the property that "raw" and "snippet"
// violated: both were listed as evidence keys, both fold onto "response", and
// the predicate compares after folding -- so neither entry could ever match and
// the contract read wider than it was.
func TestProofFieldKeysAreCanonical(t *testing.T) {
	for _, k := range ProofFieldKeys {
		if got := CanonicalFieldKey(k); got != k {
			t.Errorf("ProofFieldKeys entry %q folds to %q, so it can never match; list the canonical key instead", k, got)
		}
	}
	// The keys the drift guard in TestCanonicalFieldKeyUnification does not
	// reach. If either started folding, findings whose only evidence is under
	// that key would stop counting as proven.
	for _, k := range []string{"hash", "bodyBytes"} {
		if got := CanonicalFieldKey(k); got != k {
			t.Errorf("CanonicalFieldKey(%q) folded to %q; it is an evidence key and must stay its own", k, got)
		}
		if !slices.Contains(ProofFieldKeys, k) {
			t.Errorf("%q is no longer an evidence key", k)
		}
	}
}

// TestFindingHasProofAcceptsFoldedSpellings pins the emitter spellings that
// reach the contract by folding rather than by being listed. Dropping any of
// these folds from canonicalKeyAliases would silently strip evidence from every
// finding that spells it that way.
func TestFindingHasProofAcceptsFoldedSpellings(t *testing.T) {
	for _, spelling := range []string{"proof", "evidence", "response", "raw", "snippet", "sample", "output", "banner", "hash", "bodyBytes", "evidenceEndpoint"} {
		f := Finding{Category: "exposure", Risk: "info", Fields: Fields{{Key: spelling, Val: "deadbeef"}}}
		if !FindingHasProof(&f) {
			t.Errorf("a finding whose only evidence field is %q reads as unproven", spelling)
		}
	}
	// A field that is not evidence must not satisfy the contract, or the rule
	// stops distinguishing anything.
	for _, spelling := range []string{"vendor", "channel", "tunnel", "username"} {
		f := Finding{Category: "exposure", Risk: "info", Fields: Fields{{Key: spelling, Val: "supermicro"}}}
		if FindingHasProof(&f) {
			t.Errorf("%q is a label, not evidence, but satisfies the proof contract", spelling)
		}
	}
	// Whitespace is not evidence.
	blank := Finding{Category: "exposure", Risk: "info", Fields: Fields{{Key: "proof", Val: "  "}}}
	if FindingHasProof(&blank) {
		t.Error("a blank proof value satisfies the proof contract")
	}
}

// TestFindingNeedsProof pins which claims owe evidence.
func TestFindingNeedsProof(t *testing.T) {
	cases := []struct {
		risk, category string
		want           bool
	}{
		{"critical", "creds", true},
		{"high", "creds", true},
		{"info", "exposure", true},
		{"low", "exposure", true},
		{"medium", "creds", false},
		{"info", "identity", false},
	}
	for _, c := range cases {
		f := Finding{Risk: c.risk, Category: c.category}
		if got := FindingNeedsProof(&f); got != c.want {
			t.Errorf("risk=%s category=%s: FindingNeedsProof=%v, want %v", c.risk, c.category, got, c.want)
		}
	}
	if FindingNeedsProof(nil) || FindingHasProof(nil) {
		t.Error("a nil finding must not claim to need or carry proof")
	}
}
