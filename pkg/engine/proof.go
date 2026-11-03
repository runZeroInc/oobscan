package engine

import (
	"slices"
	"strings"
)

// The evidence contract for a finding. It lives in engine because that is the
// only package both the emitters (pkg/check) and the corpus audit (pkg/convert)
// import: pkg/convert imports pkg/check, so an emitter test cannot reach the
// audit's side. Holding the contract here keeps one definition for both instead
// of copies that drift.
//
// The emitters consume it directly, through ProofUnavailable. The audit still
// carries its own copy of the two predicates; the parity test in pkg/convert
// pins the two to the same answers until that copy delegates here.

// ProofFieldKeys are the canonical field keys that count as device-reported
// evidence. Keys are compared after CanonicalFieldKey folding, so the emitter
// spellings that fold into these (raw/snippet/sample/output -> response,
// evidence -> proof) satisfy the contract too.
//
// Every entry must be canonical, or it can never match: a folded spelling
// listed here is dead weight that makes the contract read wider than it is.
// "raw" and "snippet" were listed and both fold onto "response"; do not add
// them back.
var ProofFieldKeys = []string{"proof", "response", "banner", "evidenceEndpoint", "hash", "bodyBytes"}

// ProofUnavailableKey is the sibling field a check sets when it owes evidence
// and the probe obtained nothing the device produced. It is deliberately absent
// from ProofFieldKeys: a reason is not evidence. Written as a key inside the
// proof value instead, it makes the proof non-empty, so the contract reads as
// satisfied by the very statement that it is not -- which is the one case the
// contract exists to surface. The spelling lives next to the key list so the
// exclusion and the marker cannot drift apart.
const ProofUnavailableKey = "proofUnavailable"

// ProofUnavailable builds the marker field. The reason is short on purpose: it
// is a fixed per-check label, and the corpus audit holds any never-varying
// value of prose length to the constant-evidence rule.
func ProofUnavailable(reason string) Field {
	return Field{Key: ProofUnavailableKey, Val: reason}
}

// FindingNeedsProof reports whether a finding makes a claim that has to be
// backed by device-reported evidence: a critical/high risk, or an exposure
// claim of any risk (the disclosed content is the whole claim).
func FindingNeedsProof(f *Finding) bool {
	if f == nil {
		return false
	}
	switch f.Risk {
	case "critical", "high":
		return true
	}
	return f.Category == "exposure"
}

// FindingHasProof reports whether a finding carries a non-empty evidence field.
func FindingHasProof(f *Finding) bool {
	if f == nil {
		return false
	}
	for _, fd := range f.Fields {
		if strings.TrimSpace(fd.Val) == "" {
			continue
		}
		if slices.Contains(ProofFieldKeys, CanonicalFieldKey(fd.Key)) {
			return true
		}
	}
	return false
}
