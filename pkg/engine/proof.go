package engine

import (
	"slices"
	"strings"
)

var ProofFieldKeys = []string{"proof", "response", "banner", "evidenceEndpoint", "hash", "bodyBytes"}

const ProofUnavailableKey = "proofUnavailable"

func ProofUnavailable(reason string) Field {
	return Field{Key: ProofUnavailableKey, Val: reason}
}

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
