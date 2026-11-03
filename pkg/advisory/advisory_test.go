package advisory

import (
	"strings"
	"testing"
)

// TestCatalogShape checks the Lights Out set: 33 unique CVEs, each linked to an
// advisory URL whose slug ends in that CVE, with a valid severity.
func TestCatalogShape(t *testing.T) {
	all := All()
	if len(all) != 33 {
		t.Fatalf("catalog has %d advisories, want 33", len(all))
	}
	seen := map[string]bool{}
	for _, a := range all {
		if seen[a.CVE] {
			t.Errorf("duplicate %s", a.CVE)
		}
		seen[a.CVE] = true
		if !strings.HasPrefix(a.URL, base) || !strings.HasSuffix(a.URL, strings.ToLower(a.CVE)+"/") {
			t.Errorf("%s: URL %q does not name the CVE", a.CVE, a.URL)
		}
		switch a.Severity {
		case "critical", "high", "medium", "low":
			if a.Score == "" {
				t.Errorf("%s: severity without a score", a.CVE)
			}
		case "":
			if a.Score != "" {
				t.Errorf("%s: score without a severity", a.CVE)
			}
		default:
			t.Errorf("%s: unknown severity %q", a.CVE, a.Severity)
		}
		if got, ok := Lookup(a.CVE); !ok || got != a {
			t.Errorf("Lookup(%s) = %v, %v", a.CVE, got, ok)
		}
	}
}
