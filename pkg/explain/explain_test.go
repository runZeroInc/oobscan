package explain

import (
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func TestSectionPreservesEvidenceLimits(t *testing.T) {
	for _, test := range []struct {
		check string
		want  []string
	}{
		{"tls.cert", []string{"impersonation", "forward secrecy", "unique device identity"}},
		{"ipmi.smc.rakpUnordered", []string{"deliberately wrong key", "failure counter", "No session was obtained"}},
		{"http.redfish.amiBypass", []string{"did not create an account", "Potential impact", "Remediation"}},
	} {
		t.Run(test.check, func(t *testing.T) {
			got := Section("192.0.2.10", nil, engine.Finding{Check: test.check, Risk: "high"})
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Errorf("section missing %q:\n%s", want, got)
				}
			}
		})
	}
}

// TestSectionLinksAdvisory checks that a finding carrying a runZero advisory
// CVE ends with that advisory's link, and that other CVEs add nothing.
func TestSectionLinksAdvisory(t *testing.T) {
	f := engine.Finding{Check: "example.unregistered", Risk: "high", CVE: []string{"CVE-2026-65219"}}
	got := Section("192.0.2.10", nil, f)
	if !strings.Contains(got, "https://www.runzero.com/advisories/smc-rakp-bypass-cve-2026-65219/") {
		t.Errorf("section missing advisory link:\n%s", got)
	}
	if !strings.Contains(got, "Supermicro ATEN RAKP Authentication Bypass (CVSS 7.4, High)") {
		t.Errorf("section missing advisory title/rating:\n%s", got)
	}

	f.CVE = []string{"CVE-2013-4786"}
	if got := Section("192.0.2.10", nil, f); strings.Contains(got, "runZero advisory") {
		t.Errorf("non-advisory CVE rendered an advisory block:\n%s", got)
	}
}
