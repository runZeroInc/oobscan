package check

import (
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func TestILORAKPNoneRegistered(t *testing.T) {
	all := All()
	var found *Check
	for i := range all {
		if all[i].Name == "ipmi.ilo.rakpNoneBypass" {
			found = &all[i]
			break
		}
	}
	if found == nil {
		t.Fatal("ipmi.ilo.rakpNoneBypass not registered")
	}
	if !found.Enabled {
		t.Error("ipmi.ilo.rakpNoneBypass should be enabled by default")
	}
	if found.Category != "auth" {
		t.Errorf("category = %q, want auth", found.Category)
	}
	if found.Destructive {
		t.Error("check must not be destructive")
	}
	if !found.Applies.matches(&engine.Identity{Vendor: "hpe"}) {
		t.Error("check should apply to vendor hpe")
	}
	if found.Applies.matches(&engine.Identity{Vendor: "dell"}) {
		t.Error("check should NOT apply to non-hpe vendors")
	}
}

func TestILOIntegrityBypassFinding(t *testing.T) {
	finding := iloIntegrityBypassFinding(623, 0x00, []byte{0x20, 0x01, 0x02, 0x30}, "2.30")
	if finding.Check != "ipmi.ilo.integrityBypass" || finding.Risk != "high" {
		t.Fatalf("finding = %+v", finding)
	}
	if len(finding.CVE) != 1 || finding.CVE[0] != "CVE-2026-65205" {
		t.Errorf("CVE = %v, want [CVE-2026-65205]", finding.CVE)
	}
	for key, want := range map[string]string{
		"negotiatedIntegrity":       "hmac-sha1-96",
		"negotiatedConfidentiality": "aes-cbc-128",
		"acceptedProtection":        "cleartext",
		"getDeviceIdCc":             "0x00",
	} {
		if got := findingField(finding, key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestILORAKPNoneBypassFindingHasProof(t *testing.T) {
	finding := iloRAKPNoneBypassFinding(
		623, "Administrator", "status=0x04", "0x04", 0x00, []byte{0x20, 0x01, 0x02, 0x30},
		"cc=0x00,data=0c4200142e", "true", "2.30",
	)
	if finding.Check != "ipmi.ilo.rakpNoneBypass" || finding.Risk != "critical" {
		t.Fatalf("finding = %+v", finding)
	}
	if len(finding.CVE) != 1 || finding.CVE[0] != "CVE-2026-65206" {
		t.Errorf("CVE = %v, want [CVE-2026-65206]", finding.CVE)
	}
	proof := findingField(finding, "proof")
	if proof == "" {
		t.Fatalf("critical finding lacks proof: %+v", finding.Fields)
	}
	for _, want := range []string{
		"controlOpenStatus=0x04",
		"typeConfusedOpen=activated",
		"getDeviceIdCc=0x00",
		"adminConfirmed=true",
	} {
		if !strings.Contains(proof, want) {
			t.Fatalf("proof %q missing %q", proof, want)
		}
	}
}
