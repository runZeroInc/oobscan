package engine

import "testing"

func TestVersionFromFindings(t *testing.T) {
	// Post-auth mc-info firmware is the only version signal for SMC/ATEN BMCs
	// (they drop sessionless Get Device ID). It must win over a deviceId hit.
	fs := []Finding{
		{Check: "ipmi.deviceId", Fields: F("firmwareVersion", "1.11")},
		{Check: "ipmi.postAuth.mcInfo", Fields: F("firmwareVersion", "3.88")},
	}
	if got := versionFromFindings(fs); got != "3.88" {
		t.Fatalf("versionFromFindings=%q want 3.88", got)
	}
	if got := versionFromFindings([]Finding{{Check: "ipmi.deviceId", Fields: F("firmwareVersion", "2.40")}}); got != "2.40" {
		t.Fatalf("deviceId fallback=%q want 2.40", got)
	}
	if got := versionFromFindings(nil); got != "" {
		t.Fatalf("no findings => %q want empty", got)
	}

	// The reconstructed version (revision bytes plus the auxiliary revision) is
	// the form that matches a vendor advisory, so it wins over the two-component
	// value it extends.
	full := []Finding{{Check: "ipmi.postAuth.mcInfo",
		Fields: F("firmwareVersion", "1.09", "firmwareVersionFull", "01.09.16")}}
	if got := versionFromFindings(full); got != "01.09.16" {
		t.Fatalf("versionFromFindings=%q want 01.09.16", got)
	}
	// A deviceId hit carrying the full form still loses to post-auth mc-info.
	mixed := []Finding{
		{Check: "ipmi.deviceId", Fields: F("firmwareVersionFull", "01.11.02")},
		{Check: "ipmi.postAuth.mcInfo", Fields: F("firmwareVersion", "3.88")},
	}
	if got := versionFromFindings(mixed); got != "3.88" {
		t.Fatalf("post-auth precedence=%q want 3.88", got)
	}
}

func TestAMTFindingPromotesClass(t *testing.T) {
	if !hasAMTFinding([]Finding{{Check: "amt.detected"}}) {
		t.Error("amt.detected should be an AMT finding")
	}
	if !hasAMTFinding([]Finding{{Check: "amt.authBypass"}}) {
		t.Error("amt.authBypass should be an AMT finding")
	}
	if hasAMTFinding([]Finding{{Check: "ipmi.v20.rakpHash"}}) {
		t.Error("non-AMT finding must not trigger promotion")
	}
}
