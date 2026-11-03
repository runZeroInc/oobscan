package engine

import "testing"

// A host identify left unattributed can still carry a vendor-naming finding field --
// most often a shipped shared private key matched by SPKI.
func TestVendorFieldBackfillUsesTrustedSlugs(t *testing.T) {
	cases := []struct {
		name    string
		finding Finding
		want    string
	}{
		{
			name: "shipped shared private key names the vendor",
			finding: Finding{Check: "tls.sharedKey", Fields: F(
				"kind", "shared-private-key-spki",
				"subject", "*.sierrawireless.com",
				"vendors", "sierra")},
			want: "sierra",
		},
		{
			name:    "ipmi guid IANA PEN",
			finding: Finding{Check: "ipmi.guid", Fields: F("vendor", "supermicro")},
			want:    "supermicro",
		},
		{
			name:    "supermicro-only vmedia protocol",
			finding: Finding{Check: "kvm.usbAnywhere", Fields: F("vendor", "supermicro")},
			want:    "supermicro",
		},
		{
			name:    "default certificate match",
			finding: Finding{Check: "tls.defaultCert", Fields: F("vendor", "supermicro")},
			want:    "supermicro",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := vendorFieldFromFindings([]Finding{tc.finding})
			if !ok || got != tc.want {
				t.Fatalf("vendorFieldFromFindings = %q,%v; want %q,true", got, ok, tc.want)
			}
		})
	}
}

// The kvm.* probes carry a `vendor` field but must never attribute a host: decoys
// answer all of them at once, and they contradict each other on real hosts too.
func TestVendorFieldBackfillIgnoresDecoyContaminatedChecks(t *testing.T) {
	decoy := []Finding{
		{Check: "kvm.avocent.aps", Fields: F("vendor", "avocent")},
		{Check: "kvm.cisco.vkvm", Fields: F("vendor", "cisco")},
		{Check: "kvm.ami.vmedia", Fields: F("vendor", "ami")},
		{Check: "kvm.hpe.irc", Fields: F("vendor", "hpe")},
		{Check: "kvm.ami.redirect", Fields: F("vendor", "ami")},
	}
	if got, ok := vendorFieldFromFindings(decoy); ok {
		t.Fatalf("a host answering four mutually exclusive KVM probes was attributed to %q", got)
	}
}

// An ambiguous multi-vendor match is not attribution.
func TestVendorFieldBackfillRejectsAmbiguousAndEmpty(t *testing.T) {
	for _, f := range []Finding{
		{Check: "tls.sharedKey", Fields: F("vendors", "sierra,lantronix")},
		{Check: "tls.sharedKey", Fields: F("vendors", "unknown")},
		{Check: "tls.sharedKey", Fields: F("vendors", "")},
		{Check: "tls.sharedKey", Fields: F("subject", "*.sierrawireless.com")}, // wrong field
	} {
		if got, ok := vendorFieldFromFindings([]Finding{f}); ok {
			t.Errorf("%+v attributed to %q; want no attribution", f.Fields, got)
		}
	}
}

// Finalize must only fill a blank vendor, never override what identify resolved.
func TestVendorFieldBackfillNeverOverridesIdentify(t *testing.T) {
	tg := &Target{Identity: &Identity{Class: ClassBMC, Vendor: "dell", Confidence: ConfHigh}}
	tg.AddFindings(Finding{Check: "tls.sharedKey", Fields: F("vendors", "sierra")})
	if got := Finalize(tg).Vendor; got != "dell" {
		t.Fatalf("vendor = %q, want dell (identify's answer must win)", got)
	}
}

// And it must actually fire when identify left the vendor blank.
func TestVendorFieldBackfillFillsBlankVendor(t *testing.T) {
	tg := &Target{Identity: &Identity{Class: ClassUnknown, Confidence: ConfLow}}
	tg.AddFindings(Finding{Check: "tls.sharedKey", Risk: "high", Fields: F(
		"kind", "shared-private-key-spki", "vendors", "sierra")})
	f := Finalize(tg)
	if f.Vendor != "sierra" {
		t.Fatalf("vendor = %q, want sierra", f.Vendor)
	}
	// A cert-derived slug is good but not protocol-conclusive; medium, not high.
	if f.Confidence != ConfMedium {
		t.Errorf("confidence = %q, want medium", f.Confidence)
	}
	// The class is left alone: naming the maker does not imply the device class.
	if f.Class != ClassUnknown {
		t.Errorf("class = %q, want unknown (this signal implies no class)", f.Class)
	}
}
