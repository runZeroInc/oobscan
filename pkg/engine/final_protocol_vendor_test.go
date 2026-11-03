package engine

import "testing"

// Every key must already be canonical, so the CanonicalCheckID lookup in
// protocolVendorFromFindings can actually match it.
func TestProtocolVendorCheckKeysAreCanonical(t *testing.T) {
	for id, m := range protocolVendorChecks {
		if got := CanonicalCheckID(id); got != id {
			t.Errorf("protocolVendorChecks key %q is not canonical (canonicalises to %q)", id, got)
		}
		if m.vendor == "" {
			t.Errorf("%q has an empty vendor", id)
		}
		if m.class == ClassUnknown {
			t.Errorf("%q maps to ClassUnknown, which defeats the class backfill", id)
		}
	}
}

func TestProtocolVendorBackfillFillsBlankVendorAndClass(t *testing.T) {
	tg := &Target{Host: "192.0.2.10", Identity: &Identity{Class: ClassUnknown, Confidence: ConfLow}}
	tg.AddFindings(Finding{Check: "udp.moxa.deviceSearch", Risk: "medium"})

	f := Finalize(tg)
	if f.Vendor != "moxa" {
		t.Errorf("vendor = %q, want moxa", f.Vendor)
	}
	if f.Class != ClassSerialConsole {
		t.Errorf("class = %q, want %q", f.Class, ClassSerialConsole)
	}
	if f.Confidence != ConfHigh {
		t.Errorf("confidence = %q, want high (a proprietary-protocol response is conclusive)", f.Confidence)
	}
}

// The backfill must never override an attribution identify already made.
func TestProtocolVendorBackfillNeverOverridesIdentify(t *testing.T) {
	tg := &Target{Host: "192.0.2.11", Identity: &Identity{
		Class: ClassBMC, Vendor: "supermicro", Confidence: ConfHigh,
	}}
	tg.AddFindings(Finding{Check: "udp.moxa.deviceSearch", Risk: "medium"})

	f := Finalize(tg)
	if f.Vendor != "supermicro" {
		t.Errorf("vendor = %q, want supermicro preserved", f.Vendor)
	}
	if f.Class != ClassBMC {
		t.Errorf("class = %q, want bmc preserved", f.Class)
	}
}

// A host with no vendor-unique protocol finding must stay unattributed.
func TestProtocolVendorBackfillIgnoresUnrelatedFindings(t *testing.T) {
	tg := &Target{Host: "192.0.2.12", Identity: &Identity{Class: ClassUnknown, Confidence: ConfLow}}
	tg.AddFindings(Finding{Check: "ipmi.rmcpPing", Risk: "info"})

	if f := Finalize(tg); f.Vendor != "" {
		t.Errorf("vendor = %q, want empty", f.Vendor)
	}
}
