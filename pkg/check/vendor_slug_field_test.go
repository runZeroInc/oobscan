package check

import "testing"

// Free-form manufacturer strings are normalized in the check that produces them, so
// engine's vendor backfill can consume a slug without importing creds.
func TestVendorSlugFieldNormalizesRealStrings(t *testing.T) {
	cases := []struct{ in, want string }{
		// ipmi.postAuth.mcInfo.manufacturer / ipmi.deviceId.manufacturer (IANA PEN names)
		{"Intel Corporation", "intel"},
		{"Super Micro Computer", "supermicro"},
		{"Lenovo Group", "lenovo"},
		// kvm.vnc.certOrg (TLS certificate organization)
		{"Dell Inc.", "dell"},
		{"American Megatrends Inc.", "ami"},
	}
	for _, tc := range cases {
		got := vendorSlugField(tc.in)
		if len(got) != 1 {
			t.Errorf("vendorSlugField(%q) produced %d fields, want 1", tc.in, len(got))
			continue
		}
		if got[0].Key != "vendor" {
			t.Errorf("vendorSlugField(%q) key = %q, want vendor", tc.in, got[0].Key)
		}
		if got[0].Val != tc.want {
			t.Errorf("vendorSlugField(%q) = %q, want %q", tc.in, got[0].Val, tc.want)
		}
	}
}

// An unrecognized or empty manufacturer must emit nothing rather than a bogus slug:
// engine treats any value it finds as attribution, and a wrong vendor is worse than a
// blank one.
func TestVendorSlugFieldEmitsNothingWhenUnknown(t *testing.T) {
	for _, in := range []string{"", "   ", "Nonexistent Widgets Ltd", "0x0000"} {
		if got := vendorSlugField(in); len(got) != 0 {
			t.Errorf("vendorSlugField(%q) = %+v, want no field", in, got)
		}
	}
}
