package guid

import "testing"

// TestDecode covers every attributed family with a real/constructed GUID and
// checks the decoded fields, not just the family label. The Dell vectors guard
// the service-tag byte order, and the Supermicro board-serial case guards
// against over-attributing printable-prefix GUIDs to HPE.
func TestDecode(t *testing.T) {
	cases := []struct {
		name   string
		hex    string
		family string
		fields map[string]string // subset to assert
	}{
		{
			name: "dell-ground-truth-JSHKKXX", hex: "44454c4c53001048804bcac04f4b5858",
			family: "dell-service-tag", fields: map[string]string{"service_tag": "JSHKKXX"},
		},
		{
			name: "dell-ground-truth-4R4DZK1", hex: "44454c4c520010348044b4c04f5a4b31",
			family: "dell-service-tag", fields: map[string]string{"service_tag": "4R4DZK1"},
		},
		{
			name: "smc-board-serial", hex: "373030314d530cc47a11223300000000",
			family: "smc-board-serial", fields: map[string]string{"model_prefix": "7001MS", "mac": "0c:c4:7a:11:22:33"},
		},
		{
			name: "hpe-printable", hex: "363431303136555345333233364d4e37",
			family: "hpe-printable", fields: map[string]string{"part_id": "641016", "country": "USE", "serial": "3236MN7"},
		},
		{
			name: "uuidv1", hex: "6ba7b8109dad11d180b400c04fd430c8",
			family: "uuidv1", fields: map[string]string{"node_mac": "00:c0:4f:d4:30:c8"},
		},
		{
			name: "printable-serial-fallback", hex: "6162636465666768696a6b6c6d6e6f70",
			family: "printable-serial", fields: map[string]string{"text": "abcdefghijklmnop"},
		},
		{name: "all-zero", hex: "00000000000000000000000000000000", family: "all-zero"},
		{name: "h3c-marker", hex: "3868dd0000000000000000000000abcd", family: "marker-3868dd"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := DecodeHex(c.hex)
			if err != nil {
				t.Fatalf("DecodeHex(%q): %v", c.hex, err)
			}
			if r.Family != c.family {
				t.Errorf("family = %q, want %q", r.Family, c.family)
			}
			for k, want := range c.fields {
				if got := r.Fields[k]; got != want {
					t.Errorf("field %q = %q, want %q", k, got, want)
				}
			}
		})
	}
}

// TestDellTagNeverMisreadsStructuralByte guards the one subtlety most likely to
// regress: byte 12 (0x4f 'O') is a structural constant, not a tag character, and
// byte 10's high bit is a marker that must be stripped. If either is mishandled
// the tag comes out wrong even though the family is right.
func TestDellTagStructure(t *testing.T) {
	r, err := DecodeHex("44454c4c53001048804bcac04f4b5858")
	if err != nil {
		t.Fatal(err)
	}
	tag := r.Fields["service_tag"]
	if len(tag) != 7 {
		t.Fatalf("tag %q length = %d, want 7", tag, len(tag))
	}
	// b[10]=0xca; 0xca&0x7f = 0x4a = 'J' - the strip must happen.
	if tag[0] != 'J' {
		t.Errorf("first tag char = %q, want 'J' (b[10]&0x7f); high-bit strip missing?", tag[0])
	}
}

// TestSMCGenerationFromModelPrefix guards the Supermicro GUID board-code ->
// generation lookup (cross-checked against post-auth board SKUs on real hardware)
// and its case/space-insensitivity and unknown-code behavior.
func TestSMCGenerationFromModelPrefix(t *testing.T) {
	cases := map[string]string{
		"7001MS": "X10",
		"C001MS": "X10",
		"4101MS": "X11",
		"F401MS": "H13",
		"2401MS": "X13",
		"C301MS": "X13", // X13DAI-T, from firmware imaging
		"E401MS": "H13", // H13SSF ROT2.0, from firmware imaging
		"5601MS": "X14",
		// 9301MS ships inside the X14 images as a cross-reference but its hosts
		// present OpenSSH 8.0 (an X12/M12-era userland), so it is deliberately not
		// mapped to X14. See kb/smc/notes/smc-guid-board-codes.md.
		"9301MS": "",
		// An uncatalogued code: dropbear plus suites 0-14 places it in the X10/X11
		// era, which does not resolve to a generation, so it stays unmapped.
		"3101MS":   "",
		"f401ms":   "H13", // case-insensitive
		" 7001MS ": "X10", // trimmed
		"9Z9ZMS":   "",    // unknown code -> no signal
		"":         "",
	}
	for in, want := range cases {
		if got := SMCGenerationFromModelPrefix(in); got != want {
			t.Errorf("SMCGenerationFromModelPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}
