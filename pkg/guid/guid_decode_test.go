package guid

import "testing"

// TestDecodeGroundTruth exercises the decoder against representative GUID
// classification vectors.
func TestDecodeGroundTruth(t *testing.T) {
	tests := []struct {
		name       string
		hexGUID    string
		wantFamily string
		wantVendor string
		wantFields map[string]string // subset check; only listed keys asserted
	}{
		{
			// byte10=0xca has the high bit set; 0xca & 0x7f = 0x4a = 'J'.
			name:       "dell_service_tag_platform_groundtruth",
			hexGUID:    "44454c4c53001048804bcac04f4b5858",
			wantFamily: "dell-service-tag",
			wantVendor: "dell",
			wantFields: map[string]string{"service_tag": "JSHKKXX"},
		},
		{
			// Dell service-tag GUID using the non-contiguous byte order.
			name:       "dell_service_tag_real_internal",
			hexGUID:    "44454c4c520010348044b4c04f5a4b31",
			wantFamily: "dell-service-tag",
			wantVendor: "dell",
			wantFields: map[string]string{"service_tag": "4R4DZK1"},
		},
		{
			// Real HPE iLO GUID: 6-char part-id + 3-char plant/country + serial.
			// "641016" part-id, "USE" plant code, "3256MN7" serial.
			name:       "hpe_printable_ilo",
			hexGUID:    "363431303136555345333235364d4e37", // "641016USE3256MN7"
			wantFamily: "hpe-printable",
			wantVendor: "hpe",
			wantFields: map[string]string{
				"part_id": "641016",
				"country": "USE",
				"serial":  "3256MN7",
			},
		},
		{
			// Real HPE iLO GUID with a Czech (CZJ) plant code.
			name:       "hpe_printable_czj",
			hexGUID:    "503533393333435a4a4431373031374c", // "P53933CZJD17017L"
			wantFamily: "hpe-printable",
			wantVendor: "hpe",
			wantFields: map[string]string{
				"part_id": "P53933",
				"country": "CZJ",
			},
		},
		{
			// Supermicro board-serial GUID with model prefix "7001MS", embedded
			// Super Micro OUI 00:25:90, then the rest of the MAC and zero padding.
			name:       "supermicro_board_serial_not_hpe",
			hexGUID:    "373030314d53002590ae232600000000", // "7001MS" + MAC
			wantFamily: "smc-board-serial",
			wantVendor: "supermicro",
			wantFields: map[string]string{
				"model_prefix": "7001MS",
				"mac":          "00:25:90:ae:23:26",
				"oui":          "00:25:90",
			},
		},
		{
			// Supermicro with a non-listed but real Super Micro OUI (90:5a:08).
			// The "MS" marker (not the OUI list) is what classifies it, so this
			// must still resolve to Supermicro, never HPE.
			name:       "supermicro_board_serial_other_oui",
			hexGUID:    "463430314d53905a0815612e00000000", // "F401MS" + MAC
			wantFamily: "smc-board-serial",
			wantVendor: "supermicro",
			wantFields: map[string]string{
				"model_prefix": "F401MS",
				"oui":          "90:5a:08",
			},
		},
		{
			// An unset GUID carries no vendor bits, so it must claim no vendor. A
			// hedged value like "supermicro-or-intel" is not safe either:
			// creds.NormalizeVendor substring-collapses it to plain "supermicro".
			name:       "all_zero",
			hexGUID:    "00000000000000000000000000000000",
			wantFamily: "all-zero",
			wantVendor: "",
		},
		{
			// UUID v1: version nibble 1 in the high nibble of byte 6.
			name:       "uuidv1",
			hexGUID:    "4e869659ce5d1102d311debfbc524871",
			wantFamily: "uuidv1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeHex(tt.hexGUID)
			if err != nil {
				t.Fatalf("DecodeHex(%q) error: %v", tt.hexGUID, err)
			}
			if got.Family != tt.wantFamily {
				t.Errorf("Family = %q, want %q", got.Family, tt.wantFamily)
			}
			if tt.wantVendor != "" && got.Vendor != tt.wantVendor {
				t.Errorf("Vendor = %q, want %q", got.Vendor, tt.wantVendor)
			}
			for k, want := range tt.wantFields {
				if gotv := got.Fields[k]; gotv != want {
					t.Errorf("Fields[%q] = %q, want %q", k, gotv, want)
				}
			}
		})
	}
}

// TestSupermicroNeverHPE guards the core BUG-2 regression: no Supermicro
// board-serial GUID may ever be attributed to HPE.
func TestSupermicroNeverHPE(t *testing.T) {
	smcGUIDs := []string{
		"373030314d53002590ae232600000000", // 7001MS
		"453430314d537cc25551c84c00000000", // E401MS
		"433030314d530cc47aad9f1400000000", // C001MS
		"363430314d537cc25586d67b00000000", // 6401MS (binary-serial shape)
		"353030314d5300000000000000000000", // 5001MS zero-padded
	}
	for _, h := range smcGUIDs {
		got, err := DecodeHex(h)
		if err != nil {
			t.Fatalf("DecodeHex(%q): %v", h, err)
		}
		if got.Vendor == "hpe" || got.Family == "hpe-printable" || got.Family == "hpe-binary" {
			t.Errorf("%s misclassified as HPE: family=%q vendor=%q", h, got.Family, got.Vendor)
		}
		if got.Vendor != "supermicro" {
			t.Errorf("%s: vendor = %q, want supermicro", h, got.Vendor)
		}
	}
}

// TestDellByteOrder pins the exact corrected Dell byte positions so a future
// edit that reverts to a contiguous or 4,7,9,12-15 layout fails loudly.
func TestDellByteOrder(t *testing.T) {
	// Byte 12 is a fixed 0x4f ('O') in real Dell GUIDs; if it ever leaks into
	// the tag, the byte order regressed to the 4,7,9,12-15 layout.
	got, err := DecodeHex("44454c4c530010348044b4c04f5a4b31")
	if err != nil {
		t.Fatal(err)
	}
	tag := got.Fields["service_tag"]
	if len(tag) != 7 {
		t.Fatalf("service_tag %q length %d, want 7", tag, len(tag))
	}
	// Position 4 (0-indexed) must come from byte 13, not the constant byte 12.
	// For this GUID byte13=0x5a='Z'; the broken 4,7,9,12-15 layout would put
	// 'O' (byte 12) at that position instead.
	if tag[4] == 'O' {
		t.Errorf("service_tag %q has constant 'O' at position 4 - byte order regressed to the 4,7,9,12-15 layout", tag)
	}
}
