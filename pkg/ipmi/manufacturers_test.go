package ipmi

import "testing"

// TestManufacturerNamesVerified locks the IANA PEN -> vendor map against the
// IANA registry values used by the parser.
func TestManufacturerNamesVerified(t *testing.T) {
	want := map[uint32]string{
		2:     "IBM",
		11:    "Hewlett-Packard",
		211:   "Fujitsu Limited",
		343:   "Intel Corporation",
		674:   "Dell Inc.",
		2011:  "Huawei",
		5771:  "Cisco Systems",
		7244:  "Quanta Computer",
		10876: "Super Micro Computer",
		11129: "Google",
		19046: "Lenovo Group",
		20301: "IBM eServer",
		20569: "Inventec",
		21317: "ATEN International (Supermicro OEM)",
		49622: "ASRock Rack",
	}
	for id, name := range want {
		if got := ManufacturerNameFor(id); got != name {
			t.Errorf("PEN %d = %q, want %q", id, got, name)
		}
	}

	// Guard against common BMC-vendor PEN misattributions.
	wrong := map[uint32]string{
		2011:  "Super Micro Computer",
		10876: "Inspur",
		11129: "American Megatrends (AMI)",
		20301: "Fujitsu",
		20569: "HUAWEI",
		5771:  "Aten International",
	}
	for id, bad := range wrong {
		if got := ManufacturerNameFor(id); got == bad {
			t.Errorf("PEN %d still returns the WRONG prior name %q", id, bad)
		}
	}
}
