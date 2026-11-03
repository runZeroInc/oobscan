package ipmi

import (
	"encoding/hex"
	"testing"
)

func TestParseOpenBMCBMCRand(t *testing.T) {
	cases := []struct {
		in   string
		want string // hex of 16-byte result, "" = error
	}{
		{"00000000e89ad3010000000065000000", "00000000e89ad3010000000065000000"}, // full 16B verbatim
		{"0x01d39ae8", "00000000e89ad3010000000065000000"},                       // 4B heap ptr -> residue
		{"01d39ae8", "00000000e89ad3010000000065000000"},                         // no 0x
		{"01:d3:9a:e8", "00000000e89ad3010000000065000000"},                      // colons ok
		{"0x0066e020", "0000000020e066000000000065000000"},                       // another ptr
		{"", ""},       // empty -> error
		{"zz", ""},     // bad hex -> error
		{"001122", ""}, // 3 bytes -> error
	}
	for _, c := range cases {
		got, err := parseOpenBMCBMCRand(c.in)
		if c.want == "" {
			if err == nil {
				t.Errorf("parseOpenBMCBMCRand(%q): expected error, got %x", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseOpenBMCBMCRand(%q): unexpected error %v", c.in, err)
			continue
		}
		if h := hex.EncodeToString(got); h != c.want {
			t.Errorf("parseOpenBMCBMCRand(%q) = %s, want %s", c.in, h, c.want)
		}
	}
}

// TestOpenBMCDefaultUserKeyConstant guards the constant HMAC key used by the
// default-userKey bypass session opener.
func TestOpenBMCDefaultUserKeyConstant(t *testing.T) {
	if h := hex.EncodeToString(OpenBMCDefaultUserKey); h != "3070656e426d6300000000000000000000000000" {
		t.Errorf("OpenBMCDefaultUserKey = %s, want 0penBmc + 13 zero bytes", h)
	}
	if len(OpenBMCDefaultUserKey) != 20 {
		t.Errorf("OpenBMCDefaultUserKey len = %d, want 20", len(OpenBMCDefaultUserKey))
	}
}
