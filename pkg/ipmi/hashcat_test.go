package ipmi

import (
	"testing"
)

// mustHex(string) []byte is the shared helper defined in smcbackup.go.

// Regression guard for the hashcat -m 7300 exporter (RAKPResult.Hashcat).
// The salt is SIDc(LE) | SIDm(LE) | Rc | Rm | GUID | role(0x14) | ulen | username,
// hex-encoded, then ":" and the 40-hex HMAC. That exact line is valid -m 7300 input.
func TestRAKPHashcatLine7300(t *testing.T) {
	r := &RAKPResult{
		Username:   "ADMIN",
		AuthAlgo:   RAKPHMACSHA1,
		ClientSID:  0xEE53CD5B,
		BMCSID:     0x002ADC5F,
		ClientRand: mustHex("38774aeb436766d6721eebca8d8573e3"),
		BMCRand:    mustHex("ec7c8e96d3f4277bdf6f704cf4538041"),
		BMCGUID:    mustHex("00000000000000000000000000000000"),
		RAKPHash:   mustHex("0b4d461fe9fb1ce1139140176add5eacaa39c9d3"),
	}
	want := "5bcd53ee5fdc2a0038774aeb436766d6721eebca8d8573e3ec7c8e96d3f4277bdf6f704cf453804100000000000000000000000000000000140541444d494e:0b4d461fe9fb1ce1139140176add5eacaa39c9d3"
	if got := r.Hashcat(); got != want {
		t.Fatalf("Hashcat() -m 7300 mismatch:\n got=%s\nwant=%s", got, want)
	}
	// A short GUID must be zero-padded to 16 bytes (still a valid 7300 line).
	short := *r
	short.BMCGUID = nil
	if got := short.Hashcat(); got != want {
		t.Errorf("Hashcat() with nil GUID should zero-pad to match; got=%s", got)
	}
	// Non-SHA1 algo or truncated hash -> empty (suppress uncrackable candidate).
	bad := *r
	bad.RAKPHash = mustHex("00")
	if got := bad.Hashcat(); got != "" {
		t.Errorf("Hashcat() should be empty for a non-20-byte hash, got %q", got)
	}
	bad2 := *r
	bad2.AuthAlgo = RAKPHMACMD5
	if got := bad2.Hashcat(); got != "" {
		t.Errorf("Hashcat() should be empty for non-SHA1 algo, got %q", got)
	}
}
