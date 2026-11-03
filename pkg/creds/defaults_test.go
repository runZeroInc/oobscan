package creds

import "testing"

// TestMarqueeVendorPairs guards the firmware-confirmed credentials the talk
// leans on. They were missing from VendorPairs, so the full-chain takeover case
// (which sprays CommonUsernames x VendorPairs/DefaultPasswords) never tried the
// tool's own headline creds. Both the pair and the username must be present, or
// the pair is unreachable by the cartesian spray.
func TestMarqueeVendorPairs(t *testing.T) {
	wantPair := map[string]string{
		"sysadmin": "superuser", // AMI MegaRAC UID-0; byte-identical across ASRock+TYAN+Fujitsu
		"user1":    "user1234",  // Dell iDRAC firmware-seeded secondary account
	}
	havePair := map[string]bool{}
	for _, vp := range VendorPairs {
		havePair[vp.User+":"+vp.Password] = true
	}
	haveUser := map[string]bool{}
	for _, u := range CommonUsernames {
		haveUser[u] = true
	}
	for u, p := range wantPair {
		if !havePair[u+":"+p] {
			t.Errorf("VendorPairs missing marquee pair %s:%s", u, p)
		}
		if !haveUser[u] {
			t.Errorf("CommonUsernames missing %q - full-chain spray can't reach %s:%s", u, u, p)
		}
	}
}
