package ipmi

import (
	"testing"
	"time"
)

// TestOpenBMCResidueTiers pins the shared hot/cold split the scan check and the
// ipmi subcommand both draw from.
func TestOpenBMCResidueTiers(t *testing.T) {
	hot := OpenBMCHotResidues()
	cold := OpenBMCColdResidues()

	for _, want := range []string{"e IPMI LAN sessi", "/xyz/openbmc_pro", "/ipmi/session/et"} {
		found := false
		for _, h := range hot {
			if string(h) == want {
				found = true
			}
		}
		if !found {
			t.Errorf("confirmed residue %q missing from the hot tier", want)
		}
	}

	hotSet := map[string]bool{}
	for _, h := range hot {
		if len(h) != 16 {
			t.Errorf("hot residue %q is %d bytes, want 16", h, len(h))
		}
		hotSet[string(h)] = true
	}
	for _, c := range cold {
		if len(c) != 16 {
			t.Errorf("cold residue %q is %d bytes, want 16", c, len(c))
		}
		if hotSet[string(c)] {
			t.Errorf("residue %q appears in both tiers", c)
		}
	}
	if len(cold) < 20 {
		t.Errorf("cold tier has %d windows; expected the full sliding-window set", len(cold))
	}

	// The template's other windows must be covered somewhere.
	tmpl := OpenBMCLogStringTemplate
	covered := map[string]bool{}
	for _, r := range append(append([][]byte{}, hot...), cold...) {
		covered[string(r)] = true
	}
	for _, off := range []int{0, 4, 8, 16, 24} {
		if off+16 > len(tmpl) {
			continue
		}
		if w := tmpl[off : off+16]; !covered[w] {
			t.Errorf("template window at offset %d (%q) covered by neither tier", off, w)
		}
	}

	// The full set leads with the cold-boot all-zero, then the hot values.
	all := OpenBMCConstantResidues()
	if len(all) == 0 || string(all[0]) != string(make([]byte, 16)) {
		t.Errorf("constant set should lead with the all-zero residue")
	}
}

// TestGroomAbandonSetupSessionUnreachable pins the error path: a groom failure
// against an unroutable host is a benign false, never a panic.
func TestGroomAbandonSetupSessionUnreachable(t *testing.T) {
	suite := CipherAlgos{Suite: 17, Auth: RAKPHMACSHA256, Integrity: IntegrityHMACSHA256128, Conf: ConfAESCBC}
	if GroomAbandonSetupSession("192.0.2.1", 623, suite, 50*time.Millisecond, 0x60000000) {
		t.Error("groom reported success against an unroutable host")
	}
}

// TestOpenBMCBypassFastRejectsCipherZero guards the precondition: the bypass
// needs an authenticated suite to key the RAKP3 HMAC.
func TestOpenBMCBypassFastRejectsCipherZero(t *testing.T) {
	_, err := OpenSession20OpenBMCBypassFast(OpenBMCBypassFastOptions{
		Host: "192.0.2.1", Suite: CipherAlgos{Suite: 0, Auth: RAKPNone}, Timeout: 50 * time.Millisecond, Rounds: 1,
	})
	if err == nil {
		t.Fatal("expected cipher-zero to be rejected")
	}
}

// TestIsRetryableBypassErr covers the retry classifier: residue mismatch and
// transport timeout retry; a hard error aborts.
func TestIsRetryableBypassErr(t *testing.T) {
	cases := map[string]bool{
		"rakp4 status=0x0f; the supplied bmc-random likely does not match": true,
		"open-session: read udp ...: i/o timeout":                          true,
		"context deadline exceeded":                                        true,
		"host is required":                                                 false,
		"openbmc bypass requires an authenticated cipher suite":            false,
	}
	for msg, want := range cases {
		if got := isRetryableBypassErr(errString(msg)); got != want {
			t.Errorf("isRetryableBypassErr(%q) = %v, want %v", msg, got, want)
		}
	}
	if isRetryableBypassErr(nil) {
		t.Error("nil error must not be retryable")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
