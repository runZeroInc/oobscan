package ssh

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/bmcfp"
)

// TestBMCFPSSHBannerRulesMatchWireBanners is the regression guard for the
// producer/consumer mismatch that made 5 of 7 bmcfp SSHBanner rules inert: the
// collector fed the raw "SSH-2.0-..." line while every rule is anchored to the
// softwareversion field, so no ^-anchored rule could ever fire. It asserts both
// halves of the contract -- that a realistic full wire banner resolves to the
// expected vendor once passed through SoftwareVersion, and that feeding the raw
// line to an anchored rule does not work (so prefix removal is required, not
// incidental).
func TestBMCFPSSHBannerRulesMatchWireBanners(t *testing.T) {
	cases := []struct {
		wire       string
		wantVendor string
		anchored   bool // rule is ^-anchored, so the raw line must not match
	}{
		{"SSH-2.0-mpSSH_0.2.1", "hpe", true},
		{"SSH-2.0-mpSSH_0.0.1", "hpe", true},
		{"SSH-2.0-OpenSSH_7.4p1 +ILOM.1", "oracle", true},
		{"SSH-2.0-cryptlib", "apc", true},
		{"SSH-2.0-dropbear_2025.89", "openbmc", true},
		{"SSH-2.0-ServerTech_SSH", "servertech", false},
		{"SSH-2.0-CPS_SSH_ID", "cyberpower", false},
	}
	for _, c := range cases {
		got, _, ok := bmcfp.Match(bmcfp.SSHBanner, SoftwareVersion(c.wire))
		if !ok || got != c.wantVendor {
			t.Errorf("Match(SoftwareVersion(%q)) = (%q, ok=%v), want vendor %q",
				c.wire, got, ok, c.wantVendor)
		}
		if c.anchored {
			if _, _, rawOK := bmcfp.Match(bmcfp.SSHBanner, c.wire); rawOK {
				t.Errorf("Match(%q) matched the RAW line; rule is no longer "+
					"anchored, so the SoftwareVersion strip is untested", c.wire)
			}
		}
	}
}
