package engine

import "testing"

// TestSMCGenBandFromSSH guards the Supermicro SSH-banner generation band. The
// anchors are the board codes with firmware or lab ground truth; see
// kb/smc/notes/smc-guid-board-codes.md for the calibration.
func TestSMCGenBandFromSSH(t *testing.T) {
	cases := []struct {
		name, banner, want string
	}{
		// dropbear spans X10 (7001MS, C001MS) and X11 (4101MS), so it must not band.
		{"dropbear 2013 (X10)", "SSH-2.0-dropbear_2013.59", ""},
		{"dropbear 2016", "SSH-2.0-dropbear_2016.74", ""},
		{"dropbear 2019 (X10 and X11)", "SSH-2.0-dropbear_2019.78", ""},
		// OpenSSH 8.x: X12 (5201MS/F201MS are 8.5) and M12 (B201MS is 8.0).
		{"OpenSSH 8.0 (M12)", "SSH-2.0-OpenSSH_8.0", "X12+"},
		{"OpenSSH 8.5 (X12)", "SSH-2.0-OpenSSH_8.5", "X12+"},
		// OpenSSH 9.x+: X13 (C301MS 9.2), H13 (F401MS 9.3), X14 (5601MS 9.8).
		{"OpenSSH 9.2 (X13)", "SSH-2.0-OpenSSH_9.2", "X13+"},
		{"OpenSSH 9.3 (H13)", "SSH-2.0-OpenSSH_9.3", "X13+"},
		{"OpenSSH 9.8 (X14)", "SSH-2.0-OpenSSH_9.8", "X13+"},
		{"OpenSSH 10.0 (newer than any held image)", "SSH-2.0-OpenSSH_10.0", "X13+"},
		{"unrecognised", "SSH-2.0-Go", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := []Finding{{Check: "ssh.version", Fields: []Field{{Key: "banner", Val: c.banner}}}}
			if got := smcGenBandFromSSH(f); got != c.want {
				t.Errorf("smcGenBandFromSSH(%q) = %q, want %q", c.banner, got, c.want)
			}
		})
	}
}

// TestSMCGenRankOrdering pins the band ordering the upgrade-only refinement
// depends on: an exact generation must outrank every band, and the bands must be
// ordered oldest-floor to newest-floor.
func TestSMCGenRankOrdering(t *testing.T) {
	order := []string{"", "X10", "X10+", "X11+", "X12+", "X13+", "H13"}
	for i := 1; i < len(order); i++ {
		if smcGenRank(order[i]) <= smcGenRank(order[i-1]) {
			t.Fatalf("smcGenRank(%q)=%d must exceed smcGenRank(%q)=%d",
				order[i], smcGenRank(order[i]), order[i-1], smcGenRank(order[i-1]))
		}
	}
	// An exact generation must never be downgraded to a band.
	for _, exact := range []string{"X11", "X12", "X13", "X14", "H13", "M12"} {
		for _, band := range []string{"X10+", "X11+", "X12+", "X13+"} {
			if smcGenRank(exact) <= smcGenRank(band) {
				t.Errorf("exact %q (%d) must outrank band %q (%d)",
					exact, smcGenRank(exact), band, smcGenRank(band))
			}
		}
	}
}
