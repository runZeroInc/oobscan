package ilo

import (
	"slices"
	"testing"
)

type gate struct{ fixed, severity string }

func matchIDs(gen, fw string) map[string]gate {
	out := map[string]gate{}
	for _, m := range MatchCVEs(gen, fw) {
		out[m.ID] = gate{m.FixedIn, m.Severity}
	}
	return out
}

// TestLightsOutGates checks the 2026 HPE gates: iLO2/3/4 match every firmware
// with no fixed build, iLO5/6/7 match below the hpesbhf05170 fixed builds, and
// CVE-2026-65206 drops from critical to high on the iLO5/6/7 bands.
func TestLightsOutGates(t *testing.T) {
	cases := []struct {
		gen, fw string
		want    map[string]gate
		absent  []string
	}{
		{"iLO2", "2.33", map[string]gate{
			"CVE-2026-65205": {NoFix, "high"}, "CVE-2026-65206": {NoFix, "critical"},
		}, []string{"CVE-2026-65204", "CVE-2026-65207"}},
		{"iLO3", "1.94", map[string]gate{"CVE-2026-65206": {NoFix, "critical"}}, []string{"CVE-2026-65204"}},
		{"iLO4", "2.82", map[string]gate{
			"CVE-2026-65204": {NoFix, "high"}, "CVE-2026-65205": {NoFix, "high"}, "CVE-2026-65206": {NoFix, "critical"},
			"CVE-2026-65207": {NoFix, "high"}, "CVE-2026-65209": {NoFix, "high"},
		}, []string{"CVE-2026-65208"}},
		{"iLO5", "3.21", map[string]gate{
			"CVE-2026-65204": {"3.22", "high"}, "CVE-2026-65205": {"3.22", "high"}, "CVE-2026-65206": {"3.22", "high"},
			"CVE-2026-65207": {"3.22", "high"}, "CVE-2026-65208": {"3.22", "low"}, "CVE-2026-65209": {"3.22", "high"},
		}, nil},
		{"iLO5", "3.22", nil, []string{"CVE-2026-65204", "CVE-2026-65205", "CVE-2026-65206", "CVE-2026-65207", "CVE-2026-65208", "CVE-2026-65209"}},
		{"iLO6", "1.78", map[string]gate{"CVE-2026-65204": {"1.79", "high"}, "CVE-2026-65206": {"1.79", "high"}}, nil},
		{"iLO6", "1.79", nil, []string{"CVE-2026-65204", "CVE-2026-65206"}},
		{"iLO7", "1.25", map[string]gate{"CVE-2026-65206": {"1.25.01", "high"}, "CVE-2026-65208": {"1.25.01", "low"}}, []string{"CVE-2026-65204"}},
		{"iLO7", "1.25.01", nil, []string{"CVE-2026-65205", "CVE-2026-65206"}},
	}
	for _, c := range cases {
		got := matchIDs(c.gen, c.fw)
		for id, want := range c.want {
			if g, ok := got[id]; !ok || g != want {
				t.Errorf("%s %s: %s = %+v (matched %v), want %+v", c.gen, c.fw, id, g, ok, want)
			}
		}
		for id := range got {
			if slices.Contains(c.absent, id) {
				t.Errorf("%s %s: %s matched, want no match", c.gen, c.fw, id)
			}
		}
	}
}

// TestFixedBandsUnchanged guards the existing exclusive FixedIn comparison.
func TestFixedBandsUnchanged(t *testing.T) {
	if _, ok := matchIDs("iLO4", "2.52")["CVE-2017-12542"]; !ok {
		t.Error("iLO4 2.52 should match CVE-2017-12542")
	}
	if _, ok := matchIDs("iLO4", "2.53")["CVE-2017-12542"]; ok {
		t.Error("iLO4 2.53 should not match CVE-2017-12542")
	}
	if _, ok := matchIDs("iLO5", "3.01")["CVE-2023-50272"]; ok {
		t.Error("iLO5 3.01 is past the CVE-2023-50272 ceiling")
	}
}
