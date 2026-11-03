package check

import (
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func TestILOGenerationFor(t *testing.T) {
	cases := []struct {
		gen, product string
		want         string
	}{
		{"iLO4", "", "iLO4"},
		{"iLO3", "", "iLO3"},
		{"iLO2", "", "iLO2"},
		{"iLO5", "", "iLO5"},
		{"", "iLO4", "iLO4"},
		{"", "HP-iLO-3/1.94", "iLO3"},
		{"", "Integrated Lights-Out 2", "iLO2"},
		{"", "", "iLO"},
	}
	for _, c := range cases {
		tgt := &engine.Target{Identity: &engine.Identity{Generation: c.gen, Product: c.product}}
		if got := iloGenerationFor(tgt, "SSH-2.0-mpSSH_0.2.1"); got != c.want {
			t.Errorf("gen=%q product=%q => %q, want %q", c.gen, c.product, got, c.want)
		}
	}
}

func TestILOSSHVulnerableFindingLabels(t *testing.T) {
	// Generation labeling: the finding names the target's actual generation.
	t4 := &engine.Target{Identity: &engine.Identity{Vendor: "hpe", Generation: "iLO4"}}
	if g := iloGenerationFor(t4, ""); g != "iLO4" {
		t.Fatalf("iLO4 gen = %q", g)
	}
	t3 := &engine.Target{Identity: &engine.Identity{Vendor: "hpe", Generation: "iLO3"}}
	if g := iloGenerationFor(t3, ""); g != "iLO3" {
		t.Fatalf("iLO3 gen = %q", g)
	}
	exp := explainILOSSHOverflow("h", engine.Finding{Fields: engine.F("product", "iLO4")})
	if !strings.Contains(exp, "iLO4") {
		t.Error("iLO4 finding must reference iLO4")
	}
}
