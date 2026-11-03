package check

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func xdpPromptedFinding(port int) engine.Finding {
	return engine.Finding{
		Check: "xdp.exposed", Category: "exposure", Risk: "low",
		Port: port, Transport: "tcp", Protocol: "asd",
		Fields: engine.F("authPrompted", "true"),
	}
}

func xdpUsableFinding(port int) engine.Finding {
	return engine.Finding{
		Check: "xdp.exposed", Category: "exposure", Risk: "critical",
		Port: port, Transport: "tcp", Protocol: "asd",
		Fields: engine.F("version", "1.0", "proof", "versionQuery=ok"),
	}
}

func TestDedupeXDPExposuresMergesAuthPrompted(t *testing.T) {
	// Two auth-prompted exposures on different ports collapse to one, with both
	// ports recorded.
	out := dedupeXDPExposures([]engine.Finding{xdpPromptedFinding(5123), xdpPromptedFinding(6868)})
	if len(out) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(out))
	}
	if findingField(out[0], "ports") != "5123,6868" || findingField(out[0], "portCount") != "2" {
		t.Errorf("merged ports = %q portCount = %q", findingField(out[0], "ports"), findingField(out[0], "portCount"))
	}
}

func TestDedupeXDPExposuresKeepsUsableDistinct(t *testing.T) {
	// A confirmed usable service stays distinct per port; only the prompt-only
	// exposures merge.
	out := dedupeXDPExposures([]engine.Finding{
		xdpUsableFinding(5123), xdpPromptedFinding(6868),
	})
	if len(out) != 2 {
		t.Fatalf("usable + prompted must stay 2 findings, got %d", len(out))
	}
}

func TestDedupeXDPExposuresNoop(t *testing.T) {
	if got := dedupeXDPExposures(nil); len(got) != 0 {
		t.Errorf("nil input => %d findings", len(got))
	}
	if got := dedupeXDPExposures([]engine.Finding{xdpPromptedFinding(5123)}); len(got) != 1 {
		t.Errorf("single finding must be unchanged, got %d", len(got))
	}
}
