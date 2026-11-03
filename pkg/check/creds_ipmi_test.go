package check

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func TestIPMICredsSkipsUnresponsiveTarget(t *testing.T) {
	target := &engine.Target{Host: "192.0.2.10"}
	if findings := runIPMICreds(t.Context(), target); len(findings) != 0 {
		t.Fatalf("runIPMICreds() returned %d findings without an IPMI response", len(findings))
	}
}
