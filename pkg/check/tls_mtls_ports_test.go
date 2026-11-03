package check

import (
	"slices"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// identityWebPort builds a target whose fingerprint stage settled on this HTTPS port.
func identityWebPort(host, port string) *engine.Target {
	t := &engine.Target{Host: host, Identity: &engine.Identity{Attributes: map[string]string{}}}
	if port != "" {
		t.Identity.Attributes["web.port"] = port
	}
	return t
}

// Either candidate alone loses hosts: the port identify settled on can be a listener
// that does not run mutual TLS, while a management tier on a non-default port is
// invisible to a hardcoded 443. Both must be tried, identify's port first.
func TestMTLSCandidatePortsCoverIdentifyAndDefault(t *testing.T) {
	t.Run("non-443 identify port keeps 443 as a fallback", func(t *testing.T) {
		got := mtlsCandidatePorts(identityWebPort("192.0.2.40", "8443"))
		if len(got) == 0 || got[0] != 8443 {
			t.Fatalf("candidates = %v, want identify's port 8443 first", got)
		}
		if !slices.Contains(got, 443) {
			t.Errorf("candidates = %v, want 443 retained: mTLS is not always on identify's port", got)
		}
	})

	t.Run("443 is not probed twice", func(t *testing.T) {
		got := mtlsCandidatePorts(identityWebPort("192.0.2.41", "443"))
		if len(got) != 1 || got[0] != 443 {
			t.Errorf("candidates = %v, want exactly [443]", got)
		}
	})

	t.Run("no identify port still probes 443", func(t *testing.T) {
		got := mtlsCandidatePorts(identityWebPort("192.0.2.42", ""))
		if !slices.Contains(got, 443) {
			t.Errorf("candidates = %v, want 443", got)
		}
	})
}
