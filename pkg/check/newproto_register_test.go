package check

import "testing"

// TestNewProtocolChecksRegistered confirms the six new non-HTTP protocol
// probes registered under canonical IDs (registration panics on a duplicate
// or non-canonical name, so reaching All() at all also proves init succeeded).
func TestNewProtocolChecksRegistered(t *testing.T) {
	want := map[string]bool{
		"udp.advantech.adamConfig":     false,
		"tcp.redlion.udrReachable":     false,
		"udp.moxa.dsciConfig":          false,
		"tcp.avocent.adsap":            false,
		"tcp.servertech.jawsManager":   false,
		"udp.vertiv.velocityDiscovery": false,
	}
	for _, c := range All() {
		if _, ok := want[c.Name]; ok {
			want[c.Name] = true
			if c.Run == nil {
				t.Errorf("%s has nil Run", c.Name)
			}
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("check %q not registered", name)
		}
	}
}
