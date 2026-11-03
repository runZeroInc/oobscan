package discover

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLinkLocalLive runs a real sweep against a real segment. It needs a live
// interface (and a neighbor that answers), so it is opt-in:
//
//	OOBSCAN_LIVE_LINKLOCAL=en0 go test ./pkg/discover -run Live -v
//
// Set the variable to "lo0" for a self-contained check of the plumbing: the host
// answers its own multicast echo on loopback.
func TestLinkLocalLive(t *testing.T) {
	zone := os.Getenv("OOBSCAN_LIVE_LINKLOCAL")
	if zone == "" {
		t.Skip("set OOBSCAN_LIVE_LINKLOCAL=<interface> to run the live link-local sweep")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	found, err := LinkLocal(ctx, AllNodes+"%"+zone, Options{
		Log: func(s string) { t.Log(s) },
	})
	if err != nil {
		t.Fatalf("LinkLocal on %s: %v", zone, err)
	}
	if len(found) == 0 {
		t.Fatalf("no hosts answered on %s", zone)
	}
	for _, r := range found {
		t.Logf("%s via %s", r.Host(), strings.Join(r.Via, "+"))
		if r.Addr.IsLinkLocalUnicast() && r.Addr.Zone() != zone {
			t.Errorf("%s: link-local result lost its zone", r.Host())
		}
	}
}
