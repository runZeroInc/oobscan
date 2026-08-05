package check

import (
	"context"
	"encoding/hex"
	"strconv"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/vertiv"
	"github.com/runZeroInc/oobscan/pkg/wire"
)

func init() {
	Register(Check{
		Name:        "udp.vertiv.velocityDiscovery",
		Description: "Vertiv Velocity/IntelliSlot discovery (UDP 5555-5556) LAN enumeration channel (heuristic framing)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},

		Enabled: false,
		Run:     runVertivVelocity,
	})
}

func runVertivVelocity(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	r := vertiv.Query(t.Host, t.Timeout)
	if r == nil {
		return nil
	}
	t.MarkOpen(r.Port, "udp", "vertiv-velocity")
	return []engine.Finding{{
		Check:     "udp.vertiv.velocityDiscovery",
		Category:  "exposure",
		Risk:      "info",
		Port:      r.Port,
		Transport: "udp",
		Protocol:  "vertiv-velocity",
		Fields: engine.F(
			"framing", "heuristic",
			"scope", "lan-multicast",
			"multicastGroup", vertiv.MulticastGroup,
			"port", strconv.Itoa(r.Port),
			"mac", r.MAC,
			"ipv4", wire.Join(r.IPv4),
			"strings", wire.Join(r.Strings),
			"raw", hex.EncodeToString(r.Raw),
		),
	}}
}
