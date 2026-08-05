package check

import (
	"context"
	"encoding/hex"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/moxa"
	"github.com/runZeroInc/oobscan/pkg/wire"
)

func init() {
	Register(Check{
		Name:        "udp.moxa.dsciConfig",
		Description: "Moxa DSCI config-utility protocol (UDP) pre-auth opcode dispatcher; read-opcode disclosure (heuristic framing)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},

		Enabled: false,
		Run:     runMoxaDSCI,
	})
}

func runMoxaDSCI(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	r := moxa.DSCIQuery(t.Host, t.Timeout)
	if r == nil {
		return nil
	}
	t.MarkOpen(moxa.DSCIPort, "udp", "moxa-dsci")
	return []engine.Finding{{
		Check:     "udp.moxa.dsciConfig",
		Category:  "exposure",
		Risk:      "medium",
		Port:      moxa.DSCIPort,
		Transport: "udp",
		Protocol:  "moxa-dsci",
		Fields: engine.F(
			"opcode", r.OpName,
			"framing", "heuristic",
			"mac", r.MAC,
			"ipv4", wire.Join(r.IPv4),
			"strings", wire.Join(r.Strings),
			"raw", hex.EncodeToString(r.Raw),
		),
	}}
}
