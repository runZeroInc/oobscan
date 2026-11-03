package check

import (
	"context"
	"encoding/hex"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/moxa"
	"github.com/runZeroInc/oobscan/pkg/wire"
)

// Moxa DSCI configuration-utility protocol (UDP): the UDP dispatcher runs a
// 1-byte opcode with no authentication check, so the read opcodes disclose
// device/network state pre-auth (and an ungated network-config setter exists
// on 0x79 sub-3, which this probe never touches). Framing/port are heuristic
// (see the package doc); the probe reports every field the reply carries.
func init() {
	Register(Check{
		Name:        "udp.moxa.dsciConfig",
		Description: "Moxa DSCI config-utility protocol (UDP) pre-auth opcode dispatcher; read-opcode disclosure (heuristic framing)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		// Disabled: heuristic framing (unconfirmed port/layout) means it fires on
		// any printable UDP reply, incl. SIP reflectors. Re-enable after the DSCI
		// wire framing + port are pinned from a real capture.
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
