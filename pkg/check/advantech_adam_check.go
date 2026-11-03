package check

import (
	"context"
	"encoding/hex"

	"github.com/runZeroInc/oobscan/pkg/advantech"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/wire"
)

// Advantech ADAM/EKI configuration protocol (UDP+TCP 5058): bin/edgserver
// dispatches the 0x40xx discovery/read block before any token check. The
// returned device and network metadata is useful for identification but does
// not establish credential disclosure or a configuration-write primitive.
func init() {
	Register(Check{
		Name:        "udp.advantech.adamConfig",
		Description: "Advantech ADAM/EKI config protocol (UDP+TCP 5058) discovery metadata (MAC/model/firmware/network)",
		Category:    "discovery",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runAdvantechADAM,
	})
}

func runAdvantechADAM(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	var r *advantech.Response
	if v, ok := t.Evidenced("advantech.adam"); ok {
		if rr, ok := v.(*advantech.Response); ok && rr != nil {
			r = rr
		}
	}
	if r == nil {
		r = advantech.Query(t.Host, t.Timeout)
		if r == nil {
			return nil
		}
		t.SetEvidence("advantech.adam", r)
	}
	t.MarkOpen(advantech.ConfigPort, r.Transport, "advantech-adam")
	opcode := ""
	switch r.Opcode {
	case 0x4102:
		opcode = "0x4102-networkRead"
	case 0x4022:
		opcode = "0x4022-serialRead"
	}
	magic := ""
	if r.MagicOK {
		magic = "true"
	}
	return []engine.Finding{{
		Check:     "udp.advantech.adamConfig",
		Category:  "discovery",
		Risk:      "info",
		Port:      advantech.ConfigPort,
		Transport: r.Transport,
		Protocol:  "advantech-adam",
		Fields: engine.F(
			"opcode", opcode,
			"magicEchoed", magic,
			"mac", r.MAC,
			"model", r.Model,
			"firmware", r.Firmware,
			"ipv4", wire.Join(r.IPv4),
			"strings", wire.Join(r.Strings),
			"raw", hex.EncodeToString(r.Raw),
		),
	}}
}
