package check

import (
	"context"
	"encoding/hex"

	"github.com/runZeroInc/oobscan/pkg/avocent"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

func init() {
	Register(Check{
		Name:        "tcp.avocent.adsap",
		Description: "Avocent DSView Access Protocol (adsap2d, TCP 3502) reachable; nonsecure by default",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},

		Enabled: false,
		Run:     runAvocentADSAP,
	})
}

func runAvocentADSAP(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	r := avocent.Query(t.Host, t.Timeout)
	if r == nil {
		return nil
	}
	t.MarkOpen(avocent.ADSAPPort, "tcp", "avocent-adsap")
	fields := r.Fields()
	if len(r.Banner) > 0 {
		fields = append(fields, "raw", hex.EncodeToString(r.Banner))
	}
	return []engine.Finding{{
		Check:     "tcp.avocent.adsap",
		Category:  "exposure",
		Risk:      "low",
		Port:      avocent.ADSAPPort,
		Transport: "tcp",
		Protocol:  "avocent-adsap",
		Fields:    engine.F(fields...),
	}}
}
