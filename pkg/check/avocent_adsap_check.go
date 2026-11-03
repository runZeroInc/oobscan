package check

import (
	"context"
	"encoding/hex"

	"github.com/runZeroInc/oobscan/pkg/avocent"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

// Avocent DSView Access Protocol (adsap2d, TCP 3502). A reachable adsap2d
// listener is the DSView management transport; its default nonsecure mode
// accepts and logs presented credentials. This probe only fingerprints the
// listener and captures the connect banner (read-only, no credential sent).
func init() {
	Register(Check{
		Name:        "tcp.avocent.adsap",
		Description: "Avocent DSView Access Protocol (adsap2d, TCP 3502) reachable; nonsecure by default",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		// Disabled: reachability-only on 3502; fires on ACK-all/tarpit hosts that
		// accept any TCP port (correlated with the redlion 1594 false positives).
		// Re-enable after a distinctive adsap2d banner signature is pinned.
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
