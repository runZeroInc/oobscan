package check

import (
	"context"
	"encoding/hex"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/servertech"
)

func init() {
	Register(Check{
		Name:        "tcp.servertech.jawsManager",
		Description: "Server Technology Sentry JAWS manager XML handshake (pre-auth-reachable parser)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},

		Enabled: false,
		Run:     runServerTechJAWS,
	})
}

func runServerTechJAWS(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	r := servertech.Query(t.Host, t.Timeout)
	if r == nil {
		return nil
	}

	if !r.ServerTechSeen {
		return nil
	}
	t.MarkOpen(servertech.ManagerPort, "tcp", "servertech-jaws")
	fields := r.Fields()
	if len(r.Reply) > 0 {
		fields = append(fields, "raw", hex.EncodeToString(r.Reply))
	}
	return []engine.Finding{{
		Check:     "tcp.servertech.jawsManager",
		Category:  "exposure",
		Risk:      "info",
		Port:      servertech.ManagerPort,
		Transport: "tcp",
		Protocol:  "servertech-jaws",
		Fields:    engine.F(fields...),
	}}
}
