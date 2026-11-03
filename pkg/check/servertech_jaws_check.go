package check

import (
	"context"
	"encoding/hex"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/servertech"
)

// Server Technology (Sentry) JAWS "manager" handshake: a fixed XML init block
// parsed by the JAWS dispatch before credential exchange, making the manager
// XML parser pre-auth-reachable. The probe sends the manager-role init and
// reports the reply and the Server Technology fingerprint (no credential is
// presented).
func init() {
	Register(Check{
		Name:        "tcp.servertech.jawsManager",
		Description: "Server Technology Sentry JAWS manager XML handshake (pre-auth-reachable parser)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		// Disabled: the "Server Technology" marker matches our own <init> payload
		// echoed back inside 400/Bad-Request error pages (Apache, Python aiohttp),
		// so it false-positives on any web server. Needs a marker that is not the
		// reflected request before re-enabling.
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
	// Only report when the reply actually looks like Server Technology; the
	// handshake goes to a generic web port, so require the vendor marker to
	// avoid firing on unrelated HTTP servers.
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
