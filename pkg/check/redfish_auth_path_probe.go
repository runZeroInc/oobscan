package check

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/redfish"
)

func init() {
	Register(Check{
		Name:        "http.redfish.authPathProbe",
		Description: "Redfish auth-handler failure differential probe (protected resources 401/403, authed requests 5xx)",
		Category:    "redfish",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runRedfishAuthPathProbe,
	})
}

func runRedfishAuthPathProbe(_ context.Context, t *engine.Target) []engine.Finding {
	if t.DisableLogins {
		return nil
	}

	if len(suppliedCreds(t)) > 0 {
		return nil
	}
	r := cachedRedfish(t)
	if r == nil || !r.IsRedfish() {
		return nil
	}
	port := redfishPort(t)
	per := t.Timeout
	if per <= 0 {
		per = 4 * time.Second
	}
	base := redfish.BaseURL(t.Host, port)
	client := redfish.InsecureClient(per)

	userBytes := make([]byte, 8)
	if _, err := rand.Read(userBytes); err != nil {
		return nil
	}
	user := "probe-" + hex.EncodeToString(userBytes)
	st := redfish.ProbeAuthPathStatus(client, base, user, "invalid-probe-password", per)
	if !redfish.IsAuthPathErrorPattern(st) {
		return nil
	}
	if !t.SetEvidenceIfAbsent("redfish.authPathError", st) {
		return nil
	}
	resource := redfishAuthPathResource(st)
	return []engine.Finding{{
		Check: "http.redfish.authPathError", Category: "redfish", Risk: "info",
		Port: port, Transport: "tcp", Protocol: "redfish",
		Fields: engine.F(
			"probe_user", user,
			"source", "authPathProbe",
			"resource", resource,
			"unauth_status", fmt.Sprintf("%d", st.UnauthStatus),
			"basic_status", fmt.Sprintf("%d", st.BasicStatus),
			"session_status", fmt.Sprintf("%d", st.SessionStatus),
			"challenge", st.Challenge,
			"proof", redfishAuthPathProof(st),
		),
	}}
}
