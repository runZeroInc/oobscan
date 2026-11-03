package check

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/redfish"
)

func init() {
	Register(Check{
		Name:        "http.redfish.postAuthEnum",
		Description: "Collect post-auth Redfish inventory (vendor/model/firmware/serial) using supplied or scan-recovered credentials",
		Category:    "creds",
		Applies:     Applicability{Classes: []engine.DeviceClass{engine.ClassBMC}},
		// Not Authenticated: that flag gates on the operator supplying --creds. Since
		// suppliedCreds also returns the credentials the scan recovered, the check has its
		// own source and the gate would only suppress it.
		Enabled: true,
		Run:     runRedfishPostAuthEnum,
	})
}

const maxRedfishPostAuthAttempts = 6

func runRedfishPostAuthEnum(ctx context.Context, t *engine.Target) []engine.Finding {
	if t.DisableLogins {
		return nil
	}
	creds := suppliedCreds(t)
	if len(creds) == 0 {
		return nil
	}
	credSource := credSourceFunc(t)

	port := webPort(t)
	per := t.Timeout
	if per <= 0 {
		per = 4 * time.Second
	}
	if r, err := redfish.ProbeAt(t.Host, port, per); err != nil || r == nil || r.Status == 0 {
		return nil
	}

	base := redfish.BaseURL(t.Host, port)
	client := redfish.InsecureClient(per)

	attempts := 0
	for _, c := range creds {
		if attempts >= maxRedfishPostAuthAttempts {
			break
		}
		if c.User == "" {
			continue
		}
		attempts++

		res := redfish.OpenSession(client, base, c.User, c.Pass, per)
		if !res.Authenticated {
			st := redfish.ProbeAuthPathStatus(client, base, c.User, c.Pass, per)
			if redfish.IsAuthPathErrorPattern(st) {
				risk := redfishAuthPathRisk(redfish.VerifyCredential(client, base, c.User, c.Pass, per))
				if t.SetEvidenceIfAbsent("redfish.authPathError", st) {
					resource := redfishAuthPathResource(st)
					return []engine.Finding{{
						Check: "http.redfish.authPathError", Category: "redfish", Risk: risk,
						Port: port, Transport: "tcp", Protocol: "redfish",
						Fields: engine.F(
							"username", c.User,
							"source", credSource(c),
							"resource", resource,
							"unauthStatus", fmt.Sprintf("%d", st.UnauthStatus),
							"basicStatus", fmt.Sprintf("%d", st.BasicStatus),
							"sessionStatus", fmt.Sprintf("%d", st.SessionStatus),
							"challenge", st.Challenge,
							"proof", redfishAuthPathProof(st),
						),
					}}
				}
			}
			continue
		}

		hdrs := readHeaderFor(res, c.User, c.Pass)
		info := redfish.PullSystemInfo(client, base, hdrs, c.User, per)
		redfish.DeleteSession(client, base, res.SessionURI, res.Token, per)
		t.SetEvidence("redfish.postAuth", &redfish.PostAuthSnapshot{
			Method: "providedCreds",
			Via:    res.Via,
			User:   c.User,
			Source: credSource(c),
			Info:   info,
		})

		// Compact finding fields: the full authenticated inventory lives on
		// the top-level `redfishPostAuth` record; the finding here summarises
		// what happened so a triage view is self-contained.
		return []engine.Finding{{
			Check: "http.redfish.postAuthEnum", Category: "creds", Risk: "info",
			Port: port, Transport: "tcp", Protocol: "redfish",
			Fields: engine.F(
				"username", c.User,
				"source", credSource(c),
				"loginVia", res.Via,
				"bmcVendor", info.Vendor,
				"model", info.Model,
				"firmwareVersion", info.FirmwareVersion,
				"redfishVersion", info.RedfishVersion,
				"product", info.Product,
			),
		}}
	}
	return nil
}

func suppliedCreds(t *engine.Target) []engine.Cred {
	seen := map[string]struct{}{}
	var out []engine.Cred
	add := func(c engine.Cred) {
		if c.User == "" {
			return
		}
		k := c.User + "\x00" + c.Pass
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, c)
	}
	add(t.Cred)
	for _, c := range t.Creds {
		add(c)
	}
	// Credentials the scan recovered count too: BMC accounts are shared between the IPMI
	// and Redfish front ends on essentially every vendor, so a password cracked out of a
	// RAKP-2 hash is a Redfish credential. Looking only at the operator's --creds list
	// skips every host whose password the scan itself discovered.
	//
	// Ordered after the supplied credentials so an explicit --creds still wins, and
	// admin-looking accounts first within the discovered set.
	for _, c := range crackedCreds(t) {
		add(c)
	}
	return out
}

// credSourceFunc returns a provenance labeller for the credentials suppliedCreds
// yields: the pairs the operator passed on the command line are "cli", anything else
// came out of this scan's own IPMI recovery. A recovered credential logging into
// Redfish is a different result from an operator's own one, so the record has to say
// which it was.
func credSourceFunc(t *engine.Target) func(engine.Cred) string {
	fromCLI := make(map[engine.Cred]struct{}, len(t.Creds)+1)
	if t.Cred.User != "" {
		fromCLI[t.Cred] = struct{}{}
	}
	for _, c := range t.Creds {
		fromCLI[c] = struct{}{}
	}
	return func(c engine.Cred) string {
		if _, ok := fromCLI[c]; ok {
			return "cli"
		}
		return "ipmi.rakpCracked"
	}
}

// crackedCreds returns the verified credentials this scan recovered,
// most-privileged account first, excluding the SMCRAKP fixed-key marker (a
// forged RAKP-2 HMAC, not a real password). The ipmi.auth handle is written by
// the serial IPMI lane, so this check must run after that lane completes (see
// the deferred lane in cmd/scan.go) -- scheduled alongside it instead, it
// samples the handle early and finds nothing.
func crackedCreds(t *engine.Target) []engine.Cred {
	v, ok := t.Evidenced("ipmi.auth")
	if !ok {
		return nil
	}
	auth, _ := v.(*ipmi.AuthReport)
	if auth == nil {
		return nil
	}
	out := make([]engine.Cred, 0, len(auth.Cracked))
	for _, cr := range auth.Cracked {
		if !cr.Verified || cr.PasswordType == "smcrakp-fixed-key" {
			continue
		}
		if strings.TrimSpace(cr.Username) == "" || cr.Password == "" {
			continue
		}
		out = append(out, engine.Cred{User: cr.Username, Pass: cr.Password})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return ipmi.UsernamePrivRank(out[i].User) < ipmi.UsernamePrivRank(out[j].User)
	})
	return out
}

func init() {
	RegisterExplain("http.redfish.postAuthEnum", explainRedfishPostAuthEnum)
}

func explainRedfishPostAuthEnum(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 443)
	user := explainField(f, "username")
	via := explainField(f, "loginVia")
	model := explainField(f, "model")
	fw := explainField(f, "firmwareVersion")
	baseURL := explainBaseURL(host, f, port, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nSupplied credential authenticated to Redfish as **%s**", user))
	if via != "" {
		b.WriteString(fmt.Sprintf(" (via %s)", via))
	}
	b.WriteString(".\n")
	if model != "" || fw != "" {
		b.WriteString(fmt.Sprintf("\n**Device:** %s firmware %s\n", model, fw))
	}
	b.WriteString("\n**Validate session + inventory:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf(`curl -sk -X POST %s/redfish/v1/SessionService/Sessions \`, baseURL),
		`  -H "Content-Type: application/json" \`,
		fmt.Sprintf(`  -d '{"UserName":"%s","Password":"<password>"}'`, user),
		fmt.Sprintf("curl -sk -u '%s:<password>' %s/redfish/v1/Systems/ | python3 -m json.tool", user, baseURL),
		fmt.Sprintf("curl -sk -u '%s:<password>' %s/redfish/v1/Managers/ | python3 -m json.tool", user, baseURL),
	))
	return b.String()
}
