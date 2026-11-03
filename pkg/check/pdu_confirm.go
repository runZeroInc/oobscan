package check

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/apc"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/snmp"
)

// pdu.confirm turns the APC NMC fingerprint into confirmed findings by
// actively validating each web-tier issue: a real POST
// /Forms/login1 that establishes a session proves the shipped apc/apc |
// device/apc default works, and GET /limstat.htm returning device status
// proves the pre-auth info-disclosure page is enabled. Only confirmed issues
// are reported; the login is gated on !DisableLogins, limstat is a read-only
// GET, and no power on/off/cycle or config write is ever issued. SNMP default
// community and factory SNMPv3 creds are already confirmed by the general
// `snmp` check, so they are not duplicated here.
func init() {
	Register(Check{
		Name:        "pdu.confirm",
		Description: "Actively confirm APC NMC web exposures (default creds + limited-status leak)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runPDUConfirm,
	})
}

func runPDUConfirm(ctx context.Context, t *engine.Target) []engine.Finding {
	return apcConfirm(ctx, t)
}

// apcConfirm runs the APC NMC-specific active confirmations.
func apcConfirm(ctx context.Context, t *engine.Target) []engine.Finding {
	port := webPort(t)
	proto := webProto(t)
	cl := apc.New(t.Host, port, t.Timeout)
	var out []engine.Finding
	open, snip, _ := cl.LimitedStatusOpen(ctx)
	apcLike := identityVendor(t) == "apc" || open

	// 1. Default credential - active login (only when online logins are allowed).
	// A successful login mints a real session; the proof is a marker (model /
	// firmware) scraped from the authenticated home page, not a prose sentence.
	if !t.DisableLogins && apcLike {
		for _, c := range apcCredList(t) {
			ok, proof, err := cl.Login(ctx, c[0], c[1])
			if err != nil {
				break // login flow not available (not really an NMC / unreachable)
			}
			if ok {
				// The primary proof is the authenticated-login evidence returned by
				// cl.Login -- the post-login GET of an authenticated-only NMC page, its
				// HTTP status, and a marker scraped from that page. The SNMP sysDescr
				// model/firmware is a pre-auth source, so it is only appended as
				// context, never used as the sole proof.
				if fw := apcModelFW(t); fw != "" {
					proof = strings.TrimSpace(proof + " " + proofKV("snmpSysdescr", fw))
				}
				out = append(out, engine.Finding{
					Check: "http.apc.defaultCreds", Category: "creds", Risk: "critical",
					Port: port, Transport: "tcp", Protocol: proto,
					Fields: engine.F(
						"username", c[0],
						"password", c[1],
						"proof", proof,
						"evidenceEndpoint", "/Forms/login1 -> /NMC/<session>/home.htm",
						"loginVia", "http.form",
					),
				})
				break // stop at first working cred (avoid bad-login lockout)
			}
		}
	}

	// 2. Limited Status Page pre-auth info disclosure - a real unauthenticated
	// read, so the response snippet is the proof.
	if open {
		out = append(out, engine.Finding{
			Check: "http.apc.limitedStatus", Category: "http", Risk: "medium",
			Port: port, Transport: "tcp", Protocol: proto,
			Fields: engine.F("url", "/limstat.htm", "response", snip),
		})
	}

	return out
}

var (
	reAPCModel = regexp.MustCompile(`MN:\s*([^\s)]+)`)  // MN:AP9631
	reAPCFW    = regexp.MustCompile(`PF:\s*(v?[\d.]+)`) // PF:v6.8.2 (application firmware)
)

// apcModelFW builds a "model=.. fw=.." proof line from the APC SNMP sysDescr the
// identify step captured (e.g. "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.8.2
// ... MN:AP9631 ...)"). Returns "" when SNMP was not readable.
func apcModelFW(t *engine.Target) string {
	v, ok := t.Evidenced("snmp")
	if !ok {
		return ""
	}
	r, ok := v.(*snmp.Result)
	if !ok || r == nil || r.SysDescr == "" {
		return ""
	}
	var parts []string
	if m := reAPCModel.FindStringSubmatch(r.SysDescr); m != nil {
		parts = append(parts, "model="+m[1])
	}
	if m := reAPCFW.FindStringSubmatch(r.SysDescr); m != nil {
		parts = append(parts, "fw="+m[1])
	}
	return strings.Join(parts, " ")
}

// apcCredList returns the credentials to try, an operator-supplied --creds pair
// first (so it is confirmed even on a hardened unit), then the shipped defaults.
func apcCredList(t *engine.Target) [][2]string {
	var creds [][2]string
	if t.Cred.User != "" {
		creds = append(creds, [2]string{t.Cred.User, t.Cred.Pass})
	}
	creds = append(creds, [2]string{"apc", "apc"}, [2]string{"device", "apc"})
	return creds
}

func init() {
	RegisterExplain("http.apc.defaultCreds", explainAPCDefaultCreds)
	RegisterExplain("http.apc.limitedStatus", explainAPCLimitedStatus)
}

func explainAPCDefaultCreds(host string, f engine.Finding) string {
	user := explainField(f, "user")
	pass := explainField(f, "pass")
	proof := explainField(f, "proof")
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nAPC NMC web interface accepted the default credential **%s / %s**.\n", user, pass))
	if proof != "" {
		b.WriteString(fmt.Sprintf("\n**Proof:** `%s`\n", proof))
	}
	b.WriteString("\n**Validate (login POST):**\n")
	b.WriteString(explainSh(
		fmt.Sprintf(`curl -sk -c /tmp/apc.jar -X POST %s/Forms/login1 \`, baseURL),
		fmt.Sprintf(`  -d 'login_username=%s&login_password=%s&submit=Log+On'`, user, pass),
		fmt.Sprintf("curl -sk -b /tmp/apc.jar %s/about.htm", baseURL),
	))
	b.WriteString("\n\n**Impact:** Full NMC web access -- outlet scheduling, network config, UPS/PDU control.\n")
	return b.String()
}

func explainAPCLimitedStatus(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nAPC NMC serves `/limstat.htm` without authentication -- discloses UPS/PDU\n")
	b.WriteString("load, battery level, outlet state, model, and firmware version.\n")
	b.WriteString("\n**Retrieve the pre-auth status page:**\n")
	b.WriteString(explainSh(fmt.Sprintf("curl -sk %s/limstat.htm", baseURL)))
	return b.String()
}
