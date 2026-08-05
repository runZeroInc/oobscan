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

func apcConfirm(ctx context.Context, t *engine.Target) []engine.Finding {
	port := webPort(t)
	proto := webProto(t)
	cl := apc.New(t.Host, port, t.Timeout)
	var out []engine.Finding
	open, snip, _ := cl.LimitedStatusOpen(ctx)
	apcLike := identityVendor(t) == "apc" || open

	if !t.DisableLogins && apcLike {
		for _, c := range apcCredList(t) {
			ok, proof, err := cl.Login(ctx, c[0], c[1])
			if err != nil {
				break
			}
			if ok {

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
				break
			}
		}
	}

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
	reAPCModel = regexp.MustCompile(`MN:\s*([^\s)]+)`)
	reAPCFW    = regexp.MustCompile(`PF:\s*(v?[\d.]+)`)
)

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
