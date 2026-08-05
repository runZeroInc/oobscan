package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/guid"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func init() {
	Register(Check{
		Name:        "ipmi.smc.authBypass",
		Description: "Supermicro IPMI service authentication bypass (CVE-2026-65219).",
		Category:    "auth",
		Applies:     Applicability{Vendors: []string{"supermicro"}},
		Enabled:     true,
		Run:         runSMCauthBypass,
	})
	RegisterExplain("ipmi.smc.authBypass", explainSMCauthBypass)

	Register(Check{
		Name:        "ipmi.smc.privEsc",
		Description: "Supermicro IPMI privilege escalation (CVE-2026-65220).",
		Category:    "auth",
		Applies:     Applicability{Vendors: []string{"supermicro"}},
		Enabled:     true,
		Run:         runSMCprivEsc,
	})
	RegisterExplain("ipmi.smc.privEsc", explainSMCprivEsc)

}

func smcATENGeneration(t *engine.Target) (gen string, aten bool) {
	v, ok := t.Evidenced("guid")
	if !ok {
		return "", true
	}
	g, ok := v.(*guid.Result)
	if !ok || g == nil {
		return "", true
	}
	gen = guid.SMCGenerationFromModelPrefix(g.Fields["model_prefix"])
	if strings.EqualFold(gen, "X14") {
		return gen, false
	}
	return gen, true
}

func runSMCauthBypass(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx

	if t.DisableLogins {
		return nil
	}
	gen, aten := smcATENGeneration(t)
	if !aten {
		return nil
	}
	port := t.IPMIPort()
	probe, err := ipmi.ProbeSMCRAKPOrder(t.Host, port, t.Timeout)
	if probe == nil {
		return nil
	}

	t.SetEvidence("ipmi.smc.authBypass", probe)
	if err != nil || !probe.Defect {

		return stampIPMI([]engine.Finding{smcauthBypassNegativeFinding(port, gen, probe, err)}, port)
	}
	return stampIPMI([]engine.Finding{smcauthBypassFinding(port, gen, probe)}, port)
}

func smcauthBypassFinding(port int, generation string, p *ipmi.SMCRAKPOrderProbe) engine.Finding {
	risk := "medium"
	if p.Activated {

		risk = "high"
	}
	fields := engine.F(
		"sessionObtained", fmt.Sprintf("%t", p.Activated),
	)
	if generation != "" {
		fields = append(fields, engine.Field{Key: "smcGeneration", Val: generation})
	}
	fields = append(fields, engine.Field{Key: "proof", Val: proofKV(
		"sessionObtained", fmt.Sprintf("%t", p.Activated))})
	return engine.Finding{
		Check:    "ipmi.smc.authBypass",
		Category: "auth",
		Risk:     risk,
		CVE:      []string{"CVE-2026-65219"},
		Fields:   fields,
	}
}

func smcRAKPOutcome(answered, conformant bool, err error) string {
	switch {
	case err != nil:
		return "not-measured-probe-error"
	case !answered:
		return "not-measured-no-answer"
	case conformant:
		return "conformant-rejection"
	default:
		return "inconclusive-unexpected-status"
	}
}

func smcauthBypassNegativeFinding(port int, generation string, p *ipmi.SMCRAKPOrderProbe, err error) engine.Finding {
	fields := engine.F(
		"defect", "false",
		"outcome", smcRAKPOutcome(p.Answered, p.SpecConformant, err),
		"messageOrderEnforced", "false",
		"rakp4Status", fmt.Sprintf("0x%02x", p.RAKP4Status),
		"rakp4StatusText", p.RAKP4StatusText,
		"consoleSidEchoed", fmt.Sprintf("%t", p.SIDEchoed),
	)
	if generation != "" {
		fields = append(fields, engine.Field{Key: "smcGeneration", Val: generation})
	}
	if err != nil {
		fields = append(fields, engine.Field{Key: "probeError", Val: err.Error()})
	}
	fields = append(fields, engine.Field{Key: "proof", Val: proofKV(
		"rakp4Status", fmt.Sprintf("0x%02x", p.RAKP4Status),
		"specConformant", fmt.Sprintf("%t", p.SpecConformant))})
	return engine.Finding{
		Check:    "ipmi.smc.authBypass.negative",
		Category: "auth",
		Risk:     "info",
		Fields:   fields,
	}
}

func smcprivEscNegativeFinding(port int, generation string, p *ipmi.SMCRoleClampProbe, err error) engine.Finding {
	fields := engine.F(
		"defect", "false",
		"outcome", smcRAKPOutcome(p.ConformantAccepted || p.ReservedStatus != 0, p.ProbeRejectedConformantly, err),
		"probeRoleStatus", fmt.Sprintf("0x%02x", p.ReservedStatus),
		"controlRoleStatus", fmt.Sprintf("0x%02x", p.ConformantStatus),
		"controlAccepted", fmt.Sprintf("%t", p.ConformantAccepted),
		"namedAccount", p.Username,
	)
	if generation != "" {
		fields = append(fields, engine.Field{Key: "smcGeneration", Val: generation})
	}
	if err != nil {
		fields = append(fields, engine.Field{Key: "probeError", Val: err.Error()})
	}
	fields = append(fields, engine.Field{Key: "proof", Val: proofKV(
		"namedAccount", p.Username,
		"probeRoleStatus", fmt.Sprintf("0x%02x", p.ReservedStatus),
		"controlAccepted", fmt.Sprintf("%t", p.ConformantAccepted))})
	return engine.Finding{
		Check:    "ipmi.smc.privEsc.negative",
		Category: "auth",
		Risk:     "info",
		Fields:   fields,
	}
}

func explainSMCauthBypass(host string, f engine.Finding) string {
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe Supermicro IPMI service is vulnerable to CVE-2026-65219.\n")
	b.WriteString("\nUpdate the BMC firmware, disable IPMI over LAN where it is not required, and\n")
	b.WriteString("restrict UDP/623 to the management network.\n")
	return b.String()
}

func runSMCprivEsc(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx

	if t.DisableLogins {
		return nil
	}
	gen, aten := smcATENGeneration(t)
	if !aten {
		return nil
	}
	port := t.IPMIPort()
	probe, err := ipmi.ProbeSMCRoleClamp(t.Host, port, t.Cred.User, t.Timeout)
	if probe == nil {
		return nil
	}

	t.SetEvidence("ipmi.smc.privEsc", probe)
	if err != nil || !probe.Defect {

		return stampIPMI([]engine.Finding{smcprivEscNegativeFinding(port, gen, probe, err)}, port)
	}
	return stampIPMI([]engine.Finding{smcprivEscFinding(port, gen, probe)}, port)
}

func smcprivEscFinding(port int, generation string, p *ipmi.SMCRoleClampProbe) engine.Finding {
	fields := engine.F(
		"namedAccount", p.Username,
		"surface", "authenticated",
		"prerequisite", "valid-low-privilege-credential",
		"impactIfExploited", "privilege-escalation-not-auth-bypass",
	)
	if generation != "" {
		fields = append(fields, engine.Field{Key: "smcGeneration", Val: generation})
	}

	fields = append(fields, engine.Field{Key: "proof", Val: proofKV(
		"namedAccount", p.Username,
		"controlRoleStatus", fmt.Sprintf("0x%02x", p.ConformantStatus),
		"adminRoleStatus", fmt.Sprintf("0x%02x", p.BaselineStatus),
		"probeRoleStatus", fmt.Sprintf("0x%02x", p.ReservedStatus),
		"credentialOffered", "false")})
	return engine.Finding{
		Check:    "ipmi.smc.privEsc",
		Category: "auth",
		Risk:     "medium",
		CVE:      []string{"CVE-2026-65220"},
		Fields:   fields,
	}
}

func explainSMCprivEsc(host string, f engine.Finding) string {
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe Supermicro IPMI service is vulnerable to CVE-2026-65220.\n")
	b.WriteString("\nUpdate the BMC firmware and review which accounts hold IPMI credentials.\n")
	return b.String()
}
