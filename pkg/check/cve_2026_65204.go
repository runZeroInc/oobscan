package check

import (
	"context"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ssh"
)

func init() {
	Register(Check{
		Name:        "ssh.hpe.iloSSHOverflow",
		Description: "HPE iLO SSH service affected by CVE-2026-65204; detected by service banner and generation",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runILOSSHOverflow,
	})
	RegisterExplain("ssh.hpe.iloSSHOverflow", explainILOSSHOverflow)
}

var iloAffectedSSHGenerations = map[string]bool{"iLO4": true, "iLO5": true, "iLO6": true}

func runILOSSHOverflow(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	ports := sshPorts(t)
	if len(ports) == 0 {
		return nil
	}

	deadline := t.Timeout
	if deadline <= 0 || deadline > 4*time.Second {
		deadline = 4 * time.Second
	}

	var out []engine.Finding
	for _, port := range ports {
		banner, err := ssh.Banner(t.Host, port, deadline)
		if err != nil || !strings.Contains(strings.ToLower(banner), "mpssh") {
			continue
		}
		gen := iloGenerationFor(t, banner)
		if gen != "iLO" && !iloAffectedSSHGenerations[gen] {

			continue
		}
		out = append(out, engine.Finding{
			Check: "ssh.hpe.iloSSHOverflow", Category: "exposure", Risk: "high",
			CVE:  []string{"CVE-2026-65204"},
			Port: port, Transport: "tcp", Protocol: "ssh",
			Fields: engine.F(
				"vendor", "hpe",
				"product", gen,
				"banner", banner,
				"detectionMethod", "banner-and-generation",
				"proof", proofKV(
					"product", gen,
					"banner", banner,
				),
			),
		})
	}
	return out
}

func iloGenToken(s string) string {
	toks := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '/' || r == '-' || r == '_' || r == '(' || r == ')' || r == ','
	})
	for i, tok := range toks {
		up := strings.ToUpper(tok)

		if strings.HasPrefix(up, "ILO") && len(up) == 4 && up[3] >= '1' && up[3] <= '9' {
			return "iLO" + string(up[3])
		}

		if (up == "ILO" || up == "OUT") && i+1 < len(toks) {
			d := toks[i+1]
			if len(d) == 1 && d[0] >= '1' && d[0] <= '9' {
				return "iLO" + d
			}
		}
	}
	return ""
}

func iloGenerationFor(t *engine.Target, _ string) string {
	if t != nil && t.Identity != nil {
		cands := []string{t.Identity.Generation, t.Identity.Product}
		if a := t.Identity.Attributes; a != nil {

			cands = append(cands, a["http.server"], a["httpServer"])
		}
		for _, cand := range cands {
			if g := iloGenToken(cand); g != "" {
				return g
			}
		}
	}
	return "iLO"
}

func explainILOSSHOverflow(host string, f engine.Finding) string {
	banner := explainField(f, "banner")
	product := explainField(f, "product")
	if product == "" {
		product = "iLO"
	}
	return host + ": HPE " + product + " exposes the SSH service (" + banner + ") affected by " +
		"CVE-2026-65204. Restrict SSH to the management network and disable the iLO SSH " +
		"service where it is not required."
}
