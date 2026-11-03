package check

import (
	"context"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ssh"
)

// ssh.hpe.iloSSHOverflow detects the HPE iLO SSH transport packet-reader pre-auth
// stack buffer overflow: the plaintext branch (used up to NEWKEYS, so entirely
// pre-auth) validates the 4-byte packet length with a signed comparison where the
// encrypted branch uses an unsigned one, so a length near INT_MAX wraps negative,
// passes the check, and streams into a 2044-byte stack buffer with no canary.
//
// The probe only tests whether the server accepts a length in the signed-overflow
// window; it never sends enough body to overflow anything, does not log in, and does
// not mutate state.
//
// Applicability is CrossVendor, but Run gates the probe to HPE-identified hosts or the
// iLO "mpSSH" banner so crafted packets are not sprayed at unrelated SSH services.
// The banner is a pre-filter only -- the differential is the detector, and it clears
// other mpSSH stacks that enforce the bound.
func init() {
	Register(Check{
		Name:        "ssh.hpe.iloSSHOverflow",
		Description: "HPE iLO SSH pre-auth stack buffer overflow (signed packet-length check)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runILOSSHOverflow,
	})
	RegisterExplain("ssh.hpe.iloSSHOverflow", explainILOSSHOverflow)
}

func runILOSSHOverflow(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	ports := sshPorts(t)
	if len(ports) == 0 {
		return nil
	}
	isHPE := t.Identity != nil && strings.EqualFold(t.Identity.Vendor, "hpe")

	deadline := t.Timeout
	if deadline <= 0 || deadline > 8*time.Second {
		deadline = 8 * time.Second
	}

	var out []engine.Finding
	for _, port := range ports {
		// Cheap pre-filter: only probe HPE-identified hosts, or hosts whose SSH
		// banner is the iLO4 "mpSSH" string, to avoid sending crafted packets
		// to unrelated SSH services.
		if !isHPE {
			banner, err := ssh.Banner(t.Host, port, min(deadline, 4*time.Second))
			if err != nil || !strings.Contains(strings.ToLower(banner), "mpssh") {
				continue
			}
		}

		p := ssh.ProbeSSHOverflow(t.Host, port, deadline)
		switch p.Result {
		case ssh.SSHVulnerable:
			// The signed-length defect is in the mpSSH reader shared across
			// iLO4/iLO5/iLO6, not only iLO4, so label the finding with the
			// target's actual generation. The probe is behavior-based and
			// self-gating: iLO2/iLO3 run a different SSH server (Allegro
			// RomSShell), do not exhibit the signed-length window, and are not
			// flagged here.
			gen := iloGenerationFor(t, p.Banner)
			fields := engine.F(
				"vendor", "hpe",
				"product", gen,
				"defect", "ssh-signed-length-check",
				"banner", p.Banner,
				"proof", proofKV(
					"product", gen,
					"windowLen", "0x7ffffffc",
					"windowHeld", boolStr(p.WindowHeld),
					"legalLen", "0x00000100",
					"legalHeld", boolStr(p.LegalHeld),
					"overLen", "0x00000fff",
					"overHeld", boolStr(p.OverHeld),
				),
			)
			out = append(out, engine.Finding{
				Check: "ssh.hpe.iloSSHOverflow", Category: "exposure", Risk: "high",
				CVE:  []string{"CVE-2026-65204"},
				Port: port, Transport: "tcp", Protocol: "ssh",
				Fields: fields,
			})
		case ssh.SSHInconclusive:
			out = append(out, engine.Finding{
				Check: "ssh.hpe.iloSSHOverflow", Category: "exposure", Risk: "info",
				Port: port, Transport: "tcp", Protocol: "ssh",
				Fields: engine.F(
					"result", "inconclusive",
					"banner", p.Banner,
					"evidence", p.Detail,
				),
			})
		case ssh.SSHNotVulnerable, ssh.SSHError:
			// Report success only on proof; skip precondition/negative states.
		}
	}
	return out
}

// iloGenToken extracts an "iLO<N>" label from a free-form string, matching
// "iLO4", "iLO-3", "iLO/5", "Lights-Out 2", "HP-iLO-5/2.95". Returns "" when no
// generation token is present.
func iloGenToken(s string) string {
	toks := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '/' || r == '-' || r == '_' || r == '(' || r == ')' || r == ','
	})
	for i, tok := range toks {
		up := strings.ToUpper(tok)
		// Direct "iLO<N>" token (iLO4, ilo-3 -> ilo, 3 handled below).
		if strings.HasPrefix(up, "ILO") && len(up) == 4 && up[3] >= '1' && up[3] <= '9' {
			return "iLO" + string(up[3])
		}
		// "iLO" / "Lights-Out" token followed by a bare generation digit.
		if (up == "ILO" || up == "OUT") && i+1 < len(toks) {
			d := toks[i+1]
			if len(d) == 1 && d[0] >= '1' && d[0] <= '9' {
				return "iLO" + d
			}
		}
	}
	return ""
}

// iloGenerationFor resolves the target's iLO generation label ("iLO2".."iLO7")
// from the freshest available evidence, most authoritative first: the resolved
// identity Generation/Product, then the sessionless attributes identify
// collected (the SSDP/web Server header "HP-iLO-5/2.95", then the iLO firmware
// version). The mpSSH banner is generation-agnostic so it cannot disambiguate.
// Falling back to "iLO" when no generation is known.
func iloGenerationFor(t *engine.Target, _ string) string {
	if t != nil && t.Identity != nil {
		cands := []string{t.Identity.Generation, t.Identity.Product}
		if a := t.Identity.Attributes; a != nil {
			// The SSDP/web Server header (e.g. "HP-iLO-5/2.95") names the
			// generation explicitly and is populated during identify, before the
			// check lane reads it.
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

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func explainILOSSHOverflow(host string, f engine.Finding) string {
	proof := explainField(f, "proof")
	banner := explainField(f, "banner")
	product := explainField(f, "product")
	if product == "" {
		product = "iLO"
	}
	if explainField(f, "result") == "inconclusive" {
		return host + ": " + product + " SSH overflow probe was inconclusive (" + proof +
			"); confirm the SSH stack manually."
	}
	return host + ": HPE " + product + " SSH packet reader accepts a pre-auth packet length in the " +
		"signed-overflow window (0x7FFFFFFC) that a bounds-checked stack rejects, streaming it " +
		"into a 2044-byte stack buffer with no canary. An " +
		"unauthenticated attacker on " + banner + " can corrupt the iLO management " +
		"processor stack; restrict SSH to the management network and update the iLO firmware."
}
