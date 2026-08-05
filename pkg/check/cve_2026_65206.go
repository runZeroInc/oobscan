package check

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func init() {
	Register(Check{
		Name:        "ipmi.ilo.authBypass",
		Description: "HPE iLO RMCP+ session engine affected by an authentication bypass",
		Category:    "auth",
		Applies:     Applicability{Vendors: []string{"hpe"}},
		Enabled:     true,
		Run:         runILOauthBypass,
	})
	RegisterExplain("ipmi.ilo.authBypass", explainILOauthBypass)
	RegisterExplain("ipmi.ilo.privEsc", explainILOprivEsc)
}

var iloRMCPAffected = map[string]struct{ min, max float64 }{
	"iLO2": {2.00, 2.33},
	"iLO3": {1.70, 1.94},
	"iLO4": {1.32, 2.82},
}

func runILOauthBypass(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	port := t.IPMIPort()
	timeout := t.Timeout

	gen := iloGenerationFor(t, "")
	band, known := iloRMCPAffected[gen]
	if !known {

		return nil
	}
	fw := iloFirmwareVersion(t)
	if fw == "" {
		return nil
	}
	v, err := strconv.ParseFloat(fw, 64)
	if err != nil || v < band.min || v > band.max {
		return nil
	}

	var accepted bool
	var ctrlStatus byte
	var ctrlErr error
	for range 3 {
		accepted, ctrlStatus, ctrlErr = ipmi.ILOAlgoZeroControlAccepted(t.Host, port, timeout)
		if ctrlErr == nil {
			break
		}
	}
	if accepted {
		return nil
	}
	ctrlEvidence := fmt.Sprintf("status=0x%02x", ctrlStatus)
	if ctrlErr != nil {
		ctrlEvidence = "no-reply"
	}

	return stampIPMI([]engine.Finding{
		iloauthBypassFinding(port, gen, fw, ctrlEvidence),
		iloprivEscFinding(port, gen, fw),
	}, port)
}

func iloFirmwareVersion(t *engine.Target) string {
	if t == nil || t.Identity == nil || t.Identity.Attributes == nil {
		return ""
	}
	for _, key := range []string{"ipmi.firmwareVersionFull", "firmwareVersion", "ilo.firmwareVersion"} {
		raw := strings.TrimSpace(t.Identity.Attributes[key])
		if raw == "" {
			continue
		}

		parts := strings.Split(raw, ".")
		if len(parts) < 2 {
			continue
		}
		cand := parts[0] + "." + parts[1]
		if _, err := strconv.ParseFloat(cand, 64); err == nil {
			return cand
		}
	}

	for _, key := range []string{"http.server", "httpServer"} {
		raw := t.Identity.Attributes[key]
		if i := strings.LastIndex(raw, "/"); i >= 0 && i+1 < len(raw) {
			cand := strings.TrimSpace(raw[i+1:])
			if _, err := strconv.ParseFloat(cand, 64); err == nil {
				return cand
			}
		}
	}
	return ""
}

func iloauthBypassFinding(port int, generation, firmware, ctrlEvidence string) engine.Finding {
	return engine.Finding{
		Check:     "ipmi.ilo.authBypass",
		Category:  "auth",
		Risk:      "critical",
		CVE:       []string{"CVE-2026-65206"},
		Port:      port,
		Transport: "udp",
		Protocol:  "ipmi",
		Fields: engine.F(
			"product", generation,
			"firmwareVersion", firmware,
			"cipherSuiteZeroOffered", "false",
			"algoZeroControl", ctrlEvidence,
			"detectionMethod", "generation-and-firmware-version",
			"proof", proofKV(
				"product", generation,
				"firmwareVersion", firmware,
				"algoZeroControl", ctrlEvidence),
		),
	}
}

func iloprivEscFinding(port int, generation, firmware string) engine.Finding {
	return engine.Finding{
		Check:     "ipmi.ilo.privEsc",
		Category:  "auth",
		Risk:      "high",
		CVE:       []string{"CVE-2026-65205"},
		Port:      port,
		Transport: "udp",
		Protocol:  "ipmi",
		Fields: engine.F(
			"product", generation,
			"firmwareVersion", firmware,
			"detectionMethod", "generation-and-firmware-version",
			"proof", proofKV(
				"product", generation,
				"firmwareVersion", firmware),
		),
	}
}

func explainILOauthBypass(host string, f engine.Finding) string {
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThis iLO generation and firmware version are affected by CVE-2026-65206.\n")
	b.WriteString("Update the iLO firmware, disable IPMI over LAN where it is not required, and\n")
	b.WriteString("restrict UDP/623 to the management network.\n")
	return b.String()
}

func explainILOprivEsc(host string, f engine.Finding) string {
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThis iLO generation and firmware version are affected by CVE-2026-65205.\n")
	b.WriteString("Update the iLO firmware and restrict UDP/623 to the management network.\n")
	return b.String()
}
