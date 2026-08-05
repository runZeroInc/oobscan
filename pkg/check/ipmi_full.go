package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func init() {
	Register(Check{
		Name:        "ipmi.fullWalk",
		Description: "Full pre-auth NetFn/Cmd sweep + IPMB satellite discovery (--ipmi-full)",
		Category:    "netfn",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runIPMIFull,
	})
}

func runIPMIFull(ctx context.Context, t *engine.Target) []engine.Finding {
	if !t.IPMIFull {
		return nil
	}
	port := t.IPMIPort()

	cfg := ipmi.PreAuthMapConfig{
		NetFns:              ipmi.DefaultBroadNetFns(),
		Cmds:                ipmi.DefaultBroadCmds(),
		RunSessionZeroCheck: true,
		RunIPMBSweep:        true,
		RunRAKPChecks:       true,
		Timeout:             t.Timeout,
		Concurrency:         16,
		Logf:                t.Progress,
	}

	if t.Destructive {
		cfg.Cmds = ipmi.AllCmds()
	}

	res, err := ipmi.MapPreAuthSurface(t.Host, port, cfg)
	if err != nil || res == nil {
		return []engine.Finding{{
			Check: "ipmi.fullWalk", Category: "netfn", Risk: "none",
			Fields: engine.F("error", fmt.Sprintf("%v", err)),
		}}
	}
	t.SetEvidence("ipmi.preAuthMap", res)

	risk := "info"
	if res.PotentialBypassCount > 0 || res.PotentialLeakCount > 0 {
		risk = "medium"
	}
	findings := []engine.Finding{{
		Check: "ipmi.fullWalk", Category: "netfn", Risk: risk,
		Port: port, Transport: "udp", Protocol: "ipmi",
		Fields: engine.F(
			"responses", fmt.Sprintf("%d", res.ResponseCount),
			"accepted", fmt.Sprintf("%d", res.AcceptedCount),
			"leaks", fmt.Sprintf("%d", res.PotentialLeakCount),
			"bypasses", fmt.Sprintf("%d", res.PotentialBypassCount),
			"probes", fmt.Sprintf("%d", len(res.Requests))),
	}}

	if ipmb, err := ipmi.SweepIPMBBridge(t.Host, port, t.Timeout, t.Progress); err == nil && ipmb != nil && len(ipmb.Reachable) > 0 {
		t.SetEvidence("ipmi.ipmb", ipmb)
		findings = append(findings, engine.Finding{
			Check: "ipmi.ipmbSatellite", Category: "netfn", Risk: "medium",
			Fields: engine.F("reachable", fmt.Sprintf("%d", len(ipmb.Reachable))),
		})
	}
	return findings
}

func init() {
	RegisterExplain("ipmi.fullWalk", explainIPMIFullWalk)
	RegisterExplain("ipmi.ipmbSatellite", explainIPMBSatellite)
}

func explainIPMIFullWalk(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	responses := explainField(f, "responses")
	leaks := explainField(f, "leaks")
	bypasses := explainField(f, "bypasses")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nFull pre-auth IPMI NetFn/command walk completed.\n")
	if responses != "" {
		b.WriteString(fmt.Sprintf("\n**Responses:** %s  **Potential leaks:** %s  **Potential bypasses:** %s\n",
			responses, leaks, bypasses))
	}
	b.WriteString("\n**Re-run the walk and inspect the results:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("oobscan scan --ipmi-full %s:%d --output walk.jsonl", host, port),
		"oobscan explain walk.jsonl",
	))
	return b.String()
}

func explainIPMBSatellite(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	reachable := explainField(f, "reachable")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\n**%s** IPMB satellite controller(s) reachable pre-auth via the IPMB bridge.\n", reachable))
	b.WriteString("Satellite controllers may accept commands with weaker access controls.\n")
	b.WriteString("\n**Re-run the IPMB sweep:**\n")
	b.WriteString(explainSh(fmt.Sprintf("oobscan scan --ipmi-full %s:%d --output ipmb.jsonl", host, port)))
	return b.String()
}
