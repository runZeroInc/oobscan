package check

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func init() {
	Register(Check{
		Name:        "ipmi.sidEntropy",
		Description: "Predictable or low-entropy RMCP+ managed session IDs (sampled in the default scan)",
		Category:    "sid",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runIPMISIDEntropy,
	})
	Register(Check{
		Name:        "ipmi.sidClientCorr",
		Description: "Client SID statistically leaks into the BMC-assigned managed SID (--ipmi-full)",
		Category:    "sid",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runIPMISIDClientCorr,
	})
	Register(Check{
		Name:        "ipmi.netfnOem",
		Description: "OEM NetFn commands accepted pre-session (no auth) (--ipmi-full)",
		Category:    "netfn",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runIPMINetFnOEM,
	})
	Register(Check{
		Name:        "ipmi.rakpRatelimit",
		Description: "No network throttle on rapid RMCP+/RAKP auth attempts (--ipmi-full)",
		Category:    "auth",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runIPMIRAKPRateLimit,
	})
}

func deepIPMIUser(t *engine.Target) string {
	if t.Cred.User != "" {
		return t.Cred.User
	}
	return "admin"
}

func minP(xs [32]float64) float64 {
	m := 1.0
	for _, x := range xs {
		if x < m {
			m = x
		}
	}
	return m
}

func runIPMISIDEntropy(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	if !t.IsOpen(t.IPMIPort(), "udp") {
		return nil
	}
	n := 5
	if t.IPMIFull {
		n = 8
	}
	if t.DebugLog != nil {
		t.DebugLog(fmt.Sprintf("ipmi.sidEntropy: sampling %d session IDs", n))
	}
	samples := ipmi.SampleSessionIDs(t.Host, t.IPMIPort(), n, t.Timeout)
	finding := sidFinding(t, samples)
	if finding == nil {
		return nil
	}
	return stampIPMI([]engine.Finding{*finding}, t.IPMIPort())
}

func sidFinding(t *engine.Target, samples []uint32) *engine.Finding {
	cls, weak := ipmi.ClassifySessionIDs(samples)
	if !weak {
		return nil
	}
	risk := "high"
	checkID := cls.CheckID()
	smc := t != nil && t.Identity != nil && strings.EqualFold(t.Identity.Vendor, "supermicro")
	var cve []string
	if smc {
		risk = "critical"
		if checkID == "ipmi.sidPredictable" {
			cve = []string{"CVE-2026-65217"}
		}
	}
	return &engine.Finding{
		Check: checkID, Category: "sid", Risk: risk, CVE: cve,
		Fields: engine.F(
			"pattern", cls.Pattern,
			"samples", fmt.Sprintf("%d", len(samples)),
			"loSid", fmt.Sprintf("0x%08x", cls.Lo),
			"hiSid", fmt.Sprintf("0x%08x", cls.Hi),
			"delta", fmt.Sprintf("0x%x", cls.Delta),
			"proof", cls.Detail),
	}
}

func runIPMISIDClientCorr(ctx context.Context, t *engine.Target) []engine.Finding {
	if !t.IPMIFull {
		return nil
	}
	trials := 64
	if t.Destructive {
		trials = 512
	}
	cfg := &ipmi.SIDCorrelationConfig{
		RandomizeInputOrder: true,
		Seed:                0,
		ConfidenceLevel:     0.95,
		Logf:                t.Progress,
	}
	res, err := ipmi.MeasureSIDClientCorrelationWithConfig(t.Host, t.IPMIPort(), trials, t.Timeout, cfg)
	if err != nil || res == nil {
		return nil
	}
	if len(res.SignificantBits) == 0 {

		return nil
	}
	mp := minP(res.PerBitPValue)
	return stampIPMI([]engine.Finding{{
		Check: "ipmi.sidClientCorr", Category: "sid", Risk: "high",
		Fields: engine.F(
			"proof", fmt.Sprintf("sigBits=%v MI=%.3f maxBitCorr=%.3f minP=%.3g", res.SignificantBits, res.MutualInfoBits, res.MaxBitCorr, mp),
			"response", fmt.Sprintf("trials=%d MI=%.3f maxBitCorr=%.3f sigBits=%v minP=%.3g CI95(bit31)=[%.3f,%.3f]",
				res.Trials, res.MutualInfoBits, res.MaxBitCorr, res.SignificantBits, mp,
				res.PerBitCILow[31], res.PerBitCIHigh[31])),
	}}, t.IPMIPort())
}

func runIPMINetFnOEM(ctx context.Context, t *engine.Target) []engine.Finding {
	if !t.IPMIFull {
		return nil
	}

	sampleCmds := []byte{0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x40, 0x41, 0x80, 0x81, 0xFE, 0xFF}
	res, err := ipmi.SweepOEMNetFnsSample(t.Host, t.IPMIPort(), ipmi.SweepPreSession, sampleCmds, t.Timeout, t.Progress)
	if err != nil || res == nil || len(res.Accepted) == 0 {
		return nil
	}

	n := min(len(res.Accepted), 20)
	var ev strings.Builder
	for i := range n {
		e := res.Accepted[i]
		if i > 0 {
			ev.WriteString("\n")
		}
		ev.WriteString(fmt.Sprintf("NetFn=0x%02x cmd=0x%02x cc=0x%02x", e.NetFn, e.Cmd, e.CompletionCode))
	}
	first := res.Accepted[0]
	return stampIPMI([]engine.Finding{{
		Check: "ipmi.netfnOem", Category: "netfn", Risk: "critical",
		Fields: engine.F(
			"proof", proofKV(
				"accepted", fmt.Sprintf("%d", len(res.Accepted)),
				"firstNetFn", fmt.Sprintf("0x%02x", first.NetFn),
				"firstCmd", fmt.Sprintf("0x%02x", first.Cmd),
				"firstCc", fmt.Sprintf("0x%02x", first.CompletionCode)),
			"response", ev.String()),
	}}, t.IPMIPort())
}

func runIPMIRAKPRateLimit(ctx context.Context, t *engine.Target) []engine.Finding {
	if !t.IPMIFull {
		return nil
	}
	user := deepIPMIUser(t)

	base, _ := ipmi.DoRAKP12(t.Host, t.IPMIPort(), user, ipmi.RAKPHMACSHA1, ipmi.IntegrityNone, ipmi.ConfNone, t.Timeout)
	if base == nil || base.BMCSID == 0 {
		return nil
	}
	const N = 12
	if t.Progress != nil {
		t.Progress("ipmi.rakpRatelimit: baseline open-session ok; starting burst")
	}
	ok := 0
	t0 := time.Now()
	for i := range N {
		r, err := ipmi.DoRAKP12(t.Host, t.IPMIPort(), user, ipmi.RAKPHMACSHA1, ipmi.IntegrityNone, ipmi.ConfNone, t.Timeout)
		if err == nil && r != nil && r.BMCSID != 0 {
			ok++
		}
		if t.Progress != nil && (i == 0 || i == N-1 || (i+1)%4 == 0) {
			t.Progress(fmt.Sprintf("ipmi.rakpRatelimit: burst progress %d/%d ok=%d", i+1, N, ok))
		}
	}
	el := time.Since(t0).Round(time.Millisecond)
	switch {
	case ok >= N-1:

		return stampIPMI([]engine.Finding{{
			Check: "ipmi.rakpRatelimit", Category: "auth", Risk: "medium",
			Fields: engine.F(
				"proof", proofKV("baseline", "ok", "attempts", fmt.Sprintf("%d", N), "succeeded", fmt.Sprintf("%d", ok), "elapsed", el.String(), "throttle", "none")),
		}}, t.IPMIPort())
	case ok == 0:

		return stampIPMI([]engine.Finding{{
			Check: "ipmi.rakpRatelimit", Category: "auth", Risk: "medium",
			Fields: engine.F(
				"proof", proofKV("baseline", "ok", "attempts", fmt.Sprintf("%d", N), "succeeded", "0", "elapsed", el.String(), "throttle", "full")),
		}}, t.IPMIPort())
	default:
		return stampIPMI([]engine.Finding{{
			Check: "ipmi.rakpRatelimit", Category: "auth", Risk: "medium",
			Fields: engine.F(
				"proof", proofKV("baseline", "ok", "attempts", fmt.Sprintf("%d", N), "succeeded", fmt.Sprintf("%d", ok), "elapsed", el.String(), "throttle", "partial")),
		}}, t.IPMIPort())
	}
}

func init() {
	RegisterExplain("ipmi.sidEntropy", explainIPMISIDEntropy)
	RegisterExplain("ipmi.sidPredictable", explainIPMISIDEntropy)
	RegisterExplain("ipmi.sidClientCorr", explainIPMISIDClientCorr)
	RegisterExplain("ipmi.netfnOem", explainIPMINetFnOEM)
	RegisterExplain("ipmi.rakpRatelimit", explainIPMIRAKPRateLimit)
}

func explainIPMISIDEntropy(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe BMC returns predictable or fixed session IDs across reconnects.\n")
	b.WriteString("A network-adjacent attacker may be able to replay or predict sessions.\n")
	b.WriteString("\n**Re-run the entropy check:**\n")
	b.WriteString(explainSh(fmt.Sprintf("oobscan scan --ipmi-full --checks ipmi.sidEntropy %s:%d", host, port)))
	return b.String()
}

func explainIPMISIDClientCorr(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe BMC-assigned session ID is statistically correlated with the client-supplied\n")
	b.WriteString("SID -- an attacker may be able to influence or predict session IDs.\n")
	b.WriteString("\n**Re-run the correlation check:**\n")
	b.WriteString(explainSh(fmt.Sprintf("oobscan scan --ipmi-full --checks ipmi.sidClientCorr %s:%d", host, port)))
	return b.String()
}

func explainIPMINetFnOEM(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe BMC accepted OEM NetFn commands in the pre-session (unauthenticated) state.\n")
	b.WriteString("Vendor-specific commands that bypass normal auth may be reachable without a login.\n")
	b.WriteString("\n**Re-run the OEM NetFn sweep:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("oobscan scan --ipmi-full --checks ipmi.netfnOem %s:%d", host, port),
		"# Probe a specific OEM NetFn manually (replace 0x2e with the responding NetFn):",
		fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -C 0 -U '' -P '' raw 0x2e 0x00", host, port),
	))
	return b.String()
}

func explainIPMIRAKPRateLimit(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe BMC does not throttle rapid RMCP+/RAKP auth attempts -- hashes can be\n")
	b.WriteString("collected at line speed with no rate-limiting penalty.\n")
	b.WriteString("\n**Collect and crack:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("oobscan scan --checks ipmi.defaultCreds %s:%d --output hashes.jsonl", host, port),
		"oobscan hashcrack hashes.jsonl",
		"hashcat -m 7300 hashes.jsonl /usr/share/wordlists/rockyou.txt",
	))
	return b.String()
}
