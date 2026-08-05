package check

import (
	"context"
	"encoding/hex"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/redlion"
)

func init() {
	Register(Check{
		Name:        "tcp.redlion.udrReachable",
		Description: "Red Lion/Sixnet UDR station protocol (TCP+UDP 1594) reachable; auth off by default",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},

		Enabled: true,
		Run:     runRedLionUDR,
	})
}

func runRedLionUDR(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	isRedLion := t.Identity != nil && strings.EqualFold(t.Identity.Vendor, "redlion")

	if !isRedLion && !portInScan(t, redlion.Port) {
		return nil
	}
	r := redlion.Query(t.Host, t.Timeout)
	if r == nil {
		return nil
	}

	if !isRedLion && !r.Validated && len(r.Banner) == 0 {
		return nil
	}
	if r.TCPOpen {
		t.MarkOpen(redlion.Port, "tcp", "sixnet-udr")
	}
	if r.UDPState == "open" {
		t.MarkOpen(redlion.Port, "udp", "sixnet-udr")
	}
	fields := r.Fields()
	if len(r.Banner) > 0 {
		fields = append(fields, "raw", hex.EncodeToString(r.Banner))
	}

	risk := "info"
	if isRedLion || r.Validated {
		risk = "medium"
	}
	transport := "tcp"
	if !r.TCPOpen {
		transport = "udp"
	}
	return []engine.Finding{{
		Check:     "tcp.redlion.udrReachable",
		Category:  "exposure",
		Risk:      risk,
		Port:      redlion.Port,
		Transport: transport,
		Protocol:  "sixnet-udr",
		Fields:    engine.F(fields...),
	}}
}
