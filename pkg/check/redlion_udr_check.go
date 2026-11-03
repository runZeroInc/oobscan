package check

import (
	"context"
	"encoding/hex"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/redlion"
)

// Red Lion / Sixnet UDR station protocol (TCP+UDP 1594, service "sixtrak"),
// the primary remote-management channel on SixTRAK/VersaTRAK RTUs; auth is
// off by default (the "authentication required" flag in general.config reads
// as "0" when absent), so a reachable listener is a pre-auth control surface.
// The probe is read-only: it sends only the state-free version/identify
// (0x03) command with a correct UDR wire CRC trailer (CCITT-FALSE, xorout
// 0xFFFF, little-endian), and treats a 0x29-framed, CRC-valid reply as a
// high-confidence Red Lion signal.
func init() {
	Register(Check{
		Name:        "tcp.redlion.udrReachable",
		Description: "Red Lion/Sixnet UDR station protocol (TCP+UDP 1594) reachable; auth off by default",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		// Enabled with two emit paths: a CRC-validated UDR reply (see
		// runRedLionUDR) is trusted on its own because ACK-all/tarpit hosts and
		// UDP reflectors cannot forge a 0x29-framed, CCITT-CRC-valid station
		// frame; otherwise the finding stays corroboration-gated on identity or
		// a volunteered banner so a bare open 1594 does not false-positive.
		Enabled: true,
		Run:     runRedLionUDR,
	})
}

func runRedLionUDR(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	isRedLion := t.Identity != nil && strings.EqualFold(t.Identity.Vendor, "redlion")
	// Probe-gate: only touch the 1594 control port when the host already looks like
	// Red Lion (SNMP sysDescr / telnet banner) or the operator explicitly scanned
	// 1594. This avoids a control-channel connect to every host and the ACK-all
	// tarpit false positives.
	if !isRedLion && !portInScan(t, redlion.Port) {
		return nil
	}
	r := redlion.Query(t.Host, t.Timeout)
	if r == nil {
		return nil
	}
	// Emit-gate: a CRC-validated UDR reply is self-corroborating (a tarpit or
	// reflector cannot produce a valid 0x29-framed CCITT-CRC frame). Otherwise
	// reachability alone still fires on tarpits, so require identity corroboration
	// or a volunteered banner.
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
	// Medium when the device is confirmed Red Lion or a station reply validated
	// against the UDR framing; an unattributed host that merely volunteered bytes
	// on 1594 is reported at info for triage.
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
