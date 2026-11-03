package check

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// The RMCP presence ping is the cheapest BMC-liveness signal: an ASF presence
// request on UDP/623 whose pong carries the "IPMI supported" bit. It records
// reachability + RTT + whether IPMI is advertised, and stays quiet when the port
// does not answer.
func init() {
	Register(Check{
		Name:        "ipmi.rmcpPing",
		Description: "IPMI RMCP/ASF presence ping (UDP/623 liveness + IPMI-supported bit)",
		Category:    "discovery",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runIPMIRMCPPing,
	})
}

func runIPMIRMCPPing(ctx context.Context, t *engine.Target) []engine.Finding {
	port := t.IPMIPort()
	start := time.Now()
	resp, err := ipmi.ASFPing(t.Host, port, t.Timeout)
	if err != nil {
		return nil // no ASF pong; stay quiet (matches the old PASS/closed suppression)
	}
	rtt := time.Since(start)
	f := engine.F("rtt", fmt.Sprintf("%dus", rtt.Microseconds()))
	if s := asfIPMISupported(resp); s != "" {
		f = append(f, engine.Field{Key: "ipmi_supported", Val: s})
	}
	return []engine.Finding{{
		Check: "ipmi.rmcpPing", Category: "discovery", Risk: "info",
		Port: port, Transport: "udp", Protocol: "ipmi",
		Fields: f,
	}}
}

// asfIPMISupported reads the "IPMI supported" bit from an ASF presence-pong
// (supported-entities byte, bit 7). Returns "yes"/"no", or "" if too short.
func asfIPMISupported(resp []byte) string {
	const supportedEntitiesOff = 20 // RMCP(4)+ASF hdr(8)+OEM(8)
	if len(resp) <= supportedEntitiesOff {
		return ""
	}
	if resp[supportedEntitiesOff]&0x80 != 0 {
		return "yes"
	}
	return "no"
}

func init() {
	RegisterExplain("ipmi.rmcpPing", explainIPMIRMCPPing)
}

func explainIPMIRMCPPing(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	rtt := explainField(f, "rtt")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nThe BMC responds to IPMI RMCP/ASF presence pings on UDP/%d", port))
	if rtt != "" {
		b.WriteString(fmt.Sprintf(" (RTT: %s)", rtt))
	}
	b.WriteString(".\n")
	b.WriteString("\n**Confirm the IPMI surface:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -C 0 -U '' -P '' mc info 2>&1 | head", host, port),
		fmt.Sprintf("oobscan scan %s:%d", host, port),
	))
	return b.String()
}
