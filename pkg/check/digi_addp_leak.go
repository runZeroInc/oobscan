package check

import (
	"context"
	"strconv"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/digi"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

// Digi ADDP is an unauthenticated UDP/2362 discovery service on Digi
// PortServer/ConnectPort/TransPort/Connect ES devices; one probe returns
// hostname, LAN MAC, IPv4 config, DNS/DHCP state, product/firmware, RealPort
// port and encryption state, and serial-port count -- bounded metadata with no
// credentials or access. identify already parses this; this check surfaces it
// as an info finding, read-only, reusing identify's evidence when present.

func init() {
	Register(Check{
		Name:        "udp.digi.addpLeak",
		Description: "Digi ADDP (UDP/2362) discovery metadata (hostname/MAC/IP/firmware/serial port count)",
		Category:    "discovery",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runDigiADDPLeak,
	})
	RegisterExplain("udp.digi.addpLeak", explainDigiADDPLeak)
}

func runDigiADDPLeak(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	var r *digi.ADDPResponse
	if v, ok := t.Evidenced("digi.addp"); ok {
		if rr, ok := v.(*digi.ADDPResponse); ok && rr != nil {
			r = rr
		}
	}
	if r == nil {
		got, err := digi.Query(t.Host, t.Timeout)
		if err != nil || got == nil {
			return nil
		}
		r = got
		t.SetEvidence("digi.addp", r)
	}
	// Require at least one substantive field so a bare-minimum ADDP replier
	// (no hostname/MAC/firmware/RealPort/ports) does not fire this finding.
	if r.MAC == "" && r.Hostname == "" && r.Firmware == "" && r.HWName == "" && r.RealPort == 0 && r.Ports == 0 {
		return nil
	}
	t.MarkOpen(digi.ADDPPort, "udp", "digi-addp")
	realport := ""
	if r.RealPort > 0 {
		realport = strconv.Itoa(r.RealPort)
	}
	realportTLS := ""
	if r.RealPortEncrypted {
		realportTLS = "true"
	}
	return []engine.Finding{{
		Check: "udp.digi.addpLeak", Category: "discovery", Risk: "info",
		Port: digi.ADDPPort, Transport: "udp", Protocol: "digi-addp",
		Fields: engine.F(
			"product", strings.TrimSpace(r.HWName),
			"firmware", strings.TrimSpace(r.Firmware),
			"hostname", strings.TrimSpace(r.Hostname),
			"mac", r.MAC,
			"ip", r.IP,
			"netmask", r.Mask,
			"gateway", r.Gateway,
			"dns", r.DNS,
			"serialPorts", strconv.Itoa(r.Ports),
			"realport", realport,
			"realportEncrypted", realportTLS,
		),
	}}
}

func explainDigiADDPLeak(host string, f engine.Finding) string {
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe Digi appliance answers ADDP (Advanced Device Discovery Protocol) on\n")
	b.WriteString("UDP/2362 with no authentication. The reply exposes the LAN MAC, hostname,\n")
	b.WriteString("IPv4 addressing, DNS/gateway, DHCP state, product name, firmware version,\n")
	b.WriteString("count of serial ports, and the RealPort listener port + encryption state.\n")
	b.WriteString("This is intended discovery metadata: it contains no credential and does not\n")
	b.WriteString("by itself grant access to RealPort or another management service.\n")
	product := explainField(f, "product")
	firmware := explainField(f, "firmware")
	if product != "" || firmware != "" {
		b.WriteString("\n**Product/firmware:** ")
		b.WriteString(product)
		if firmware != "" {
			b.WriteString(" ")
			b.WriteString(firmware)
		}
		b.WriteString("\n")
	}
	if rp := explainField(f, "realport"); rp != "" {
		b.WriteString("\n**RealPort listener:** ")
		b.WriteString(rp)
		if explainField(f, "realportEncrypted") == "true" {
			b.WriteString(" (TLS)")
		}
		b.WriteString("\n")
	}
	b.WriteString("\n**Reproduce the disclosure (Metasploit ADDP module):**\n")
	b.WriteString(explainSh(
		"msf6 > use auxiliary/scanner/digi/addp_reset",
		"msf6 auxiliary(scanner/digi/addp_reset) > set RHOSTS "+host,
		"msf6 auxiliary(scanner/digi/addp_reset) > set ACTION LIST",
		"msf6 auxiliary(scanner/digi/addp_reset) > run",
	))
	b.WriteString("\n**Mitigation:** Disable ADDP on the Digi appliance (Configuration -> System -> Device Discovery)\n")
	b.WriteString("or block inbound UDP/2362 at the network boundary. ADDP is not required for\n")
	b.WriteString("normal RealPort/console operation.\n")
	return b.String()
}
