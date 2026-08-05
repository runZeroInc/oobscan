package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func init() {
	Register(Check{
		Name:        "serialconsole.exposure",
		Description: "Serial console-server exposure and fingerprinting (Moxa/Opengear/Lantronix/Digi/Perle/ZPE)",
		Category:    "exposure",
		Applies:     Applicability{Classes: []engine.DeviceClass{engine.ClassSerialConsole}},
		Enabled:     true,
		Run:         runSerialConsoleExposure,
	})
}

func runSerialConsoleExposure(ctx context.Context, t *engine.Target) []engine.Finding {
	return oobDeviceExposure(ctx, t, "serialconsole")
}

func oobDeviceExposure(ctx context.Context, t *engine.Target, kind string) []engine.Finding {
	_ = ctx

	vendor := identityVendor(t)
	product := identityProduct(t)
	port := webPort(t)
	proto := webProto(t)

	var out []engine.Finding

	out = append(out, engine.Finding{
		Check: kind + ".fingerprint", Category: "exposure", Risk: "info",
		Port: port, Transport: "tcp", Protocol: proto,
		Fields: engine.F(
			"class", string(classFor(t)),
			"vendor", vendor,
			"product", product,
			"proof", proofKV(
				"tcpPort", fmt.Sprintf("%d", port),
				"scheme", proto,
				"signals", identitySignalSummary(t),
				"httpServer", identityAttr(t, "http.server"),
				"httpTitle", identityAttr(t, "http.title"),
			)),
	})

	return out
}

var signalEvidenceAttrs = map[string][]string{
	"lantronix":        {"lantronix.setup_telnet", "device.fw", "mac"},
	"lantronix.telnet": {"lantronix.setup_telnet", "mac"},
	"moxa":             {"moxa.model", "moxa.firmware", "mac"},
	"digi.addp":        {"digi.hostname", "device.fw", "mac"},
	"digi.realport":    {"digi.realport_name", "digi.realport_ports"},
	"snmp":             {"snmp.engine_id"},
	"snmp.sysdescr":    {"snmp.engine_id"},
	"snmp.v3.engineId": {"snmp.v3.engineIdSuffix", "snmp.engine_id"},
	"redfish":          {"redfish.product", "redfish.version", "redfish.uuid"},
	"wsman":            {"wsman.product", "wsman.vendor"},
	"ilo":              {"ilo.model", "ilo.fw"},
	"idrac":            {"idrac.systemModelName", "idrac.fw"},
	"guid":             {"guid.family"},
	"slp":              {"slp.services"},
	"mdns":             {"mdns.services"},
	"http.title":       {"http.title"},
	"fingerprint":      {"http.server", "http.title"},
}

const signalEvidenceLimit = 64

func signalDetailFallback(t *engine.Target, source string) string {
	for _, key := range signalEvidenceAttrs[source] {
		v := identityAttr(t, key)
		if v == "" {
			continue
		}
		if len(v) > signalEvidenceLimit {
			v = v[:signalEvidenceLimit]
		}
		return v
	}
	return ""
}

func identitySignalSummary(t *engine.Target) string {
	if t == nil || t.Identity == nil {
		return ""
	}
	parts := make([]string, 0, len(t.Identity.Signals))
	for _, s := range t.Identity.Signals {
		detail := strings.TrimSpace(s.Detail)
		if detail == "" {
			detail = signalDetailFallback(t, s.Source)
		}
		bits := make([]string, 0, 3)
		for _, v := range []string{s.Source, s.Vendor, detail} {
			if v = strings.TrimSpace(v); v != "" {
				bits = append(bits, v)
			}
		}
		if len(bits) > 0 {
			parts = append(parts, strings.Join(bits, ":"))
		}
	}
	return cleanSnippet(strings.Join(parts, "; "))
}

func identityAttr(t *engine.Target, key string) string {
	if t == nil || t.Identity == nil || t.Identity.Attributes == nil {
		return ""
	}
	return cleanSnippet(t.Identity.Attributes[key])
}

func identityProduct(t *engine.Target) string {
	if t.Identity != nil {
		return t.Identity.Product
	}
	return ""
}

func identityVendor(t *engine.Target) string {
	if t.Identity != nil {
		return t.Identity.Vendor
	}
	return ""
}

func classFor(t *engine.Target) engine.DeviceClass {
	if t.Identity != nil {
		return t.Identity.Class
	}
	return engine.ClassUnknown
}

func init() {
	for _, prefix := range []string{"serialconsole", "pdu"} {
		p := prefix
		RegisterExplain(p+".fingerprint", func(host string, f engine.Finding) string {
			return explainDeviceFingerprint(host, f)
		})
		_ = p
	}
}

func explainDeviceFingerprint(host string, f engine.Finding) string {
	class := explainField(f, "class")
	vendor := explainField(f, "vendor")
	product := explainField(f, "product")
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nDevice identified as **%s %s** (class: %s).\n", vendor, product, class))
	b.WriteString("\n**Browse the management interface:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk %s/ -o /dev/null -w '%%{http_code} %%{url_effective}\n'", baseURL),
		fmt.Sprintf("oobscan scan %s", host),
	))
	return b.String()
}

func explainSharedSSHHostKey(host string, f engine.Finding) string {
	vendor := explainField(f, "vendor")
	product := explainField(f, "product")
	fp := explainField(f, "fingerprint")
	keyType := explainField(f, "keyType")
	if keyType == "" {
		keyType = "rsa"
	}
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe device's SSH host key is shared fleet-wide -- the private key is baked\n")
	b.WriteString("into every unit's firmware, making it effectively public. Any device with\n")
	b.WriteString("this key can be impersonated (MitM) and captured SSH sessions can be decrypted.\n")
	if vendor != "" {
		b.WriteString(fmt.Sprintf("\n**Vendor/product:** %s %s\n", vendor, product))
	}
	if fp != "" {
		b.WriteString(fmt.Sprintf("**Fingerprint:** `%s`\n", fp))
	}
	b.WriteString("\n**Capture the host key:**\n")
	b.WriteString(explainSh(fmt.Sprintf("ssh-keyscan -t %s,%s %s 2>/dev/null", keyType, "rsa,ecdsa,ed25519", host)))
	b.WriteString("\n\n**Impact:** Known private key allows impersonation and passive SSH decryption.\n")
	return b.String()
}
