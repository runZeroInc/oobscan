package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// The serialConsole check covers the serial-over-IP / console-server device
// class (Moxa NPort, Opengear CM/IM/OM, Lantronix SLC/SLB/Spider, Digi
// PortServer/ConnectPort, Perle IOLAN, ZPE Nodegrid); identify forces
// ClassSerialConsole for the vendors it discovers directly (Lantronix
// UDP/30718, Moxa UDP/4800). It fingerprints the appliance from signals
// identify already gathered (vendor slug, HTTP Server header, HTML title) and
// surfaces vulndb console CVEs keyed off this class as candidates.
// No login or vulnerability-triggering request is sent (e.g. the Moxa
// auth-bypass/overflow CVEs) is ever sent; those stay separate, dedicated checks.
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

// oobDeviceExposure is the shared body for the serialConsole and PDU exposure
// checks. It fingerprints the device (best-effort HTTP sweep to populate the
// Server header / title when identify did not), reports the identity, and lists
// the vulndb candidates whose Probe matches this check's fingerprint id.
func oobDeviceExposure(ctx context.Context, t *engine.Target, kind string) []engine.Finding {
	_ = ctx
	// The device identity is already resolved by the identify stage; the
	// fingerprint finding below reads it directly. Do not run the broader HTTP
	// endpoint sweep here: embedded PDU web servers cannot absorb many concurrent
	// connections. APC's specific pre-auth endpoints are confirmed sequentially by
	// pdu.confirm.

	vendor := identityVendor(t)
	product := identityProduct(t)
	port := webPort(t)
	proto := webProto(t)

	var out []engine.Finding

	// 1. Report the fingerprinted appliance as info so the class detection is
	// captured even when nothing else fires. class/vendor/product are labels the
	// identify step derived, so the proof carries what the device actually said
	// to earn them: the identify signals, plus the HTTP Server header and page
	// title when the web surface supplied them.
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

	// Note: fingerprint-derived CVE "candidates" are intentionally not emitted as
	// per-CVE findings here - that was noisy and read as "potential". Confirmable
	// issues are actively verified (pdu.confirm / the checks below).

	return out
}

// signalEvidenceAttrs names the identify attributes each signal source records,
// most specific first. A signal's Detail is the product string the collector
// resolved, and several collectors resolve none -- a Lantronix unit that reports
// no model, an SNMP engine-ID match, a Redfish root with no product. Those
// signals render as "source:vendor" alone, which is the same text on every unit
// of the family and says nothing the label did not. The attributes below are
// what that same collector read off the device, so they stand in for the
// missing detail.
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

// signalEvidenceLimit caps one signal's substitute detail so a long banner
// cannot crowd the other signals out of the summary.
const signalEvidenceLimit = 64

// signalDetailFallback returns the first attribute the signal's collector
// recorded, for signals that carry no product detail of their own.
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

// identitySignalSummary renders the identify signals that produced the device
// label as "source:vendor:detail" entries, so the fingerprint finding records
// the observations behind the label rather than only the label. A signal with
// no detail falls back to what its collector read off the device. Empty parts
// are skipped and the result is capped to one readable field value.
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

// identityAttr reads one identify attribute, tolerating a target with no
// identity.
func identityAttr(t *engine.Target, key string) string {
	if t == nil || t.Identity == nil || t.Identity.Attributes == nil {
		return ""
	}
	return cleanSnippet(t.Identity.Attributes[key])
}

// identityProduct returns the identify step's product label, if any.
func identityProduct(t *engine.Target) string {
	if t.Identity != nil {
		return t.Identity.Product
	}
	return ""
}

// identityVendor returns the identified vendor slug, or "".
func identityVendor(t *engine.Target) string {
	if t.Identity != nil {
		return t.Identity.Vendor
	}
	return ""
}

// classFor returns the identified device class, or ClassUnknown.
func classFor(t *engine.Target) engine.DeviceClass {
	if t.Identity != nil {
		return t.Identity.Class
	}
	return engine.ClassUnknown
}

func init() {
	for _, prefix := range []string{"serialconsole", "pdu"} {
		p := prefix // capture
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
	b.WriteString("\n\n**Impact:** A known host private key permits server impersonation. It does not by itself decrypt recorded SSH sessions that used ephemeral key exchange. Replace the shared host key and verify client trust records.\n")
	return b.String()
}
