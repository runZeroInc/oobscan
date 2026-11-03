package check

import (
	"context"
	"regexp"
	"slices"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/tlscert"
)

// The ident check reports the device the identify step attributed, as an
// informational finding, whenever a vendor or a non-unknown class was determined.
// It carries
// the identity as structured fields so the detection is captured in both text
// and NDJSON output.
func init() {
	Register(Check{
		Name:        "id",
		Description: "Report the identified device (vendor/product/class) as INFO",
		Applies:     Applicability{CrossVendor: true},
		Category:    "discovery",
		Enabled:     true,
		Run:         runIdent,
	})
}

// RunIdentityReport re-runs the identity reporter ("id") against t and returns
// its finding(s). The scan pipeline uses it to regenerate the lone identity
// finding after a late reclassification (post-battery honeypot detection)
// discards the check battery's now-invalid findings; runIdent reads the current
// t.Identity, so calling it after the reclassification yields the honeypot
// verdict.
func RunIdentityReport(ctx context.Context, t *engine.Target) []engine.Finding {
	return runIdent(ctx, t)
}

func runIdent(ctx context.Context, t *engine.Target) []engine.Finding {
	id := t.Identity
	if id == nil || (id.Vendor == "" && id.Class == engine.ClassUnknown) {
		return nil
	}
	// engine.F drops empty values, so generation/version only appear when the
	// identify step actually fingerprinted them.
	fields := engine.F(
		"class", string(id.Class),
		"vendor", id.Vendor,
		"product", id.Product,
		"generation", deriveGeneration(t, id),
		"version", identVersion(id),
		"confidence", string(id.Confidence))
	// When identify flagged a deception node, surface WHY on the id finding so
	// the operator sees the host was recognized as a honeypot and skipped.
	if id.Attributes != nil {
		if why := id.Attributes["honeypot"]; why != "" {
			fields = append(fields, engine.Field{Key: "honeypot", Val: why})
		}
	}
	return []engine.Finding{{
		Check: "id", Category: "discovery", Risk: "info",
		Fields: fields,
	}}
}

// identGeneration returns the explicitly-fingerprinted device generation when it
// adds information beyond the product string (e.g. product "iDRAC" + generation "9").
func identGeneration(id *engine.Identity) string {
	if id.Generation == "" || id.Generation == id.Product {
		return ""
	}
	return id.Generation
}

var (
	smcGenRe     = regexp.MustCompile(`(?i)\b([XH]1?\d)\b`) // X9, X10, X11, H11, H12
	iloGenRe     = regexp.MustCompile(`(?i)hpe?-ilo-(\d+)`) // HP-iLO-4/2.55 -> 4
	hdrVerRe     = regexp.MustCompile(`/(\d+\.\d[\w.]*)`)   // "HP-iLO-4/2.55" -> 2.55, "Z51/2.22.0" -> 2.22.0
	idracCNRe    = regexp.MustCompile(`(?i)idrac(\d+)`)     // subject CN=iDRAC9... -> 9
	idracCNLower = regexp.MustCompile(`^idrac-[0-9A-Za-z]`) // lowercase factory cert CN (older band)
	idracCNUpper = regexp.MustCompile(`^iDRAC-[0-9A-Za-z]`) // uppercase factory cert CN (newer band)
)

// deriveGeneration returns the device generation, preferring the explicit one
// from identify and otherwise inferring it from sessionless signals that differ
// between a vendor's generations (TLS default-cert product, HTTP Server header,
// RMCP+ cipher set, Redfish presence), so we can tell e.g. an SMC X9 from an X10
// even without a firmware version.
func deriveGeneration(t *engine.Target, id *engine.Identity) string {
	if g := identGeneration(id); g != "" {
		return g
	}
	products := certProducts(t)
	server := id.Attributes["http.server"]
	switch id.Vendor {
	case "supermicro":
		// 1. The shipped/default TLS cert usually encodes the board line ("X10 ATEN").
		for _, p := range products {
			if m := smcGenRe.FindStringSubmatch(p); m != nil {
				return strings.ToUpper(m[1])
			}
		}
		// 2. The Nuvoton WPCM450 web stack is the X9 (pre-ATEN/AST) generation.
		if strings.Contains(server, "WPCM450") {
			return "X9"
		}
		// 3. Coarse: SHA256 RMCP+ (cipher suite 17) or a Redfish service are
		// AST-era (X10 and later); their absence points at the X9/legacy stack.
		if _, redfish := t.Evidenced("redfish"); hasCipherSuite(t, 17) || redfish {
			return "X10+"
		}
		return "X9"
	case "dell":
		// iDRAC default-cert templates name the generation band ("iDRAC6",
		// "iDRAC7/8"); prefer that full label, then fall back to the exact number
		// in the subject CN (CN=iDRAC9-<tag>).
		for _, p := range products {
			low := strings.ToLower(p)
			// A bare "iDRAC" cert product is not a generation label; skip it so
			// CN/SNMP-derived generation can still be surfaced.
			if strings.HasPrefix(low, "idrac") && low != "idrac" {
				return p
			}
		}
		if m := idracCNRe.FindStringSubmatch(certSubjectCN(t)); m != nil {
			return "iDRAC" + m[1]
		}
		cn := certSubjectCN(t)
		newerCN := idracCNUpper.MatchString(cn)
		newerSNMP := idracEngineIDNewer(id.Attributes["snmp.engine_id"])
		olderCN := idracCNLower.MatchString(cn)
		switch {
		case newerCN || newerSNMP:
			return "iDRAC9/10"
		case olderCN:
			return "iDRAC7/8/9"
		}
	case "hpe":
		// HP-iLO-<N>/<ver> server header gives the generation (fallback when
		// /xmldata was unreachable).
		if m := iloGenRe.FindStringSubmatch(server); m != nil {
			return "iLO" + m[1]
		}
	case "lenovo":
		// IMM2 -> XCC -> XCC2 (the Avocent "Z51" Redfish token is XCC2-era).
		switch {
		case strings.Contains(server, "Z51"):
			return "XCC2"
		case strings.Contains(strings.ToLower(server), "imm2"):
			return "IMM2"
		case strings.Contains(server, "XCC") || strings.Contains(server, "Lenovo HTTP"):
			return "XCC"
		}
	}
	return ""
}

// certSubjectCN returns the TLS leaf certificate subject CommonName, if probed.
func certSubjectCN(t *engine.Target) string {
	v, ok := t.Evidenced("tls")
	if !ok {
		return ""
	}
	if ci, ok := v.(*tlscert.CertInfo); ok && ci != nil {
		return ci.SubjectCN
	}
	return ""
}

// hasCipherSuite reports whether the enumerated RMCP+ cipher suites include id.
func hasCipherSuite(t *engine.Target, id int) bool {
	v, ok := t.Evidenced("ipmi.ciphers")
	if !ok {
		return false
	}
	ids, ok := v.([]int)
	if !ok {
		return false
	}
	return slices.Contains(ids, id)
}

// certProducts returns the product labels the TLS fingerprint attributed, most
// specific first (shared-key match, then default-subject, then DN inference).
func certProducts(t *engine.Target) []string {
	v, ok := t.Evidenced("tls")
	if !ok {
		return nil
	}
	ci, ok := v.(*tlscert.CertInfo)
	if !ok || ci == nil {
		return nil
	}
	var out []string
	if ci.SharedKeyMatch != nil {
		out = append(out, ci.SharedKeyMatch.Product)
	}
	if ci.DefaultSubject != nil {
		out = append(out, ci.DefaultSubject.Product)
	}
	if ci.Product != "" {
		out = append(out, ci.Product)
	}
	return out
}

// idracEngineIDNewer reports whether a Dell SNMP engine ID uses net-snmp
// format-4 (MAC-based), whose format byte is 0x04 at hex positions 8:10.
func idracEngineIDNewer(engineID string) bool {
	engineID = strings.ToLower(strings.TrimSpace(engineID))
	if !strings.HasPrefix(engineID, "80001f88") || len(engineID) < 10 {
		return false
	}
	return engineID[8:10] == "04"
}

// identVersion returns the best firmware/version the identify step captured:
// a vendor-specific firmware attribute first, then a version embedded in the
// HTTP Server header (e.g. "HP-iLO-4/2.55" or "Z51/2.22.0").
func identVersion(id *engine.Identity) string {
	for _, k := range []string{"idrac.fw", "ilo.fw", "redfish.fw", "ipmi.fw"} {
		if v := id.Attributes[k]; v != "" {
			return v
		}
	}
	if m := hdrVerRe.FindStringSubmatch(id.Attributes["http.server"]); m != nil {
		return m[1]
	}
	return ""
}
