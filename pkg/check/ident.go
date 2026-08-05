package check

import (
	"context"
	"regexp"
	"slices"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/tlscert"
)

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

func RunIdentityReport(ctx context.Context, t *engine.Target) []engine.Finding {
	return runIdent(ctx, t)
}

func runIdent(ctx context.Context, t *engine.Target) []engine.Finding {
	id := t.Identity
	if id == nil || (id.Vendor == "" && id.Class == engine.ClassUnknown) {
		return nil
	}

	fields := engine.F(
		"class", string(id.Class),
		"vendor", id.Vendor,
		"product", id.Product,
		"generation", deriveGeneration(t, id),
		"version", identVersion(id),
		"confidence", string(id.Confidence))

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

func identGeneration(id *engine.Identity) string {
	if id.Generation == "" || id.Generation == id.Product {
		return ""
	}
	return id.Generation
}

var (
	smcGenRe     = regexp.MustCompile(`(?i)\b([XH]1?\d)\b`)
	iloGenRe     = regexp.MustCompile(`(?i)hpe?-ilo-(\d+)`)
	hdrVerRe     = regexp.MustCompile(`/(\d+\.\d[\w.]*)`)
	idracCNRe    = regexp.MustCompile(`(?i)idrac(\d+)`)
	idracCNLower = regexp.MustCompile(`^idrac-[0-9A-Za-z]`)
	idracCNUpper = regexp.MustCompile(`^iDRAC-[0-9A-Za-z]`)
)

func deriveGeneration(t *engine.Target, id *engine.Identity) string {
	if g := identGeneration(id); g != "" {
		return g
	}
	products := certProducts(t)
	server := id.Attributes["http.server"]
	switch id.Vendor {
	case "supermicro":

		for _, p := range products {
			if m := smcGenRe.FindStringSubmatch(p); m != nil {
				return strings.ToUpper(m[1])
			}
		}

		if strings.Contains(server, "WPCM450") {
			return "X9"
		}

		if _, redfish := t.Evidenced("redfish"); hasCipherSuite(t, 17) || redfish {
			return "X10+"
		}
		return "X9"
	case "dell":

		for _, p := range products {
			low := strings.ToLower(p)

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

		if m := iloGenRe.FindStringSubmatch(server); m != nil {
			return "iLO" + m[1]
		}
	case "lenovo":

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

func idracEngineIDNewer(engineID string) bool {
	engineID = strings.ToLower(strings.TrimSpace(engineID))
	if !strings.HasPrefix(engineID, "80001f88") || len(engineID) < 10 {
		return false
	}
	return engineID[8:10] == "04"
}

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
