package identify

import (
	"regexp"
	"slices"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/guid"
	"github.com/runZeroInc/oobscan/pkg/tlscert"
)

var (
	smcLighttpdX9  = regexp.MustCompile(`(?i)^lighttpd/1\.4\.23\b`)
	smcLighttpdX10 = regexp.MustCompile(`(?i)^lighttpd/1\.4\.(?:32|35)\b`)

	iloHdrGenRe = regexp.MustCompile(`(?i)hpe?-ilo-(\d+)`)
	idracCNGen  = regexp.MustCompile(`(?i)idrac(\d+)`)

	proLiantGenRe = regexp.MustCompile(`(?i)\bgen(1[01]|[89])\b`)

	idracCNLower = regexp.MustCompile(`^idrac-[0-9A-Za-z]`)
	idracCNUpper = regexp.MustCompile(`^iDRAC-[0-9A-Za-z]`)
	idrac7CertRe = regexp.MustCompile(`(?i)^iDRAC7 default`)

	xccTitleGenRe = regexp.MustCompile(`(?i)XClarity Controller\s*([23])\b`)

	irmcGenRe = regexp.MustCompile(`(?i)\biRMC S(\d)\b`)
)

func refineGeneration(t *engine.Target, id *engine.Identity) {
	if id == nil || id.Vendor == "" {
		return
	}

	if id.Generation != "" && id.Generation != id.Product {
		return
	}
	server := ""
	title := ""
	redfishProduct := ""
	if id.Attributes != nil {
		server = id.Attributes["http.server"]
		title = id.Attributes["http.title"]
		redfishProduct = id.Attributes["redfish.product"]
		if redfishProduct == "" {
			redfishProduct = id.Attributes["redfishProduct"]
		}
	}
	switch id.Vendor {
	case "supermicro":
		id.Generation = supermicroGeneration(t, server)
	case "dell":
		if g := dellGeneration(t, id, server); g != "" {
			id.Generation = g
		}
	case "hpe":
		if m := iloHdrGenRe.FindStringSubmatch(server); m != nil {
			id.Generation = "iLO" + m[1]
		} else if m := proLiantGenRe.FindStringSubmatch(redfishProduct); m != nil {

			switch m[1] {
			case "10":
				id.Generation = "iLO5"
			case "11":
				id.Generation = "iLO6"
			default:
				id.Generation = "iLO4"
			}
		}
	case "lenovo":

		if g := xccTitleGen(title); g != "" {
			id.Generation = g
		} else if strings.Contains(server, "Z51") {
			id.Generation = "XCC2"
		} else if strings.Contains(strings.ToLower(server), "imm2") {
			id.Generation = "IMM2"
		} else if strings.Contains(server, "XCC") || strings.Contains(server, "Lenovo HTTP") {
			id.Generation = "XCC"
		}
	case "fujitsu":
		if g := irmcGen(server, title); g != "" {
			id.Generation = g
		}
	case "huawei":

		id.Generation = huaweiGeneration(id)
	}
}

func supermicroGeneration(t *engine.Target, server string) string {

	code, boardSerial := smcGUIDCode(t)
	if code != "" {
		return code
	}

	switch {
	case smcLighttpdX9.MatchString(server):
		return "X9"
	case smcLighttpdX10.MatchString(server):
		return "X10"
	}

	if strings.Contains(server, "WPCM450") {
		return "X9"
	}

	if _, redfishUp := t.Evidenced("redfish"); boardSerial || hasCipherSuite(t, 17) || redfishUp {
		return "X10+"
	}
	return ""
}

func smcGUIDCode(t *engine.Target) (gen string, boardSerial bool) {
	v, ok := t.Evidenced("guid")
	if !ok {
		return "", false
	}
	g, ok := v.(*guid.Result)
	if !ok || g == nil {
		return "", false
	}
	boardSerial = g.Family == "smc-board-serial"
	if g.Fields != nil {
		gen = guid.SMCGenerationFromModelPrefix(g.Fields["model_prefix"])
	}
	return gen, boardSerial
}

func dellGeneration(t *engine.Target, id *engine.Identity, server string) string {
	for _, p := range certProducts(t) {
		low := strings.ToLower(p)

		if strings.HasPrefix(low, "idrac") && low != "idrac" {
			return p
		}
	}
	cn := certSubjectCN(t)

	if m := idracCNGen.FindStringSubmatch(cn); m != nil {
		return "iDRAC" + m[1]
	}
	if idrac7CertRe.MatchString(cn) {
		return "iDRAC7"
	}

	if g := idracGenFromFW(id.Attributes["idrac.fw"]); g != "" {
		return g
	}

	newerCN := idracCNUpper.MatchString(cn)
	newerSNMP := idracEngineIDNewer(id.Attributes["snmp.engine_id"])
	olderCN := idracCNLower.MatchString(cn)
	switch {
	case newerCN || newerSNMP:
		return "iDRAC9/10"
	case olderCN:
		return "iDRAC7/8/9"
	}
	if strings.Contains(strings.ToLower(server), "appweb") {
		return "iDRAC6/7"
	}
	return ""
}

func idracEngineIDNewer(engineID string) bool {
	engineID = strings.ToLower(strings.TrimSpace(engineID))
	if !strings.HasPrefix(engineID, "80001f88") || len(engineID) < 10 {
		return false
	}
	return engineID[8:10] == "04"
}

func idracGenFromFW(fw string) string {
	fw = strings.TrimSpace(fw)
	if fw == "" {
		return ""
	}
	major := fw
	if i := strings.IndexByte(fw, '.'); i > 0 {
		major = fw[:i]
	}
	switch major {
	case "1":
		return "iDRAC7"
	case "2":
		return "iDRAC8"
	case "3", "4", "5", "6", "7":
		return "iDRAC9"
	case "8", "9", "10":
		return "iDRAC10"
	}
	return ""
}

var iBMCVerRe = regexp.MustCompile(`(?i)\biBMC/([\d.]+)`)

func huaweiGeneration(id *engine.Identity) string {
	server := ""
	if id.Attributes != nil {
		server = id.Attributes["http.server"]
	}
	m := iBMCVerRe.FindStringSubmatch(server)
	if m == nil {
		return ""
	}
	ver := m[1]
	major := ver
	if i := strings.IndexByte(ver, '.'); i > 0 {
		major = ver[:i]
	}
	switch major {
	case "2", "3":
		return "V3"
	case "5", "6":
		return "V5"
	}
	return ""
}

func xccTitleGen(title string) string {
	if m := xccTitleGenRe.FindStringSubmatch(title); m != nil {
		return "XCC" + m[1]
	}
	return ""
}

func irmcGen(server, title string) string {
	if m := irmcGenRe.FindStringSubmatch(server); m != nil {
		return "iRMC S" + m[1]
	}
	if m := irmcGenRe.FindStringSubmatch(title); m != nil {
		return "iRMC S" + m[1]
	}
	return ""
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
