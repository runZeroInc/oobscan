package identify

import (
	"regexp"
	"slices"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/guid"
	"github.com/runZeroInc/oobscan/pkg/tlscert"
)

// This file derives the device generation at identify time from sessionless
// signals a stage-1 probe already collected (HTTP Server header, TLS cert product
// label, RMCP+ cipher suites, Redfish presence, iLO/iDRAC probe results). Setting
// Identity.Generation here lets both the stage-1 `id` reporter and the post-check
// `id.final` record inherit it without re-deriving. Where the sessionless fields
// cannot split a generation, the coarsest defensible label is returned.

var (
	// lighttpd version -> Supermicro board era. 1.4.23 is the WPCM450/X9 web
	// stack; 1.4.35 is the AST2400/AST2500 ATEN stack (X10/X11 era).
	smcLighttpdX9  = regexp.MustCompile(`(?i)^lighttpd/1\.4\.23\b`)
	smcLighttpdX10 = regexp.MustCompile(`(?i)^lighttpd/1\.4\.(?:32|35)\b`)

	iloHdrGenRe = regexp.MustCompile(`(?i)hpe?-ilo-(\d+)`) // "HP-iLO-4/2.55" -> 4
	idracCNGen  = regexp.MustCompile(`(?i)idrac(\d+)`)     // CN=iDRAC9-<tag> -> 9
	// ProLiant system generation names map to the iLO generation that manages
	// them (Gen8/Gen9 -> iLO4, Gen10 -> iLO5, Gen11 -> iLO6). This is the
	// sessionless seed when /xmldata and the SSDP HP-iLO-N banner are absent
	// but Redfish exposes the system product ("ProLiant DL380 Gen10").
	proLiantGenRe = regexp.MustCompile(`(?i)\bgen(1[01]|[89])\b`)

	// iDRAC factory-cert CN casing tracks the firmware era: the newer firmware
	// changed the leaf CN from lowercase "idrac-<tag>" (iDRAC7/8/9) to uppercase
	// "iDRAC-<tag>" (iDRAC9-late/10).
	idracCNLower = regexp.MustCompile(`^idrac-[0-9A-Za-z]`)  // idrac-<tag> (older)
	idracCNUpper = regexp.MustCompile(`^iDRAC-[0-9A-Za-z]`)  // iDRAC-<tag> (newer)
	idrac7CertRe = regexp.MustCompile(`(?i)^iDRAC7 default`) // "iDRAC7 default certificate"

	// Lenovo XCC generation is in the login <title>: "Lenovo XClarity Controller 2"
	// -> XCC2, "... 3" -> XCC3. The Server header is shared across generations.
	xccTitleGenRe = regexp.MustCompile(`(?i)XClarity Controller\s*([23])\b`)
	// Fujitsu iRMC generation is in the Server header ("iRMC S4/S5/S6 Webserver")
	// and the older S2/S3 login <title> ("ServerView ... iRMC S2 Web Server").
	irmcGenRe = regexp.MustCompile(`(?i)\biRMC S(\d)\b`)
)

// refineGeneration fills or upgrades a.generation-derived Identity.Generation
// using sessionless evidence, when the collectors did not already attribute one.
// It is called from resolve() after the best candidate is chosen. It never
// downgrades an explicitly-probed generation (iLO /xmldata, iDRAC banner).
func refineGeneration(t *engine.Target, id *engine.Identity) {
	if id == nil || id.Vendor == "" {
		return
	}
	// An explicit, probe-derived generation (from collectILO/collectIDRAC/
	// collectRedfish) is authoritative - leave it.
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
			// ProLiant Gen8/Gen9 -> iLO4, Gen10 -> iLO5, Gen11 -> iLO6.
			switch m[1] {
			case "10":
				id.Generation = "iLO5"
			case "11":
				id.Generation = "iLO6"
			default: // 8, 9
				id.Generation = "iLO4"
			}
		}
	case "lenovo":
		// The login title separates XCC2/XCC3; fall back to Server-header tells.
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
		// iBMC major version -> board generation (V3/V5/V6). Filled by
		// refineGenerationFinal from the Server header version when present.
		id.Generation = huaweiGeneration(id)
	}
}

// supermicroGeneration classifies the SMC generation from the sessionless signals
// available at identify time. The authoritative modern-Redfish tell and the
// post-auth board SKU are only observed later, so a bare-IPMI box is refined
// further in engine.Finalize (refineGenerationFromFindings).
//
// The shipped TLS cert product label ("X10 ATEN") is a shared cert template that
// is byte-identical across X10..X14/H13 boards. It names the cert, not the board,
// so it must not be used for generation.
func supermicroGeneration(t *engine.Target, server string) string {
	// 1. The GUID board-code prefix (e.g. "F401MS") is the most reliable pre-auth
	// generation signal: it derives from the actual board model, not a shared
	// template. A catalogued code pins the exact generation.
	code, boardSerial := smcGUIDCode(t)
	if code != "" {
		return code
	}
	// 2. lighttpd version splits X9 (1.4.23) from X10-era (1.4.32/1.4.35).
	switch {
	case smcLighttpdX9.MatchString(server):
		return "X9"
	case smcLighttpdX10.MatchString(server):
		return "X10"
	}
	// 3. The Nuvoton WPCM450 web stack is the X9 (pre-ATEN/AST) generation.
	if strings.Contains(server, "WPCM450") {
		return "X9"
	}
	// 4. An uncatalogued smc-board-serial GUID is still an AST-era ATEN board, so
	// it is X10 or newer (engine.Finalize upgrades the band from coreui/Redfish).
	// A SHA256 RMCP+ cipher suite (17) or a Redfish service says the same.
	if _, redfishUp := t.Evidenced("redfish"); boardSerial || hasCipherSuite(t, 17) || redfishUp {
		return "X10+"
	}
	return ""
}

// smcGUIDCode returns the exact generation for a catalogued Supermicro board-code
// prefix in the pre-auth System GUID, plus whether the GUID is the smc-board-serial
// family at all (so the caller can apply the coarse "X10+" AST floor for an
// uncatalogued code).
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

// dellGeneration classifies the iDRAC generation from sessionless signals, in
// order: default-cert product band, explicit iDRAC number in the subject CN, CN
// casing, the SNMP engine ID byte-5 format marker, then firmware version. The
// iDRAC probe's own generation is preferred upstream; this is the fallback. The
// SSH banner, the strongest signal, is only observed by the ssh.version check and
// applied later in engine.Finalize (refineGenerationFromFindings).
func dellGeneration(t *engine.Target, id *engine.Identity, server string) string {
	for _, p := range certProducts(t) {
		low := strings.ToLower(p)
		// bmcfp's Dell x509 rule can yield a bare "iDRAC" product label from the
		// cert subject DN; that proves vendor but not generation. Skip that generic
		// label so CN casing / SNMP engine-id / firmware can still derive a band.
		if strings.HasPrefix(low, "idrac") && low != "idrac" {
			return p
		}
	}
	cn := certSubjectCN(t)
	// Explicit generation number in the CN (CN=iDRAC9-<tag>) wins.
	if m := idracCNGen.FindStringSubmatch(cn); m != nil {
		return "iDRAC" + m[1]
	}
	if idrac7CertRe.MatchString(cn) {
		return "iDRAC7"
	}
	// Firmware version, if it was ever captured (rare in practice).
	if g := idracGenFromFW(id.Attributes["idrac.fw"]); g != "" {
		return g
	}
	// CN casing + SNMP engine-ID format together separate the older 7/8/9-early
	// band from the newer 9-late/10 band. Uppercase "iDRAC-" CN or the net-snmp
	// format-4 (MAC-based) engine ID (byte-5 == 0x04) are newer-firmware tells.
	newerCN := idracCNUpper.MatchString(cn)
	newerSNMP := idracEngineIDNewer(id.Attributes["snmp.engine_id"])
	olderCN := idracCNLower.MatchString(cn)
	switch {
	case newerCN || newerSNMP:
		return "iDRAC9/10" // 9-late or 10; not separable without fw/Redfish product
	case olderCN:
		return "iDRAC7/8/9" // lowercase factory cert: the older long-lived band
	}
	if strings.Contains(strings.ToLower(server), "appweb") {
		return "iDRAC6/7" // Mbedthis-Appweb era (rare/none in practice for real Dell)
	}
	return ""
}

// idracEngineIDNewer reports whether a Dell SNMP engine ID uses the net-snmp
// format-4 (MAC-based) encoding, whose 5th byte is 0x04 - a newer-firmware
// (iDRAC9-late/10) tell. The older text format (byte-5 == 0x80) returns false.
// The engine ID is the net-snmp PEN prefix "80001f88" followed by the format
// byte; byte-5 is hex chars 8-9.
func idracEngineIDNewer(engineID string) bool {
	engineID = strings.ToLower(strings.TrimSpace(engineID))
	if !strings.HasPrefix(engineID, "80001f88") || len(engineID) < 10 {
		return false
	}
	return engineID[8:10] == "04"
}

// idracGenFromFW maps an iDRAC firmware major version to its generation: 1.x ->
// iDRAC7, 2.x -> iDRAC8, 3.x-7.x -> iDRAC9, >=8.x -> iDRAC10. The whole 3-7 band
// is iDRAC9 because Dell bumped the firmware major across 14G/15G/16G without
// changing the controller generation.
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

// iBMCVerRe pulls the iBMC firmware version out of the UPnP Server header
// ("UPnP/2.0 iBMC/<ver> ProductName/..."), per the recog http_servers rule.
var iBMCVerRe = regexp.MustCompile(`(?i)\biBMC/([\d.]+)`)

// huaweiGeneration maps the iBMC board generation from the firmware version the
// UPnP Server header reports. iBMC V3 maps to firmware 3.x; V5 maps loosely to
// firmware 5.x/6.x.
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

// xccTitleGen returns "XCC2"/"XCC3" from a Lenovo XClarity Controller login
// title, or "" for gen1 (no number) and non-XCC titles.
func xccTitleGen(title string) string {
	if m := xccTitleGenRe.FindStringSubmatch(title); m != nil {
		return "XCC" + m[1]
	}
	return ""
}

// irmcGen returns the Fujitsu iRMC generation ("iRMC S4".."iRMC S6", or the
// older "iRMC S2"/"iRMC S3") from the Server header (preferred) or login title.
func irmcGen(server, title string) string {
	if m := irmcGenRe.FindStringSubmatch(server); m != nil {
		return "iRMC S" + m[1]
	}
	if m := irmcGenRe.FindStringSubmatch(title); m != nil {
		return "iRMC S" + m[1]
	}
	return ""
}

// certProducts returns the product labels the TLS fingerprint attributed, most
// specific first (shared-key match, default-subject, then DN inference). Mirrors
// the reader in pkg/check/ident.go so identify can classify without it.
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
