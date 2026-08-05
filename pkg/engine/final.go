package engine

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/guid"
)

type Final struct {
	Class      DeviceClass `json:"class"`
	Vendor     string      `json:"vendor,omitempty"`
	Product    string      `json:"product,omitempty"`
	Generation string      `json:"generation,omitempty"`
	Version    string      `json:"version,omitempty"`
	Confidence Confidence  `json:"confidence"`

	Flags map[string]string `json:"flags,omitempty"`

	Findings int    `json:"findingCount"`
	TopRisk  string `json:"topRisk,omitempty"`
}

func (f Final) MarshalJSON() ([]byte, error) {
	type finalJSON struct {
		Class        DeviceClass       `json:"class"`
		Vendor       string            `json:"vendor,omitempty"`
		Product      string            `json:"product,omitempty"`
		Generation   string            `json:"generation,omitempty"`
		Version      string            `json:"version,omitempty"`
		Confidence   Confidence        `json:"confidence"`
		Flags        map[string]string `json:"flags,omitempty"`
		FindingCount int               `json:"findingCount"`
		TopRisk      string            `json:"topRisk,omitempty"`
	}
	return json.Marshal(finalJSON{
		Class:        f.Class,
		Vendor:       f.Vendor,
		Product:      f.Product,
		Generation:   f.Generation,
		Version:      f.Version,
		Confidence:   f.Confidence,
		Flags:        CanonicalStringMap(f.Flags),
		FindingCount: f.Findings,
		TopRisk:      f.TopRisk,
	})
}

type finalFlagRule struct {
	flag    string
	matches []string
}

var finalFlagRules = []finalFlagRule{

	{flag: "rakpHash", matches: []string{"ipmi.v20.rakpHash"}},

	{flag: "defaultCreds", matches: []string{
		"ipmi.v20.defaultCreds", "ipmi.v15.defaultCreds",
		"http.idrac.defaultCreds", "ssh.defaultCreds", "kvm.vnc.defaultCreds",
		"snmp.defaultCreds", "http.apc.defaultCreds", "http.gude.defaultCreds",
	}},

	{flag: "cipherZero", matches: []string{"ipmi.v20.cipherZero"}},

	{flag: "sharedKey", matches: []string{"tls.sharedKey"}},

	{flag: "defaultCert", matches: []string{"tls.defaultCert", "tls.selfSigned"}},

	{flag: "authNone", matches: []string{
		"ipmi.authNull", "ipmi.authAnon", "ipmi.v15.authNoneSession",
	}},

	{flag: "kvm", matches: []string{"kvm."}},

	{flag: "vmedia", matches: []string{"kvm.ami.vmedia"}},

	{flag: "authBypass", matches: []string{
		"tls.mtls.ami.caBypass", "http.ilo.authBypass", "amt.authBypass",
	}},
}

func flagMatch(check string, tokens []string) bool {
	for _, tok := range tokens {
		if tok == "" {
			continue
		}
		if strings.HasSuffix(tok, ".") {
			if strings.HasPrefix(check, tok) {
				return true
			}
			continue
		}
		if check == tok {
			return true
		}
	}
	return false
}

func Finalize(t *Target) *Final {
	f := &Final{Class: ClassUnknown, Confidence: ConfLow}
	if id := t.Identity; id != nil {
		f.Class = id.Class
		f.Vendor = id.Vendor
		f.Product = id.Product
		f.Generation = id.Generation
		f.Confidence = id.Confidence
		if id.Attributes != nil {
			f.Version = versionFromAttrs(id.Attributes)
		}
	}

	findings := t.FindingsSnapshot()

	if f.Vendor == "" {
		if v, p := faviconVendorFromFindings(findings); v != "" {
			f.Vendor, f.Product, f.Confidence = v, p, ConfMedium

			if f.Class == ClassUnknown {
				if c, ok := faviconVendorClass[v]; ok {
					f.Class = c
				}
			}
		}
	}

	if f.Vendor == "" {
		if v, c, ok := protocolVendorFromFindings(findings); ok {
			f.Vendor = v
			if f.Confidence == ConfLow {
				f.Confidence = ConfHigh
			}
			if f.Class == ClassUnknown {
				f.Class = c
			}
		}
	}

	if f.Vendor == "" {
		if v, ok := vendorFieldFromFindings(findings); ok {
			f.Vendor = v
			if f.Confidence == ConfLow {
				f.Confidence = ConfMedium
			}
		}
	}

	attrs := map[string]string(nil)
	if t.Identity != nil {
		attrs = t.Identity.Attributes
	}
	refineGenerationFromFindings(f, findings, attrs)

	if f.Version == "" {
		f.Version = versionFromFindings(findings)
	}

	if f.Product == "" {
		f.Product = productFromFRUFindings(findings)
	}

	if f.Class == ClassUnknown && hasAMTFinding(findings) {
		f.Class = ClassAMT
		if f.Vendor == "" {
			f.Vendor = "intel"
		}
		if f.Confidence == ConfLow {
			f.Confidence = ConfMedium
		}
	}

	flags := map[string]string{}
	topRank := 0
	actionable := 0
	for i := range findings {
		fd := &findings[i]
		risk := fd.Risk
		if risk == "" {
			risk = "none"
		}
		rank := RiskRank(risk)

		if rank < RiskRank("info") {
			continue
		}
		actionable++
		if rank > topRank {
			topRank = rank
			f.TopRisk = risk
		}
		for _, rule := range finalFlagRules {
			if !flagMatch(fd.Check, rule.matches) {
				continue
			}

			if cur, ok := flags[rule.flag]; !ok || RiskRank(risk) > RiskRank(cur) {
				flags[rule.flag] = risk
			}
		}
	}
	f.Findings = actionable
	if len(flags) > 0 {
		f.Flags = flags
	}
	return f
}

func versionFromAttrs(attrs map[string]string) string {
	for _, k := range []string{"idrac.fw", "ilo.fw", "redfish.fw", "ipmi.fw", "device.fw"} {
		if v := attrs[k]; v != "" {
			return v
		}
	}
	return ""
}

func versionFromFindings(findings []Finding) string {
	for _, want := range []string{"ipmi.postAuth.mcInfo", "ipmi.deviceId"} {
		for i := range findings {
			if findings[i].Check != want {
				continue
			}
			if v := findingField(findings[i], "firmwareVersionFull"); v != "" {
				return v
			}
			if v := findingField(findings[i], "firmwareVersion"); v != "" {
				return v
			}
		}
	}
	return ""
}

func hasAMTFinding(findings []Finding) bool {
	for i := range findings {
		switch findings[i].Check {
		case "amt.detected", "amt.authBypass":
			return true
		}
	}
	return false
}

func findingField(f Finding, key string) string {
	for _, fld := range f.Fields {
		if fld.Key == key {
			return fld.Val
		}
	}
	return ""
}

var (
	smcModernTarRe = regexp.MustCompile(`(?i)redfish-(?:metadata|schema) tar .*supermicro`)

	smcModelGenRe = regexp.MustCompile(`(?i)^\s*(X1[0-4]|X[89]|H1[1-3]|M1[12]|B1[0-9])[A-Z0-9]`)

	sshVerRe = regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)
)

func refineGenerationFromFindings(f *Final, findings []Finding, attrs map[string]string) {

	origVendor := f.Vendor
	if (origVendor == "openbmc" || origVendor == "") && smcHardwareFromFindings(findings) {
		f.Vendor = "supermicro"

		if origVendor == "openbmc" || smcIsOpenBMC(findings, attrs) {

			if g := smcModelFromFindings(findings); g != "" {
				f.Generation = g
			} else {
				f.Generation = "X14"
			}
			return
		}
	}
	switch f.Vendor {
	case "supermicro":

		if g := smcModelFromFindings(findings); g != "" {
			f.Generation = g
			break
		}

		if g := smcGenFromGUIDFinding(findings); g != "" {
			f.Generation = g
			break
		}

		best := f.Generation
		upgrade := func(g string) {
			if smcGenRank(g) > smcGenRank(best) {
				best = g
			}
		}
		if smcHasBoardSerialGUID(findings) {

			upgrade("X10+")
		}
		if smcIsOpenBMC(findings, attrs) {

			upgrade("X14")
		}
		if hasSMCModernTar(findings) {

			upgrade("X13+")
		}
		if smcCoreUILogin(findings) {

			upgrade("X11+")
		}
		if g := smcGenBandFromSSH(findings); g != "" {
			upgrade(g)
		}
		f.Generation = best
	case "dell":
		if g := dellGenFromAttrs(attrs); g != "" && preferDellGen(f.Generation, g) {
			f.Generation = g
		}
		if g := dellGenFromSSH(findings); g != "" && preferDellGen(f.Generation, g) {
			f.Generation = g
		}
	}
}

var smcSSHOpenSSHRe = regexp.MustCompile(`OpenSSH[_-](\d+)\.`)

var (
	idracServerGenRe = regexp.MustCompile(`(?i)\b(\d{1,2})G\b`)

	idracGenTokenRe = regexp.MustCompile(`(?i)idrac\s*(\d{1,2})`)
)

func dellGenFromAttrs(attrs map[string]string) string {
	if len(attrs) == 0 {
		return ""
	}
	if g := idracGenFromFW(attrs["idrac.fw"]); g != "" {
		return g
	}
	if g := idracGenFromServerGen(attrs["idrac.serverGen"]); g != "" {
		return g
	}
	if g := idracGenFromToken(attrs["idrac.version"]); g != "" {
		return g
	}
	for _, k := range []string{"redfish.product", "redfishProduct", "http.title"} {
		if g := idracGenFromToken(attrs[k]); g != "" {
			return g
		}
	}
	return ""
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

func idracGenFromServerGen(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	m := idracServerGenRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return ""
	}
	switch {
	case n <= 12:
		return "iDRAC7"
	case n == 13:
		return "iDRAC8"
	case n >= 14 && n <= 16:
		return "iDRAC9"
	case n >= 17:
		return "iDRAC10"
	}
	return ""
}

func idracGenFromToken(s string) string {
	m := idracGenTokenRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return ""
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n < 6 || n > 20 {
		return ""
	}
	if n >= 10 {
		return "iDRAC10"
	}
	return "iDRAC" + strconv.Itoa(n)
}

var faviconVendorClass = map[string]DeviceClass{
	"supermicro": ClassBMC, "dell": ClassBMC, "lenovo": ClassBMC, "fujitsu": ClassBMC,
	"huawei": ClassBMC, "cisco": ClassBMC, "ami": ClassBMC,
	"opengear": ClassSerialConsole, "perle": ClassSerialConsole,
	"raritan": ClassPDU, "cyberpower": ClassPDU,
	"nanokvm": ClassKVM, "jetkvm": ClassKVM, "pikvm": ClassKVM, "blikvm": ClassKVM,
}

func faviconVendorFromFindings(findings []Finding) (vendor, product string) {
	for i := range findings {
		if findings[i].Check != "web.service" {
			continue
		}
		var v, p string
		for _, fld := range findings[i].Fields {
			switch CanonicalFieldKey(fld.Key) {
			case "faviconVendor":
				v = fld.Val
			case "faviconProduct":
				p = fld.Val
			}
		}
		if v != "" {
			return v, p
		}
	}
	return "", ""
}

var protocolVendorChecks = map[string]struct {
	vendor string
	class  DeviceClass
}{
	"udp.moxa.deviceSearch":     {"moxa", ClassSerialConsole},
	"udp.moxa.dsciConfig":       {"moxa", ClassSerialConsole},
	"tcp.moxa.serialBanner":     {"moxa", ClassSerialConsole},
	"udp.lantronix.setup":       {"lantronix", ClassSerialConsole},
	"tcp.lantronix.setupBanner": {"lantronix", ClassSerialConsole},
	"tcp.digi.realportBanner":   {"digi", ClassSerialConsole},
	"udp.digi.addpLeak":         {"digi", ClassSerialConsole},
	"udp.advantech.adamConfig":  {"advantech", ClassSerialConsole},
}

func protocolVendorFromFindings(findings []Finding) (vendor string, class DeviceClass, ok bool) {
	for i := range findings {
		if m, hit := protocolVendorChecks[CanonicalCheckID(findings[i].Check)]; hit {
			return m.vendor, m.class, true
		}
	}
	return "", ClassUnknown, false
}

var vendorSlugFieldChecks = map[string]string{
	"tls.sharedKey":     "vendors",
	"tls.defaultCert":   "vendor",
	"ssh.sharedHostKey": "vendor",
	"ipmi.guid":         "vendor",
	"kvm.usbAnywhere":   "vendor",
	"tcp.telnetBanner":  "vendor",

	"ipmi.deviceId":        "vendor",
	"ipmi.postAuth.mcInfo": "vendor",
	"ipmi.postAuth.fru":    "vendor",
	"kvm.vnc":              "vendor",
}

func vendorFieldFromFindings(findings []Finding) (string, bool) {
	for i := range findings {
		key, hit := vendorSlugFieldChecks[CanonicalCheckID(findings[i].Check)]
		if !hit {
			continue
		}
		v := strings.TrimSpace(findingField(findings[i], key))

		if v == "" || strings.ContainsAny(v, ",;") {
			continue
		}
		v = strings.ToLower(v)
		if v == "unknown" || v == "none" {
			continue
		}
		return v, true
	}
	return "", false
}

func smcGenerationFromModel(model string) string {
	m := strings.TrimSpace(model)
	if m == "" || strings.Contains(strings.ToUpper(m), "ATEN") {
		return ""
	}
	if mm := smcModelGenRe.FindStringSubmatch(m); mm != nil {
		return strings.ToUpper(mm[1])
	}
	return ""
}

func smcModelFromFindings(findings []Finding) string {
	for i := range findings {
		switch findings[i].Check {
		case "http.endpoint", "http.exposure", "http.redfish.defaultCreds":
			for _, key := range []string{"model", "product"} {
				if g := smcGenerationFromModel(findingField(findings[i], key)); g != "" {
					return g
				}
			}
		case "ipmi.postAuth.fru", "ipmi.postAuthEnum":

			for _, key := range []string{"boardProduct", "productName"} {
				if g := smcGenerationFromModel(findingField(findings[i], key)); g != "" {
					return g
				}
			}

			for _, key := range []string{"preview", "fruPreview"} {
				if g := smcGenFromFRUPreview(findingField(findings[i], key)); g != "" {
					return g
				}
			}
		}
	}
	return ""
}

var smcFRUTokenRe = regexp.MustCompile(`(?i)(?:board|product)\[-?\d+\]=([A-Za-z0-9][A-Za-z0-9+._-]*)`)

func smcGenFromFRUPreview(preview string) string {
	for _, m := range smcFRUTokenRe.FindAllStringSubmatch(preview, -1) {
		if g := smcGenerationFromModel(m[1]); g != "" {
			return g
		}
	}
	return ""
}

func smcGenFromGUIDFinding(findings []Finding) string {
	for i := range findings {
		if findings[i].Check != "ipmi.guid" {
			continue
		}
		if g := guid.SMCGenerationFromModelPrefix(findingField(findings[i], "modelPrefix")); g != "" {
			return g
		}
	}
	return ""
}

func smcHasBoardSerialGUID(findings []Finding) bool {
	for i := range findings {
		if findings[i].Check == "ipmi.guid" && findingField(findings[i], "family") == "smc-board-serial" {
			return true
		}
	}
	return false
}

func productFromFRUFindings(findings []Finding) string {
	for i := range findings {
		if findings[i].Check != "ipmi.postAuth.fru" {
			continue
		}
		for _, key := range []string{"productName", "boardProduct"} {
			if v := strings.TrimSpace(findingField(findings[i], key)); v != "" {
				return v
			}
		}
	}
	return ""
}

func smcHardwareFromFindings(findings []Finding) bool {
	for i := range findings {
		switch findings[i].Check {
		case "ipmi.postAuth.mcInfo":
			switch findingField(findings[i], "manufacturerId") {
			case "10876", "21317":
				return true
			}
			if isSupermicroName(findingField(findings[i], "manufacturer")) {
				return true
			}
		case "ipmi.postAuth.fru":
			if isSupermicroName(findingField(findings[i], "boardMfg")) ||
				isSupermicroName(findingField(findings[i], "productMfg")) {
				return true
			}
		}
	}
	return false
}

func isSupermicroName(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.Contains(s, "super micro") || strings.Contains(s, "supermicro")
}

func smcIsOpenBMC(findings []Finding, attrs map[string]string) bool {
	if attrs != nil && strings.Contains(strings.ToLower(attrs["http.server"]), "bmcweb") {
		return true
	}
	for i := range findings {
		if findings[i].Check == "web.service" &&
			strings.Contains(strings.ToLower(findingField(findings[i], "server")), "bmcweb") {
			return true
		}
	}
	return false
}

func smcCoreUILogin(findings []Finding) bool {
	for i := range findings {
		switch findings[i].Check {
		case "web.service":
			if strings.EqualFold(strings.TrimSpace(findingField(findings[i], "title")), "Supermicro BMC Login") {
				return true
			}
		case "http.exposure", "http.endpoint":

			if fp := findingField(findings[i], "fingerprint"); strings.Contains(fp, "smc-ui:coreui") || strings.Contains(fp, "smc-ui:kendo") {
				return true
			}
		}
	}
	return false
}

func smcGenRank(gen string) int {
	switch gen {
	case "":
		return 0
	case "X9", "X10":
		return 1
	case "X10+":
		return 2
	case "X11+":
		return 3
	case "X12+":
		return 4
	case "X13+":
		return 5
	default:
		return 6
	}
}

func hasSMCModernTar(findings []Finding) bool {
	for i := range findings {
		if findings[i].Check != "http.exposure" {
			continue
		}
		for _, fld := range findings[i].Fields {
			if fld.Key == "fingerprint" && smcModernTarRe.MatchString(fld.Val) {
				return true
			}
		}
	}
	return false
}

func dellGenFromSSH(findings []Finding) string {
	for i := range findings {
		if findings[i].Check != "ssh.version" {
			continue
		}
		banner := ""
		for _, fld := range findings[i].Fields {
			if fld.Key == "banner" || fld.Key == "product" {
				banner = fld.Val
			}
			if fld.Key == "banner" {
				break
			}
		}
		if banner == "" {
			continue
		}
		low := strings.ToLower(banner)
		if strings.Contains(low, "debian") || strings.Contains(low, "ubuntu") {
			return ""
		}
		if strings.Contains(strings.ToUpper(banner), "SSHSERVER") {
			return "iDRAC7"
		}
		m := sshVerRe.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		switch m[1] {
		case "5", "6":
			return "iDRAC7"
		case "7":
			if m[2] == "4" {
				return "iDRAC8/9"
			}
			return "iDRAC9"
		case "8":
			return "iDRAC9"
		case "9", "10":
			return "iDRAC9/10"
		}
	}
	return ""
}

func preferDellGen(cur, ssh string) bool {
	if cur == "" || cur == "0" || cur == "iDRAC" {
		return true
	}

	return strings.Contains(cur, "/")
}

func (f *Final) FlagsString() string {
	if len(f.Flags) == 0 {
		return ""
	}
	keys := make([]string, 0, len(f.Flags))
	for k := range f.Flags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, CanonicalFieldKey(k)+"="+f.Flags[k])
	}
	return strings.Join(parts, " ")
}

func smcGenBandFromSSH(findings []Finding) string {
	for i := range findings {
		if findings[i].Check != "ssh.version" {
			continue
		}
		banner := findingField(findings[i], "banner")
		if banner == "" {
			banner = findingField(findings[i], "product")
		}
		if banner == "" {
			continue
		}
		m := smcSSHOpenSSHRe.FindStringSubmatch(banner)
		if m == nil {

			continue
		}
		major, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		switch {
		case major >= 9:
			return "X13+"
		case major == 8:
			return "X12+"
		}
	}
	return ""
}
