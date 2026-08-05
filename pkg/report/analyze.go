package report

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/guid"
	"github.com/runZeroInc/oobscan/pkg/ilo"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/output"
	"github.com/runZeroInc/oobscan/pkg/scanfile"
	"github.com/runZeroInc/oobscan/pkg/ssh"
)

type Source struct {
	Name     string
	Total    int
	Redacted bool

	vendor     *counter
	class      *counter
	product    *counter
	generation *counter
	osVersion  *counter
	hwProduct  *counter
	portsTCP   *counter
	portsUDP   *counter
	protocols  *counter
	httpServer *counter
	checks     *counter
	risks      *counter

	unclassified *counter
	rakpUsers    *counter
	snmpComm     *counter
	crackMethod  *counter
	crackPass    *counter
	guidFamily   *counter
	guidVendor   *counter
	guidCountry  *counter

	exposureTotals map[string]int
	byVendorExp    map[string]*vendorStat

	resolvedVendor   int
	honeypotHosts    int
	honeypotFindings int

	withCritical int
	withHigh     int
	withMedium   int
	withLow      int
	withNone     int

	bmcSeverity       map[string]int
	rakpHosts         int
	autoCrackedHosts  int
	potCrackedHosts   int
	autoNamedHosts    int
	autoEmptyHosts    int
	potOnlyHosts      int
	crackedTotal      int
	hashRows          int
	scanRowCracks     int
	potRowCracks      int
	immediatePreHosts int
	immediateExtHosts int
	adminHosts        int
	chainedAdminHosts int
	hostReachHosts    int
	escalationOnly    int

	unclassifiedFindings int
	compromiseTotals     map[string]int
	crackVendorPass      map[string]*counter
	patterns             *patternAccum

	serviceHosts      int
	findingHosts      int
	nativeVendorHosts int
	versionHosts      int
	guidHosts         int
	guidDecodedHosts  int
	guidServiceTags   int
	guidSerials       int
	guidCountries     int
	guidNodeMACs      int
	guidModelPrefixes int

	potCheck func(rec *scanfile.Record) []PotCrack
	potLabel string

	addrSeen  int
	addrInRed int
}

type vendorStat struct {
	count int
	exp   map[string]int
}

func NewSource(name string) *Source {
	return &Source{
		Name:             name,
		vendor:           newCounter(),
		class:            newCounter(),
		product:          newCounter(),
		generation:       newCounter(),
		osVersion:        newCounter(),
		hwProduct:        newCounter(),
		portsTCP:         newCounter(),
		portsUDP:         newCounter(),
		protocols:        newCounter(),
		httpServer:       newCounter(),
		checks:           newCounter(),
		risks:            newCounter(),
		unclassified:     newCounter(),
		rakpUsers:        newCounter(),
		snmpComm:         newCounter(),
		crackMethod:      newCounter(),
		crackPass:        newCounter(),
		guidFamily:       newCounter(),
		guidVendor:       newCounter(),
		guidCountry:      newCounter(),
		exposureTotals:   map[string]int{},
		byVendorExp:      map[string]*vendorStat{},
		compromiseTotals: map[string]int{},
		bmcSeverity:      map[string]int{},
		crackVendorPass:  map[string]*counter{},
		patterns:         newPatternAccum(),
	}
}

func (s *Source) Add(rec *scanfile.Record) {
	s.Total++
	s.sniffRedaction(rec)
	if len(rec.Services) > 0 {
		s.serviceHosts++
	}
	if len(rec.Findings) > 0 {
		s.findingHosts++
	}
	if nativeVendor := recordVendor(rec); !strings.EqualFold(nativeVendor, "unknown") && nativeVendor != "" {
		s.nativeVendorHosts++
	}

	slug := vendorSlug(rec)
	vendor := displayVendor(slug)
	class := displayClass(resolvedClass(rec, slug))
	s.vendor.add(vendor)
	s.class.add(class)
	switch slug {
	case "unknown":

	case "honeypot":

		s.honeypotHosts++
	default:
		s.resolvedVendor++
	}

	product := ""
	if p := recordProduct(rec); p != "" {
		s.product.add(p)
		product = strings.TrimSpace(vendor + " " + p)
	}
	if generation := recordGeneration(rec); generation != "" {
		s.generation.add(generation)
	}
	if version := recordVersion(rec); version != "" {
		s.osVersion.add(version)
		s.versionHosts++
	}
	if hw := rec.Attributes["hw_product"]; hw != "" {
		s.hwProduct.add(hw)
	}

	seen := map[string]bool{}
	for k := range rec.Ports {
		port, transport := splitPortKey(k)
		if port == 0 {
			continue
		}
		switch transport {
		case "tcp":
			s.portsTCP.add(strconv.Itoa(port))
		case "udp":
			s.portsUDP.add(strconv.Itoa(port))
		}
		for p := range strings.SplitSeq(rec.Ports[k], ",") {
			if p = canonicalProtocol(strings.TrimSpace(p)); p != "" && !seen[p] {
				seen[p] = true
				s.protocols.add(p)
			}
		}
	}
	for i := range rec.Services {
		if srv := rec.Services[i].Attributes["http.head.server"]; srv != "" {
			s.httpServer.add(srv)
			break
		}
	}

	if isHoneypotRecord(rec) {
		s.honeypotFindings += len(rec.Findings)
		return
	}
	exp := map[string]bool{}
	compromise := map[string]bool{}
	crackMethods := map[string]bool{}
	topRisk := ""
	for i := range rec.Findings {
		f := &rec.Findings[i]
		if f.Check == "" {
			continue
		}
		s.checks.add(f.Check)
		if f.Risk != "" {
			s.risks.add(f.Risk)
		}
		if engine.RiskRank(f.Risk) > engine.RiskRank(topRisk) {
			topRisk = f.Risk
		}

		expOne, pathOne := map[string]bool{}, map[string]bool{}
		scoreCheck(f.Check, expOne)
		scoreCompromiseFinding(f, pathOne)

		if engine.RiskRank(f.Risk) >= engine.RiskRank("medium") && unclassifiedScore(expOne, pathOne) {
			s.unclassifiedFindings++
			s.unclassified.add(f.Check)
		}
		for key := range expOne {
			exp[key] = true
		}
		for key := range pathOne {
			compromise[key] = true
		}
		if method := normalizeCrackMethod(findingField(f, "crackedFrom")); method != "" {
			crackMethods[method] = true
		}

		if f.Check == "ipmi.versions" {
			v := findingField(f, "versions")
			if strings.Contains(v, "1.5") {
				exp["ipmi_1_5"] = true
			}
			if strings.Contains(v, "2.0") {
				exp["ipmi_2_0"] = true
			}
		}
	}
	scoreServiceExposure(rec, exp)
	for method := range crackMethods {
		s.crackMethod.add(method)
	}
	s.observeGUID(rec)
	if rec.Final != nil && rec.Final.TopRisk != "" {
		topRisk = rec.Final.TopRisk
	}
	if class == "BMC" {
		band := topRisk
		switch band {
		case "critical", "high", "medium", "low":
		default:
			band = "none"
		}
		s.bmcSeverity[band]++
	}
	switch topRisk {
	case "critical":
		s.withCritical++
	case "high":
		s.withHigh++
	case "medium":
		s.withMedium++
	case "low":
		s.withLow++
	default:

		s.withNone++
	}

	for i := range rec.RAKP {
		s.rakpUsers.add(displayUser(rec.RAKP[i].Username))
	}
	if len(rec.RAKP) > 0 {
		exp["ipmi_rakp_hash"] = true
		exp["ipmi"] = true
		exp["ipmi_2_0"] = true
		s.rakpHosts++
		s.hashRows += len(rec.RAKP)
	}

	if sids := rakpSessionIDs(rec.RAKP); len(sids) >= 3 {
		if _, weak := ipmi.ClassifySessionIDs(sids); weak {
			exp["ipmi_sid_weak"] = true
		}
	}

	autoCracked := false
	autoNamed := false
	autoEmpty := false
	for i := range rec.RAKP {
		if !isRecoveredPassword(rec.RAKP[i].Cracked) {
			continue
		}
		pw := strings.TrimSpace(rec.RAKP[i].Cracked)
		s.scanRowCracks++
		s.crackPass.add(pw)
		if vc := s.crackVendorPass[vendor]; vc == nil {
			s.crackVendorPass[vendor] = newCounter()
		}
		s.crackVendorPass[vendor].add(pw)
		s.patterns.add(pw, rec.Host, vendor, product)
		autoCracked = true
		if strings.TrimSpace(rec.RAKP[i].Username) == "" {
			autoEmpty = true
		} else {
			autoNamed = true
		}
	}
	if autoCracked {
		exp["ipmi_rakp_cracked"] = true
		s.autoCrackedHosts++
	}
	if autoNamed {
		s.autoNamedHosts++
	}
	if autoEmpty {
		s.autoEmptyHosts++
	}
	potRows := 0
	potNamed := false
	if s.potCheck != nil {
		potCracks := s.potCheck(rec)
		potRows = len(potCracks)

		for _, c := range potCracks {
			s.patterns.add(c.Password, rec.Host, vendor, product)
			if strings.TrimSpace(c.Username) != "" {
				potNamed = true
			}
		}
	}

	if autoNamed || potNamed {
		compromise["rakp_named"] = true
	}
	potCracked := potRows > 0
	if potCracked {
		exp["ipmi_rakp_cracked"] = true
		s.potCrackedHosts++
		s.potRowCracks += potRows
	}
	if potCracked && !autoCracked {
		s.potOnlyHosts++
	}
	if autoCracked || potCracked {
		s.crackedTotal++
	}

	for i := range rec.Findings {
		f := &rec.Findings[i]
		if f.Check == "snmp.defaultCreds" || f.Check == "snmp.vendorCommunity" {
			if c := findingField(f, "community"); c != "" {
				s.snmpComm.add(c)
			}
		}
	}

	vs := s.byVendorExp[vendor]
	if vs == nil {
		vs = &vendorStat{exp: map[string]int{}}
		s.byVendorExp[vendor] = vs
	}
	vs.count++

	for key := range inferExposures(rec, vendor) {
		exp[key] = true
	}
	var mask uint64
	for key := range exp {
		s.exposureTotals[key]++
		vs.exp[key]++
		if idx, ok := exposureOrder[key]; ok {
			mask |= 1 << uint(idx)
		}
	}

	inferred := inferResearchPaths(rec, vendor, exp)
	for key := range inferred {
		compromise[key] = true
	}
	if len(compromise) > 0 {
		for key := range compromise {
			s.compromiseTotals[key]++
		}

		a := classifyAccess(compromise)
		s.immediateExtHosts++
		if a.pre {
			s.immediatePreHosts++
		}
		if a.admin() {
			s.adminHosts++
		}
		if a.chained() {
			s.chainedAdminHosts++
		}
		if a.hostReach() {
			s.hostReachHosts++
		}
		if !a.entry {

			s.escalationOnly++
		}
	}

}

func (s *Source) Finalize() {
	s.Redacted = s.addrSeen > 0 && s.addrInRed == s.addrSeen
}

func recordVendor(rec *scanfile.Record) string {
	if rec.Final != nil && rec.Final.Vendor != "" {
		return rec.Final.Vendor
	}
	if rec.Identity != nil && rec.Identity.Vendor != "" {
		return rec.Identity.Vendor
	}
	if v := rec.Attributes["vendor"]; v != "" {
		return v
	}
	return "unknown"
}

func recordClass(rec *scanfile.Record) string {
	if rec.Final != nil && rec.Final.Class != "" {
		return string(rec.Final.Class)
	}
	if rec.Identity != nil && rec.Identity.Class != "" {
		return string(rec.Identity.Class)
	}
	return "unknown"
}

func isHoneypotRecord(rec *scanfile.Record) bool {
	return recordClass(rec) == "honeypot"
}

func recordProduct(rec *scanfile.Record) string {
	if rec.Final != nil {
		if p := firstNonEmpty(rec.Final.Product, rec.Final.Generation); p != "" {
			return p
		}
	}
	if rec.Identity != nil {
		if p := firstNonEmpty(rec.Identity.Product, rec.Identity.Generation); p != "" {
			return p
		}
	}
	return ""
}

func recordGeneration(rec *scanfile.Record) string {
	if rec.Final != nil && rec.Final.Generation != "" {
		return rec.Final.Generation
	}
	if rec.Identity != nil {
		return rec.Identity.Generation
	}
	return ""
}

func recordVersion(rec *scanfile.Record) string {
	if rec.Final != nil && rec.Final.Version != "" {
		return rec.Final.Version
	}
	for _, attrs := range []map[string]string{
		rec.Attributes,
		func() map[string]string {
			if rec.Identity != nil {
				return rec.Identity.Attributes
			}
			return nil
		}(),
	} {
		for _, key := range []string{"firmwareVersion", "firmware.version", "fwVersion", "os_version"} {
			if value := strings.TrimSpace(attrs[key]); value != "" {
				return value
			}
		}
	}
	for i := range rec.Findings {
		if value := findingField(&rec.Findings[i], "firmwareVersion"); value != "" {
			return value
		}
		if value := findingField(&rec.Findings[i], "iloFirmwareVersion"); value != "" {
			return value
		}
	}
	return ""
}

func resolvedClass(rec *scanfile.Record, vendor string) string {
	if class := recordClass(rec); class != "" && class != "unknown" {
		return class
	}
	if vendor == "honeypot" {
		return "honeypot"
	}
	if recordHasProtocol(rec, "ipmi") || recordHasProtocol(rec, "redfish") {
		return "bmc"
	}
	switch vendor {
	case "hpe", "dell", "supermicro", "ami", "huawei", "lenovo", "ibm", "cisco",
		"intel", "fujitsu", "inspur", "gigabyte", "asrockrack", "asrock", "asus",
		"quanta", "tyan", "oracle", "openbmc", "h3c", "nec", "xfusion", "nvidia":
		return "bmc"
	case "apc", "eaton", "cyberpower", "servertech", "gude", "tripplite":
		return "pdu"
	case "lantronix", "moxa", "opengear", "digi", "perle":
		return "serial"
	case "raritan", "avocent", "pikvm", "nanokvm", "tinypilot", "jetkvm", "blikvm":
		return "kvm"
	}
	return "unknown"
}

func scoreServiceExposure(rec *scanfile.Record, set map[string]bool) {
	if recordHasProtocol(rec, "ipmi") {
		set["ipmi"] = true
	}
	if recordHasProtocol(rec, "snmp3") {
		set["snmp_v3"] = true
	}
	if recordHasProtocol(rec, "vnc") {
		set["kvm_exposed"] = true
		set["vnc_exposed"] = true
	}
	if recordHasProtocol(rec, "redfish") {
		set["redfish_exposed"] = true
	}
	for _, protocol := range []string{"raw-serial", "serial", "lantronix-setup"} {
		if recordHasProtocol(rec, protocol) {
			set["serial_exposed"] = true
			break
		}
	}
}

const smcrakpFixedKeyMarker = "<smcrakp-fixed-key>"

func isRecoveredPassword(cracked string) bool {
	c := strings.TrimSpace(cracked)
	return c != "" && c != smcrakpFixedKeyMarker
}

func canonicalProtocol(p string) string {
	switch p {
	case "snmp1", "snmp2", "snmp3", "snmpv1", "snmpv2", "snmpv2c", "snmpv3":
		return "snmp"
	case "tls", "ssl":
		return "https"
	}
	return p
}

func inferResearchPaths(rec *scanfile.Record, vendor string, exp map[string]bool) map[string]bool {
	out := map[string]bool{}
	slug := strings.ToLower(vendor)
	if slug == "supermicro" {

		for i := range rec.RAKP {
			if rakpRecordUsesSMCRAKPFixedKey(&rec.RAKP[i]) {
				out["smcrakp_bypass"] = true
				break
			}
		}
	}
	return out
}

func inferExposures(rec *scanfile.Record, vendor string) map[string]bool {
	out := map[string]bool{}

	for _, key := range []string{"ssh.hostKey.sha256", "ssh.hostKeyRSA.sha256",
		"ssh.hostKeyDSS.sha256", "ssh.hostKeyECDSA.sha256", "ssh.hostKeyED25519.sha256"} {
		fp := firstServiceAttr(rec, key)
		if fp == "" {
			continue
		}
		if !strings.HasPrefix(fp, "SHA256:") {
			fp = "SHA256:" + fp
		}
		if _, ok := ssh.MatchSharedHostKey(fp); ok {
			out["ssh_shared_key"] = true
			break
		}
	}

	if strings.EqualFold(vendor, "hpe") {
		gen := iloGenerationLabel(recordGeneration(rec), recordProduct(rec))
		fw := recordVersion(rec)
		if gen != "" && fw != "" && len(ilo.MatchCVEs(gen, fw)) > 0 {
			out["ilo_known_cve"] = true
		}
	}
	return out
}

func iloGenerationLabel(parts ...string) string {
	for _, p := range parts {
		if g := ilo.GenerationFromString(p); g != "" {
			return g
		}
	}
	return ""
}

func scoreCompromiseFinding(f *engine.Finding, set map[string]bool) {
	switch f.Check {
	case "ipmi.v20.cipherZero":
		set["cipher_zero"] = true
	case "ipmi.v15.authNoneSession":
		set["ipmi_auth_none"] = true
	case "ipmi.v20.defaultCreds", "ipmi.v15.defaultCreds":
		user := strings.TrimSpace(findingField(f, "username"))
		if user != "" && !strings.EqualFold(user, "(null)") {
			set["ipmi_default_creds"] = true
		}
	case "ipmi.v20.smcrakpBypass":

		if !strings.EqualFold(findingField(f, "exploitable"), "false") {
			set["smcrakp_bypass"] = true
		}
	case "ipmi.ilo.authBypass":

		set["ilo_ipmi_bypass"] = true
	case "ipmi.rakp.state.setupIdentity":

		set["rakp_setup_identity"] = true
	case "ipmi.smc.privEsc":

		set["smc_reserved_role"] = true
	case "http.smc.psBlock":

		set["smc_psblock_creds"] = true
	case "ipmi.netfnOem":

		set["ipmi_oem_preauth"] = true
	case "ipmi.openbmc.rakpAuthBypass":

		if !strings.EqualFold(findingField(f, "authBypassed"), "false") {
			set["openbmc_rakp_bypass"] = true
		}
	case "http.redfish.amiBypass", "http.redfish.ami.cve202334329", "http.redfish.ami.noXffBypass":
		set["ami_redfish_bypass"] = true
	case "tls.mtls.ami.caBypass":
		set["ami_mtls_bypass"] = true
	case "http.ilo.authBypass":
		set["ilo_http_bypass"] = true
	case "ssh.hpe.iloSSHOverflow":
		set["ssh_ilo_overflow"] = true
	case "kvm.vnc.unauth", "ipkvm.noAuth":
		set["kvm_no_auth"] = true
	case "kvm.vnc.defaultCreds":
		set["vnc_default_creds"] = true
	case "kvm.smc.ws.bypass":

		set["smc_kvm_bypass"] = true
	case "kvm.smc.ikvm.sessionHijack":

		set["smc_ikvm_hijack"] = true
	case "amt.authBypass":
		set["amt_auth_bypass"] = true
	case "http.apc.demoBackdoor":
		set["apc_demo_backdoor"] = true
	case "ssh.defaultCreds":
		set["ssh_default_creds"] = true
	default:
		if strings.HasPrefix(f.Check, "http.") && strings.Contains(strings.ToLower(f.Check), "defaultcreds") {
			set["web_default_creds"] = true
		}
	}
}

func normalizeCrackMethod(method string) string {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "default", "defaults":
		return "Default list"
	case "common":
		return "Common list"
	case "permutation":
		return "Permutations"
	case "custom":
		return "Custom list"
	case "online":
		return "Online verification"
	case "straight":
		return "Straight"
	case "md5":
		return "Legacy MD5"
	}
	return ""
}

func (s *Source) observeGUID(rec *scanfile.Record) {
	raw := ""
	family := ""
	vendor := ""
	for i := range rec.Findings {
		if rec.Findings[i].Check != "ipmi.guid" {
			continue
		}
		raw = findingField(&rec.Findings[i], "guid")
		family = findingField(&rec.Findings[i], "family")
		vendor = findingField(&rec.Findings[i], "vendor")
		break
	}
	if raw == "" {
		raw = firstNonEmpty(rec.Attributes["ipmiSystemGuid"], rec.Attributes["ipmi.system.guid"])
	}
	if raw == "" {
		return
	}
	s.guidHosts++
	decoded, err := guid.DecodeHex(raw)
	if err == nil {
		if decoded.Family != "" {
			family = decoded.Family
		}
		if decoded.Vendor != "" && decoded.Vendor != "unknown" {
			vendor = decoded.Vendor
		}
		if _, ok := decoded.Fields["service_tag"]; ok {
			s.guidServiceTags++
		}
		if _, ok := decoded.Fields["serial"]; ok {
			s.guidSerials++
		}
		if country := decoded.Fields["country"]; country != "" {
			s.guidCountries++
			s.guidCountry.add(country)
		}
		if _, ok := decoded.Fields["node_mac"]; ok {
			s.guidNodeMACs++
		}
		if _, ok := decoded.Fields["model_prefix"]; ok {
			s.guidModelPrefixes++
		}
	}
	if family == "" {
		family = "unknown"
	}
	s.guidFamily.add(family)
	if family != "unknown" && family != "short" {
		s.guidDecodedHosts++
	}
	if slug := normalizeVendorSlug(vendor); slug != "" {
		s.guidVendor.add(displayVendor(slug))
	}
}

func normalizeServiceRecord(rec *scanfile.Record) {
	if rec.Host == "" {
		for i := range rec.Services {
			if rec.Services[i].Address != "" {
				rec.Host = rec.Services[i].Address
				break
			}
		}
	}
	if rec.Ports == nil {
		rec.Ports = engine.OpenPorts{}
	}
	for i := range rec.Services {
		svc := &rec.Services[i]
		if svc.Port > 0 && svc.Transport != "" {
			key := strconv.Itoa(svc.Port) + "/" + strings.ToLower(svc.Transport)
			for _, protocol := range svc.Protocols {
				protocol = strings.TrimSpace(protocol)
				if protocol != "" {
					rec.Ports[key] = appendCSVValue(rec.Ports[key], protocol)
				}
			}
		}

		server := serviceHTTPHeader(svc.Summary, "Server")
		auth := serviceHTTPHeader(svc.Summary, "WWW-Authenticate")
		csp := serviceHTTPHeader(svc.Summary, "Content-Security-Policy")
		title := serviceHTMLTitle(svc.Summary)
		sshBanner := ""
		if strings.HasPrefix(strings.TrimSpace(svc.Summary), "SSH-") {
			sshBanner = strings.TrimSpace(strings.SplitN(svc.Summary, "\n", 2)[0])
		}
		if server == "" && auth == "" && csp == "" && title == "" && sshBanner == "" && svc.VHost == "" {
			continue
		}
		if svc.Attributes == nil {
			svc.Attributes = map[string]string{}
		}
		setMissing := func(key, value string) {
			if value != "" && svc.Attributes[key] == "" {
				svc.Attributes[key] = value
			}
		}
		setMissing("http.head.server", server)
		setMissing("http.head.wwwAuthenticate", auth)
		setMissing("http.head.contentSecurityPolicy", csp)
		setMissing("http.title", title)
		setMissing("ssh.banner", sshBanner)
		setMissing("tls.vhost", svc.VHost)
	}
}

func appendCSVValue(csv, value string) string {
	for existing := range strings.SplitSeq(csv, ",") {
		if strings.EqualFold(strings.TrimSpace(existing), value) {
			return csv
		}
	}
	if csv == "" {
		return value
	}
	return csv + "," + value
}

func serviceHTTPHeader(summary, name string) string {
	for line := range strings.SplitSeq(summary, "\n") {
		line = strings.TrimSuffix(line, "\r")
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(key), name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func serviceHTMLTitle(summary string) string {
	lower := strings.ToLower(summary)
	start := strings.Index(lower, "<title")
	if start < 0 {
		return ""
	}
	start = strings.Index(lower[start:], ">") + start
	if start < 0 {
		return ""
	}
	start++
	end := strings.Index(lower[start:], "</title>")
	if end < 0 {
		return ""
	}
	return strings.Join(strings.Fields(summary[start:start+end]), " ")
}

func (s *Source) sniffRedaction(rec *scanfile.Record) {
	consider := func(v string) {
		ip, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(v), "[]"))
		if err != nil {
			return
		}
		s.addrSeen++
		if inRedactionRange(ip) {
			s.addrInRed++
		}
	}
	consider(rec.Host)
}

func inRedactionRange(ip netip.Addr) bool {
	if ip.Is4() {
		b := ip.As4()
		return b[0] == 10 || (b[0] >= 224 && b[0] <= 239)
	}
	b := ip.As16()
	if b[0] == 0xfd {
		return true
	}
	return b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8
}

func findingField(f *engine.Finding, key string) string {
	want := engine.CanonicalFieldKey(key)
	for _, fd := range f.Fields {
		if engine.CanonicalFieldKey(fd.Key) == want && fd.Val != "" {
			return fd.Val
		}
	}
	return ""
}

func displayUser(u string) string {
	if u == "" {
		return "(null)"
	}
	return u
}

func rakpSessionIDs(rows []output.RAKPRecord) []uint32 {
	var out []uint32
	for i := range rows {
		if rows[i].BMCSID != 0 {
			out = append(out, rows[i].BMCSID)
		}
	}
	return out
}

func splitPortKey(k string) (port int, transport string) {
	slash := strings.LastIndexByte(k, '/')
	if slash < 0 {
		if n, err := strconv.Atoi(k); err == nil {
			return n, "tcp"
		}
		return 0, ""
	}
	n, err := strconv.Atoi(k[:slash])
	if err != nil {
		return 0, ""
	}
	return n, k[slash+1:]
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
