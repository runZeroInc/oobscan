package engine

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/guid"
)

// Final is the post-check aggregate identity of a host (the "id.final" record):
// resolved vendor/product/generation/version plus summary flags read back out of
// the findings the checks produced.
//
// Finalize neither re-probes nor re-computes exposure. Every flag is a projection
// of a finding a check emitted during this scan (see finalFlagRules), so id.final
// cannot disagree with the per-check findings it summarizes.
type Final struct {
	Class      DeviceClass `json:"class"`
	Vendor     string      `json:"vendor,omitempty"`
	Product    string      `json:"product,omitempty"`
	Generation string      `json:"generation,omitempty"`
	Version    string      `json:"version,omitempty"` // firmware / software version, when captured
	Confidence Confidence  `json:"confidence"`

	// Flags are the derived boolean/summary signals, keyed by a stable short
	// name (rakpHash, defaultCreds, cipherZero, sharedKey, authNone, kvm,
	// vmedia, ...). A flag is present only when a finding backed it; the value is
	// the highest risk the backing finding carried ("critical".."info"), so a
	// consumer can both test presence and rank severity without re-reading every
	// finding. Rendered in output as sorted key=risk pairs.
	Flags map[string]string `json:"flags,omitempty"`

	// Findings is the count of actionable (>= info) findings on the host, and
	// TopRisk is the single most-severe risk level observed, so a fleet view can
	// sort/triage on id.final alone.
	Findings int    `json:"findingCount"`
	TopRisk  string `json:"topRisk,omitempty"`
}

// MarshalJSON renders Final with camelCase flag names while preserving the
// internal rule names used by Finalize.
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

// finalFlagRule maps a summary flag name to the finding checks that, when
// present at >= info risk, set it. Matching is by exact check name or by dotted
// prefix (a trailing "." on the token). The point is to read the flags back out
// of the existing findings rather than re-deriving exposure from raw evidence,
// so id.final stays a faithful projection of what the checks concluded.
type finalFlagRule struct {
	flag    string
	matches []string // exact check name, or "prefix." for a dotted-prefix match
}

// finalFlagRules is the projection table: each headline OOB weakness maps to the
// check(s) that confirm it. Keep these names aligned with the check registry; a
// rename there silently drops a flag. Three easy mistakes:
//   - rakpHash is offline-crackable material, not proof of live access. The
//     live-access signals are defaultCreds / cipherZero / authNoneSession, kept as
//     separate flags so a consumer can tell them apart.
//   - KVM auth exposure surfaces as kvm.vnc, not ipkvm.*; the other kvm.* checks
//     are info-only reachability probes.
//   - authBypass covers only the mTLS shipped-CA bypass (tls.mtls.ami.caBypass).
//     The header-spoof variants are their own critical findings and stay out of the
//     flag so it does not double-count the same AMI weakness.
var finalFlagRules = []finalFlagRule{
	// RAKP-2 HMAC leak (offline-crackable password hash), the IPMI 2.0 flaw.
	{flag: "rakpHash", matches: []string{"ipmi.v20.rakpHash"}},
	// A working default credential confirmed by live login or crypto proof.
	{flag: "defaultCreds", matches: []string{
		"ipmi.v20.defaultCreds", "ipmi.v15.defaultCreds",
		"http.idrac.defaultCreds", "ssh.defaultCreds", "kvm.vnc.defaultCreds",
		"snmp.defaultCreds", "http.apc.defaultCreds", "http.gude.defaultCreds",
	}},
	// RMCP+ cipher suite 0 (auth bypass): a no-auth session established.
	{flag: "cipherZero", matches: []string{"ipmi.v20.cipherZero"}},
	// A shipped/shared private key served on TLS (cross-unit key reuse).
	{flag: "sharedKey", matches: []string{"tls.sharedKey"}},
	// A default/self-signed factory certificate (weaker than sharedKey).
	{flag: "defaultCert", matches: []string{"tls.defaultCert", "tls.selfSigned"}},
	// Passwordless IPMI access: null/anonymous 1.5 auth or a no-auth 1.5 session.
	{flag: "authNone", matches: []string{
		"ipmi.authNull", "ipmi.authAnon", "ipmi.v15.authNoneSession",
	}},
	// KVM / video-redirection reachable (kvm.vnc critical = default creds too).
	{flag: "kvm", matches: []string{"kvm."}},
	// Virtual-media exposure (BMC virtual CD/USB reachable).
	{flag: "vmedia", matches: []string{"kvm.ami.vmedia"}},
	// A pre-auth Redfish/HTTP/AMT auth-bypass (AMI shipped-CA mTLS, iLO, AMT).
	{flag: "authBypass", matches: []string{
		"tls.mtls.ami.caBypass", "http.ilo.authBypass", "amt.authBypass",
	}},
}

// flagMatch reports whether a check name matches a rule token: exact name, or a
// dotted-prefix token ("kvm." matches "kvm.anything").
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

// Finalize builds the id.final record for a completed target. It runs after all
// checks so it can read t.Findings; it never re-probes. A nil identity yields a
// low-confidence unknown record so every scanned host still gets one row.
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

	// If identify could not attribute a vendor, adopt the one the favicon
	// fingerprint gave us. Favicons are OEM-rebrandable, so this only fills a blank
	// vendor and lands at medium confidence.
	if f.Vendor == "" {
		if v, p := faviconVendorFromFindings(findings); v != "" {
			f.Vendor, f.Product, f.Confidence = v, p, ConfMedium
			// The favicon also implies the device class (all favicon-attributable
			// vendors are OOB devices); adopt it only when identify left the class
			// unknown, so we never contradict a real class attribution.
			if f.Class == ClassUnknown {
				if c, ok := faviconVendorClass[v]; ok {
					f.Class = c
				}
			}
		}
	}

	// Adopt the vendor implied by a vendor-unique protocol response when identify
	// left it blank. Unlike a favicon this is not rebrandable, so confidence is high.
	// Only fills a blank vendor, and only fills the class when identify left it unknown.
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
	// Then a vendor slug carried in a trusted finding field (shipped shared key SPKI,
	// default cert, IPMI GUID PEN, ...). Vendor only: these signals name the maker
	// without implying a device class, so the class is left for identify to decide.
	if f.Vendor == "" {
		if v, ok := vendorFieldFromFindings(findings); ok {
			f.Vendor = v
			if f.Confidence == ConfLow {
				f.Confidence = ConfMedium
			}
		}
	}

	// Refine the generation using signals only a check could observe (the SSH
	// banner, the Supermicro Redfish metadata-tar exposure). identify already set
	// a sessionless baseline; this upgrades it where a finding is more specific.
	attrs := map[string]string(nil)
	if t.Identity != nil {
		attrs = t.Identity.Attributes
	}
	refineGenerationFromFindings(f, findings, attrs)

	// Version from a CHECK-phase signal when identify's sessionless attributes
	// left it blank. The main beneficiary is Supermicro (17k+ BMCs, ~0% version):
	// ATEN/SMC silently drop the sessionless Get Device ID that fills ipmi.fw, so
	// the only firmware we ever see is the authenticated mc-info revision from a
	// cracked default credential. Record it here so those hosts carry a version.
	if f.Version == "" {
		f.Version = versionFromFindings(findings)
	}

	// Post-auth FRU carries the exact hardware model, which identify (sessionless)
	// never sees. For non-SMC BMCs this is the only place the make/model appears
	// (Inspur SA5280M6, HPE ProLiant DL365 Gen11, Dell/Silicom VEP-4600, Intel
	// SE7320SP2, IBM System x3650 M4). Fill a blank Product so every inventoried
	// host carries its model; SMC board SKUs already feed the generation refinement
	// above, so this only fills what identify left empty.
	if f.Product == "" {
		f.Product = productFromFRUFindings(findings)
	}

	// Promote to the AMT class when Intel AMT was detected/confirmed but identify
	// left the host unclassified. The amt.detected / amt.authBypass checks run
	// after identify (a cheap TCP/16992 probe on every host), so the sessionless
	// class never saw them - leaving hundreds of AMT boxes as "unknown". Only fill
	// a blank class; never override a positively-attributed one (a vPro server
	// board legitimately identified as a BMC stays a BMC).
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
		// Only findings that actually reported something (>= info) count as
		// evidence; a check that ran clean ("none") must not raise a flag.
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
			// Keep the highest risk seen for this flag (a flag can be backed by
			// more than one finding, e.g. two default-cred hits).
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

// versionFromAttrs returns the best firmware/software version among the identity
// attributes, in vendor-preference order (the same order the id reporter uses).
func versionFromAttrs(attrs map[string]string) string {
	for _, k := range []string{"idrac.fw", "ilo.fw", "redfish.fw", "ipmi.fw", "device.fw"} {
		if v := attrs[k]; v != "" {
			return v
		}
	}
	return ""
}

// versionFromFindings recovers a firmware version from check-phase evidence when
// the sessionless attributes had none: post-auth mc-info revision first (the only
// firmware SMC/ATEN BMCs expose), then a sessionless Get Device ID revision.
//
// firmwareVersionFull wins over firmwareVersion. Get Device ID splits the version
// across the revision bytes and the vendor-defined auxiliary bytes, so the
// two-component value is only a prefix (01.09.16 renders as "1.09"); the full form
// is the one that matches a vendor advisory.
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

// hasAMTFinding reports whether the Intel AMT probe found AMT present on the host.
func hasAMTFinding(findings []Finding) bool {
	for i := range findings {
		switch findings[i].Check {
		case "amt.detected", "amt.authBypass":
			return true
		}
	}
	return false
}

// findingField returns the value of the named field on a finding, or "".
func findingField(f Finding, key string) string {
	for _, fld := range f.Fields {
		if fld.Key == key {
			return fld.Val
		}
	}
	return ""
}

var (
	// The Supermicro modern-Redfish generations (X13/X14) serve the schema
	// archive at /Metadata.tar.xz; the http.exposure check fingerprints it as
	// "xz redfish-metadata tar (N files, supermicro)" or "...redfish-schema...".
	// Its presence is authoritative for a modern-Redfish board, overriding the
	// IPMI-only X9 default that identify falls back to for a bare-IPMI box.
	smcModernTarRe = regexp.MustCompile(`(?i)redfish-(?:metadata|schema) tar .*supermicro`)
	// smcModelGenRe pulls the board generation prefix out of a real Supermicro
	// board SKU (Redfish Model / Product), e.g. "X12DPi-N6" -> X12, "H13SRD-F" ->
	// H13, "M12SWA-TF" -> M12. The trailing [A-Z0-9] requires a board suffix so we
	// only fire on an actual SKU, not a bare token. The generic default-cert label
	// "X10 ATEN" is rejected separately (it names the cert template, not the board).
	smcModelGenRe = regexp.MustCompile(`(?i)^\s*(X1[0-4]|X[89]|H1[1-3]|M1[12]|B1[0-9])[A-Z0-9]`)
	// OpenSSH major version -> iDRAC generation band: 6.x/SSHSERVER = iDRAC7;
	// 7.4 = iDRAC8/9; 8.x = 9;
	// 9.x = 9-late/10.
	sshVerRe = regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)
)

// refineGenerationFromFindings upgrades f.Generation using evidence only the
// check phase produced. It never blanks an existing, more specific generation.
func refineGenerationFromFindings(f *Final, findings []Finding, attrs map[string]string) {
	// A Supermicro board running OpenBMC firmware IS the X14 generation. identify
	// attributes it to vendor "openbmc" from the bmcweb SPA title, which skips the
	// SMC generation logic entirely. Reclaim it using the authoritative post-auth
	// IPMI/FRU manufacturer (Get Device ID mfr 10876/21317, or FRU Board Mfg
	// "Super Micro") - that only appears with valid credentials, so this is a
	// post-auth correction. A genuine non-SMC OpenBMC box reports its own mfr and
	// is left untouched.
	origVendor := f.Vendor
	if (origVendor == "openbmc" || origVendor == "") && smcHardwareFromFindings(findings) {
		f.Vendor = "supermicro"
		// Supermicro hardware + OpenBMC firmware = X14. The OpenBMC signal is either
		// the SPA-title vendor identify already resolved ("openbmc") or a bmcweb
		// Server string. Capture origVendor before the reclaim above overwrites it.
		if origVendor == "openbmc" || smcIsOpenBMC(findings, attrs) {
			// Prefer a real board SKU if exposed (already X14-generation), else X14.
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
		// A real board SKU (Redfish Model/Product, or post-auth FRU Board Product)
		// is authoritative and pins the exact generation (X11/X12/X13/X14/H13/...),
		// overriding every band and the coarse cert-derived baseline.
		if g := smcModelFromFindings(findings); g != "" {
			f.Generation = g
			break
		}
		// The GUID board-code prefix pins the exact generation from a catalogued
		// board family; it is board-derived (unlike the shared "X10 ATEN" cert) and
		// available pre-auth, so a catalogued code beats the coarse HTTP bands below.
		if g := smcGenFromGUIDFinding(findings); g != "" {
			f.Generation = g
			break
		}
		// Otherwise refine with sessionless HTTP bands, upgrade-only by specificity.
		best := f.Generation
		upgrade := func(g string) {
			if smcGenRank(g) > smcGenRank(best) {
				best = g
			}
		}
		if smcHasBoardSerialGUID(findings) {
			// Uncatalogued smc-board-serial GUID: still an AST-era ATEN board, so at
			// least X10+ (coreui/Redfish below can push the band higher).
			upgrade("X10+")
		}
		if smcIsOpenBMC(findings, attrs) {
			// bmcweb Server string on Supermicro hardware = the OpenBMC generation.
			upgrade("X14")
		}
		if hasSMCModernTar(findings) {
			// Modern Redfish schema archive (X13/X14). These fields cannot separate
			// X13 from X14 (no OpenBMC/bmcweb Server string is exposed), so band it.
			upgrade("X13+")
		}
		if smcCoreUILogin(findings) {
			// coreui "Supermicro BMC Login" UI: X11 or newer. Upgrades the coarse
			// "X10 ATEN" cert baseline, which mislabels X11/X12/X13 boards as X10.
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

// smcSSHOpenSSHRe captures the OpenSSH major version from an SSH banner, e.g.
// "SSH-2.0-OpenSSH_9.3" -> "9". Supermicro ATEN images ship either dropbear
// (X10/X11) or OpenSSH (X12 and newer).
var smcSSHOpenSSHRe = regexp.MustCompile(`OpenSSH[_-](\d+)\.`)

var (
	// iDRAC server generation labels from Dell metadata endpoints: "12G", "14G", "16G", "17G".
	idracServerGenRe = regexp.MustCompile(`(?i)\b(\d{1,2})G\b`)
	// Some Dell fields carry explicit iDRAC generation tokens, e.g. "iDRAC9".
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

// faviconVendorClass maps a favicon-attributable vendor to its OOB device class,
// so an identity rescued purely by its favicon still gets a class (not just a
// vendor). Every vendor with a bmcfp favicon.mmh3 rule appears here. Raritan and
// CyberPower are PDU-first (the favicons were observed on their PDU/UPS-card web
// UIs); the four appliance-KVMs are ClassKVM; Opengear/Perle are console servers.
var faviconVendorClass = map[string]DeviceClass{
	"supermicro": ClassBMC, "dell": ClassBMC, "lenovo": ClassBMC, "fujitsu": ClassBMC,
	"huawei": ClassBMC, "cisco": ClassBMC, "ami": ClassBMC,
	"opengear": ClassSerialConsole, "perle": ClassSerialConsole,
	"raritan": ClassPDU, "cyberpower": ClassPDU,
	"nanokvm": ClassKVM, "jetkvm": ClassKVM, "pikvm": ClassKVM, "blikvm": ClassKVM,
}

// faviconVendorFromFindings returns the vendor/product the favicon fingerprint
// attributed, read from the web.service check's faviconVendor/faviconProduct
// fields (set by bmcfp's favicon.mmh3 rules). Empty when no web.service finding
// carried a favicon match.
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

// protocolVendorChecks maps a check whose mere presence identifies the vendor to
// that vendor and its device class: each key is a vendor-unique discovery/config
// protocol (Moxa device-search, Lantronix setup, Digi ADDP/RealPort, Advantech
// ADAM config) that only that vendor's devices answer, so a hit is conclusive
// attribution. Backfills identity when identify's own collectors miss the signal
// (e.g. their probe budget expired) even though a check later gets a clean
// response on the same port.
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

// protocolVendorFromFindings returns the vendor implied by a vendor-unique
// protocol response, for filling a blank vendor only.
func protocolVendorFromFindings(findings []Finding) (vendor string, class DeviceClass, ok bool) {
	for i := range findings {
		if m, hit := protocolVendorChecks[CanonicalCheckID(findings[i].Check)]; hit {
			return m.vendor, m.class, true
		}
	}
	return "", ClassUnknown, false
}

// vendorSlugFieldChecks maps a check to the field holding a normalized vendor
// slug. Unlike protocolVendorChecks these checks fire for many vendors, so the
// value rather than the mere presence is the signal. The kvm.* probes are excluded
// despite carrying a `vendor` field: they contradict each other on real hosts and
// decoys answer all of them at once. Every field listed must already hold a slug;
// checks whose native field is a free-form manufacturer string normalize it
// themselves via check.vendorSlugField, so engine need not import creds.
var vendorSlugFieldChecks = map[string]string{
	"tls.sharedKey":     "vendors", // shipped shared private key, SPKI-matched
	"tls.defaultCert":   "vendor",
	"ssh.sharedHostKey": "vendor",
	"ipmi.guid":         "vendor", // IANA PEN out of the System GUID
	"kvm.usbAnywhere":   "vendor", // Supermicro-only vMedia protocol
	"tcp.telnetBanner":  "vendor", // banner already resolved to a slug

	// Normalized from a free-form manufacturer / cert-organization string. All four are
	// first-party or authenticated, so none can come from a decoy: ipmi.deviceId is the
	// BMC's own IANA PEN, the post-auth pair need a working credential, and
	// kvm.vnc.certOrg is a TLS certificate subject.
	"ipmi.deviceId":        "vendor",
	"ipmi.postAuth.mcInfo": "vendor",
	"ipmi.postAuth.fru":    "vendor",
	"kvm.vnc":              "vendor",
}

// vendorFieldFromFindings returns a vendor slug carried in a trusted finding field,
// for filling a blank vendor only.
func vendorFieldFromFindings(findings []Finding) (string, bool) {
	for i := range findings {
		key, hit := vendorSlugFieldChecks[CanonicalCheckID(findings[i].Check)]
		if !hit {
			continue
		}
		v := strings.TrimSpace(findingField(findings[i], key))
		// A multi-vendor match is ambiguous and must not attribute the host.
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

// smcGenerationFromModel maps a real Supermicro board model / SKU to its BMC
// generation, e.g. "X12DPi-N6" -> "X12", "H13SRD-F" -> "H13", "M12SWA-TF" ->
// "M12". Returns "" for anything that is not a recognizable board SKU, including
// the generic ATEN default-cert label "X10 ATEN" (which ships across X10..X13/H13
// boards and names the cert template, not the board).
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

// smcModelFromFindings returns the exact generation implied by a real board SKU
// leaked in an HTTP finding (Redfish Model/Product), or "". Only endpoints that
// carry a genuine board string are consulted; the sessionless TLS default cert
// ("X10 ATEN") is deliberately not one of them.
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
			// Post-auth FRU: "Board Product" is the motherboard SKU (X13SEED-SF,
			// X11DPH-T, H13SRD-F, ...), the most reliable exact-generation signal.
			// "Product Name" (system SKU) is a weaker fallback.
			for _, key := range []string{"boardProduct", "productName"} {
				if g := smcGenerationFromModel(findingField(findings[i], key)); g != "" {
					return g
				}
			}
			// Fall back to the flattened FRU dump: on multi-node/twin boards or when
			// the primary "Board Product" reads "NONE", the real SKU still appears in
			// a board[N]=/product[N]= token of the preview (e.g. board[3]=X11DPT-PS).
			for _, key := range []string{"preview", "fruPreview"} {
				if g := smcGenFromFRUPreview(findingField(findings[i], key)); g != "" {
					return g
				}
			}
		}
	}
	return ""
}

// smcFRUTokenRe pulls the value out of a flattened FRU token such as
// "board[3]=X11DPT-PS" or "product[2]=SYS-2029TP-HC1R" in an ipmi.postAuth.fru
// preview string (pipe-separated "d0:board[3]=X11DPT-PS | ...").
var smcFRUTokenRe = regexp.MustCompile(`(?i)(?:board|product)\[-?\d+\]=([A-Za-z0-9][A-Za-z0-9+._-]*)`)

// smcGenFromFRUPreview scans a flattened FRU preview for the first board/product
// token that resolves to a real Supermicro board SKU, returning its generation.
func smcGenFromFRUPreview(preview string) string {
	for _, m := range smcFRUTokenRe.FindAllStringSubmatch(preview, -1) {
		if g := smcGenerationFromModel(m[1]); g != "" {
			return g
		}
	}
	return ""
}

// smcGenFromGUIDFinding maps the Supermicro GUID board-code prefix (emitted as
// modelPrefix on the ipmi.guid finding) to a catalogued generation, or "".
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

// smcHasBoardSerialGUID reports whether the ipmi.guid finding is the Supermicro
// smc-board-serial family -- any such board is AST-era ATEN (X10 or newer), the
// basis for the coarse "X10+" floor when the board-code is not catalogued.
func smcHasBoardSerialGUID(findings []Finding) bool {
	for i := range findings {
		if findings[i].Check == "ipmi.guid" && findingField(findings[i], "family") == "smc-board-serial" {
			return true
		}
	}
	return false
}

// productFromFRUFindings returns the device model from a post-auth FRU finding:
// the system "Product Name" (e.g. "ProLiant DL365 Gen11", "System x3650 M4",
// "ThinkSystem SR250") when present, else the motherboard "Board Product" SKU
// (e.g. "SE7320SP2"). This is the only place a non-SMC BMC's make/model appears -
// identify sees a sessionless vendor but never the model. Empty when no FRU model.
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

// smcHardwareFromFindings reports whether post-auth IPMI/FRU evidence
// authoritatively names Supermicro hardware: Get Device ID manufacturer 10876
// (Super Micro Computer) or 21317 (ATEN International, the Supermicro OEM), or an
// FRU Board/Product manufacturer string containing "Super Micro". Only a genuine
// Supermicro board reports these, so it is safe to reclaim an "openbmc"-labeled
// unit as Supermicro on this signal.
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

// smcIsOpenBMC reports whether the BMC firmware stack is OpenBMC (bmcweb), the
// architecture that defines the Supermicro X14 generation, read from the bmcweb
// Server string (identify's http.server attribute and the web.service finding).
// The vendor=="openbmc" SPA-title signal is handled by the caller, which must
// capture it before reclaiming the vendor as supermicro.
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

// smcCoreUILogin reports whether the host serves the modern coreui/kendo BMC web
// UI (the "Supermicro BMC Login" page introduced with X11). True X10 boards ship
// the legacy prototype.js/YUI login with an empty <title>, so a coreui login is a
// reliable "X11 or newer" tell that upgrades the coarse cert-derived X10 baseline.
func smcCoreUILogin(findings []Finding) bool {
	for i := range findings {
		switch findings[i].Check {
		case "web.service":
			if strings.EqualFold(strings.TrimSpace(findingField(findings[i], "title")), "Supermicro BMC Login") {
				return true
			}
		case "http.exposure", "http.endpoint":
			// coreui and kendo are both the modern (X11+) login stacks; only the
			// legacy X10 UI (smc-ui:legacy) must not match here.
			if fp := findingField(findings[i], "fingerprint"); strings.Contains(fp, "smc-ui:coreui") || strings.Contains(fp, "smc-ui:kendo") {
				return true
			}
		}
	}
	return false
}

// smcGenRank ranks Supermicro generation labels by specificity so refinement only
// ever replaces a label with a more specific / more reliable one. Exact single
// generations (from a board SKU) outrank every band; the "X10"/"X9" identify
// baseline (derived from the shared default cert / lighttpd version) is the
// coarsest.
func smcGenRank(gen string) int {
	switch gen {
	case "":
		return 0
	case "X9", "X10":
		return 1 // identify baseline: cert "X10 ATEN" / lighttpd - coarse
	case "X10+":
		return 2 // "X10 or newer" (SHA256 cipher / Redfish, no ATEN cert tell)
	case "X11+":
		return 3 // coreui-era band (X11/X12/X13/X14)
	case "X12+":
		return 4 // OpenSSH-8.x band (X12/H12/M12 and newer; X10/X11 ship dropbear)
	case "X13+":
		return 5 // modern-Redfish / OpenSSH-9.x band (X13/H13/X14)
	default:
		return 6 // exact single generation from a board SKU
	}
}

// hasSMCModernTar reports whether any http.exposure finding carried the
// Supermicro Redfish schema-tar fingerprint.
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

// dellGenFromSSH maps the SSH banner (from the ssh.version finding) to an iDRAC
// generation band. Debian/Ubuntu-tagged OpenSSH banners are Linux hosts that got
// a spurious Dell TLS attribution, so they are ignored.
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
			return "" // non-iDRAC Linux host mislabeled dell
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

// preferDellGen decides whether the SSH-derived generation should replace the
// current one. It replaces an empty or coarser label but never overwrites an
// explicit single-generation number (e.g. an "iDRAC9" from a Redfish product
// string should not be widened back to "iDRAC9/10").
func preferDellGen(cur, ssh string) bool {
	if cur == "" || cur == "0" || cur == "iDRAC" {
		return true
	}
	// A banded current label (contains '/') can be tightened or replaced by the
	// SSH signal; a crisp single-gen current label is left alone.
	return strings.Contains(cur, "/")
}

// FlagsString renders Flags as sorted "name=risk" pairs (deterministic), for the
// TUI line and any text rendering.
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

// smcGenBandFromSSH bands a Supermicro BMC generation from the SSH server banner,
// which tracks the firmware's userland base. It resolves to an era rather than a
// single generation, so it returns an upgrade-only band (see
// kb/smc/notes/smc-guid-board-codes.md for the calibration):
//
//	dropbear      -> no band; X10 and X11 both ship it, so the X10+ floor stands
//	OpenSSH 8.x   -> X12+
//	OpenSSH >=9.x -> X13+
//
// A band must not overwrite an exact board-code generation: the caller reaches
// this only after smcGenFromGUIDFinding comes up empty, and smcGenRank keeps an
// exact generation above every band.
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
			// dropbear (X10 and X11 alike) or an unrecognised banner: no band.
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
