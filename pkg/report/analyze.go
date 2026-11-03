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

// Source is the analysis of one named corpus.
type Source struct {
	Name     string // display name from the CLI (e.g. "Internal")
	Total    int    // records read
	Redacted bool   // every address fell in the redaction ranges -> treat as shareable

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
	checks     *counter // finding check id histogram
	risks      *counter // finding risk histogram
	// unclassified holds check ids that scored neither an exposure nor a
	// compromise path. A new check id is otherwise invisible here: it lands in
	// the check histogram and then contributes to nothing, which is how a defect
	// this scan actively confirms can be absent from every rollup on the page.
	unclassified *counter
	rakpUsers    *counter // usernames that leaked a RAKP-2 hash
	snmpComm     *counter // SNMP default communities observed
	crackMethod  *counter // scan-time crack method, counted once per host
	crackPass    *counter // recovered plaintext passwords (per RAKP row)
	guidFamily   *counter // decoded IPMI GUID family, counted once per host
	guidVendor   *counter // vendor recovered from the GUID itself
	guidCountry  *counter // HPE plant/country token from decoded GUIDs

	exposureTotals map[string]int         // exposure key -> host count
	byVendorExp    map[string]*vendorStat // vendor -> counts
	// firmware cross-tabulates firmware version by product line, so the report can
	// break an inventory down by release (the iLO4 hosts on 2.82 vs an older rev)
	// instead of pooling every vendor's versions into one flat list. Keyed by
	// "vendor\x00line" where the line is the most specific identity resolved.
	firmware map[string]*firmwareGroup

	// derived population counters
	resolvedVendor   int // hosts whose vendor is known
	honeypotHosts    int // classified honeypots with no recoverable vendor
	honeypotFindings int // decoy findings excluded from the check/exposure rollups
	// Host severity is the whole distribution, not just the top two bands: a
	// question like "what share of the population is critical" needs a
	// denominator that adds up, so every host lands in exactly one bucket by its
	// highest-risk finding (withNone = a host that carried no finding at all).
	withCritical int
	withHigh     int
	withMedium   int
	withLow      int
	withNone     int
	// bmcSeverity is the same distribution restricted to hosts that classified as
	// an actual BMC. A share of "BMC hosts that are critical" needs the numerator
	// and the denominator drawn from the same population: the sweep also lands on
	// honeypots, serial consoles and PDUs, and mixing an all-responder numerator
	// with a BMC-only denominator produced buckets summing to 117%.
	bmcSeverity       map[string]int
	rakpHosts         int
	autoCrackedHosts  int // password recovered live during the scan
	potCrackedHosts   int // crack already present in the oobscan potfile
	autoNamedHosts    int // live crack on a named account
	autoEmptyHosts    int // live crack on the empty/callback account
	potOnlyHosts      int // potfile hit not already cracked in the source
	crackedTotal      int // union of source and potfile cracks
	hashRows          int // total captured RAKP-2 exchanges (several per host)
	scanRowCracks     int // RAKP rows with a live recovered password (excludes fixed-key markers)
	potRowCracks      int // RAKP rows whose captured hash matches the loaded potfile
	immediatePreHosts int // ... reachable by a pre-research (already-known) path
	immediateExtHosts int // unique hosts with any compromise path, known or new-research
	adminHosts        int // ... reaching administrator-equivalent on the management plane
	chainedAdminHosts int // ... where administrator ONLY exists because two legs compose
	hostReachHosts    int // ... reaching the managed host (console, virtual media, debug)
	escalationOnly    int // hosts carrying only a credential-gated leg: no entry observed
	// unclassifiedFindings counts findings whose check id scored nothing at all,
	// so "the report says zero" and "the report cannot see this check" stay
	// distinguishable on real data.
	unclassifiedFindings int
	compromiseTotals     map[string]int
	crackVendorPass      map[string]*counter // vendor -> recovered password frequencies
	patterns             *patternAccum       // recovered plaintexts for password-pattern analysis

	// Collection coverage keeps "zero observed" distinct from "not present in
	// this source". Service-only inventory files, for example, have rich
	// population data but no vulnerability findings, RAKP material, or GUIDs.
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

	// potCheck, when set, returns the cracks the loaded potfile holds for a
	// record's captured RAKP hashes, one per cracked hash. It is supplied by the
	// caller so the report package need not depend on the potfile / hashcrack
	// machinery. The one-day / run label, if any, is carried in potLabel.
	potCheck func(rec *scanfile.Record) []PotCrack
	potLabel string

	addrSeen  int // addresses parsed while sniffing redaction
	addrInRed int // ... that fell in a redaction range

}

// vendorStat holds a vendor's population and its per-exposure host counts
// within one source.
type vendorStat struct {
	count int
	exp   map[string]int
}

// firmwareGroup accumulates the firmware-version distribution within one product
// line, identified at the most specific granularity the scan resolved: a
// generation (iLO4, iDRAC9, X11) when present, the product family otherwise. It
// answers a question the flat product and version lists cannot on their own --
// which releases a given controller line is split across -- by keeping a version
// histogram per line rather than one pooled across the whole fleet. total counts
// every host on the line; versions.total is those that also exposed a firmware
// version, so the coverage gap (controllers that never revealed one) stays
// measurable.
type firmwareGroup struct {
	vendor     string   // display vendor
	line       string   // most specific line label (generation, else product)
	product    string   // resolved product family, for context
	generation string   // resolved generation, for context
	total      int      // hosts on this line, with or without a resolved version
	versions   *counter // firmware version -> host count (version-bearing hosts only)
}

// NewSource returns an empty Source ready to Add records. Every view the report
// renders is a bounded aggregate, so a Source holds no per-host rows: the bundle
// is meant to be shareable, and an address that is never accumulated cannot leak.
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
		firmware:         map[string]*firmwareGroup{},
		compromiseTotals: map[string]int{},
		bmcSeverity:      map[string]int{},
		crackVendorPass:  map[string]*counter{},
		patterns:         newPatternAccum(),
	}
}

// Add folds one record into the source aggregate.
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
		// Genuinely unattributed: no identity vendor and no recoverable tell.
	case "honeypot":
		// A classified non-device; counted apart from both resolved and unknown.
		s.honeypotHosts++
	default:
		s.resolvedVendor++
	}
	// product is the vendor-qualified model label, reused below by the
	// password-pattern analysis (a bare model name repeats across vendors).
	product := ""
	rawProduct := recordProduct(rec)
	if rawProduct != "" {
		s.product.add(rawProduct)
		product = strings.TrimSpace(vendor + " " + rawProduct)
	}
	rawGeneration := recordGeneration(rec)
	if rawGeneration != "" {
		s.generation.add(rawGeneration)
	}
	rawVersion := recordVersion(rec)
	if rawVersion != "" {
		s.osVersion.add(rawVersion)
		s.versionHosts++
	}
	// Cross-tabulate the version against the product line, so a per-line firmware
	// breakdown is answerable (iLO4 at 2.82 vs older) rather than the flat pooled
	// list. Runs alongside the flat counters above, sharing their honeypot policy.
	s.observeFirmware(vendor, rawProduct, rawGeneration, rawVersion)
	if hw := rec.Attributes["hw_product"]; hw != "" {
		s.hwProduct.add(hw)
	}

	// Ports / protocols, counted once per host.
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

	// Exposure scoring from the findings.
	//
	// The scanner retains honeypot records whole (see reclassifyHoneypotByBreadth in
	// cmd/scan.go) on the grounds that finalIdentity.class excludes them downstream, and
	// this is the place that has to honor it: a decoy answers several mutually exclusive
	// vendor probes at once, so its findings inflate per-vendor rollups. The host itself
	// still counts; only its emulated findings are withheld.
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
		// Score into scratch sets so a check that classifies as nothing specific is
		// countable, then merge: another finding on the same host may already have
		// set the same key, so the per-host sets keep union semantics.
		expOne, pathOne := map[string]bool{}, map[string]bool{}
		scoreCheck(f.Check, expOne)
		scoreCompromiseFinding(f, pathOne)
		// Only medium-and-above findings are worth flagging. Discovery, inventory,
		// and low-risk detail legitimately score nothing -- "this host answered
		// SSDP" is not a weakness -- and counting those buries the one case this
		// exists for: a check the scan rates a real risk that no rollup can see.
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
		// The IPMI version taxonomy (ipmi_1_5 / ipmi_2_0) is only expressed by a
		// version-specific check on a native scan; the ipmi.versions finding (which
		// both native scans and rz projections emit) carries the negotiated
		// versions in its `versions` field, so read them here to cover both.
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
		// "info" and "" both mean nothing actionable was found on this host.
		s.withNone++
	}

	// RAKP: any leaked hash, any cracked account, and the accounts involved.
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
	// Predictable/weak managed session IDs, derived from the BMC session IDs the
	// scan captured across this host's RAKP rows (one per probed username/cipher).
	// A native scan that ran the ipmi.sidEntropy/sidPredictable sampler already
	// carries the finding (scored via scoreCheck above); this covers corpora that
	// predate that check but still captured several distinct SIDs -- exactly the
	// case for the internet sweeps. Needs >=3 samples, so single-row hosts are
	// silently skipped.
	if sids := rakpSessionIDs(rec.RAKP); len(sids) >= 3 {
		if _, weak := ipmi.ClassifySessionIDs(sids); weak {
			exp["ipmi_sid_weak"] = true
		}
	}
	// Two independent "cracked" signals: whether the scan recovered a password
	// live during testing (rakp[].cracked), and whether our accumulated oobscan
	// potfile already holds the crack for one of this host's hashes. The second
	// grows as more cracking is done and more results are imported into the pot,
	// so the report can show real recovered totals over time.
	//
	// A `cracked` value of the SMCRAKP fixed-key marker is not a recovered
	// password (it records that the RAKP-2 HMAC was forged with the shared ATEN
	// key), so it never counts as a live crack or a named-account takeover.
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
		// Offline recoveries feed the pattern analysis too: on a mature potfile
		// they are most of what is known, and a factory-generated password is
		// far likelier to be cracked offline than during the scan window.
		for _, c := range potCracks {
			s.patterns.add(c.Password, rec.Host, vendor, product)
			if strings.TrimSpace(c.Username) != "" {
				potNamed = true
			}
		}
	}
	// A recovered password on a named account is a usable credential however it
	// was recovered. Gating this on the scan-window crack alone dropped every
	// host whose hash only fell to the offline pot-run, which on a mature potfile
	// is most of them.
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
	// SNMP default communities from the finding fields, for the detail view.
	for i := range rec.Findings {
		f := &rec.Findings[i]
		if f.Check == "snmp.defaultCreds" || f.Check == "snmp.vendorCommunity" {
			if c := findingField(f, "community"); c != "" {
				s.snmpComm.add(c)
			}
		}
	}

	// Roll the exposure set into the totals and the per-vendor stats.
	vs := s.byVendorExp[vendor]
	if vs == nil {
		vs = &vendorStat{exp: map[string]int{}}
		s.byVendorExp[vendor] = vs
	}
	vs.count++
	// Infer exposure keys the scan never scored from data it did capture: a
	// shared/fleet-wide SSH host key (the per-service host-key fingerprint),
	// and the iLO version-gated known-CVE set (generation + firmware). Done
	// before the exposure rollup so the inferred keys are counted.
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
	// Infer the new-research compromise paths a source never actively probed
	// from the vendor/generation/protocol evidence it DID carry, so the deck can
	// extend the risk model to that corpus instead of reporting a static zero.
	// These count affected hosts (exposure-side), which is why the deck labels
	// the extended figure "affected / reachable", not "live-confirmed".
	inferred := inferResearchPaths(rec, vendor, exp)
	for key := range inferred {
		compromise[key] = true
	}
	if len(compromise) > 0 {
		for key := range compromise {
			s.compromiseTotals[key]++
		}
		// Fold the path set along both axes. Extended counts any path at all; pre
		// counts the hosts an already-public path reaches; admin/hostReach are the
		// composed figures, so a pre-auth foothold plus a credential-gated
		// escalation observed on the same host reads as Administrator rather than
		// as two unrelated weaknesses.
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
			// Only an escalation leg was observed. Real exposure -- anyone holding
			// any account on this host is an administrator -- but not remote access
			// on its own, so it is reported rather than counted as a compromise.
			s.escalationOnly++
		}
	}

}

// Finalize resolves derived flags after the last record. It decides whether the
// source was redacted: a corpus is treated as shareable when it parsed at least
// one address and every address it parsed fell inside a redaction range, which
// is exactly what `oobscan convert --redact` produces.
func (s *Source) Finalize() {
	s.Redacted = s.addrSeen > 0 && s.addrInRed == s.addrSeen
}

// recordVendor resolves the display vendor slug, preferring the post-check
// final identity. Empty resolves to "unknown".
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

// recordClass resolves the device class, preferring the final identity.
func recordClass(rec *scanfile.Record) string {
	if rec.Final != nil && rec.Final.Class != "" {
		return string(rec.Final.Class)
	}
	if rec.Identity != nil && rec.Identity.Class != "" {
		return string(rec.Identity.Class)
	}
	return "unknown"
}

// isHoneypotRecord reports whether the record was classified as a deception node.
// Such a host's findings are emulated by the decoy, not measured on a real device,
// so they must not feed the check histogram, the exposure/compromise scores, the
// GUID tallies, or the recovered-password pattern analysis -- a decoy's "cracked"
// password would otherwise pollute the cross-vendor default-password work.
func isHoneypotRecord(rec *scanfile.Record) bool {
	return recordClass(rec) == "honeypot"
}

// recordProduct resolves a best-effort product line.
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

// observeFirmware folds one host into its product-line firmware distribution.
// The line is the most specific identity the scan resolved -- a generation
// (iLO4, iDRAC9, X11) when present, the product family otherwise -- so the
// version histogram is attributed to a controller line instead of the whole
// inventory. A host that resolved neither a product nor a generation is not grouped:
// its firmware could not be attributed to any line. A host on a known line with
// no resolved version still counts toward the line total, which is how the view
// distinguishes "we have no firmware for this line" from "this line has few
// hosts".
func (s *Source) observeFirmware(vendor, product, generation, version string) {
	product = strings.TrimSpace(product)
	generation = strings.TrimSpace(generation)
	// The line is the most descriptive identity available. Prefer the generation
	// -- it is the specific tell (iLO4 rather than a bare "iLO") -- but a
	// generation that is only a number carries no product family (Dell reports the
	// iDRAC9 generation as "9"), so fall back to a product label that names the
	// controller when the generation cannot stand on its own.
	line := generation
	if !hasLetter(line) && hasLetter(product) {
		line = product
	}
	if line == "" {
		return
	}
	key := vendor + "\x00" + line
	g := s.firmware[key]
	if g == nil {
		g = &firmwareGroup{vendor: vendor, line: line, versions: newCounter()}
		s.firmware[key] = g
	}
	// Keep the first non-empty product/generation the line has seen, so a host
	// that carried only the generation does not blank context a fuller host gave.
	if g.product == "" {
		g.product = product
	}
	if g.generation == "" {
		g.generation = generation
	}
	g.total++
	if version != "" {
		g.versions.add(version)
	}
}

// resolvedClass preserves a native class and otherwise infers only from strong
// OOB evidence. A service-only IPMI record is a BMC, not an unknown device; a
// generic HTTPS endpoint remains unknown unless its vendor family is specific.
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

// smcrakpFixedKeyMarker is the placeholder oobscan records in rakp[].cracked
// when a RAKP-2 HMAC verified against the shared Supermicro/ATEN fixed key
// rather than an account password. It is evidence of the SMCRAKP fixed-key
// weakness, not a recovered credential.
const smcrakpFixedKeyMarker = "<smcrakp-fixed-key>"

// isRecoveredPassword reports whether a rakp[].cracked value is a real
// recovered plaintext password (i.e. not empty and not the fixed-key marker),
// so the marker never inflates the recovered/named-account crack counts.
func isRecoveredPassword(cracked string) bool {
	c := strings.TrimSpace(cracked)
	return c != "" && c != smcrakpFixedKeyMarker
}

// canonicalProtocol collapses protocol tokens that name the same service under
// different labels across scan profiles, so two corpora stay directly
// comparable. SNMP version tokens fold to a single snmp; the tls/https split
// (one profile tags the TLS transport, the other the HTTP-over-TLS app
// protocol) folds to https.
func canonicalProtocol(p string) string {
	switch p {
	case "snmp1", "snmp2", "snmp3", "snmpv1", "snmpv2", "snmpv2c", "snmpv3":
		return "snmp"
	case "tls", "ssl":
		return "https"
	}
	return p
}

// inferResearchPaths is retained for corpora that carry captured RAKP-2 hash
// material but no finding rows (a service-only export). A native or converted
// corpus already carries these as findings (projected at convert time), so this
// only fills the SMCRAKP gap from the magic-hash recompute; the iLO/OpenBMC
// generation projections come from the findings themselves.
func inferResearchPaths(rec *scanfile.Record, vendor string, exp map[string]bool) map[string]bool {
	out := map[string]bool{}
	slug := strings.ToLower(vendor)
	if slug == "supermicro" {
		// SMCRAKP fixed-key bypass: only when a captured RAKP-2 leak actually
		// verifies against the fixed ATEN key. SMCRAKP is off by default and the
		// mode is opt-in, so inferring it for every SMC host wildly overstates
		// exposure; the magic-hash recompute is the sound affected-set test.
		for i := range rec.RAKP {
			if rakpRecordUsesSMCRAKPFixedKey(&rec.RAKP[i]) {
				out["smcrakp_bypass"] = true
				break
			}
		}
	}
	return out
}

// inferExposures projects exposure keys a source never scored from data it did
// capture, so a lighter scan profile still surfaces those weaknesses instead of
// a bare "not tested".
//
//   - ssh_shared_key: the scan captured each SSH service's host-key fingerprint
//     (ssh.hostKey*.sha256) but never ran the shared-host-key check; match the
//     captured fingerprint against the known fleet-wide set.
//   - ilo_known_cve: the scan resolved the iLO generation and firmware version
//     (identity evidence) but never ran the version-gated CVE projection; run
//     the same generation+firmware match offline.
func inferExposures(rec *scanfile.Record, vendor string) map[string]bool {
	out := map[string]bool{}
	// Shared / fleet-wide SSH host key from the captured fingerprint.
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
	// iLO version-gated known CVEs from generation + firmware identity evidence.
	if strings.EqualFold(vendor, "hpe") {
		gen := iloGenerationLabel(recordGeneration(rec), recordProduct(rec))
		fw := recordVersion(rec)
		if gen != "" && fw != "" && len(ilo.MatchCVEs(gen, fw)) > 0 {
			out["ilo_known_cve"] = true
		}
	}
	return out
}

// iloGenerationLabel resolves the "iLO2".."iLO6" label MatchCVEs expects from
// a free-form generation/product string, or "" when no generation is named.
func iloGenerationLabel(parts ...string) string {
	for _, p := range parts {
		if g := ilo.GenerationFromString(p); g != "" {
			return g
		}
	}
	return ""
}

// scoreCompromiseFinding maps one finding onto the compromise-path keys it
// establishes. Every check that proves an access path belongs here; a check that
// only proves reachability or leaks non-credential detail belongs in scoreCheck.
// notAnAccessPath in paths_coverage_test.go records that decision for the
// critical/high checks deliberately left out, so a new one cannot be forgotten.
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
		// SMCRAKP fixed-key session forgery. Only an exploitable (command-capable)
		// result is an immediate path; an advertised-but-protected handshake
		// (exploitable=false, e.g. X14) is not.
		if !strings.EqualFold(findingField(f, "exploitable"), "false") {
			set["smcrakp_bypass"] = true
		}
	case "ipmi.ilo.rakpNoneBypass":
		// iLO RMCP+ type-confusion passwordless session. The live check only
		// ever emits this finding on a confirmed bypass (it returns nil
		// otherwise) and a converted corpus's generation-derived projection
		// carries the same uniform-across-firmware guarantee (all iLO2/3/4), so
		// no further per-host proof gate is needed -- the finding itself is proof.
		set["ilo_ipmi_bypass"] = true
	case "ipmi.openbmc.rakp1ActiveRelabel", "ipmi.rakp.state.activeRelabelLowToAdmin":
		// Active-session RAKP1 relabel to Administrator. Both emitters only fire on
		// a confirmed escalation, so no further proof gate is needed -- but the
		// precondition differs per host and decides which leg this is. The newer
		// emitter records it: credentialRequired=false means the default-userKey
		// bypass supplied the seed, so the whole chain ran with no credential and
		// the host is unauthenticated-to-Administrator outright. Otherwise the
		// escalation presupposes a valid low-privilege credential and only reaches
		// Administrator once an entry leg supplies one.
		if strings.EqualFold(findingField(f, "credentialRequired"), "false") {
			set["relabel_admin_unauth"] = true
		} else {
			set["relabel_admin"] = true
		}
	case "ipmi.smc.rakpReservedRole":
		// CVE-2026-65220: the reserved role nibble copies the session slot's privilege
		// over the per-user clamp. The finding's own fields spell the precondition
		// out (prerequisite=low-priv-credential-plus-admin-account-name,
		// impactIfExploited=privilege-escalation-not-auth-bypass), so this is an
		// escalation leg, never unauthenticated access. The measured negative is a
		// distinct check id and never lands here.
		set["smc_reserved_role"] = true
	case "ipmi.smc.rakpUnorderedForge":
		// CVE-2026-65219 exploited: a forged session was opened with no password and its
		// reach confirmed. The signature-only ipmi.smc.rakpUnordered is NOT a path
		// -- it proves the state machine is unordered, not that a session opened.
		set["smc_rakp_forge"] = true
	case "http.smc.psBlock":
		// Cleartext IPMI credential store readable pre-auth: the recovered
		// credentials are the administrator accounts themselves.
		set["smc_psblock_creds"] = true
	case "ipmi.netfnOem":
		// OEM NetFn commands accepted with no session. Which commands landed varies
		// per host and the check records only the completion codes, so the reach is
		// a session, not a proven Administrator.
		set["ipmi_oem_preauth"] = true
	case "ipmi.openbmc.defaultUserKeyAuthBypass":
		// OpenBMC default-userKey auth bypass. Unlike the checks above, this one
		// also emits a negative "precondition tested, not confirmed" finding
		// (authBypassed=false); exclude only that explicit negative. A live
		// confirmation (authBypassed=true) and the converted corpus's
		// fingerprint-derived projection (authBypassed=fingerprint-derived) both
		// count -- the hardcoded userKey is a property of the stack itself.
		if !strings.EqualFold(findingField(f, "authBypassed"), "false") {
			set["openbmc_userkey"] = true
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
		// SMC/ATEN lighttpd wstunnel reaches ikvmserver without Redfish auth:
		// unauthenticated console plus virtual media, i.e. the host, without any
		// claim about privilege on the BMC itself.
		set["smc_kvm_bypass"] = true
	case "kvm.smc.ikvm.sessionHijack":
		// Console reachable via the unauthenticated .IKVM page, but the check needs
		// a valid credential to get there, so it is a host-reach escalation leg.
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

// normalizeServiceRecord projects service-centric .oob records onto the same
// canonical fields a native scan carries. Some inventory exports contain only
// {host,services}, with the address, ports, protocols, and fingerprint evidence
// nested under each service. Normalizing once at the load boundary keeps the
// HTML aggregate and artifact tree in lockstep without changing native records.
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

// sniffRedaction records whether the record's addresses fall in the redaction
// ranges, so Finalize can label a shareable source.
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

// inRedactionRange reports whether an address is one the redactor mints:
// 10.0.0.0/8 or 224.0.0.0/4 for IPv4, fd00::/8 or 2001:db8::/32 for IPv6.
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

// findingField returns the first value for a canonical field key on a finding.
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

// rakpSessionIDs extracts the BMC-assigned managed session IDs captured across a
// record's RAKP rows (one per probed username/cipher), skipping zero/absent
// values. The order follows the rows, which is the sample order the SID
// classifier expects.
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
