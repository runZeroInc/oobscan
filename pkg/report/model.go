package report

import (
	"sort"
	"strings"
)

// This file projects the aggregated Sources onto the JSON payload embedded in
// the HTML bundle. Every number the report renders is precomputed here so the
// page does no analysis at load — it only lays out.
//
// Percentages are always relative to a source's own population, never to the
// combined total: the whole point of the comparison is that two populations of
// wildly different size (a 10k internal fleet vs a 150k internet sweep) are
// judged on prevalence, not volume. Absolute counts travel alongside so the
// population gap is still visible.

// Report is the full payload for the HTML bundle.
type Report struct {
	Generated   string             `json:"generated"`
	Title       string             `json:"title,omitempty"`
	Subtitle    string             `json:"subtitle,omitempty"`
	Byline      string             `json:"byline,omitempty"`
	Advisories  *AdvisoryView      `json:"advisories,omitempty"`
	Keys        []Exposure         `json:"keys"`
	Sources     []SourceView       `json:"sources"`
	Compare     *CompareView       `json:"compare,omitempty"`
	NewFindings []FindingHighlight `json:"newFindings,omitempty"`
	Passwords   *PasswordsView     `json:"passwords,omitempty"`
}

// FindingHighlight is one newly researched BMC weakness, tying its advisory/CVE
// identifier to the report's own taxonomy exposure key and the class of proof
// behind it. Hosts is parallel to Report.Sources by index (how many hosts in
// each source carry the observable check); it is 0 for firmware/source-only
// findings that have no live scan check.
type FindingHighlight struct {
	ID       string    `json:"id"` // advisory or CVE identifier
	Vendor   string    `json:"vendor"`
	Title    string    `json:"title"`
	Risk     string    `json:"risk"`     // critical | high | medium | low
	Check    string    `json:"check"`    // native oobscan check id, or "" if source-only
	Key      string    `json:"key"`      // taxonomy exposure key this rolls into
	Evidence string    `json:"evidence"` // live-confirmed | scan-observed | firmware-source
	Hosts    []int     `json:"hosts"`
	Pct      []float64 `json:"pct"`
	Tested   []bool    `json:"tested"` // whether each source's scan probed for this finding
}

// newFindingCatalog is the curated set of new BMC findings highlighted in the
// deck. Evidence class is fixed per finding and never inferred from a version
// match: live-confirmed means a session/credential was proven, scan-observed
// means the defect signature was seen, firmware-source means it is advisory-
// backed root cause with no live check. Key must exist in Taxonomy so the
// per-source Hosts/Pct can be filled from the exposure totals.
var newFindingCatalog = []FindingHighlight{
	{ID: "CVE-2026-18449", Vendor: "Supermicro", Title: "Supermicro BMC Hardcoded RAKP Key", Risk: "high", Check: "ipmi.v20.smcrakpBypass", Key: "ipmi_smcrakp_bypass", Evidence: "live-confirmed"},
	{ID: "CVE-2026-18450", Vendor: "Supermicro", Title: "Supermicro BMC Unauthenticated IPMI Commands", Risk: "high", Check: "ipmi.smc.integrityBypass", Key: "ipmi_smc_integrity_bypass", Evidence: "scan-observed"},
	{ID: "SMC-0011", Vendor: "Supermicro", Title: "Predictable managed session IDs (vendor-disputed, no CVE)", Risk: "medium", Check: "ipmi.sidPredictable", Key: "ipmi_sid_weak", Evidence: "scan-observed"},
	{ID: "CVE-2026-65206", Vendor: "HPE", Title: "HPE iLO 2/3/4 RMCP+ type confusion enables passwordless administrator sessions", Risk: "critical", Check: "ipmi.ilo.rakpNoneBypass", Key: "ipmi_ilo_auth_bypass", Evidence: "live-confirmed"},
	{ID: "CVE-2026-65205", Vendor: "HPE", Title: "HPE iLO 2/3/4 missing RMCP+ integrity enforcement allows IPMI session injection", Risk: "high", Check: "ipmi.ilo.integrityBypass", Key: "ipmi_ilo_auth_bypass", Evidence: "scan-observed"},
	{ID: "CVE-2026-65204", Vendor: "HPE", Title: "HPE iLO 4/5/6 pre-authentication stack overflow in SSH packet processor", Risk: "high", Check: "ssh.hpe.iloSSHOverflow", Key: "ssh_ilo_overflow", Evidence: "scan-observed"},
	{ID: "CVE-2026-16141", Vendor: "OpenBMC", Title: "OpenBMC IPMI Authentication Bypass via Default userKey and Stale Challenge Value", Risk: "high", Check: "ipmi.openbmc.defaultUserKeyAuthBypass", Key: "ipmi_openbmc_bypass", Evidence: "scan-observed"},
	{ID: "CVE-2026-16140", Vendor: "OpenBMC", Title: "OpenBMC IPMI Privilege Escalation via Retargeted RAKP 1", Risk: "high", Check: "ipmi.openbmc.rakp1ActiveRelabel", Key: "ipmi_openbmc_bypass", Evidence: "scan-observed"},
	{ID: "CVE-2024-54085", Vendor: "AMI MegaRAC", Title: "Redfish Host-Interface (X-Server-Addr) auth bypass", Risk: "critical", Check: "http.redfish.amiBypass", Key: "ami_redfish_bypass", Evidence: "scan-observed"},
	{ID: "CVE-2023-34329", Vendor: "AMI MegaRAC", Title: "Redfish Host-header / X-Forwarded auth bypass", Risk: "high", Check: "http.redfish.ami.cve202334329", Key: "ami_redfish_bypass", Evidence: "scan-observed"},
	{ID: "AMI-mTLS", Vendor: "AMI MegaRAC", Title: "Redfish mTLS CA-trust bypass", Risk: "high", Check: "tls.mtls.ami.caBypass", Key: "ami_mtls_bypass", Evidence: "scan-observed"},
	{ID: "CVE-2026-18451", Vendor: "Supermicro", Title: "Supermicro BMC Predictable KVM Tokens", Risk: "low", Check: "", Key: "", Evidence: "firmware-source"},
}

// AdvisoryView summarizes a repository advisory inventory without mixing its
// firmware/source evidence into the scan-derived host denominators.
type AdvisoryView struct {
	Total      int            `json:"total"`
	Vendors    int            `json:"vendors"`
	States     []Pair         `json:"states"`
	Risks      []Pair         `json:"risks"`
	Surfaces   []Pair         `json:"surfaces"`
	ByVendor   []Pair         `json:"byVendor"`
	Highlights []AdvisoryItem `json:"highlights"`
}

// AdvisoryItem is a protocol-relevant finding used on the research-evidence
// slide. It describes affected code, not observed prevalence in a scan corpus.
type AdvisoryItem struct {
	ID        string `json:"id"`
	Vendor    string `json:"vendor"`
	Risk      string `json:"risk"`
	Surface   string `json:"surface"`
	Component string `json:"component"`
	Title     string `json:"title"`
}

// SourceView is one source's precomputed overview and detail data.
type SourceView struct {
	Name     string `json:"name"`
	Total    int    `json:"total"`
	Redacted bool   `json:"redacted"`
	Resolved int    `json:"resolved"`
	Unknown  int    `json:"unknown"`
	Honeypot int    `json:"honeypot"`
	// HoneypotFindings is how many decoy findings were withheld from the check and
	// exposure rollups. Reported so the exclusion is visible rather than a silent cap.
	HoneypotFindings int `json:"honeypotFindings"`
	// Host severity buckets, by each host's highest-risk finding. Every host is
	// in exactly one, so the five sum to Total and a "what share is critical"
	// answer has a denominator that adds up.
	WithCritical int `json:"withCritical"`
	WithHigh     int `json:"withHigh"`
	WithMedium   int `json:"withMedium"`
	WithLow      int `json:"withLow"`
	WithNone     int `json:"withNone"`
	// BMCHosts and BMCSeverity restrict the population and the severity
	// distribution to hosts that classified as an actual BMC, which is the pair the
	// overview slide quotes: the bands sum to BMCHosts, so the shares add to 100%.
	BMCHosts    int            `json:"bmcHosts"`
	BMCSeverity map[string]int `json:"bmcSeverity,omitempty"`
	RakpHosts   int            `json:"rakpHosts"`
	AutoCracked int            `json:"autoCracked"` // recovered live during the scan
	PotCracked  int            `json:"potCracked"`  // crack present in the oobscan potfile
	HasPot      bool           `json:"hasPot"`      // a potfile was supplied for this run
	// Immediate-compromise rollups. ImmediatePre / ImmediateExt are the
	// known-vs-extended headline; Admin / HostReach are the same populations read
	// along the privilege axis, and are what "compromised" usually means to a
	// reader. Chained is the part of Admin that exists only because a pre-auth
	// entry leg and a credential-gated escalation leg were seen on the same host,
	// reported separately so the composition is auditable.
	ImmediatePre    int                 `json:"immediatePre"`    // reachable by a pre-research (already-known) path
	ImmediateExt    int                 `json:"immediateExt"`    // any path, known or from this research (extended)
	Admin           int                 `json:"admin"`           // ... administrator-equivalent on the management plane
	Chained         int                 `json:"chained"`         // ... administrator only via a composed two-leg chain
	HostReach       int                 `json:"hostReach"`       // ... reaching the managed host (console, vMedia, debug)
	EscalationOnly  int                 `json:"escalationOnly"`  // hosts with only a credential-gated leg, no entry
	Unclassified    int                 `json:"unclassified"`    // findings whose check id maps to no exposure or path
	UnclassifiedIDs []Pair              `json:"unclassifiedIds"` // ... the check ids behind that count
	Coverage        CoverageView        `json:"coverage"`
	Cracks          CrackView           `json:"cracks"`
	GUID            GUIDView            `json:"guid"`
	Compromise      []ExposureRow       `json:"compromise"`
	Exposures       []ExposureRow       `json:"exposures"`
	Vendors         []VendorRow         `json:"vendors"`
	Classes         []Pair              `json:"classes"`
	Products        []Pair              `json:"products"`
	Generations     []Pair              `json:"generations"`
	Versions        []Pair              `json:"versions"`
	Firmware        []FirmwareGroupView `json:"firmware,omitempty"`
	PortsTCP        []Pair              `json:"portsTcp"`
	PortsUDP        []Pair              `json:"portsUdp"`
	Protocols       []Pair              `json:"protocols"`
	HTTPServers     []Pair              `json:"httpServers"`
	Checks          []Pair              `json:"checks"`
	Risks           map[string]int      `json:"risks"`
	RakpUsers       []Pair              `json:"rakpUsers"`
	SNMPComm        []Pair              `json:"snmpCommunities"`
}

// CoverageView records how many hosts carried each evidence family. It lets a
// report distinguish a measured zero from a source that did not contain that
// class of data.
type CoverageView struct {
	Services int `json:"services"`
	Findings int `json:"findings"`
	Identity int `json:"identity"`
	Versions int `json:"versions"`
	RAKP     int `json:"rakp"`
	GUID     int `json:"guid"`
}

// CrackView separates the captured-hash population, live scan recovery, account
// privilege shape, and later potfile growth. Host-scoped fields count unique
// hosts; row-scoped fields (HashRows, ScanRowCracks, PotRowCracks) count
// individual RAKP-2 exchanges, of which a host commonly has several. Total is
// the unique union of scan and potfile hits.
type CrackView struct {
	HashHosts       int                 `json:"hashHosts"`
	HashRows        int                 `json:"hashRows"`
	ScanAny         int                 `json:"scanAny"`
	ScanNamed       int                 `json:"scanNamed"`
	ScanEmpty       int                 `json:"scanEmpty"`
	ScanRowCracks   int                 `json:"scanRowCracks"`
	PotTotal        int                 `json:"potTotal"`
	PotOnly         int                 `json:"potOnly"`
	PotRowCracks    int                 `json:"potRowCracks"`
	PotLabel        string              `json:"potLabel,omitempty"`
	Total           int                 `json:"total"`
	Methods         []Pair              `json:"methods"`
	TopPasswords    []Pair              `json:"topPasswords"`
	TailPasswords   []Pair              `json:"tailPasswords"`      // recovered passwords after the vendor-default head
	VendorPasswords []VendorPasswordRow `json:"vendorPasswords"`    // per-vendor recovered passwords
	Patterns        []PatternRow        `json:"patterns,omitempty"` // detected generated-password families
}

// GUIDView summarizes the pre-auth information decoded from System GUIDs.
type GUIDView struct {
	Hosts          int    `json:"hosts"`
	Decoded        int    `json:"decoded"`
	VendorResolved int    `json:"vendorResolved"`
	ServiceTags    int    `json:"serviceTags"`
	Serials        int    `json:"serials"`
	Countries      int    `json:"countries"`
	NodeMACs       int    `json:"nodeMacs"`
	ModelPrefixes  int    `json:"modelPrefixes"`
	Families       []Pair `json:"families"`
	Vendors        []Pair `json:"vendors"`
	CountryCodes   []Pair `json:"countryCodes"`
}

// ExposureRow is one exposure prevalence row for a source.
type ExposureRow struct {
	Key   string  `json:"key"`
	Label string  `json:"label"`
	Hosts int     `json:"hosts"`
	Pct   float64 `json:"pct"`
	// Entry / Gain / New are set on compromise-path rows only (see paths.go), so
	// the page can group by precondition and privilege instead of re-encoding the
	// taxonomy in JavaScript.
	Entry string `json:"entry,omitempty"`
	Gain  string `json:"gain,omitempty"`
	New   bool   `json:"new,omitempty"`
	// Advisory is the advisory ID or CVE a reader can look the path up under.
	Advisory string `json:"advisory,omitempty"`
}

// VendorRow is one vendor's population and per-exposure counts for a source.
type VendorRow struct {
	Vendor string         `json:"vendor"`
	Count  int            `json:"count"`
	Pct    float64        `json:"pct"`
	Exp    map[string]int `json:"exp,omitempty"`
}

// FirmwareGroupView is one product line and the firmware-version distribution
// within it. It answers what the flat product and version lists cannot on their
// own -- which releases a given controller line is split across -- by
// cross-tabulating the two: across the iLO4 hosts, how many run 2.82 versus an
// older firmware. Only lines that resolved at least one firmware version
// appear. Total counts every host on the line and Known those that also exposed
// a version, so the coverage gap (controllers that never revealed one) stays
// visible; Versions percentages are of Known.
type FirmwareGroupView struct {
	Vendor     string `json:"vendor"`
	Product    string `json:"product,omitempty"`
	Generation string `json:"generation,omitempty"`
	Label      string `json:"label"`
	Total      int    `json:"total"`
	Known      int    `json:"known"`
	Versions   []Pair `json:"versions"`
}

// CompareView holds the cross-source comparison, present only when more than
// one source was named.
type CompareView struct {
	Exposures   []CompareRow `json:"exposures"`
	Classes     []CompareRow `json:"classes"`
	Vendors     []CompareRow `json:"vendors"`
	Products    []CompareRow `json:"products"`
	Generations []CompareRow `json:"generations"`
	Versions    []CompareRow `json:"versions"`
	Protocols   []CompareRow `json:"protocols"`
	PortsTCP    []CompareRow `json:"portsTcp"`
	PortsUDP    []CompareRow `json:"portsUdp"`
}

// CompareRow is one axis value compared across every source. Hosts and Pct are
// parallel to Report.Sources by index. Spread is the max-minus-min prevalence,
// the sort key that floats the sharpest divergences to the top.
type CompareRow struct {
	Key    string    `json:"key"`
	Label  string    `json:"label"`
	Hosts  []int     `json:"hosts"`
	Pct    []float64 `json:"pct"`
	Spread float64   `json:"spread"`
}

// topN caps the long-tail axes carried into the payload.
const (
	topVendors   = 40
	topProducts  = 25
	topPorts     = 25
	topProtocols = 25
	topServers   = 20
	topChecks    = 60
	topRakpUsers = 25
	topSNMP      = 25
	topCompareV  = 30
	// Firmware breakdown: the busiest product lines (selected by population across
	// all vendors, then grouped by vendor for display), and within each the most
	// common releases. The group cap is generous because it is a scrollable detail
	// page and a mixed corpus spans many real product lines.
	topFirmwareGroups   = 60
	topFirmwareVersions = 30
)

// Build projects the finalized sources onto the report payload.
func Build(generated string, sources []*Source) Report {
	r := Report{Generated: generated, Keys: Taxonomy}
	for _, s := range sources {
		r.Sources = append(r.Sources, s.view())
	}
	if len(sources) >= 2 {
		r.Compare = buildCompare(sources)
	}
	r.NewFindings = buildNewFindings(sources)
	names := make([]string, 0, len(sources))
	accums := make([]*patternAccum, 0, len(sources))
	for _, s := range sources {
		names = append(names, s.Name)
		accums = append(accums, s.patterns)
	}
	r.Passwords = passwordsView(names, accums)
	return r
}

// buildNewFindings fills each highlighted finding's per-source prevalence from
// the sources' own exposure totals, keeping every count anchored to the source
// population it came from. A firmware/source-only finding (no Key) carries no
// host numbers, so it is presented as evidence context, never a scan count.
func buildNewFindings(sources []*Source) []FindingHighlight {
	out := make([]FindingHighlight, 0, len(newFindingCatalog))
	for _, f := range newFindingCatalog {
		// One short title per advisory, shared with the compromise and exposure
		// slides; the catalog's long-form title is the fallback.
		if short, ok := advisoryTitles[f.ID]; ok {
			f.Title = short
		}
		f.Hosts = make([]int, len(sources))
		f.Pct = make([]float64, len(sources))
		f.Tested = make([]bool, len(sources))
		if f.Key != "" {
			for i, s := range sources {
				n := s.exposureTotals[f.Key]
				f.Hosts[i] = n
				f.Pct[i] = pct(n, s.Total)
				// A source "tested" for a finding when it observed the exposure at
				// least once or ran the probe check at least once; otherwise the
				// scan profile never looked, so a 0 must read as not-tested.
				f.Tested[i] = n > 0 || (f.Check != "" && s.checks.counts[f.Check] > 0)
			}
		}
		out = append(out, f)
	}
	// Sort by finding name so the table is a lookup: a reader who knows what they
	// are looking for finds it without scanning the risk column. Risk still
	// travels with every row, so severity is one column away.
	sort.SliceStable(out, func(a, b int) bool {
		na, nb := strings.ToLower(out[a].Title), strings.ToLower(out[b].Title)
		if na != nb {
			return na < nb
		}
		return out[a].ID < out[b].ID
	})
	return out
}

// VendorPasswordRow is one vendor's recovered-password breakdown for the deck.
type VendorPasswordRow struct {
	Vendor string `json:"vendor"`
	Count  int    `json:"count"` // total recovered RAKP rows for this vendor
	Top    []Pair `json:"top"`   // most frequent recovered passwords
}

// defaultPasswordSet marks the vendor-shipped default credentials that dominate
// the head of every recovered-password histogram. The long tail is everything
// else: operator-chosen secrets that survived cracking.
var defaultPasswordSet = map[string]bool{
	"admin": true, "ADMIN": true, "Admin": true, "administrator": true,
	"calvin": true, "root": true, "password": true, "Password": true,
	"superuser": true, "sysadmin": true, "user": true, "private": true,
	"public": true, "changeme": true, "common": true, "support": true,
}

// tailPasswords returns the n most frequent recovered passwords that are not a
// known vendor default — the operator-chosen long tail, not the default head.
func tailPasswords(c *counter, n int) []Pair {
	if c == nil {
		return nil
	}
	var out []Pair
	for _, p := range c.top(0) {
		if defaultPasswordSet[p.Value] {
			continue
		}
		out = append(out, p)
		if n > 0 && len(out) >= n {
			break
		}
	}
	return out
}

// vendorPasswordRows builds the per-vendor recovered-password breakdown,
// vendors sorted by their total recovered-row count (desc).
func vendorPasswordRows(s *Source) []VendorPasswordRow {
	type agg struct {
		vendor string
		total  int
		top    []Pair
	}
	rows := make([]agg, 0, len(s.crackVendorPass))
	for vendor, c := range s.crackVendorPass {
		rows = append(rows, agg{vendor: vendor, total: c.total, top: redactSecretPairs(c.top(5))})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].total != rows[j].total {
			return rows[i].total > rows[j].total
		}
		return rows[i].vendor < rows[j].vendor
	})
	out := make([]VendorPasswordRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, VendorPasswordRow{Vendor: r.vendor, Count: r.total, Top: r.top})
	}
	return out
}

func (s *Source) view() SourceView {
	v := SourceView{
		Name:             s.Name,
		Total:            s.Total,
		Redacted:         s.Redacted,
		Resolved:         s.resolvedVendor,
		Unknown:          s.Total - s.resolvedVendor - s.honeypotHosts,
		Honeypot:         s.honeypotHosts,
		HoneypotFindings: s.honeypotFindings,
		WithCritical:     s.withCritical,
		WithHigh:         s.withHigh,
		WithMedium:       s.withMedium,
		WithLow:          s.withLow,
		WithNone:         s.withNone,
		BMCHosts:         bmcPopulation(s),
		BMCSeverity:      s.bmcSeverity,
		RakpHosts:        s.rakpHosts,
		AutoCracked:      s.autoCrackedHosts,
		PotCracked:       s.potCrackedHosts,
		HasPot:           s.potCheck != nil,
		ImmediatePre:     s.immediatePreHosts,
		ImmediateExt:     s.immediateExtHosts,
		Admin:            s.adminHosts,
		Chained:          s.chainedAdminHosts,
		HostReach:        s.hostReachHosts,
		EscalationOnly:   s.escalationOnly,
		Unclassified:     s.unclassifiedFindings,
		UnclassifiedIDs:  s.unclassified.top(12),
		Coverage: CoverageView{
			Services: s.serviceHosts, Findings: s.findingHosts, Identity: s.nativeVendorHosts,
			Versions: s.versionHosts, RAKP: s.rakpHosts, GUID: s.guidHosts,
		},
		Cracks: CrackView{
			HashHosts: s.rakpHosts, HashRows: s.hashRows,
			ScanAny: s.autoCrackedHosts, ScanNamed: s.autoNamedHosts,
			ScanEmpty: s.autoEmptyHosts, ScanRowCracks: s.scanRowCracks,
			PotTotal: s.potCrackedHosts, PotOnly: s.potOnlyHosts, PotRowCracks: s.potRowCracks,
			PotLabel: s.potLabel, Total: s.crackedTotal, Methods: s.crackMethod.top(12),
			TopPasswords:    redactSecretPairs(s.crackPass.top(12)),
			TailPasswords:   redactSecretPairs(tailPasswords(s.crackPass, 14)),
			VendorPasswords: vendorPasswordRows(s),
			Patterns:        s.patterns.patternRows(),
		},
		GUID: GUIDView{
			Hosts: s.guidHosts, Decoded: s.guidDecodedHosts, VendorResolved: s.guidVendor.total,
			ServiceTags: s.guidServiceTags, Serials: s.guidSerials, Countries: s.guidCountries,
			NodeMACs: s.guidNodeMACs, ModelPrefixes: s.guidModelPrefixes,
			Families: s.guidFamily.top(20), Vendors: s.guidVendor.top(20), CountryCodes: s.guidCountry.top(20),
		},
		Classes:     s.class.top(0),
		Products:    s.product.top(topProducts),
		Generations: s.generation.top(topProducts),
		Versions:    s.osVersion.top(topProducts),
		Firmware:    s.firmwareGroups(),
		PortsTCP:    s.portsTCP.top(topPorts),
		PortsUDP:    s.portsUDP.top(topPorts),
		Protocols:   s.protocols.top(topProtocols),
		HTTPServers: s.httpServer.top(topServers),
		Checks:      s.checks.top(topChecks),
		Risks:       s.risks.counts,
		RakpUsers:   s.rakpUsers.top(topRakpUsers),
		SNMPComm:    s.snmpComm.top(topSNMP),
	}
	for _, path := range CompromisePaths {
		v.Compromise = append(v.Compromise, ExposureRow{
			Key: path.Key, Label: shortTitle(path.Advisory, path.Label), Hosts: s.compromiseTotals[path.Key],
			Pct:   pct(s.compromiseTotals[path.Key], s.Total),
			Entry: string(path.Entry), Gain: string(path.Gain), New: path.New,
			Advisory: path.Advisory,
		})
	}
	for _, e := range Taxonomy {
		v.Exposures = append(v.Exposures, ExposureRow{
			Key:   e.Key,
			Label: exposureLabel(e.Key, e.Label),
			Hosts: s.exposureTotals[e.Key],
			Pct:   pct(s.exposureTotals[e.Key], s.Total),
		})
	}
	for _, p := range s.vendor.top(topVendors) {
		vs := s.byVendorExp[p.Value]
		row := VendorRow{Vendor: p.Value, Count: p.Count, Pct: pct(p.Count, s.Total)}
		if vs != nil && len(vs.exp) > 0 {
			row.Exp = vs.exp
		}
		v.Vendors = append(v.Vendors, row)
	}
	return v
}

// firmwareGroups projects the per-line firmware distributions. A line the scan
// resolved a product for but never a single firmware version is dropped (a
// firmware breakdown with no firmware is noise, and the flat product list already
// carries that population). The surviving lines are then chosen and ordered in
// two independent steps:
//
//   - Selection is by population: the busiest lines across ALL vendors are kept,
//     so the cap can never be eaten by one vendor's long tail of one-off SKUs --
//     a fleet with forty single-host HPE storage models must not push iDRAC and
//     the SMC X-series off the page.
//   - Display groups the survivors by vendor (largest vendor block first), and
//     within a vendor keeps a product family together with its busiest family
//     leading, but orders the generations inside a family naturally (iLO4 before
//     iLO5, iDRAC8 before iDRAC9) rather than by host count.
//
// The generation and product context columns are cleared when they merely repeat
// the line label, so a row that reads "HPE iLO4" is not padded with "iLO4 · iLO4".
func (s *Source) firmwareGroups() []FirmwareGroupView {
	kept := make([]*firmwareGroup, 0, len(s.firmware))
	for _, g := range s.firmware {
		if g.versions.total > 0 {
			kept = append(kept, g)
		}
	}
	// Keep the most populous lines regardless of vendor. Ties break on the line
	// label so the selection is deterministic.
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].versions.total != kept[j].versions.total {
			return kept[i].versions.total > kept[j].versions.total
		}
		return kept[i].line < kept[j].line
	})
	if len(kept) > topFirmwareGroups {
		kept = kept[:topFirmwareGroups]
	}
	// Aggregate the survivors by vendor and by product family for the display
	// ordering (family = the line with digit runs folded out; see firmwareFamilyKey).
	vendorKnown := map[string]int{}
	familyKnown := map[string]int{}
	for _, g := range kept {
		vendorKnown[g.vendor] += g.versions.total
		familyKnown[g.vendor+"\x00"+firmwareFamilyKey(g.line)] += g.versions.total
	}
	sort.SliceStable(kept, func(i, j int) bool {
		gi, gj := kept[i], kept[j]
		if gi.vendor != gj.vendor {
			if vendorKnown[gi.vendor] != vendorKnown[gj.vendor] {
				return vendorKnown[gi.vendor] > vendorKnown[gj.vendor]
			}
			return gi.vendor < gj.vendor
		}
		fi, fj := firmwareFamilyKey(gi.line), firmwareFamilyKey(gj.line)
		if fi != fj {
			ki, kj := gi.vendor+"\x00"+fi, gj.vendor+"\x00"+fj
			if familyKnown[ki] != familyKnown[kj] {
				return familyKnown[ki] > familyKnown[kj]
			}
			return fi < fj
		}
		return naturalLess(gi.line, gj.line)
	})
	rows := make([]FirmwareGroupView, 0, len(kept))
	for _, g := range kept {
		gen := g.generation
		// Drop the generation context column when it just repeats the line label
		// or is a bare number that names nothing on its own (Dell's iDRAC9
		// generation "9"): the line label already carries the identity.
		if gen == g.line || !hasLetter(gen) {
			gen = ""
		}
		product := g.product
		if product == g.line {
			product = ""
		}
		rows = append(rows, FirmwareGroupView{
			Vendor:     g.vendor,
			Product:    product,
			Generation: gen,
			Label:      strings.TrimSpace(g.vendor + " " + g.line),
			Total:      g.total,
			Known:      g.versions.total,
			Versions:   g.versions.top(topFirmwareVersions),
		})
	}
	return rows
}

// firmwareFamilyKey folds a product line to its family by dropping digit runs and
// normalizing case/spacing, so a family's generations rank and sort together:
// iLO4/iLO5/iLO6 -> "ilo", iDRAC8/iDRAC9 -> "idrac", X10/X11/X12 -> "x". It is a
// grouping key only and is never displayed; an occasional over-merge (two
// unrelated models folding together) only affects adjacency, never a count.
func firmwareFamilyKey(line string) string {
	var b strings.Builder
	for i := 0; i < len(line); i++ {
		if c := line[i]; c < '0' || c > '9' {
			b.WriteByte(c)
		}
	}
	return strings.Join(strings.Fields(strings.ToLower(b.String())), " ")
}

// naturalLess orders strings so embedded numbers compare by value rather than
// lexically: "iLO4" sorts before "iLO5", "X10" before "X11", "iDRAC8" before
// "iDRAC9". It walks both strings in alternating text and digit runs, comparing
// digit runs numerically (leading zeros ignored) and text case-insensitively, so
// a plain "iLO10" does not fall between "iLO1" and "iLO2".
func naturalLess(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if isDigit(a[i]) && isDigit(b[j]) {
			si, sj := i, j
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
			na := strings.TrimLeft(a[si:i], "0")
			nb := strings.TrimLeft(b[sj:j], "0")
			if len(na) != len(nb) {
				return len(na) < len(nb)
			}
			if na != nb {
				return na < nb
			}
			continue
		}
		if a[i] != b[j] {
			return a[i] < b[j]
		}
		i++
		j++
	}
	return len(a)-i < len(b)-j
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// hasLetter reports whether s contains an ASCII letter, used to tell a
// descriptive identity token ("iDRAC9") from a bare numeric one ("9").
func hasLetter(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

// buildCompare builds the cross-source comparison rows.
func buildCompare(sources []*Source) *CompareView {
	c := &CompareView{}

	// Exposures: every taxonomy key, in taxonomy order, with the spread computed
	// so the view can offer a "biggest divergence" sort.
	for _, e := range Taxonomy {
		row := CompareRow{Key: e.Key, Label: exposureLabel(e.Key, e.Label)}
		for _, s := range sources {
			h := s.exposureTotals[e.Key]
			row.Hosts = append(row.Hosts, h)
			row.Pct = append(row.Pct, pct(h, s.Total))
		}
		row.Spread = spread(row.Pct)
		c.Exposures = append(c.Exposures, row)
	}

	// Classes: union of classes across sources.
	c.Classes = compareCounter(sources, func(s *Source) *counter { return s.class }, 0)
	// Vendors: union, capped to the busiest, spread-sorted.
	c.Vendors = compareCounter(sources, func(s *Source) *counter { return s.vendor }, topCompareV)
	c.Products = compareCounter(sources, func(s *Source) *counter { return s.product }, topCompareV)
	c.Generations = compareCounter(sources, func(s *Source) *counter { return s.generation }, topCompareV)
	c.Versions = compareCounter(sources, func(s *Source) *counter { return s.osVersion }, topCompareV)
	c.Protocols = compareCounter(sources, func(s *Source) *counter { return s.protocols }, topCompareV)
	c.PortsTCP = compareCounter(sources, func(s *Source) *counter { return s.portsTCP }, topCompareV)
	c.PortsUDP = compareCounter(sources, func(s *Source) *counter { return s.portsUDP }, topCompareV)
	return c
}

// compareCounter builds comparison rows for a per-source counter (class or
// vendor). Rows are sorted by spread desc, then combined volume desc. limit<=0
// keeps all.
func compareCounter(sources []*Source, pick func(*Source) *counter, limit int) []CompareRow {
	keys := map[string]bool{}
	for _, s := range sources {
		for k := range pick(s).counts {
			keys[k] = true
		}
	}
	rows := make([]CompareRow, 0, len(keys))
	for k := range keys {
		row := CompareRow{Key: k, Label: k}
		for _, s := range sources {
			h := pick(s).counts[k]
			row.Hosts = append(row.Hosts, h)
			row.Pct = append(row.Pct, pct(h, s.Total))
		}
		row.Spread = spread(row.Pct)
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Spread != rows[j].Spread {
			return rows[i].Spread > rows[j].Spread
		}
		vi, vj := sum(rows[i].Hosts), sum(rows[j].Hosts)
		if vi != vj {
			return vi > vj
		}
		return rows[i].Key < rows[j].Key
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// pct returns 100*n/total rounded to two decimals (0 when total is 0).
func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	v := 100 * float64(n) / float64(total)
	return float64(int64(v*100+0.5)) / 100
}

func spread(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	lo, hi := vals[0], vals[0]
	for _, v := range vals[1:] {
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
	}
	return hi - lo
}

func sum(vals []int) int {
	t := 0
	for _, v := range vals {
		t += v
	}
	return t
}
