package report

import (
	"sort"
	"strings"
)

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

type FindingHighlight struct {
	ID       string    `json:"id"`
	Vendor   string    `json:"vendor"`
	Title    string    `json:"title"`
	Risk     string    `json:"risk"`
	Check    string    `json:"check"`
	Key      string    `json:"key"`
	Evidence string    `json:"evidence"`
	Hosts    []int     `json:"hosts"`
	Pct      []float64 `json:"pct"`
	Tested   []bool    `json:"tested"`
}

var newFindingCatalog = []FindingHighlight{
	{ID: "CVE-2024-54085", Vendor: "AMI MegaRAC", Title: "Redfish Host-Interface (X-Server-Addr) auth bypass", Risk: "critical", Check: "http.redfish.amiBypass", Key: "ami_redfish_bypass", Evidence: "scan-observed"},
	{ID: "CVE-2023-34329", Vendor: "AMI MegaRAC", Title: "Redfish Host-header / X-Forwarded auth bypass", Risk: "high", Check: "http.redfish.ami.cve202334329", Key: "ami_redfish_bypass", Evidence: "scan-observed"},
	{ID: "AMI-mTLS", Vendor: "AMI MegaRAC", Title: "Redfish mTLS CA-trust bypass", Risk: "high", Check: "tls.mtls.ami.caBypass", Key: "ami_mtls_bypass", Evidence: "scan-observed"},
}

type AdvisoryView struct {
	Total      int            `json:"total"`
	Vendors    int            `json:"vendors"`
	States     []Pair         `json:"states"`
	Risks      []Pair         `json:"risks"`
	Surfaces   []Pair         `json:"surfaces"`
	ByVendor   []Pair         `json:"byVendor"`
	Highlights []AdvisoryItem `json:"highlights"`
}

type AdvisoryItem struct {
	ID        string `json:"id"`
	Vendor    string `json:"vendor"`
	Risk      string `json:"risk"`
	Surface   string `json:"surface"`
	Component string `json:"component"`
	Title     string `json:"title"`
}

type SourceView struct {
	Name     string `json:"name"`
	Total    int    `json:"total"`
	Redacted bool   `json:"redacted"`
	Resolved int    `json:"resolved"`
	Unknown  int    `json:"unknown"`
	Honeypot int    `json:"honeypot"`

	HoneypotFindings int `json:"honeypotFindings"`

	WithCritical int `json:"withCritical"`
	WithHigh     int `json:"withHigh"`
	WithMedium   int `json:"withMedium"`
	WithLow      int `json:"withLow"`
	WithNone     int `json:"withNone"`

	BMCHosts    int            `json:"bmcHosts"`
	BMCSeverity map[string]int `json:"bmcSeverity,omitempty"`
	RakpHosts   int            `json:"rakpHosts"`
	AutoCracked int            `json:"autoCracked"`
	PotCracked  int            `json:"potCracked"`
	HasPot      bool           `json:"hasPot"`

	ImmediatePre    int            `json:"immediatePre"`
	ImmediateExt    int            `json:"immediateExt"`
	Admin           int            `json:"admin"`
	Chained         int            `json:"chained"`
	HostReach       int            `json:"hostReach"`
	EscalationOnly  int            `json:"escalationOnly"`
	Unclassified    int            `json:"unclassified"`
	UnclassifiedIDs []Pair         `json:"unclassifiedIds"`
	Coverage        CoverageView   `json:"coverage"`
	Cracks          CrackView      `json:"cracks"`
	GUID            GUIDView       `json:"guid"`
	Compromise      []ExposureRow  `json:"compromise"`
	Exposures       []ExposureRow  `json:"exposures"`
	Vendors         []VendorRow    `json:"vendors"`
	Classes         []Pair         `json:"classes"`
	Products        []Pair         `json:"products"`
	Generations     []Pair         `json:"generations"`
	Versions        []Pair         `json:"versions"`
	PortsTCP        []Pair         `json:"portsTcp"`
	PortsUDP        []Pair         `json:"portsUdp"`
	Protocols       []Pair         `json:"protocols"`
	HTTPServers     []Pair         `json:"httpServers"`
	Checks          []Pair         `json:"checks"`
	Risks           map[string]int `json:"risks"`
	RakpUsers       []Pair         `json:"rakpUsers"`
	SNMPComm        []Pair         `json:"snmpCommunities"`
}

type CoverageView struct {
	Services int `json:"services"`
	Findings int `json:"findings"`
	Identity int `json:"identity"`
	Versions int `json:"versions"`
	RAKP     int `json:"rakp"`
	GUID     int `json:"guid"`
}

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
	TailPasswords   []Pair              `json:"tailPasswords"`
	VendorPasswords []VendorPasswordRow `json:"vendorPasswords"`
	Patterns        []PatternRow        `json:"patterns,omitempty"`
}

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

type ExposureRow struct {
	Key   string  `json:"key"`
	Label string  `json:"label"`
	Hosts int     `json:"hosts"`
	Pct   float64 `json:"pct"`

	Entry string `json:"entry,omitempty"`
	Gain  string `json:"gain,omitempty"`
	New   bool   `json:"new,omitempty"`

	Advisory string `json:"advisory,omitempty"`
}

type VendorRow struct {
	Vendor string         `json:"vendor"`
	Count  int            `json:"count"`
	Pct    float64        `json:"pct"`
	Exp    map[string]int `json:"exp,omitempty"`
}

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

type CompareRow struct {
	Key    string    `json:"key"`
	Label  string    `json:"label"`
	Hosts  []int     `json:"hosts"`
	Pct    []float64 `json:"pct"`
	Spread float64   `json:"spread"`
}

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
)

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

func buildNewFindings(sources []*Source) []FindingHighlight {
	out := make([]FindingHighlight, 0, len(newFindingCatalog))
	for _, f := range newFindingCatalog {

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

				f.Tested[i] = n > 0 || (f.Check != "" && s.checks.counts[f.Check] > 0)
			}
		}
		out = append(out, f)
	}

	sort.SliceStable(out, func(a, b int) bool {
		na, nb := strings.ToLower(out[a].Title), strings.ToLower(out[b].Title)
		if na != nb {
			return na < nb
		}
		return out[a].ID < out[b].ID
	})
	return out
}

type VendorPasswordRow struct {
	Vendor string `json:"vendor"`
	Count  int    `json:"count"`
	Top    []Pair `json:"top"`
}

var defaultPasswordSet = map[string]bool{
	"admin": true, "ADMIN": true, "Admin": true, "administrator": true,
	"calvin": true, "root": true, "password": true, "Password": true,
	"superuser": true, "sysadmin": true, "user": true, "private": true,
	"public": true, "changeme": true, "common": true, "support": true,
}

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

func buildCompare(sources []*Source) *CompareView {
	c := &CompareView{}

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

	c.Classes = compareCounter(sources, func(s *Source) *counter { return s.class }, 0)

	c.Vendors = compareCounter(sources, func(s *Source) *counter { return s.vendor }, topCompareV)
	c.Products = compareCounter(sources, func(s *Source) *counter { return s.product }, topCompareV)
	c.Generations = compareCounter(sources, func(s *Source) *counter { return s.generation }, topCompareV)
	c.Versions = compareCounter(sources, func(s *Source) *counter { return s.osVersion }, topCompareV)
	c.Protocols = compareCounter(sources, func(s *Source) *counter { return s.protocols }, topCompareV)
	c.PortsTCP = compareCounter(sources, func(s *Source) *counter { return s.portsTCP }, topCompareV)
	c.PortsUDP = compareCounter(sources, func(s *Source) *counter { return s.portsUDP }, topCompareV)
	return c
}

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
