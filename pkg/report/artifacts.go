package report

import (
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/hashcrack"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/output"
	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

type Artifacts struct {
	name  string
	total int

	potCheck func(rec *scanfile.Record) []PotCrack

	vendor      *counter
	class       *counter
	product     *counter
	osVersion   *counter
	hwProduct   *counter
	portsTCP    *counter
	portsUDP    *counter
	protocols   *counter
	httpServers *counter
	checks      *counter
	risks       *counter

	exposureTotals map[string]int
	byVendorExp    map[string]*expVendor
	withCritical   int
	withHigh       int

	ipmiHosts    int
	cipherIDs    *counter
	cipherSuites *counter
	ipmiVersions *counter
	guidVendors  *counter
	oemNames     *counter
	rakpUsers    *counter
	rakpCracked  *counter

	snmpHosts       int
	snmpV3Hosts     int
	snmpVersions    *counter
	snmpCommunities *counter
	snmpEngines     *counter
	snmpSysDesc     *counter
	snmpSysOID      *counter

	rakp []rakpArtifact

	vendors map[string]*vendorArtifact
}

type expVendor struct {
	total int
	exp   map[string]int
}

type rakpArtifact struct {
	vendor   string
	product  string
	username string
	algo     string
	salt     string
	mac      string
	smcFixed bool
	redacted bool
	cracked  string
}

type vendorArtifact struct {
	assets      int
	osVersion   *counter
	firmware    *counter
	product     *counter
	portsTCP    *counter
	portsUDP    *counter
	protocols   *counter
	httpServers *counter
	htmlTitles  *counter
	tlsNames    *counter
}

func newVendorArtifact() *vendorArtifact {
	return &vendorArtifact{
		osVersion: newCounter(), firmware: newCounter(), product: newCounter(),
		portsTCP: newCounter(), portsUDP: newCounter(), protocols: newCounter(),
		httpServers: newCounter(), htmlTitles: newCounter(), tlsNames: newCounter(),
	}
}

func NewArtifacts(name string) *Artifacts {
	return &Artifacts{
		name:            name,
		vendor:          newCounter(),
		class:           newCounter(),
		product:         newCounter(),
		osVersion:       newCounter(),
		hwProduct:       newCounter(),
		portsTCP:        newCounter(),
		portsUDP:        newCounter(),
		protocols:       newCounter(),
		httpServers:     newCounter(),
		checks:          newCounter(),
		risks:           newCounter(),
		exposureTotals:  map[string]int{},
		byVendorExp:     map[string]*expVendor{},
		cipherIDs:       newCounter(),
		cipherSuites:    newCounter(),
		ipmiVersions:    newCounter(),
		guidVendors:     newCounter(),
		oemNames:        newCounter(),
		rakpUsers:       newCounter(),
		rakpCracked:     newCounter(),
		snmpVersions:    newCounter(),
		snmpCommunities: newCounter(),
		snmpEngines:     newCounter(),
		snmpSysDesc:     newCounter(),
		snmpSysOID:      newCounter(),
		vendors:         map[string]*vendorArtifact{},
	}
}

func (a *Artifacts) SetPotCheck(fn func(rec *scanfile.Record) []PotCrack) {
	a.potCheck = fn
}

func (a *Artifacts) Observe(rec *scanfile.Record) {
	a.total++

	slug := vendorSlug(rec)
	vendor := displayVendor(slug)
	class := displayClass(resolvedClass(rec, slug))
	product := recordProduct(rec)

	a.vendor.add(vendor)
	a.class.add(class)
	if product != "" {
		a.product.add(product)
	}
	if rec.Final != nil && rec.Final.Version != "" {
		a.osVersion.add(rec.Final.Version)
	}
	if hw := rec.Attributes["hw_product"]; hw != "" {
		a.hwProduct.add(hw)
	}

	for k := range rec.Ports {
		port, transport := splitPortKey(k)
		if port == 0 {
			continue
		}
		switch transport {
		case "tcp":
			a.portsTCP.add(strconv.Itoa(port))
		case "udp":
			a.portsUDP.add(strconv.Itoa(port))
		}
	}
	seenProto := map[string]bool{}
	for k := range rec.Ports {
		for p := range strings.SplitSeq(rec.Ports[k], ",") {
			if p = strings.TrimSpace(p); p != "" && !seenProto[p] {
				seenProto[p] = true
				a.protocols.add(p)
			}
		}
	}
	httpServer := firstServiceAttr(rec, "http.head.server")
	if httpServer != "" {
		a.httpServers.add(httpServer)
	}

	exp := map[string]bool{}
	topRisk := ""
	ipmiSeen := false
	for i := range rec.Findings {
		f := &rec.Findings[i]
		if f.Check == "" {
			continue
		}
		a.checks.add(f.Check)
		if f.Risk != "" {
			a.risks.add(f.Risk)
		}
		if engine.RiskRank(f.Risk) > engine.RiskRank(topRisk) {
			topRisk = f.Risk
		}
		scoreCheck(f.Check, exp)
		if strings.HasPrefix(f.Check, "ipmi.") {
			ipmiSeen = true
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
		a.observeIPMIFinding(f)
	}
	scoreServiceExposure(rec, exp)
	if rec.Final != nil && rec.Final.TopRisk != "" {
		topRisk = rec.Final.TopRisk
	}
	switch topRisk {
	case "critical":
		a.withCritical++
	case "high":
		a.withHigh++
	}

	for i := range rec.RAKP {
		a.observeRAKP(&rec.RAKP[i], vendor, product)
	}
	if len(rec.RAKP) > 0 {
		exp["ipmi_rakp_hash"] = true
		exp["ipmi"] = true
		exp["ipmi_2_0"] = true
		ipmiSeen = true
	}

	for i := range rec.RAKP {
		if isRecoveredPassword(rec.RAKP[i].Cracked) {
			exp["ipmi_rakp_cracked"] = true
			break
		}
	}
	if !exp["ipmi_rakp_cracked"] && a.potCheck != nil && len(a.potCheck(rec)) > 0 {
		exp["ipmi_rakp_cracked"] = true
	}
	if sids := rakpSessionIDs(rec.RAKP); len(sids) >= 3 {
		if _, weak := ipmi.ClassifySessionIDs(sids); weak {
			exp["ipmi_sid_weak"] = true
		}
	}
	if exp["ipmi"] || ipmiSeen {
		a.ipmiHosts++
	}

	a.observeIPMIAttrs(rec)
	a.observeSNMP(rec, exp)

	ev := a.byVendorExp[vendor]
	if ev == nil {
		ev = &expVendor{exp: map[string]int{}}
		a.byVendorExp[vendor] = ev
	}
	ev.total++
	for key := range exp {
		a.exposureTotals[key]++
		ev.exp[key]++
	}

	a.observeVendor(rec, vendor, product, httpServer)
}

func (a *Artifacts) observeIPMIFinding(f *engine.Finding) {
	switch f.Check {
	case "ipmi.ciphers":
		if suites := findingField(f, "suites"); suites != "" {
			a.cipherSuites.add(suites)
			for id := range strings.SplitSeq(suites, ",") {
				if id = strings.TrimSpace(id); id != "" {
					a.cipherIDs.add(id)
				}
			}
		}
	case "ipmi.versions":
		if v := findingField(f, "versions"); v != "" {
			a.ipmiVersions.add(v)
		}
	case "ipmi.guid":
		if v := findingField(f, "vendor"); v != "" {
			a.guidVendors.add(v)
		}
	}
}

func (a *Artifacts) observeIPMIAttrs(rec *scanfile.Record) {
	if oem := firstServiceAttr(rec, "ipmi.oemName", "ipmi.manufacturerName"); oem != "" {
		a.oemNames.add(oem)
	}
}

func (a *Artifacts) observeRAKP(r *output.RAKPRecord, vendor, product string) {
	art := rakpArtifact{
		vendor:   vendor,
		product:  product,
		username: displayUser(r.Username),
		cracked:  strings.TrimSpace(r.Cracked),
		redacted: r.Redacted,
	}
	if algo := hashcrack.AlgoName(r.AuthAlgo); algo != "?" {
		art.algo = algo
	}
	if rr, ok := reconstructRAKP(r); ok {
		art.salt = fmt.Sprintf("%x", rr.Salt())
		art.mac = fmt.Sprintf("%x", rr.RAKPHash)
		art.smcFixed = rr.UsesSMCRAKPFixedKey()
	}
	a.rakp = append(a.rakp, art)
	a.rakpUsers.add(art.username)
	if isRecoveredPassword(art.cracked) {
		a.rakpCracked.add(art.cracked)
	}
}

func (a *Artifacts) observeSNMP(rec *scanfile.Record, exp map[string]bool) {
	ver := firstServiceAttr(rec, "snmp.version")
	comm := firstServiceAttr(rec, "snmp.defaultCommunities")
	engineID := firstServiceAttr(rec, "snmp.engine", "snmp.engineID.raw")
	sysDesc := firstServiceAttr(rec, "snmp.sysDesc", "snmp.sysdescr")
	sysOID := firstServiceAttr(rec, "snmp.sysObjectID")

	if comm == "" {
		for i := range rec.Findings {
			f := &rec.Findings[i]
			if f.Check == "snmp.defaultCreds" || f.Check == "snmp.vendorCommunity" {
				if c := findingField(f, "community"); c != "" {
					comm = c
					break
				}
			}
		}
	}

	present := ver != "" || engineID != "" || sysDesc != "" || sysOID != "" || comm != "" || exp["snmp_v3"] || exp["snmp_default_cred"]
	if !present {
		return
	}
	a.snmpHosts++

	for _, v := range splitTabComma(ver) {
		a.snmpVersions.add(v)
	}
	if strings.Contains(ver, "3") || exp["snmp_v3"] {
		a.snmpV3Hosts++
	}
	for _, c := range splitTabComma(comm) {
		a.snmpCommunities.add(c)
	}
	if engineID != "" {
		a.snmpEngines.add(engineID)
	}
	if sysDesc != "" {
		a.snmpSysDesc.add(firstLine(sysDesc))
	}
	if sysOID != "" {
		a.snmpSysOID.add(sysOID)
	}
}

func (a *Artifacts) observeVendor(rec *scanfile.Record, vendor, product, httpServer string) {
	va := a.vendors[vendor]
	if va == nil {
		va = newVendorArtifact()
		a.vendors[vendor] = va
	}
	va.assets++
	if rec.Final != nil && rec.Final.Version != "" {
		va.osVersion.add(rec.Final.Version)
	}
	if fw := firstNonEmpty(firstServiceAttr(rec, "ipmi.firmwareVersion"), rec.Attributes["firmwareVersion"]); fw != "" {
		va.firmware.add(fw)
	}
	if product != "" {
		va.product.add(product)
	}
	for k := range rec.Ports {
		port, transport := splitPortKey(k)
		if port == 0 {
			continue
		}
		switch transport {
		case "tcp":
			va.portsTCP.add(strconv.Itoa(port))
		case "udp":
			va.portsUDP.add(strconv.Itoa(port))
		}
	}
	seen := map[string]bool{}
	for k := range rec.Ports {
		for p := range strings.SplitSeq(rec.Ports[k], ",") {
			if p = strings.TrimSpace(p); p != "" && !seen[p] {
				seen[p] = true
				va.protocols.add(p)
			}
		}
	}
	if httpServer != "" {
		va.httpServers.add(httpServer)
	}
	if title := firstServiceAttr(rec, "http.title"); title != "" {
		va.htmlTitles.add(title)
	}
	if name := firstServiceAttr(rec, "tls.subject", "tls.names"); name != "" {
		va.tlsNames.add(name)
	}
}

func (a *Artifacts) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, w := range []func(string) error{
		a.writeOverview,
		a.writeExposure,
		a.writeIPMI,
		a.writeSNMP,
		a.writeHashes,
		a.writeVendors,
		a.writeSummary,
	} {
		if err := w(dir); err != nil {
			return err
		}
	}
	return nil
}

func (a *Artifacts) writeOverview(dir string) error {
	d := filepath.Join(dir, "overview")
	tables := []struct {
		c              *counter
		file, valueCol string
	}{
		{a.vendor, "vendor.csv", "vendor"},
		{a.class, "class.csv", "class"},
		{a.product, "products.csv", "product"},
		{a.osVersion, "os_version.csv", "os_version"},
		{a.hwProduct, "hw_product.csv", "hw_product"},
		{a.portsTCP, "ports_tcp.csv", "tcp_port"},
		{a.portsUDP, "ports_udp.csv", "udp_port"},
		{a.protocols, "protocols.csv", "protocol"},
		{a.httpServers, "http_servers.csv", "http_server"},
		{a.checks, "checks.csv", "check"},
		{a.risks, "risks.csv", "risk"},
	}
	for _, t := range tables {
		if err := writeCounterCSV(filepath.Join(d, t.file), t.c, t.valueCol); err != nil {
			return err
		}
	}
	return nil
}

func (a *Artifacts) writeExposure(dir string) error {
	d := filepath.Join(dir, "exposure")

	rates := [][]string{{"key", "label", "hosts", "percent"}}
	for _, e := range Taxonomy {
		n := a.exposureTotals[e.Key]
		rates = append(rates, []string{e.Key, e.Label, strconv.Itoa(n), pctString(n, a.total)})
	}
	if err := writeCSVRows(filepath.Join(d, "exposure_rates.csv"), rates); err != nil {
		return err
	}

	header := []string{"vendor", "total"}
	for _, e := range Taxonomy {
		header = append(header, e.Key)
	}
	matrix := [][]string{header}
	type vrow struct {
		vendor string
		ev     *expVendor
	}
	rows := make([]vrow, 0, len(a.byVendorExp))
	for v, ev := range a.byVendorExp {
		rows = append(rows, vrow{v, ev})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ev.total != rows[j].ev.total {
			return rows[i].ev.total > rows[j].ev.total
		}
		return rows[i].vendor < rows[j].vendor
	})
	for _, r := range rows {
		cells := []string{r.vendor, strconv.Itoa(r.ev.total)}
		for _, e := range Taxonomy {
			cells = append(cells, strconv.Itoa(r.ev.exp[e.Key]))
		}
		matrix = append(matrix, cells)
	}
	return writeCSVRows(filepath.Join(d, "vendor_matrix.csv"), matrix)
}

func (a *Artifacts) writeIPMI(dir string) error {
	d := filepath.Join(dir, "ipmi")
	tables := []struct {
		c              *counter
		file, valueCol string
	}{
		{a.cipherIDs, "cipher_ids.csv", "cipher_id"},
		{a.cipherSuites, "cipher_suites.csv", "cipher_suites"},
		{a.ipmiVersions, "versions.csv", "ipmi_versions"},
		{a.guidVendors, "guid_vendors.csv", "guid_vendor"},
		{a.oemNames, "oem_names.csv", "oem_name"},
		{a.rakpUsers, "rakp_users.csv", "username"},
		{a.rakpCracked, "rakp_cracked.csv", "password"},
	}
	for _, t := range tables {
		if err := writeCounterCSV(filepath.Join(d, t.file), t.c, t.valueCol); err != nil {
			return err
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "IPMI summary (%s)\n\n", a.name)
	fmt.Fprintf(&b, "ipmi_reachable_hosts: %d\n", a.ipmiHosts)
	fmt.Fprintf(&b, "rakp_hashes_captured: %d\n", len(a.rakp))
	fmt.Fprintf(&b, "rakp_users_distinct:  %d\n", len(a.rakpUsers.counts))
	fmt.Fprintf(&b, "rakp_cracked_hashes:  %d\n", a.rakpCracked.total)
	fmt.Fprintf(&b, "distinct_cipher_sets: %d\n", len(a.cipherSuites.counts))
	fmt.Fprintf(&b, "distinct_guid_vendors:%d\n", len(a.guidVendors.counts))
	return writeText(filepath.Join(d, "summary.txt"), b.String())
}

func (a *Artifacts) writeSNMP(dir string) error {
	d := filepath.Join(dir, "snmp")
	tables := []struct {
		c              *counter
		file, valueCol string
	}{
		{a.snmpVersions, "versions.csv", "snmp_version"},
		{a.snmpCommunities, "communities.csv", "community"},
		{a.snmpEngines, "engine_ids.csv", "engine_id"},
		{a.snmpSysDesc, "sys_descriptions.csv", "sys_desc"},
		{a.snmpSysOID, "sys_object_ids.csv", "sys_object_id"},
	}
	for _, t := range tables {
		if err := writeCounterCSV(filepath.Join(d, t.file), t.c, t.valueCol); err != nil {
			return err
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "SNMP summary (%s)\n\n", a.name)
	fmt.Fprintf(&b, "snmp_hosts:            %d\n", a.snmpHosts)
	fmt.Fprintf(&b, "snmp_v3_hosts:         %d\n", a.snmpV3Hosts)
	fmt.Fprintf(&b, "default_community_hosts:%d\n", a.exposureTotals["snmp_default_cred"])
	fmt.Fprintf(&b, "distinct_communities:  %d\n", len(a.snmpCommunities.counts))
	return writeText(filepath.Join(d, "summary.txt"), b.String())
}

func (a *Artifacts) writeHashes(dir string) error {
	d := filepath.Join(dir, "hashes")

	var sha1HC, md5HC, jtrSHA1, jtrMD5, jtrSHA256 []string
	rows := [][]string{{"vendor", "product", "username", "algo", "salt", "mac", "smcrakp_fixed_key", "redacted", "cracked"}}
	seen := map[string]bool{}
	for i := range a.rakp {
		h := &a.rakp[i]
		rows = append(rows, []string{
			h.vendor, h.product, h.username, h.algo, h.salt, h.mac,
			strconv.FormatBool(h.smcFixed), strconv.FormatBool(h.redacted), h.cracked,
		})

		if h.redacted || h.smcFixed || h.salt == "" || len(h.mac) != 2*macHexLen(h.algo) {
			continue
		}
		key := h.algo + "|" + h.salt + "|" + h.mac
		if seen[key] {
			continue
		}
		seen[key] = true
		switch h.algo {
		case "sha1":
			sha1HC = append(sha1HC, h.salt+":"+h.mac)
			jtrSHA1 = append(jtrSHA1, "$rakp$"+h.salt+"$"+h.mac)
		case "md5":
			md5HC = append(md5HC, h.mac+":"+h.salt)
			jtrMD5 = append(jtrMD5, "$rakp$"+h.salt+"$"+h.mac)
		case "sha256":
			jtrSHA256 = append(jtrSHA256, "$rakp$"+h.salt+"$"+h.mac)
		}
	}

	files := []struct {
		name  string
		lines []string
	}{
		{"rakp-sha1.7300.hc", sha1HC},
		{"rakp-md5.7350.hc", md5HC},
		{"rakp-sha1.jtr", jtrSHA1},
		{"rakp-md5.jtr", jtrMD5},
		{"rakp-sha256.jtr", jtrSHA256},
	}
	for _, f := range files {
		if err := writeLinesFile(filepath.Join(d, f.name), f.lines); err != nil {
			return err
		}
	}
	if err := writeCSVRows(filepath.Join(d, "rakp-hashes.csv"), rows); err != nil {
		return err
	}

	readme := fmt.Sprintf(`RAKP hash artifacts (%s)
=========================

hashcat:
  hashcat -m 7300 rakp-sha1.7300.hc -a 0 <wordlist>   # %d SHA1 lines (salt:mac)
  hashcat -m 7350 rakp-md5.7350.hc  -a 0 <wordlist>   # %d MD5 lines  (mac:salt)

John the Ripper:
  john --format=RAKP        rakp-sha1.jtr             # %d lines
  john --format=RAKP-MD5    rakp-md5.jtr              # %d lines
  john --format=RAKP-SHA256 rakp-sha256.jtr           # %d lines

oobscan:
  oobscan hashcrack rakp-sha1.jtr --wordlist <wordlist>

Notes:
  * hashcat has no SHA256 RAKP mode; SHA256 hashes are John/oobscan only.
  * These files match "oobscan hashdump" byte for byte: only full-length
    captured HMACs are emitted, and SMCRAKP fixed-key hashes are excluded (they
    are keyed by a firmware constant, not a password, so no wordlist recovers
    them -- see the smcrakp_fixed_key column in rakp-hashes.csv).
  * rakp-hashes.csv lists every captured hash (including redacted, malformed,
    fixed-key, and already-cracked rows) with vendor/product/user/crack metadata.
  * The salt layout is SIDc(LE)|SIDm(LE)|Rc|Rm|GUID|0x14|ulen|username.
`, a.name, len(sha1HC), len(md5HC), len(jtrSHA1), len(jtrMD5), len(jtrSHA256))
	return writeText(filepath.Join(d, "README.txt"), readme)
}

func (a *Artifacts) writeVendors(dir string) error {
	d := filepath.Join(dir, "vendors")
	index := newCounter()
	for vendor, va := range a.vendors {
		index.counts[vendor] = va.assets
		index.total += va.assets
		vd := filepath.Join(d, vendorDirName(vendor))
		tables := []struct {
			c              *counter
			file, valueCol string
		}{
			{va.osVersion, "os_versions.csv", "os_version"},
			{va.firmware, "firmware.csv", "firmware"},
			{va.product, "products.csv", "product"},
			{va.portsTCP, "ports_tcp.csv", "tcp_port"},
			{va.portsUDP, "ports_udp.csv", "udp_port"},
			{va.protocols, "protocols.csv", "protocol"},
			{va.httpServers, "http_servers.csv", "http_server"},
			{va.htmlTitles, "html_titles.csv", "html_title"},
			{va.tlsNames, "tls_names.csv", "tls_name"},
		}
		for _, t := range tables {
			if err := writeCounterCSV(filepath.Join(vd, t.file), t.c, t.valueCol); err != nil {
				return err
			}
		}
	}
	return writeCounterCSV(filepath.Join(d, "vendors_index.csv"), index, "vendor")
}

func (a *Artifacts) writeSummary(dir string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "oobscan report artifacts -- %s\n", a.name)
	fmt.Fprintf(&b, "================================\n\n")
	fmt.Fprintf(&b, "hosts:             %d\n", a.total)
	fmt.Fprintf(&b, "distinct_vendors:  %d\n", len(a.vendor.counts))
	fmt.Fprintf(&b, "critical_risk_hosts:%d\n", a.withCritical)
	fmt.Fprintf(&b, "high_risk_hosts:   %d\n", a.withHigh)
	fmt.Fprintf(&b, "ipmi_hosts:        %d\n", a.ipmiHosts)
	fmt.Fprintf(&b, "rakp_hashes:       %d\n", len(a.rakp))
	fmt.Fprintf(&b, "snmp_hosts:        %d\n", a.snmpHosts)
	b.WriteString("\nTop exposures (percent of population):\n")
	for _, e := range Taxonomy {
		n := a.exposureTotals[e.Key]
		if n == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %-38s %7d  %s%%\n", e.Label, n, pctString(n, a.total))
	}
	b.WriteString("\nArtifacts:\n")
	b.WriteString("  overview/   vendor, class, product, os, hardware, ports, protocols, http servers, checks, risks\n")
	b.WriteString("  exposure/   exposure_rates.csv, vendor_matrix.csv\n")
	b.WriteString("  ipmi/       cipher ids/suites, versions, guid vendors, oem names, rakp users/cracked\n")
	b.WriteString("  snmp/       versions, communities, engine ids, sysDescr, sysObjectID\n")
	b.WriteString("  hashes/     rakp-*.hc / *.jtr cracker inputs, rakp-hashes.csv, README.txt\n")
	b.WriteString("  vendors/    per-vendor sub-reports + vendors_index.csv\n")
	return writeText(filepath.Join(dir, "summary.txt"), b.String())
}

func reconstructRAKP(r *output.RAKPRecord) (*ipmi.RAKPResult, bool) {
	if r.RAKPHash == "" {
		return nil, false
	}
	mac, err := hex.DecodeString(r.RAKPHash)
	if err != nil || len(mac) == 0 {
		return nil, false
	}
	cRand, err1 := hex.DecodeString(r.ClientRand)
	bRand, err2 := hex.DecodeString(r.BMCRand)
	guid, err3 := hex.DecodeString(r.BMCGUID)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, false
	}
	return &ipmi.RAKPResult{
		Username:   r.Username,
		AuthAlgo:   r.AuthAlgo,
		ClientSID:  r.ClientSID,
		BMCSID:     r.BMCSID,
		ClientRand: cRand,
		BMCRand:    bRand,
		BMCGUID:    guid,
		RAKPHash:   mac,
	}, true
}

func macHexLen(algo string) int {
	switch algo {
	case "sha1":
		return 20
	case "md5":
		return 16
	case "sha256":
		return 32
	}
	return 0
}

func firstServiceAttr(rec *scanfile.Record, keys ...string) string {
	for i := range rec.Services {
		at := rec.Services[i].Attributes
		if at == nil {
			continue
		}
		for _, k := range keys {
			if v := at[k]; v != "" {
				return v
			}
		}
	}
	return ""
}

func splitTabComma(v string) []string {
	if v == "" {
		return nil
	}
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == '\t' || r == ',' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func pctString(n, total int) string {
	if total <= 0 {
		return "0.00"
	}
	return strconv.FormatFloat(100*float64(n)/float64(total), 'f', 2, 64)
}

func vendorDirName(vendor string) string {
	v := strings.ToLower(strings.TrimSpace(vendor))
	if v == "" {
		return "unknown"
	}
	var b strings.Builder
	prevDash := false
	for _, r := range v {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	name := strings.Trim(b.String(), "-")
	if name == "" {
		return "unknown"
	}
	return name
}

func writeCounterCSV(path string, c *counter, valueCol string) error {
	rows := [][]string{{valueCol, "count", "percent"}}
	for _, e := range c.top(0) {
		rows = append(rows, []string{e.Value, strconv.Itoa(e.Count), pctString(e.Count, c.total)})
	}
	return writeCSVRows(path, rows)
}

func writeCSVRows(path string, rows [][]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.WriteAll(rows); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}

func writeLinesFile(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			return err
		}
	}
	return nil
}

func writeText(path, s string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(s), 0o600)
}
