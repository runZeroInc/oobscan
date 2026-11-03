package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportCredentialLabelsReflectEvidence(t *testing.T) {
	if !strings.Contains(reportHTML, "recovered named-account secrets") {
		t.Error("report must describe credential recovery without asserting login or privileges")
	}
	for _, unsupported := range []string{"real login, full takeover", "Trivial exploitation (before)"} {
		if strings.Contains(reportHTML, unsupported) {
			t.Errorf("report contains unsupported evidence label %q", unsupported)
		}
	}
}

// writeLines writes NDJSON lines to a temp file and returns its path.
func writeLines(t *testing.T, name string, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func loadOne(t *testing.T, name string, lines ...string) *Source {
	t.Helper()
	src, _, err := LoadSource(Input{Name: name, Path: writeLines(t, name+".jsonl", lines...)})
	if err != nil {
		t.Fatalf("LoadSource: %v", err)
	}
	return src
}

// TestExposureScoring checks the finding -> exposure taxonomy mapping and the
// prevalence rollup. A cipher-zero finding must set both ipmi and ipmi_2_0; a
// rakpHash row must imply IPMI 2.0 reachability.
func TestExposureScoring(t *testing.T) {
	src := loadOne(t, "exp",
		`{"host":"10.0.0.1","identity":{"class":"bmc","vendor":"supermicro","confidence":"high"},"findings":[{"check":"ipmi.v20.cipherZero","risk":"critical"},{"check":"tls.selfSigned","risk":"low"}]}`,
		`{"host":"10.0.0.2","identity":{"class":"bmc","vendor":"dell","confidence":"high"},"findings":[{"check":"ssh.sharedHostKey","risk":"high"}]}`,
	)
	v := src.view()
	want := map[string]int{
		"ipmi": 1, "ipmi_2_0": 1, "ipmi_cipher_zero": 1, "tls_weak": 1,
		"ssh_shared_key": 1, "ssh_weak": 1,
	}
	got := map[string]int{}
	for _, e := range v.Exposures {
		if e.Hosts > 0 {
			got[e.Key] = e.Hosts
		}
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("exposure %q = %d, want %d (all: %v)", k, got[k], n, got)
		}
	}
	if v.Total != 2 {
		t.Errorf("total = %d, want 2", v.Total)
	}
	if v.Resolved != 2 {
		t.Errorf("resolved = %d, want 2 (both vendors known)", v.Resolved)
	}
}

// A honeypot's findings are emulated by the decoy, so they must not reach the check
// histogram or the exposure scores: one decoy answers several mutually exclusive vendor
// probes at once and inflates per-vendor rollups. The host still counts in the
// population; only its findings are withheld.
func TestHoneypotFindingsExcludedFromRollups(t *testing.T) {
	// One real Supermicro, and one decoy simultaneously claiming three vendors.
	src := loadOne(t, "hpleak",
		`{"host":"10.0.0.1","identity":{"class":"bmc","vendor":"supermicro","confidence":"high"},`+
			`"findings":[{"check":"ipmi.v20.cipherZero","risk":"critical"}]}`,
		`{"host":"10.0.0.2","identity":{"class":"honeypot","vendor":"lantronix","confidence":"high",`+
			`"attributes":{"honeypot":"implausible open-port breadth (16 ports)"}},`+
			`"finalIdentity":{"class":"honeypot","vendor":"lantronix"},`+
			`"findings":[{"check":"kvm.avocent.aps","risk":"info"},{"check":"kvm.cisco.vkvm","risk":"info"},`+
			`{"check":"kvm.ami.vmedia","risk":"info"},{"check":"ipmi.v20.cipherZero","risk":"critical"}]}`,
	)
	v := src.view()

	if v.Total != 2 {
		t.Errorf("total = %d, want 2 (the decoy is still a scanned host)", v.Total)
	}
	// The decoy claims to be Lantronix. The honeypot verdict must outrank that costume,
	// or it is counted as a resolved Lantronix host and inflates the vendor breakdown.
	if v.Honeypot != 1 {
		t.Errorf("honeypot = %d, want 1; the emulated vendor was believed over the verdict", v.Honeypot)
	}
	if v.Resolved != 1 {
		t.Errorf("resolved = %d, want 1 (only the real Supermicro)", v.Resolved)
	}
	for _, row := range v.Vendors {
		if row.Vendor == "Lantronix" {
			t.Errorf("the decoy's emulated Lantronix identity was counted as a real vendor (%d hosts)", row.Count)
		}
	}
	// The exclusion must be reported, not silent.
	if v.HoneypotFindings != 4 {
		t.Errorf("honeypotFindings = %d, want 4 withheld", v.HoneypotFindings)
	}
	// cipher-zero appeared on both hosts but only the real one may be counted.
	for _, e := range v.Exposures {
		if e.Key == "ipmi_cipher_zero" && e.Hosts != 1 {
			t.Errorf("ipmi_cipher_zero = %d hosts, want 1; the decoy's copy leaked in", e.Hosts)
		}
	}
	// A decoy must never make the report claim a critical-risk host.
	if v.WithCritical != 1 {
		t.Errorf("withCritical = %d, want 1; the decoy was scored as a compromised host", v.WithCritical)
	}
	// And its emulated KVM probes must not appear in the check histogram at all.
	for _, c := range v.Checks {
		switch c.Value {
		case "kvm.avocent.aps", "kvm.cisco.vkvm", "kvm.ami.vmedia":
			t.Errorf("decoy check %q reached the histogram with %d hosts", c.Value, c.Count)
		}
	}
}

// TestVendorInferenceAndHoneypot checks the side-channel vendor recovery and the
// honeypot bucket that pull the report's unknown-vendor rate down. A record with
// no identity vendor is resolved from a TLS-cert org token; an IPMI GUID vendor
// resolves a record with neither identity nor cert; a classified honeypot with no
// recoverable vendor is counted apart from a genuinely unattributed host.
func TestVendorInferenceAndHoneypot(t *testing.T) {
	src := loadOne(t, "vendorinfer",
		// identity vendor present -> trusted as-is
		`{"host":"10.0.0.1","identity":{"class":"bmc","vendor":"dell","confidence":"high"}}`,
		// no identity vendor, but a self-signed cert names the org -> recovered
		`{"host":"10.0.0.2","identity":{"class":"bmc","vendor":"unknown"},"services":[{"port":443,"attributes":{"tls.subject":"CN=hpiLO, O=Hewlett Packard Enterprise"}}]}`,
		// no identity, no cert, but the IPMI GUID names the vendor -> recovered
		`{"host":"10.0.0.3","findings":[{"check":"ipmi.guid","fields":{"vendor":"supermicro"}}]}`,
		// classified honeypot with no vendor tell -> honeypot bucket, not unknown
		`{"host":"10.0.0.4","identity":{"class":"honeypot","vendor":"unknown"}}`,
		// genuinely unattributed real host -> unknown
		`{"host":"10.0.0.5","identity":{"class":"bmc","vendor":"unknown"}}`,
	)
	v := src.view()
	if v.Total != 5 {
		t.Fatalf("total = %d, want 5", v.Total)
	}
	if v.Resolved != 3 {
		t.Errorf("resolved = %d, want 3 (dell + cert-recovered hpe + guid-recovered supermicro)", v.Resolved)
	}
	if v.Honeypot != 1 {
		t.Errorf("honeypot = %d, want 1", v.Honeypot)
	}
	if v.Unknown != 1 {
		t.Errorf("unknown = %d, want 1 (only the genuinely unattributed host)", v.Unknown)
	}
	slugs := map[string]int{}
	for _, row := range v.Vendors {
		slugs[row.Vendor] = row.Count
	}
	if slugs["HPE"] != 1 {
		t.Errorf("cert org token not recovered to HPE (vendors: %v)", slugs)
	}
	if slugs["Supermicro"] != 1 {
		t.Errorf("ipmi guid not recovered to Supermicro (vendors: %v)", slugs)
	}
	if slugs["Honeypot"] != 1 {
		t.Errorf("honeypot not bucketed (vendors: %v)", slugs)
	}
}

func TestServiceOnlyRecordNormalization(t *testing.T) {
	src := loadOne(t, "services",
		`{"host":"","services":[{"port":443,"transport":"tcp","protocols":["http","tls"],"vhost":"IPMI","address":"10.0.0.7","summary":"HTTP/1.1 302 Found\r\nServer: Linux/5.4.62, UPnP/1.0, Portable SDK for UPnP devices/1.14.12\r\n\r\n"},{"port":623,"transport":"udp","protocols":["ipmi"],"address":"10.0.0.7"}]}`,
	)
	v := src.view()
	if v.Resolved != 1 || v.Unknown != 0 {
		t.Errorf("vendor attribution = resolved %d unknown %d, want 1/0", v.Resolved, v.Unknown)
	}
	if v.Coverage.Services != 1 || v.Coverage.Findings != 0 || v.Coverage.Identity != 0 {
		t.Errorf("coverage = %+v, want service-only evidence", v.Coverage)
	}
	// The service-only record still resolves an identity from its service
	// attributes, which is what the class/vendor rollups are built from. The
	// bundle keeps no per-host row, so the identity is asserted through the
	// aggregates rather than through a retained address.
	if got := pairCount(v.Classes, "BMC"); got != 1 {
		t.Errorf("normalized class rollup = %d BMC hosts, want 1", got)
	}
	if len(v.Vendors) != 1 || v.Vendors[0].Vendor != "Supermicro" {
		t.Errorf("normalized vendor rollup = %+v, want one Supermicro row", v.Vendors)
	}
	if got := exposureHosts(v.Exposures, "ipmi"); got != 1 {
		t.Errorf("service-derived ipmi exposure = %d, want 1", got)
	}
}

func TestCrackClassesAndImmediateCompromise(t *testing.T) {
	src := loadOne(t, "compromise",
		`{"host":"10.0.0.1","identity":{"class":"bmc","vendor":"supermicro"},"rakp":[{"username":"ADMIN","authAlgo":1,"cracked":"ADMIN"}],"findings":[{"check":"ipmi.v20.cipherZero","risk":"critical"},{"check":"ipmi.v20.smcrakpBypass","risk":"critical","fields":{"exploitable":"true"}},{"check":"ipmi.v20.defaultCreds","risk":"critical","fields":{"username":"ADMIN","crackedFrom":"default"}}]}`,
		`{"host":"10.0.0.2","identity":{"class":"bmc","vendor":"supermicro"},"rakp":[{"username":"","authAlgo":1,"cracked":"admin"}],"findings":[{"check":"ipmi.v20.defaultCreds","risk":"critical","fields":{"username":"","crackedFrom":"common"}}]}`,
	)
	v := src.view()
	if v.Cracks.ScanAny != 2 || v.Cracks.ScanNamed != 1 || v.Cracks.ScanEmpty != 1 {
		t.Errorf("crack classes = %+v, want any=2 named=1 empty=1", v.Cracks)
	}
	// Host .1 has a live-confirmed path (rakp_named/cipher_zero/defaults) plus the
	// actively-confirmed smcrakpBypass; host .2's empty-username default is not a
	// named-account compromise. SMCRAKP inference now requires a captured RAKP-2
	// hash that verifies against the fixed ATEN key (the sound affected-set test);
	// neither synthetic row carries real hash material, so .2 is not inferred.
	if v.ImmediatePre != 1 {
		t.Errorf("immediate (pre/known) hosts = %d, want 1 unique host with a live-confirmed path", v.ImmediatePre)
	}
	if v.ImmediateExt != 1 {
		t.Errorf("immediateExt hosts = %d, want 1 (only the live-confirmed host; no valid fixed-key hash to infer)", v.ImmediateExt)
	}
	// Confirmed-only per-path counts: known paths fire only where a finding confirmed them.
	for _, key := range []string{"rakp_named", "cipher_zero", "ipmi_default_creds"} {
		if got := exposureHosts(v.Compromise, key); got != 1 {
			t.Errorf("compromise path %q = %d, want 1", key, got)
		}
	}
	// smcrakp_bypass: only the actively-confirmed host counts; the second host's
	// synthetic RAKP row has no hash that verifies against the fixed key.
	if got := exposureHosts(v.Compromise, "smcrakp_bypass"); got != 1 {
		t.Errorf("compromise path %q = %d, want 1 (confirmed only; no inferable fixed-key hash)", "smcrakp_bypass", got)
	}
}

func TestGUIDIntelligence(t *testing.T) {
	src := loadOne(t, "guid",
		`{"host":"10.0.0.1","findings":[{"check":"ipmi.guid","risk":"info","fields":{"guid":"44454c4c3200104c8047c8c04f354834"}}]}`,
		`{"host":"10.0.0.2","findings":[{"check":"ipmi.guid","risk":"info","fields":{"guid":"3638373531394d583235313630304633"}}]}`,
	)
	v := src.view()
	if v.GUID.Hosts != 2 || v.GUID.Decoded != 2 {
		t.Errorf("guid coverage = %+v, want 2/2 decoded", v.GUID)
	}
	if v.GUID.ServiceTags != 1 || v.GUID.Serials != 1 || v.GUID.Countries != 1 {
		t.Errorf("guid disclosures = %+v, want one Dell tag and one HPE serial/country", v.GUID)
	}
}

func exposureHosts(rows []ExposureRow, key string) int {
	for _, row := range rows {
		if row.Key == key {
			return row.Hosts
		}
	}
	return 0
}

func findFirmwareGroup(rows []FirmwareGroupView, label string) *FirmwareGroupView {
	for i := range rows {
		if rows[i].Label == label {
			return &rows[i]
		}
	}
	return nil
}

func versionCount(g *FirmwareGroupView, version string) int {
	if g == nil {
		return 0
	}
	for _, p := range g.Versions {
		if p.Value == version {
			return p.Count
		}
	}
	return 0
}

// TestFirmwareBreakdown pins the per-line firmware cross-tab: versions are
// grouped under the most specific product line (a generation when the scan
// resolved one), a host with a line but no version still counts toward the line
// total so the coverage gap is visible, a host with neither product nor
// generation is not grouped, and a line that never resolved a single version is
// dropped rather than shown as an empty firmware row.
func TestFirmwareBreakdown(t *testing.T) {
	src := loadOne(t, "firmware",
		// iLO4: two on 2.82, one on 2.55, and one with no firmware exposed.
		`{"host":"10.0.0.1","finalIdentity":{"class":"bmc","vendor":"hpe","generation":"iLO4","version":"2.82"}}`,
		`{"host":"10.0.0.2","finalIdentity":{"class":"bmc","vendor":"hpe","generation":"iLO4","version":"2.82"}}`,
		`{"host":"10.0.0.3","finalIdentity":{"class":"bmc","vendor":"hpe","generation":"iLO4","version":"2.55"}}`,
		`{"host":"10.0.0.4","finalIdentity":{"class":"bmc","vendor":"hpe","generation":"iLO4"}}`,
		// iLO5: five hosts -- more firmware than iLO4 -- so ordering by count alone
		// would float it above iLO4. Natural order must still put iLO4 first.
		`{"host":"10.0.0.11","finalIdentity":{"class":"bmc","vendor":"hpe","generation":"iLO5","version":"2.90"}}`,
		`{"host":"10.0.0.12","finalIdentity":{"class":"bmc","vendor":"hpe","generation":"iLO5","version":"2.90"}}`,
		`{"host":"10.0.0.13","finalIdentity":{"class":"bmc","vendor":"hpe","generation":"iLO5","version":"2.90"}}`,
		`{"host":"10.0.0.14","finalIdentity":{"class":"bmc","vendor":"hpe","generation":"iLO5","version":"2.44"}}`,
		`{"host":"10.0.0.15","finalIdentity":{"class":"bmc","vendor":"hpe","generation":"iLO5","version":"2.44"}}`,
		// iDRAC9: product family "iDRAC" refined by the generation, one firmware.
		`{"host":"10.0.0.5","finalIdentity":{"class":"bmc","vendor":"dell","product":"iDRAC","generation":"iDRAC9","version":"7.00.00.183"}}`,
		// A host with a firmware version but no product/generation: cannot be
		// attributed to a line, so it must not appear as a group.
		`{"host":"10.0.0.6","finalIdentity":{"class":"bmc","vendor":"hpe","version":"9.9"}}`,
		// A product line that never exposed a firmware version: dropped entirely.
		`{"host":"10.0.0.7","finalIdentity":{"class":"bmc","vendor":"supermicro","product":"X10"}}`,
	)
	v := src.view()

	ilo := findFirmwareGroup(v.Firmware, "HPE iLO4")
	if ilo == nil {
		t.Fatalf("no HPE iLO4 firmware group; got %+v", v.Firmware)
	}
	if ilo.Total != 4 || ilo.Known != 3 {
		t.Errorf("iLO4 total/known = %d/%d, want 4/3 (one host exposed no firmware)", ilo.Total, ilo.Known)
	}
	if got := versionCount(ilo, "2.82"); got != 2 {
		t.Errorf("iLO4 2.82 = %d, want 2", got)
	}
	if got := versionCount(ilo, "2.55"); got != 1 {
		t.Errorf("iLO4 2.55 = %d, want 1", got)
	}
	// The generation is the line label, so it is not repeated as a context column.
	if ilo.Generation != "" {
		t.Errorf("iLO4 generation column = %q, want empty (it is already the line)", ilo.Generation)
	}

	idrac := findFirmwareGroup(v.Firmware, "Dell iDRAC9")
	if idrac == nil {
		t.Fatalf("no Dell iDRAC9 firmware group; got %+v", v.Firmware)
	}
	if idrac.Known != 1 || versionCount(idrac, "7.00.00.183") != 1 {
		t.Errorf("iDRAC9 = %+v, want one host on 7.00.00.183", idrac)
	}
	// The product family refines into a context column when it differs from the
	// generation the line is keyed on.
	if idrac.Product != "iDRAC" {
		t.Errorf("iDRAC9 product column = %q, want \"iDRAC\"", idrac.Product)
	}

	// The version-only host and the version-less X10 line must not create groups.
	if g := findFirmwareGroup(v.Firmware, "Supermicro X10"); g != nil {
		t.Errorf("Supermicro X10 group present with no firmware: %+v", g)
	}
	for _, g := range v.Firmware {
		if g.Known == 0 {
			t.Errorf("group %q has no firmware-bearing hosts but was kept", g.Label)
		}
	}

	// Lines are grouped by vendor (the larger HPE block leads Dell), and within a
	// vendor they run in natural order -- so iLO4 precedes iLO5 even though iLO5
	// has more firmware-resolved hosts, and every HPE line precedes the Dell one.
	order := map[string]int{}
	for i, g := range v.Firmware {
		order[g.Label] = i
	}
	if order["HPE iLO4"] > order["HPE iLO5"] {
		t.Errorf("HPE iLO5 (idx %d) sorted before iLO4 (idx %d); natural order must put iLO4 first", order["HPE iLO5"], order["HPE iLO4"])
	}
	if order["HPE iLO5"] > order["Dell iDRAC9"] {
		t.Errorf("Dell iDRAC9 (idx %d) is interleaved before an HPE line (idx %d); lines must group by vendor", order["Dell iDRAC9"], order["HPE iLO5"])
	}
}

// TestFirmwareFamilyAndNaturalOrder locks the two helpers the firmware display
// order depends on: generations of one product line must fold to a shared family
// key so they group and rank together, and numbers inside a label must compare by
// value so a plain "iLO10" is not sorted between "iLO1" and "iLO2".
func TestFirmwareFamilyAndNaturalOrder(t *testing.T) {
	fams := map[string]string{
		"iLO4": "ilo", "iLO5": "ilo", "iLO": "ilo",
		"iDRAC8": "idrac", "iDRAC9": "idrac",
		"X10": "x", "X11": "x", "X12": "x",
		"Alletra Storage Server 4120": "alletra storage server",
	}
	for line, want := range fams {
		if got := firmwareFamilyKey(line); got != want {
			t.Errorf("firmwareFamilyKey(%q) = %q, want %q", line, got, want)
		}
	}
	seq := []string{"iLO", "iLO2", "iLO4", "iLO5", "iLO6", "iLO10"}
	for i := 0; i+1 < len(seq); i++ {
		if !naturalLess(seq[i], seq[i+1]) {
			t.Errorf("naturalLess(%q,%q) = false, want true", seq[i], seq[i+1])
		}
	}
	if naturalLess("iLO10", "iLO2") {
		t.Error("naturalLess(iLO10, iLO2) = true; embedded numbers must compare by value, not lexically")
	}
}

// TestNamedBypassAndOverflowExposures checks that the named-defect exposures are
// broken out into their own columns while still rolling up into the generic
// buckets: Supermicro's unprotected-RMCP+ defect sets ipmi_integrity_bypass and
// the distinct ipmi_smc_integrity_bypass (not the SMCRAKP fixed-key column), an
// iLO IPMI bypass sets ipmi_integrity_bypass and ipmi_ilo_auth_bypass, the iLO
// SSH overflow sets ssh_ilo_overflow, and an iLO firmware CVE sets ilo_known_cve.
func TestNamedBypassAndOverflowExposures(t *testing.T) {
	src := loadOne(t, "named",
		`{"host":"10.0.0.1","identity":{"class":"bmc","vendor":"supermicro","confidence":"high"},"findings":[{"check":"ipmi.smc.integrityBypass","risk":"critical"},{"check":"ipmi.sidPredictable","risk":"critical"}]}`,
		`{"host":"10.0.0.2","identity":{"class":"bmc","vendor":"hpe","confidence":"high"},"findings":[{"check":"ipmi.ilo.rakpNoneBypass","risk":"critical"},{"check":"ssh.hpe.iloSSHOverflow","risk":"high"},{"check":"http.ilo.knownCVEs","risk":"critical"}]}`,
		`{"host":"10.0.0.3","identity":{"class":"bmc","vendor":"openbmc","confidence":"high"},"findings":[{"check":"ipmi.openbmc.defaultUserKeyAuthBypass","risk":"high"}]}`,
	)
	v := src.view()
	got := map[string]int{}
	for _, e := range v.Exposures {
		if e.Hosts > 0 {
			got[e.Key] = e.Hosts
		}
	}
	want := map[string]int{
		"ipmi":                      3, // ipmi.smc.*, ipmi.ilo.*, ipmi.openbmc.* all prefix ipmi.
		"ipmi_integrity_bypass":     3, // smc + ilo + openbmc
		"ipmi_smc_integrity_bypass": 1,
		"ipmi_ilo_auth_bypass":      1,
		"ipmi_openbmc_bypass":       1,
		"ipmi_sid_weak":             1,
		"ssh_ilo_overflow":          1,
		"ilo_known_cve":             1,
	}
	if got["ipmi_smcrakp_bypass"] != 0 {
		t.Errorf("ipmi.smc.integrityBypass must not set the SMCRAKP fixed-key column; got %d", got["ipmi_smcrakp_bypass"])
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("exposure %q = %d, want %d (all: %v)", k, got[k], n, got)
		}
	}
}

// TestRAKPImpliesExposure checks that a captured RAKP row alone marks the host
// as IPMI-reachable with a leaked hash, and a cracked row marks it cracked.
func TestRAKPImpliesExposure(t *testing.T) {
	src := loadOne(t, "rakp",
		`{"host":"10.0.0.3","identity":{"class":"bmc","vendor":"ami","confidence":"high"},"rakp":[{"username":"ADMIN","authAlgo":1,"cracked":"ADMIN"}]}`,
	)
	v := src.view()
	if v.RakpHosts != 1 || v.AutoCracked != 1 {
		t.Errorf("rakp=%d autoCracked=%d, want 1/1", v.RakpHosts, v.AutoCracked)
	}
	got := map[string]int{}
	for _, e := range v.Exposures {
		got[e.Key] = e.Hosts
	}
	for _, k := range []string{"ipmi", "ipmi_2_0", "ipmi_rakp_hash", "ipmi_rakp_cracked"} {
		if got[k] != 1 {
			t.Errorf("exposure %q = %d, want 1", k, got[k])
		}
	}
}

// TestRedactionDetection checks that a corpus whose addresses all fall in the
// redaction ranges is flagged Redacted, and a corpus with a routable address is
// not.
func TestRedactionDetection(t *testing.T) {
	red := loadOne(t, "red", `{"host":"10.0.0.1"}`, `{"host":"224.0.0.5"}`, `{"host":"fd00::1"}`)
	if !red.Redacted {
		t.Error("all-redaction-range corpus not flagged Redacted")
	}
	live := loadOne(t, "live", `{"host":"10.0.0.1"}`, `{"host":"8.8.8.8"}`)
	if live.Redacted {
		t.Error("corpus with a routable address wrongly flagged Redacted")
	}
}

// TestCompareIsPercentOfWhole verifies population-normalized comparison:
// two populations of very different size are judged on prevalence, and the
// absolute counts travel alongside. A 1-of-10 source and a 500-of-1000 source
// must compare 10% vs 50%, not 1 vs 500.
func TestCompareIsPercentOfWhole(t *testing.T) {
	var small, big []string
	small = append(small, `{"host":"10.0.0.1","findings":[{"check":"ipmi.v20.cipherZero","risk":"critical"}]}`)
	for range 9 {
		small = append(small, `{"host":"10.0.0.9"}`)
	}
	for range 500 {
		big = append(big, `{"host":"8.8.8.8","findings":[{"check":"ipmi.v20.cipherZero","risk":"critical"}]}`)
	}
	for range 500 {
		big = append(big, `{"host":"8.8.4.4"}`)
	}
	s1 := loadOne(t, "small", small...)
	s2 := loadOne(t, "big", big...)

	r := Build("now", []*Source{s1, s2})
	if r.Compare == nil {
		t.Fatal("no comparison built for two sources")
	}
	var cz *CompareRow
	for i := range r.Compare.Exposures {
		if r.Compare.Exposures[i].Key == "ipmi_cipher_zero" {
			cz = &r.Compare.Exposures[i]
		}
	}
	if cz == nil {
		t.Fatal("cipher-zero row missing from comparison")
	}
	if cz.Hosts[0] != 1 || cz.Hosts[1] != 500 {
		t.Errorf("hosts = %v, want [1 500]", cz.Hosts)
	}
	if cz.Pct[0] != 10 || cz.Pct[1] != 50 {
		t.Errorf("pct = %v, want [10 50] (prevalence, not volume)", cz.Pct)
	}
	if cz.Spread != 40 {
		t.Errorf("spread = %v, want 40", cz.Spread)
	}
}

// TestSingleSourceNoComparison checks that one source produces a report with no
// comparison view.
func TestSingleSourceNoComparison(t *testing.T) {
	r := Build("now", []*Source{loadOne(t, "only", `{"host":"10.0.0.1"}`)})
	if r.Compare != nil {
		t.Error("single source should not produce a comparison")
	}
	if len(r.Sources) != 1 {
		t.Errorf("sources = %d, want 1", len(r.Sources))
	}
}

// TestParseInput covers the Name=path grammar and the bare-path default.
func TestParseInput(t *testing.T) {
	cases := []struct{ arg, name, path string }{
		{"Internal=a.jsonl", "Internal", "a.jsonl"},
		{"data/oob41.jsonl.gz", "oob41", "data/oob41.jsonl.gz"},
		{"scan.ndjson", "scan", "scan.ndjson"},
	}
	for _, c := range cases {
		in, err := ParseInput(c.arg)
		if err != nil {
			t.Fatalf("ParseInput(%q): %v", c.arg, err)
		}
		if in.Name != c.name || in.Path != c.path {
			t.Errorf("ParseInput(%q) = {%q,%q}, want {%q,%q}", c.arg, in.Name, in.Path, c.name, c.path)
		}
	}
	if _, err := ParseInput("=nopath"); err == nil {
		t.Error("empty name should be rejected")
	}
}

// TestRenderEmbedsPayloadAndTaxonomy checks the payload is embedded and the
// exposure taxonomy carries its short codes for the heatmap headers.
func TestRenderEmbedsPayloadAndTaxonomy(t *testing.T) {
	r := Build("now", []*Source{loadOne(t, "s", `{"host":"10.0.0.1","findings":[{"check":"ipmi.v20.rakpHash","risk":"high"}]}`)})
	html, err := Render(r)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(html, "__REPORT_DATA__") {
		t.Error("payload token was not replaced")
	}
	// The payload is embedded compressed, so assert on the model Render serializes:
	// the exposure taxonomy must carry the short codes the heatmap headers use.
	if len(r.Keys) != len(Taxonomy) {
		t.Errorf("keys = %d, want %d", len(r.Keys), len(Taxonomy))
	}
	if b, _ := json.Marshal(r.Keys); !strings.Contains(string(b), `"short":"RAKP"`) {
		t.Error("taxonomy short codes missing from the serialized payload")
	}
}

// pairCount returns the count for a value in a Pair histogram, or -1 if absent.
func pairCount(rows []Pair, value string) int {
	for _, r := range rows {
		if r.Value == value {
			return r.Count
		}
	}
	return -1
}
