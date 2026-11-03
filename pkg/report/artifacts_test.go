package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

// observeLines streams NDJSON lines through an Artifacts collector and writes
// the tree into a temp dir, returning the dir.
func observeLines(t *testing.T, name string, lines ...string) string {
	t.Helper()
	path := writeLines(t, name+".jsonl", lines...)
	r, err := scanfile.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer r.Close()
	a := NewArtifacts(name)
	for r.Next() {
		a.Observe(r.Record())
	}
	if err := r.Err(); err != nil {
		t.Fatalf("read: %v", err)
	}
	dir := filepath.Join(t.TempDir(), name)
	if err := a.Write(dir); err != nil {
		t.Fatalf("write artifacts: %v", err)
	}
	return dir
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestArtifactsRAKPHashFiles checks that a captured (unredacted) RAKP-2 SHA1
// hash produces cracker-ready hashcat/john lines and a CSV row, while a redacted
// row appears in the CSV but not in the crackable files.
func TestArtifactsRAKPHashFiles(t *testing.T) {
	// A real-shaped SHA1 RAKP row: 20-byte HMAC, 16-byte nonces, 16-byte GUID.
	const rakp = `{"host":"10.0.0.1","identity":{"class":"bmc","vendor":"supermicro"},` +
		`"rakp":[{"username":"ADMIN","authAlgo":1,"clientSid":1,"bmcSid":2,` +
		`"clientRand":"00112233445566778899aabbccddeeff","bmcRand":"ffeeddccbbaa99887766554433221100",` +
		`"bmcGuid":"0102030405060708090a0b0c0d0e0f10",` +
		`"rakpHash":"0123456789abcdef0123456789abcdef01234567","cracked":"ADMIN"}]}`
	const redacted = `{"host":"10.0.0.2","identity":{"class":"bmc","vendor":"dell"},` +
		`"rakp":[{"username":"root","authAlgo":1,"redacted":true}]}`

	dir := observeLines(t, "Internal", rakp, redacted)

	hc := readFile(t, filepath.Join(dir, "hashes", "rakp-sha1.7300.hc"))
	lines := strings.Split(strings.TrimSpace(hc), "\n")
	if len(lines) != 1 {
		t.Fatalf("rakp-sha1.7300.hc = %q, want exactly one line", hc)
	}
	// hashcat -m 7300 is salt:mac; the mac is the RAKPHash we fed in.
	if !strings.HasSuffix(lines[0], ":0123456789abcdef0123456789abcdef01234567") {
		t.Errorf("7300 line %q does not end with the expected mac", lines[0])
	}
	if !strings.Contains(lines[0], ":") {
		t.Errorf("7300 line %q missing salt:mac separator", lines[0])
	}

	jtr := readFile(t, filepath.Join(dir, "hashes", "rakp-sha1.jtr"))
	if !strings.HasPrefix(strings.TrimSpace(jtr), "$rakp$") {
		t.Errorf("john line %q missing $rakp$ prefix", jtr)
	}

	csv := readFile(t, filepath.Join(dir, "hashes", "rakp-hashes.csv"))
	if !strings.Contains(csv, "ADMIN") || !strings.Contains(csv, "root") {
		t.Errorf("rakp-hashes.csv missing a captured user:\n%s", csv)
	}
	// The redacted row must be in the CSV but must not contribute a crack line.
	if strings.Count(strings.TrimSpace(jtr), "\n") != 0 {
		t.Errorf("expected exactly one john line (redacted row excluded), got:\n%s", jtr)
	}
	if got := readFile(t, filepath.Join(dir, "ipmi", "rakp_cracked.csv")); !strings.Contains(got, "ADMIN") {
		t.Errorf("rakp_cracked.csv should record the recovered password:\n%s", got)
	}
}

// TestArtifactsOverviewAndExposure checks the overview CSVs use display vendor
// names and the exposure_rates.csv reports prevalence over the whole population.
func TestArtifactsOverviewAndExposure(t *testing.T) {
	dir := observeLines(t, "External",
		`{"host":"8.8.8.8","identity":{"class":"bmc","vendor":"supermicro"},"ports":{"623/udp":"ipmi"},"findings":[{"check":"ipmi.v20.cipherZero","risk":"critical"}]}`,
		`{"host":"8.8.4.4","identity":{"class":"bmc","vendor":"dell"},"ports":{"443/tcp":"tls"}}`,
	)

	vendor := readFile(t, filepath.Join(dir, "overview", "vendor.csv"))
	if !strings.Contains(vendor, "Supermicro") || !strings.Contains(vendor, "Dell") {
		t.Errorf("vendor.csv should use display names, got:\n%s", vendor)
	}
	if strings.Contains(vendor, "supermicro,") {
		t.Errorf("vendor.csv leaked a codename slug:\n%s", vendor)
	}

	tcp := readFile(t, filepath.Join(dir, "overview", "ports_tcp.csv"))
	if !strings.Contains(tcp, "443") {
		t.Errorf("ports_tcp.csv missing 443:\n%s", tcp)
	}
	udp := readFile(t, filepath.Join(dir, "overview", "ports_udp.csv"))
	if !strings.Contains(udp, "623") {
		t.Errorf("ports_udp.csv missing 623:\n%s", udp)
	}

	rates := readFile(t, filepath.Join(dir, "exposure", "exposure_rates.csv"))
	// One of two hosts is cipher-zero -> 50.00%.
	if !strings.Contains(rates, "ipmi_cipher_zero,IPMI: cipher-zero session,1,50.00") {
		t.Errorf("exposure_rates.csv wrong cipher-zero prevalence:\n%s", rates)
	}

	matrix := readFile(t, filepath.Join(dir, "exposure", "vendor_matrix.csv"))
	if !strings.HasPrefix(matrix, "vendor,total,ipmi,") {
		t.Errorf("vendor_matrix.csv header unexpected:\n%s", strings.SplitN(matrix, "\n", 2)[0])
	}
}

// TestArtifactsPerVendorTree checks each vendor gets its own sub-report dir and
// the index totals match.
func TestArtifactsPerVendorTree(t *testing.T) {
	dir := observeLines(t, "Internal",
		`{"host":"10.0.0.1","identity":{"class":"bmc","vendor":"supermicro"},"finalIdentity":{"vendor":"supermicro","class":"bmc","version":"1.2.3"}}`,
		`{"host":"10.0.0.2","identity":{"class":"bmc","vendor":"supermicro"},"finalIdentity":{"vendor":"supermicro","class":"bmc","version":"1.2.3"}}`,
		`{"host":"10.0.0.3","identity":{"class":"bmc","vendor":"hpe"},"finalIdentity":{"vendor":"hpe","class":"bmc"}}`,
	)

	idx := readFile(t, filepath.Join(dir, "vendors", "vendors_index.csv"))
	if !strings.Contains(idx, "Supermicro,2,") {
		t.Errorf("vendors_index.csv should show Supermicro=2:\n%s", idx)
	}

	osv := readFile(t, filepath.Join(dir, "vendors", "supermicro", "os_versions.csv"))
	if !strings.Contains(osv, "1.2.3,2,") {
		t.Errorf("per-vendor os_versions.csv wrong:\n%s", osv)
	}
	if _, err := os.Stat(filepath.Join(dir, "vendors", "hpe")); err != nil {
		t.Errorf("expected an hpe vendor dir: %v", err)
	}
}

// TestArtifactsSNMP checks SNMP surface CSVs are populated from service
// attributes.
func TestArtifactsSNMP(t *testing.T) {
	dir := observeLines(t, "External",
		`{"host":"8.8.8.8","identity":{"class":"bmc","vendor":"dell"},"services":[{"port":161,"transport":"udp","attributes":{"snmp.version":"2c,3","snmp.defaultCommunities":"public\tprivate","snmp.sysDesc":"Linux bmc-01 5.10"}}],"findings":[{"check":"snmp.v3","risk":"info"}]}`,
	)
	comm := readFile(t, filepath.Join(dir, "snmp", "communities.csv"))
	if !strings.Contains(comm, "public") || !strings.Contains(comm, "private") {
		t.Errorf("communities.csv missing tab-split communities:\n%s", comm)
	}
	desc := readFile(t, filepath.Join(dir, "snmp", "sys_descriptions.csv"))
	if !strings.Contains(desc, "Linux bmc-01 5.10") {
		t.Errorf("sys_descriptions.csv missing sysDesc:\n%s", desc)
	}
}

// TestArtifactsExposureMatchesSource verifies artifact/source consistency:
// the artifact exposure totals must equal the HTML Source's exposure totals for
// the same records, so a CSV never disagrees with the heatmap. In particular an
// ipmi.versions finding must set ipmi_1_5 / ipmi_2_0 in both.
func TestArtifactsExposureMatchesSource(t *testing.T) {
	lines := []string{
		`{"host":"10.0.0.1","identity":{"class":"bmc","vendor":"supermicro"},"findings":[{"check":"ipmi.versions","risk":"info","fields":{"versions":"1.5,2.0"}},{"check":"ipmi.v20.cipherZero","risk":"critical"}]}`,
		`{"host":"10.0.0.2","identity":{"class":"bmc","vendor":"dell"},"findings":[{"check":"ipmi.versions","risk":"info","fields":{"versions":"1.5"}}]}`,
		`{"host":"10.0.0.3","identity":{"class":"bmc","vendor":"hpe"},"rakp":[{"username":"ADMIN","authAlgo":1}]}`,
		// a cracked RAKP row: the artifacts CSV path must score ipmi_rakp_cracked
		// the same as the HTML/source path (the divergence this test guards).
		`{"host":"10.0.0.4","identity":{"class":"bmc","vendor":"ami"},"rakp":[{"username":"ADMIN","authAlgo":1,"cracked":"ADMIN"}]}`,
	}
	src := loadOne(t, "cons", lines...)

	a := NewArtifacts("cons")
	path := writeLines(t, "cons2.jsonl", lines...)
	r, err := scanfile.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer r.Close()
	for r.Next() {
		a.Observe(r.Record())
	}
	if err := r.Err(); err != nil {
		t.Fatalf("read: %v", err)
	}

	for _, e := range Taxonomy {
		if a.exposureTotals[e.Key] != src.exposureTotals[e.Key] {
			t.Errorf("exposure %q: artifacts=%d source=%d", e.Key,
				a.exposureTotals[e.Key], src.exposureTotals[e.Key])
		}
	}
	// Concretely: ipmi_1_5 must be 2 (both versions findings mention 1.5), not 0.
	if a.exposureTotals["ipmi_1_5"] != 2 {
		t.Errorf("ipmi_1_5 = %d, want 2 (ipmi.versions must drive it)", a.exposureTotals["ipmi_1_5"])
	}
	// And the cracked RAKP row must be scored by the artifacts path, not left 0.
	if a.exposureTotals["ipmi_rakp_cracked"] != 1 {
		t.Errorf("ipmi_rakp_cracked = %d, want 1 (artifacts path must score rakp[].cracked)", a.exposureTotals["ipmi_rakp_cracked"])
	}
}

// TestVendorDirName covers the filesystem-safe slugging.
func TestVendorDirName(t *testing.T) {
	cases := map[string]string{
		"Supermicro":  "supermicro",
		"Super Micro": "super-micro",
		"HPE (iLO)":   "hpe-ilo",
		"":            "unknown",
		"///":         "unknown",
	}
	for in, want := range cases {
		if got := vendorDirName(in); got != want {
			t.Errorf("vendorDirName(%q) = %q, want %q", in, got, want)
		}
	}
}
