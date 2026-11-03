package convert

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRedactRenumbersByScope checks the headline rule: internal addresses are
// renumbered from 10.0.0.0 and external ones from 224.0.0.0, in first-seen
// order, with one stable mapping per source address.
func TestRedactRenumbersByScope(t *testing.T) {
	r := NewRedactor()
	cases := []struct{ in, want string }{
		{"192.168.1.5", "10.0.0.0"},
		{"10.114.122.48", "10.0.0.1"},
		{"192.168.1.5", "10.0.0.0"}, // stable: same input, same output
		{"203.0.113.7", "224.0.0.0"},
		{"8.8.8.8", "224.0.0.1"},
		{"203.0.113.7", "224.0.0.0"}, // stable
		{"100.64.3.9", "10.0.0.2"},   // CGNAT counts as internal
		{"127.0.0.1", "10.0.0.3"},
	}
	for _, c := range cases {
		if got := r.address(c.in); got != c.want {
			t.Errorf("address(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if s := r.Stats(); s.InternalAddrs != 4 || s.ExternalAddrs != 2 {
		t.Errorf("stats = %+v, want 4 internal / 2 external", s)
	}
}

// TestRedactIPv6UsesReservedRanges checks that IPv6, which cannot fit in the
// IPv4 ranges, lands in ULA for internal and the documentation prefix for
// external.
func TestRedactIPv6UsesReservedRanges(t *testing.T) {
	r := NewRedactor()
	if got := r.address("fd12:3456::1"); got != "fd00::" {
		t.Errorf("internal v6 = %q, want fd00::", got)
	}
	if got := r.address("2606:4700::1111"); got != "2001:db8::" {
		t.Errorf("external v6 = %q, want 2001:db8::", got)
	}
	if got := r.address("fe80::1%eth0"); got != "fd00::1%eth0" {
		t.Errorf("zoned link-local = %q, want fd00::1%%eth0", got)
	}
}

// TestRedactMACKeepsOUI checks that the vendor half of a MAC survives and the
// per-unit half does not.
func TestRedactMACKeepsOUI(t *testing.T) {
	r := NewRedactor()
	for in, want := range map[string]string{
		"60:65:25:f2:24:0f": "60:65:25:f2:00:00",
		"60-65-25-F2-24-0F": "60-65-25-F2-00-00",
	} {
		if got := r.value("macs", in); got != want {
			t.Errorf("mac %q = %q, want %q", in, got, want)
		}
	}
}

// TestRedactPreservesEquality is the property the whole design rests on: two
// hosts that shared a key or a name still share its stand-in, so cross-host
// clustering survives redaction.
func TestRedactPreservesEquality(t *testing.T) {
	r := NewRedactor()
	a := r.value("tls.fp.sha256", "AA:BB:CC")
	b := r.value("ssh.hostKey.fingerprint", "AA:BB:CC")
	if a != b {
		t.Errorf("same fingerprint mapped to %q and %q; clustering is broken", a, b)
	}
	if !strings.HasPrefix(a, "redacted-") {
		t.Errorf("fingerprint pseudonym = %q, want redacted-N", a)
	}
	n1 := r.value("tls.names", "bmc-01.corp.example.com")
	n2 := r.value("tls.subject", "bmc-01.corp.example.com")
	if n1 != n2 || !strings.HasSuffix(n1, ".invalid") {
		t.Errorf("name pseudonyms = %q / %q, want one stable host-N.invalid", n1, n2)
	}
	if got := r.value("banner.ssh", "SSH-2.0-OpenSSH_5.3 bmc-01"); got != redactedText {
		t.Errorf("banner = %q, want %q", got, redactedText)
	}
}

// TestRedactKeepsClassLevelKeys checks the exemptions: values that describe a
// device class rather than a device are analysis inputs and must survive.
func TestRedactKeepsClassLevelKeys(t *testing.T) {
	r := NewRedactor()
	for key, val := range map[string]string{
		"ssh.hostKeyAlgs":        "ssh-rsa,ssh-ed25519",
		"ssh.hostKeyType":        "ssh-rsa",
		"tls.keyBits":            "2048",
		"tls.cipherName":         "TLS_RSA_WITH_RC4_128_MD5",
		"tls.signatureAlgorithm": "sha1WithRSA",
		"ipmi.guid.vendor":       "Supermicro",
		"hw_vendor":              "Super Micro Computer",
	} {
		if got := r.value(key, val); got != val {
			t.Errorf("value(%q) = %q, want it kept as %q", key, got, val)
		}
	}
}

// TestRedactWalksPostAuthBlobs checks that the opaque captures are not a hole
// in the policy: an IPMI LAN config is full of addresses, MACs and community
// strings, and passing it through untouched would leak all three.
func TestRedactWalksPostAuthBlobs(t *testing.T) {
	in := writeLines(t, "postauth.jsonl", `{"host":"192.168.5.10","ipmiPostAuth":{"lan":{"ipAddress":"192.168.5.10","macAddress":"aa:bb:cc:dd:ee:ff","communityString":"s3cret","defaultGateway":"192.168.5.1"}}}`)
	out := filepath.Join(t.TempDir(), "out.jsonl")

	if _, err := Run(Options{Format: FormatOOBScan, Input: in, Output: out, Redact: true}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	for _, leaked := range []string{"192.168.5.10", "192.168.5.1", "s3cret", "ee:ff"} {
		if strings.Contains(got, leaked) {
			t.Errorf("redacted output still contains %q: %s", leaked, got)
		}
	}

	var rec struct {
		Host     string `json:"host"`
		IPMIPost struct {
			LAN map[string]string `json:"lan"`
		} `json:"ipmiPostAuth"`
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatalf("decode redacted record: %v", err)
	}
	// The host address and the LAN block's own copy of it are one address, so
	// they have to renumber to the same stand-in.
	if rec.Host != rec.IPMIPost.LAN["ipAddress"] {
		t.Errorf("host %q and lan.ipAddress %q diverged; the mapping is not stable",
			rec.Host, rec.IPMIPost.LAN["ipAddress"])
	}
	if rec.IPMIPost.LAN["macAddress"] != "aa:bb:cc:dd:00:00" {
		t.Errorf("lan.macAddress = %q, want aa:bb:cc:dd:00:00", rec.IPMIPost.LAN["macAddress"])
	}
}

// TestRedactDropsRAKPHashMaterial checks that a shareable corpus keeps the fact
// of a leak without the crackable bytes behind it.
func TestRedactDropsRAKPHashMaterial(t *testing.T) {
	in := writeLines(t, "rakp.jsonl", `{"host":"198.51.100.4","rakp":[{"username":"ADMIN","authAlgo":1,"clientSid":123,"bmcSid":456,"clientRand":"aabb","bmcRand":"ccdd","bmcGuid":"eeff","rakpHash":"deadbeef","hashcat":"salt:mac","cracked":"ADMIN"}]}`)
	out := filepath.Join(t.TempDir(), "out.jsonl")

	if _, err := Run(Options{Format: FormatOOBScan, Input: in, Output: out, Redact: true}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		RAKP []map[string]any `json:"rakp"`
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rec.RAKP) != 1 {
		t.Fatalf("rakp rows = %d, want 1", len(rec.RAKP))
	}
	row := rec.RAKP[0]
	if row["username"] != "ADMIN" {
		t.Errorf("username = %v, want it kept", row["username"])
	}
	if row["cracked"] != "yes" {
		t.Errorf("cracked = %v, want the bare yes marker", row["cracked"])
	}
	for _, k := range []string{"clientRand", "bmcRand", "bmcGuid", "rakpHash", "hashcat"} {
		if v, ok := row[k]; ok && v != "" {
			t.Errorf("%s survived redaction as %v", k, v)
		}
	}
}

// TestRedactMappingReversesAddresses checks the escape hatch: the address
// mapping is the only way back, and it is returned rather than written.
func TestRedactMappingReversesAddresses(t *testing.T) {
	in := writeLines(t, "map.jsonl", `{"host":"192.168.9.9"}`)
	out := filepath.Join(t.TempDir(), "out.jsonl")
	st, err := Run(Options{Format: FormatOOBScan, Input: in, Redact: true, Output: out})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := "192.168.9.9 -> 10.0.0.0"
	if len(st.Mapping) != 1 || st.Mapping[0] != want {
		t.Errorf("mapping = %v, want [%q]", st.Mapping, want)
	}
}

// TestRedactLeavesDottedNonAddressesAlone is a regression test for the free-
// text scrubber: a bare dotted-quad regex matches the first four arcs of an
// SNMP OID and the leading components of a firmware version, and rewriting
// either corrupts the record while protecting nothing. Converting the staging
// lab export originally renumbered "0.1.0.0" and "0.0.0.8" as if they were
// hosts.
func TestRedactLeavesDottedNonAddressesAlone(t *testing.T) {
	r := NewRedactor()
	for key, val := range map[string]string{
		"snmp.sysObjectID":     "1.3.6.1.4.1.674.10892.5",
		"ipmi.firmwareVersion": "0.1.0.0",
		"os_version":           "2.14.0.0",
		"lan.subnetMask":       "255.255.255.0",
		"some.freeText":        "walk 1.3.6.1.2.1.1 returned 4 rows",
	} {
		if got := r.value(key, val); got != val {
			t.Errorf("value(%q, %q) = %q, want it unchanged", key, val, got)
		}
	}
	// A real address in free text still gets rewritten.
	if got := r.value("some.freeText", "peer 192.168.4.7 timed out"); got != "peer 10.0.0.0 timed out" {
		t.Errorf("free-text address = %q, want it renumbered", got)
	}
}

// TestRedactScrubsSignalDetailsAndEnterpriseNamespaces is a regression test for
// two leaks found on the staging-lab corpus: identity signal details are
// banner-derived free text that can carry an embedded address, and Windows
// enterprise-service namespaces (mssql/smb) carry computer names and share
// paths that no OOB analysis needs.
func TestRedactScrubsSignalDetailsAndEnterpriseNamespaces(t *testing.T) {
	in := writeLines(t, "enterprise.jsonl",
		`{"host":"192.168.7.7","identity":{"class":"bmc","confidence":"low","signals":[{"source":"runzero.service","detail":"seen at 192.168.7.7 on 623"}]},`+
			`"services":[{"port":1433,"transport":"tcp","attributes":{"mssql.nps":"\\\\WIN2022-MECM01\\pipe\\MSSQL$SQL2022\\query","smb.computerName":"QA-LEGACY-2K8R2"}}]}`)
	out := filepath.Join(t.TempDir(), "out.jsonl")
	if _, err := Run(Options{Format: FormatOOBScan, Input: in, Output: out, Redact: true}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	for _, leaked := range []string{"192.168.7.7", "WIN2022-MECM01", "QA-LEGACY-2K8R2"} {
		if strings.Contains(got, leaked) {
			t.Errorf("redacted output still contains %q: %s", leaked, got)
		}
	}
	// The signal detail is kept (model text is useful) with its address rewritten.
	var rec struct {
		Identity struct {
			Signals []struct {
				Detail string `json:"detail"`
			} `json:"signals"`
		} `json:"identity"`
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rec.Identity.Signals) != 1 || !strings.Contains(rec.Identity.Signals[0].Detail, "on 623") {
		t.Errorf("signal detail was not preserved with its address scrubbed: %+v", rec.Identity.Signals)
	}
}

// TestRedactHostnamesInFreeText covers the generic FQDN pseudonymizer: a
// hostname embedded in an otherwise-kept value (runZero's fp.*.source
// provenance, a Redfish self-link, an iLO remote-support host) is replaced
// while the surrounding structure, the port, and any version string survive.
func TestRedactHostnamesInFreeText(t *testing.T) {
	r := NewRedactor()
	cases := []struct{ key, in, wantContains, wantGone string }{
		{"fp.hw.source", "10.0.1.175/2381/tcp/DBSLP2179xxUHC.COM/1", "/2381/tcp/", "DBSLP2179xxUHC.COM"},
		{"ilo.mp.irs", "ndc-console.ops.software.dsddcom:7906", ":7906", "ndc-console"},
		{"json.links.login", "https://10.1.1.116:8443/x\thttps://rp0.xxuhc.com:8443/x", ":8443/x", "rp0.xxuhc.com"},
	}
	for _, c := range cases {
		got := r.value(c.key, c.in)
		if !strings.Contains(got, c.wantContains) {
			t.Errorf("value(%q) = %q, want it to contain %q", c.key, got, c.wantContains)
		}
		if strings.Contains(got, c.wantGone) {
			t.Errorf("value(%q) = %q, still leaks %q", c.key, got, c.wantGone)
		}
	}
	// A version string (numeric labels, no letters-only TLD on a boundary) is not
	// mistaken for a hostname.
	for _, v := range []string{"5.14.0-570.el9_6.x86_64", "1.3.6.1.4.1.674", "255.255.255.0"} {
		if got := r.scrub(v); got != v {
			t.Errorf("scrub(%q) = %q, want it left intact (not a hostname)", v, got)
		}
	}
	// A two-label filename is not a hostname.
	if got := r.scrub("favicon.ico"); got != "favicon.ico" {
		t.Errorf("scrub(favicon.ico) = %q, want it kept", got)
	}
}

// TestRedactNewNamedAndDroppedFields checks the explicit rules added for
// tls.sans (pseudonymized SAN list), snmp.sysDesc (dropped banner with a
// hostname), and *.lastUser (dropped account name).
func TestRedactNewNamedAndDroppedFields(t *testing.T) {
	r := NewRedactor()
	sans := r.value("tls.sans", "foo.example.com\turn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6")
	if strings.Contains(sans, "foo.example.com") || strings.Contains(sans, "f81d4fae") {
		t.Errorf("tls.sans = %q, still leaks a SAN element", sans)
	}
	if got := r.value("snmp.sysDesc", "Linux bldsrv161.corp.example.com 5.14.0 x86_64"); got != redactedText {
		t.Errorf("snmp.sysDesc = %q, want %q", got, redactedText)
	}
	if got := r.value("crowdstrike.lastUser", "jsmith"); got != redactedText {
		t.Errorf("crowdstrike.lastUser = %q, want %q", got, redactedText)
	}
}
