package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/bmcfp"
)

// The tlscert vendor attribution relies on bmcfp matching the full leaf DN.
// This guards the wiring: a per-unit (non-shipped-default) Supermicro/Dell cert
// whose fingerprint won't hit knownDefaults must still resolve a vendor.
func TestBMCFPAttributesCertDN(t *testing.T) {
	cases := []struct {
		subjectDN  string
		wantVendor string
	}{
		{"CN=IPMI,OU=Software,O=Super Micro Computer,ST=California,C=US", "supermicro"},
		{"CN=idrac-JXJJC02,OU=Remote Access Group,O=Dell Inc.,L=Round Rock,ST=Texas,C=US", "dell"},
		{"CN=C-series CIMC,OU=PID:UCSC-C220-M5SX SERIAL:WAA0000A0AA,O=Cisco Self Signed,L=San Jose,ST=California,C=US", "cisco"},
	}
	for _, c := range cases {
		if v, _, ok := bmcfp.Match(bmcfp.TLSSubjectDN, c.subjectDN); !ok || v != c.wantVendor {
			t.Errorf("bmcfp.Match(subject %q) = (%q, %v), want vendor %q", c.subjectDN, v, ok, c.wantVendor)
		}
	}
}

func TestClassifyIdentityDellServiceTag(t *testing.T) {
	accepted := map[string]string{
		"idrac-JXJJC02":  "JXJJC02",
		"iDRAC-ABC1234":  "ABC1234",
		"iDRAC9-a1b2c3d": "A1B2C3D",
	}
	for cn, want := range accepted {
		vendor, tag, notes := ClassifyIdentity(cn, "")
		if vendor != "dell" || tag != want || len(notes) == 0 {
			t.Errorf("ClassifyIdentity(%q) = (%q, %q, %v), want dell, %q, notes", cn, vendor, tag, notes, want)
		}
	}

	for _, cn := range []string{
		"idrac-ABC123",
		"idrac-ABC12345",
		"idrac-ABC-123",
		"iDRACdefault001122334455",
		"customer-idrac-ABC1234",
	} {
		vendor, tag, _ := ClassifyIdentity(cn, "")
		if vendor == "dell" || tag != "" {
			t.Errorf("ClassifyIdentity(%q) = (%q, %q), want no Dell service tag", cn, vendor, tag)
		}
	}
}

func TestColonHexUpper(t *testing.T) {
	got := colonHexUpper([]byte{0x0e, 0x08, 0x7f, 0x40, 0xab})
	if want := "0E:08:7F:40:AB"; got != want {
		t.Fatalf("colonHexUpper = %q, want %q", got, want)
	}
}

// A typo'd fingerprint would silently never match a real cert, so validate the
// shipped known-default DB is well-formed: 32 colon-separated hex bytes each,
// with vendor + subject populated.
func TestKnownDefaultsWellFormed(t *testing.T) {
	if len(knownDefaults) == 0 {
		t.Fatal("knownDefaults is empty")
	}
	for _, kd := range knownDefaults {
		parts := strings.Split(kd.SHA256, ":")
		if len(parts) != 32 {
			t.Errorf("%s %s: fingerprint has %d bytes, want 32", kd.Vendor, kd.Product, len(parts))
		}
		for _, p := range parts {
			if len(p) != 2 {
				t.Errorf("%s %s: fp byte %q not 2 hex chars", kd.Vendor, kd.Product, p)
				continue
			}
			if _, err := hex.DecodeString(p); err != nil {
				t.Errorf("%s %s: fp byte %q not hex: %v", kd.Vendor, kd.Product, p, err)
			}
		}
		if strings.ToUpper(kd.SHA256) != kd.SHA256 {
			t.Errorf("%s %s: fingerprint must be uppercase for case-insensitive... prefer canonical uppercase", kd.Vendor, kd.Product)
		}
		// A shipped default must have a vendor and at least one matchable signal:
		// an exact cert SHA256, or a subject CN/O (some certs, e.g. BliKVM's OpenSSL
		// placeholder, carry only O=... with an empty CN; field-observed default-cert
		// clusters are matched by exact SHA256 with no reliable subject).
		if kd.Vendor == "" || (kd.SHA256 == "" && kd.SubjectCN == "" && kd.SubjectO == "") {
			t.Errorf("%s: missing vendor or matchable signal (SHA256/CN/O)", kd.Product)
		}
	}
}

// Guards the 2026 "Lights Out" firmware-audit shared/default cert additions.
// Each SHA256 was computed with openssl over the actual shipped cert.pem/server.pem
// and verified byte-identical across the images the finding claims (BliKVM v1-v4,
// Lantronix SLC key/cert pair modulus). A typo here would silently never match.
func TestLightsOutDefaultCertsPresent(t *testing.T) {
	want := map[string]string{ // vendor -> a SHA256 that must be catalogued
		"blikvm":    "CA:97:26:7D:7A:90:61:A7:21:14:EF:26:54:35:F2:75:FB:B1:6D:73:71:5C:96:D4:97:1C:C6:4F:12:D7:0D:9F",
		"lantronix": "83:44:62:75:57:B4:0B:8E:1A:08:28:0D:C0:BA:96:67:02:05:32:AD:BB:BC:E0:36:05:67:8B:24:A7:7D:90:7C",
		"asus":      "6D:EC:FE:56:53:D9:80:0B:55:AB:8F:44:D3:AB:52:AC:8C:0A:B5:AC:92:35:95:66:BA:51:1E:D6:34:36:BC:D0",
	}
	have := map[string]bool{}
	for _, kd := range knownDefaults {
		have[kd.Vendor+"|"+kd.SHA256] = true
	}
	for vendor, sha := range want {
		if !have[vendor+"|"+sha] {
			t.Errorf("missing %s default cert %s", vendor, sha)
		}
	}
}

// knownSharedKeys are matched by SPKI (public-key) SHA-256, stored as plain
// uppercase hex (no separators) to equal strings.ToUpper(hex(sha256(RawSPKI))).
// A typo'd or lowercase value would silently never match a served cert.
func TestKnownSharedKeysWellFormed(t *testing.T) {
	if len(knownSharedKeys) == 0 {
		t.Fatal("knownSharedKeys is empty")
	}
	seen := map[string]bool{}
	for _, sk := range knownSharedKeys {
		if len(sk.SPKI256) != 64 {
			t.Errorf("%s: SPKI256 %q has %d chars, want 64", sk.Label, sk.SPKI256, len(sk.SPKI256))
		}
		if _, err := hex.DecodeString(sk.SPKI256); err != nil {
			t.Errorf("%s: SPKI256 %q not hex: %v", sk.Label, sk.SPKI256, err)
		}
		if strings.ToUpper(sk.SPKI256) != sk.SPKI256 {
			t.Errorf("%s: SPKI256 must be uppercase (matched against uppercase hex)", sk.Label)
		}
		if seen[sk.SPKI256] {
			t.Errorf("%s: duplicate SPKI256 %q", sk.Label, sk.SPKI256)
		}
		seen[sk.SPKI256] = true
		// A shared key must name at least one vendor and document its sharing
		// scope in Note. Cross-OEM keys (AMI) list >=2 vendors; single-vendor
		// fleet keys (e.g. Lantronix lantronix.key shared across a vendor's whole
		// product line) list one -- both are "shared" and warrant the finding.
		if len(sk.Vendors) < 1 {
			t.Errorf("%s: a shared key must list >=1 vendor, got %v", sk.Label, sk.Vendors)
		}
		if strings.TrimSpace(sk.Note) == "" {
			t.Errorf("%s: a shared key must document its sharing scope in Note", sk.Label)
		}
	}
}

// Guards the specific cross-OEM shared AMI keys. SPKI values were computed with
// openssl and verified to equal Go's sha256(cert.RawSubjectPublicKeyInfo).
func TestSharedAMIKeysPresent(t *testing.T) {
	want := []string{
		"DADF500ADB79CA6B807837CC4E6C543F43FF451CD5A7669FBB22557764AF114C", // CA CN=www.ami.com (asrock+gigabyte+tyan)
		"59307DA93E1540FC3E5ECC81D7C31B96062A24762FEDEB008BA7B923E80684D4", // server CN=megarac.com (tyan+gigabyte)
		"5D2B4DC1F88BC84DEE6E6D7C976EFE46E115647894D2048EEB26C09EB39083F2", // server CN=www.ami.com (asrock+gigabyte)
	}
	have := map[string]bool{}
	for _, sk := range knownSharedKeys {
		have[sk.SPKI256] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("missing cross-OEM shared AMI key %s", w)
		}
	}
}

// Guards the AUDIT-4/5 shipped fleet keys added from firmware analysis. SPKI
// values were computed with openssl over the actual server_key_default.pem /
// ACEmanager server.crt in the product trees and verified byte-identical across
// the fleet (Raritan PX3, Sierra RV50==RV55). A typo here would silently never
// match a real served leaf.
func TestSharedFleetKeysPresent(t *testing.T) {
	want := map[string]string{ // SPKI256 -> expected vendor
		"65B1C6E5FE6D2FD91B2D2F2B756B432C28A6FA3AF2740A21EAB19DD7F66C11FF": "raritan", // PX3 Xerus CN=Demo Certificate
		"C104651ED8B02BBF777406E8545AA677731A1A6D1AB8D5F6FBA6CB88AA45C58E": "sierra",  // ALEOS ACEmanager CN=*.sierrawireless.com
		"F342C3FFB8A6AD7C2CDBAE34CE0FE5E54F70C30F89773C3D5B7340662C4A1AA6": "h3c",     // R4900 HDM KVM stunnel CN=H3C
		"582F3ED9741ADEE172AE83648B33CB3793B25666929F20AF1F81B08222582551": "rittal",  // CMC III reos-defaults server.pem O=Rittal
		"A6338A902DD61745A79CF44611D81AC404B778DF35C3DD5233EC33B5F0528871": "eaton",   // NetworkMS/MGE-Pulsar shared RSA-1024 device key
	}
	have := map[string]*SharedPubKey{}
	for i := range knownSharedKeys {
		have[knownSharedKeys[i].SPKI256] = &knownSharedKeys[i]
	}
	for spki, vendor := range want {
		sk, ok := have[spki]
		if !ok {
			t.Errorf("missing shipped fleet key %s (%s)", vendor, spki)
			continue
		}
		if len(sk.Vendors) == 0 || sk.Vendors[0] != vendor {
			t.Errorf("fleet key %s: Vendors = %v, want first %q", spki, sk.Vendors, vendor)
		}
	}
}

// Guards the new badkeys bkhash entries (Raritan PX3 demo, Sierra ALEOS
// ACEmanager). bkhash = base64.RawStdEncoding(sha256(N.Bytes())[:15]); values
// computed from the actual PEMs in the product trees.
func TestFleetBadKeysPresent(t *testing.T) {
	cases := []struct{ bkhash, vendor string }{
		{"0W8iKD0cT1uafFFFq5Ii", "raritan"},
		{"3gOnPlFxsZCsr6Ztgr67", "sierra"},
		{"8at6LLitmmTMZcTRx0m6", "h3c"},
		{"UnT0h3IQ3H3GmYIUBjTU", "rittal"}, // CMC III server.pem
		{"Hlj/L0gDKtOqkBNlXvhg", "sierra"}, // ALEOS Dropbear RSA host key
		{"8y1de1e89X4lv2thEgHp", "sierra"}, // ALEOS Dropbear ECDSA host key
	}
	for _, c := range cases {
		bk, ok := MatchBadKey(c.bkhash)
		if !ok {
			t.Errorf("MatchBadKey(%q) not found, want vendor %q", c.bkhash, c.vendor)
			continue
		}
		if bk.Vendor != c.vendor {
			t.Errorf("MatchBadKey(%q).Vendor = %q, want %q", c.bkhash, bk.Vendor, c.vendor)
		}
	}
}

// TestAMIMegaRACDefaultLeafCatalogued pins the AMI MegaRAC default server.pem
// leaf (CN=megarac.com), shipped with its private key and served by any MegaRAC
// OEM board that has not regenerated. The SHA-256 begins 53:22:36:0A (source:
// TYAN S8030 v6.02 firmware). A unit whose served leaf matches this fingerprint
// is using a public-in-firmware TLS key -> passive decrypt / MITM. A typo here
// would silently never match a real cert.
func TestAMIMegaRACDefaultLeafCatalogued(t *testing.T) {
	const wantSHA = "53:22:36:0A:61:C2:51:A9:93:4A:9C:32:EF:87:E2:50:BD:3B:6C:95:1E:3C:34:FC:A6:37:FA:8A:7B:41:B1:55"
	var found *KnownDefault
	for i := range knownDefaults {
		if knownDefaults[i].SHA256 == wantSHA {
			found = &knownDefaults[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("AMI MegaRAC default leaf %s not catalogued in knownDefaults", wantSHA)
	}
	if !strings.HasPrefix(found.SHA256, "53:22:36:0A") {
		t.Errorf("SHA256 %q does not start with the documented 53:22:36:0A prefix", found.SHA256)
	}
	if found.Vendor != "ami" {
		t.Errorf("vendor = %q, want ami", found.Vendor)
	}
	if found.SubjectCN != "megarac.com" {
		t.Errorf("SubjectCN = %q, want megarac.com", found.SubjectCN)
	}
}

// The badkeys.xml `pattern` is base64.RawStdEncoding of a 15-byte hash prefix,
// which is always exactly 20 base64 chars. A malformed pattern (wrong length or
// not base64) would silently never match a served key, so guard the imported DB.
func TestKnownBadKeysWellFormed(t *testing.T) {
	if len(knownBadKeys) == 0 {
		t.Fatal("knownBadKeys is empty")
	}
	seen := map[string]bool{}
	for _, bk := range knownBadKeys {
		if len(bk.BKHash) != 20 {
			t.Errorf("%s %s: pattern %q has %d chars, want 20", bk.Vendor, bk.Product, bk.BKHash, len(bk.BKHash))
		}
		raw, err := base64.RawStdEncoding.DecodeString(bk.BKHash)
		if err != nil {
			t.Errorf("%s %s: pattern %q not RawStdEncoding base64: %v", bk.Vendor, bk.Product, bk.BKHash, err)
		} else if len(raw) != 15 {
			t.Errorf("%s %s: pattern decodes to %d bytes, want 15 (BlockHashPrefix)", bk.Vendor, bk.Product, len(raw))
		}
		if bk.Vendor == "" || bk.Product == "" || bk.Device == "" {
			t.Errorf("%q: missing vendor/product/device", bk.BKHash)
		}
		if bk.Kind != "FW/TLS" && bk.Kind != "FW/SSH" {
			t.Errorf("%s %s: kind %q must be FW/TLS or FW/SSH", bk.Vendor, bk.Product, bk.Kind)
		}
		if seen[bk.BKHash] {
			t.Errorf("%s %s: duplicate pattern %q", bk.Vendor, bk.Product, bk.BKHash)
		}
		seen[bk.BKHash] = true
	}
}

// Guards that the OOB vendors imported from badkeys.xml -- especially the ones
// we hold no local firmware key material for -- are actually catalogued, so a
// served default key from those devices attributes the vendor.
func TestBadKeysImportedVendorsPresent(t *testing.T) {
	wantPattern := map[string]string{ // pattern -> vendor
		"nV0uP9zNZS3dnPy11hHD": "huawei",   // Huawei iBMC
		"EjLXygBPF/Ts1oByPd7n": "oracle",   // Oracle ILOM
		"S7YmTb6gK0DHhzmlbqT2": "inspur",   // Inspur BMC
		"Km7mVdzkyGBo2/XUQj7m": "h3c",      // H3C HDM
		"IM+lAPVkEI/4EApQUNcf": "quanta",   // Quanta BMC
		"eD7FldnmZAPyWac5v1v0": "nokia",    // Nokia AirFrame BMC
		"gB2ZgNO9UXofmozWl/7G": "raritan",  // Raritan
		"TS7N+VyfEOL1QR+ubIv/": "opengear", // Opengear (SSH)
		"2gr/LCgigKgwE9zxZbNF": "dell",     // Dell Secure Connect Gateway (SSH)
	}
	for pat, vendor := range wantPattern {
		bk, ok := MatchBadKey(pat)
		if !ok {
			t.Errorf("imported badkey pattern %q (%s) not catalogued", pat, vendor)
			continue
		}
		if bk.Vendor != vendor {
			t.Errorf("pattern %q vendor = %q, want %q", pat, bk.Vendor, vendor)
		}
	}
	if _, ok := MatchBadKey(""); ok {
		t.Error("empty bkhash must not match")
	}
	if _, ok := MatchBadKey("notARealBkhash0000"); ok {
		t.Error("unknown bkhash must not match")
	}
}

// BadKeyHash must replicate sshamble/badkeys.PrefixFromPublicKey for RSA:
// bkhash = base64.RawStdEncoding(sha256(N.Bytes())[:15]). We reconstruct the
// Supermicro X10 httpd server.pem public key from its modulus/exponent (values
// extracted from the shipped firmware cert) and verify the bkhash equals the
// pattern we exported to badkeys.xml. This pins the algorithm end-to-end.
func TestBadKeyHashRSA(t *testing.T) {
	// SMC X10 usr/local/httpd/server.pem public key (RSA-2048, e=65537).
	// Modulus hex captured from the shipped cert (CN=IPMI,O=Super Micro Computer).
	n, ok := new(big.Int).SetString(smcX10ModulusHex, 16)
	if !ok {
		t.Fatalf("bad test modulus")
	}
	pub := &rsa.PublicKey{N: n, E: 65537}
	got, gok := BadKeyHash(pub)
	if !gok {
		t.Fatalf("BadKeyHash(rsa) not ok")
	}
	const want = "//jJvoICu3MHEJctzNhc"
	if got != want {
		t.Fatalf("BadKeyHash = %q, want %q (SMC X10)", got, want)
	}
	bk, mok := MatchBadKey(got)
	if !mok || bk.Vendor != "supermicro" {
		t.Fatalf("MatchBadKey(%q) = (%+v, %v), want supermicro", got, bk, mok)
	}
}

func TestBadKeyHashECDSA(t *testing.T) {
	encoded, err := hex.DecodeString("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := BadKeyHash(pub)
	if !ok || got != "QFdwkdli0sNiF7jho8fu" {
		t.Fatalf("BadKeyHash(P-256 generator) = %q, %t", got, ok)
	}
}

// smcX10ModulusHex is the RSA-2048 modulus of the Supermicro X10 ATEN
// usr/local/httpd/server.pem shipped cert (CN=IPMI, O=Super Micro Computer),
// extracted from the firmware. Used to exercise BadKeyHash against a real key.
const smcX10ModulusHex = "c73cdf858618a58b22f9cc3fd413042709fc1666b6fe0a2db44a731a60110f726e8267d92e4330e1152d6538016460eee53e33c4e4dda669845be049974d6a13750b07e6671bf8de6767fc2eb5c4fff26511c8056eb19acc63bc2a086524039d443fae11c4b96122df60307d3c20285d671eec245ccd3e9cae53d57a1e5ce0747349111e93b605d404ec42af24d5567fa265bdda6ee46435d715dadfb54670cc4a76701fefe785c65c39a0e308c1449a914830ce203827e16c1f18b1be036fd1000e7bd50874bede80bab2d571f141ce73fbf46e1ef65540d946a14b76fd25158ba77d757c7e990f955dcee8c6b67f6f2743628081a0127171fb1aeaeff8872f"

// TestConnectUPSKeysMatch confirms the Eaton ConnectUPS 512-bit RSA patterns
// resolve via MatchBadKey so a served ConnectUPS leaf is flagged as a
// shared/factorable key.
func TestConnectUPSKeysMatch(t *testing.T) {
	for _, pat := range []string{"DKIUdcS9cVuel/WPENV5", "I1XObVXQOJHKiihuxNxq", "8ptY7lq+1M6SlzTKaE13"} {
		bk, ok := MatchBadKey(pat)
		if !ok {
			t.Errorf("ConnectUPS pattern %q not matched by MatchBadKey", pat)
			continue
		}
		if bk.Vendor != "eaton" || bk.Product != "ConnectUPS Web/SNMP" {
			t.Errorf("pattern %q resolved to %s/%s, want eaton/ConnectUPS Web/SNMP", pat, bk.Vendor, bk.Product)
		}
	}
}

// networkMSModulusHex is the RSA-1024 modulus of the Eaton NetworkMS /
// MGE-Pulsar (HE/LD/LE) shared device key, recovered from the DES-EDE3-CBC
// PEM in firmware (passphrase "password"), byte-identical across HE/LD/LE.
const networkMSModulusHex = "aa0905cc7b9cba8184a36e388e0bcd3d6818cb2c4e5d87db5ea6220e4dee2ba5152d18057073e3a082328d756fffac9e3465d476eea313b0fbc6755cc14ca6b1befda90098726a982b0492372dc5eb8bb29e9fbd2f96bfbe6e8b4ea3846078369865d5b0feef3d51ee781b22491b20539fba352ef72441ce8c457e3ae1d38b19"

// TestNetworkMSKeyMatch confirms the Eaton NetworkMS shared RSA-1024 key
// resolves via MatchBadKey, and that the catalogued bkhash is exactly the one
// BadKeyHash derives from the recovered modulus (guards against a typo'd
// pattern). A served leaf carrying this key is attributed to the NetworkMS /
// MGE-Pulsar HE/LD/LE product line.
func TestNetworkMSKeyMatch(t *testing.T) {
	mod, ok := new(big.Int).SetString(networkMSModulusHex, 16)
	if !ok {
		t.Fatal("failed to parse NetworkMS modulus hex")
	}
	bkhash, ok := BadKeyHash(&rsa.PublicKey{N: mod, E: 65537})
	if !ok {
		t.Fatal("BadKeyHash returned ok=false for the NetworkMS RSA key")
	}
	const wantPattern = "bNmvE5s+CXOu0OeuqaiW"
	if bkhash != wantPattern {
		t.Fatalf("BadKeyHash(NetworkMS) = %q, want %q", bkhash, wantPattern)
	}
	bk, ok := MatchBadKey(bkhash)
	if !ok {
		t.Fatalf("NetworkMS bkhash %q not matched by MatchBadKey", bkhash)
	}
	if bk.Vendor != "eaton" || bk.Product != "NetworkMS/MGE-Pulsar (HE/LD/LE)" {
		t.Errorf("NetworkMS bkhash resolved to %s/%s, want eaton/NetworkMS/MGE-Pulsar (HE/LD/LE)", bk.Vendor, bk.Product)
	}
	// The same key is also catalogued in the SPKI matcher (knownSharedKeys) so a
	// served leaf is flagged even when re-wrapped in a fresh cert. SPKI256 =
	// sha256(RawSubjectPublicKeyInfo) of the recovered key.
	const wantSPKI = "A6338A902DD61745A79CF44611D81AC404B778DF35C3DD5233EC33B5F0528871"
	foundSPKI := false
	for i := range knownSharedKeys {
		if knownSharedKeys[i].SPKI256 == wantSPKI {
			foundSPKI = true
			if len(knownSharedKeys[i].Vendors) == 0 || knownSharedKeys[i].Vendors[0] != "eaton" {
				t.Errorf("NetworkMS shared key vendors = %v, want first \"eaton\"", knownSharedKeys[i].Vendors)
			}
		}
	}
	if !foundSPKI {
		t.Errorf("NetworkMS shared key SPKI %s not in knownSharedKeys", wantSPKI)
	}
}

// TestCiscoLegacySharedHostKeyPresent confirms the Cisco CIMC legacy default
// host.key (byte-identical S3260 4.3 / C220 M4 4.1, SPKI independently verified
// via openssl) is catalogued as a shared key so a served leaf is flagged.
func TestCiscoLegacySharedHostKeyPresent(t *testing.T) {
	const want = "8962BC2DF11A9AC6E9CAF651C904B670D2558C85689D03263E9CE462BD3B78FD"
	for _, sk := range knownSharedKeys {
		if sk.SPKI256 == want {
			found := false
			for _, v := range sk.Vendors {
				if v == "cisco" {
					found = true
				}
			}
			if !found {
				t.Errorf("Cisco shared key present but vendor 'cisco' not listed: %v", sk.Vendors)
			}
			return
		}
	}
	t.Errorf("Cisco CIMC legacy shared host.key SPKI %s not in knownSharedKeys", want)
}
