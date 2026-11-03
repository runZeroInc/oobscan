package report

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The bundle is meant to be shareable: a reader gets the prevalence findings
// without learning which specific systems were scanned. That property is easy to
// lose by accident -- one new field carrying rec.Host, or a per-host row added
// back for a detail view -- and impossible to walk back once a bundle has been
// sent. So it is asserted over the rendered payload rather than trusted to
// review.

var (
	ipv4Literal = regexp.MustCompile(`(?:^|[^0-9.])((?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3})(?:[^0-9.]|$)`)
	cidrLiteral = regexp.MustCompile(`\b[0-9]{1,3}(?:\.[0-9]{1,3}){3}/[0-9]{1,2}\b`)
	ipv6Literal = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b`)
	macLiteral  = regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b`)
	guidLiteral = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)
)

// firmwareVersionish reports whether a dotted-quad match is a firmware version
// string rather than an address. BMC versions really do look like 7.00.00.183,
// so the check would false-positive on every HPE corpus without this: a version
// keeps its leading zeros, which no printed address does.
func firmwareVersionish(s string) bool {
	for _, part := range strings.Split(s, ".") {
		if len(part) > 1 && part[0] == '0' {
			return true
		}
	}
	return false
}

// TestPayloadCarriesNoHostIdentifiers renders a report from records with real
// addresses, hostnames, GUIDs and MACs, then asserts none of it survives into
// the payload.
func TestPayloadCarriesNoHostIdentifiers(t *testing.T) {
	src := loadOne(t, "privacy",
		`{"host":"198.51.100.23","identity":{"class":"bmc","vendor":"hpe"},"final":{"vendor":"hpe","version":"2.82"},"ports":{"623/udp":"ipmi","443/tcp":"https"},"rakp":[{"username":"Administrator","authAlgo":1,"rakpHash":"aa","bmcGuid":"3138b3a2-1f4c-4d5e-8a9b-00219b9a1c2d"}],"services":[{"port":443,"transport":"tcp","protocols":["https"],"address":"198.51.100.23","attributes":{"tls.subject":"CN=ilo-prod-db14.corp.example.com","ipmi.guid":"3138b3a2-1f4c-4d5e-8a9b-00219b9a1c2d","ipmi.guid.nodeMac":"00:21:9b:9a:1c:2d"}}],"findings":[{"check":"ipmi.v20.cipherZero","risk":"critical","fields":{"proof":"host 198.51.100.23 accepted suite 0"}}]}`,
		`{"host":"2001:db8:dead:beef::7","identity":{"class":"bmc","vendor":"supermicro"},"ports":{"623/udp":"ipmi"},"findings":[{"check":"ipmi.v20.defaultCreds","risk":"critical","fields":{"username":"ADMIN","proof":"2001:db8:dead:beef::7 ADMIN/ADMIN"}}]}`,
	)
	payload, err := json.Marshal(Build("2026-01-01 00:00 UTC", []*Source{src}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(payload)

	if strings.Contains(body, `"systems"`) {
		t.Error(`payload carries a "systems" key: per-host rows are back, and they hold addresses`)
	}
	for _, secret := range []string{
		"198.51.100.23",
		"2001:db8:dead:beef::7",
		"ilo-prod-db14.corp.example.com",
		"3138b3a2-1f4c-4d5e-8a9b-00219b9a1c2d",
		"00:21:9b:9a:1c:2d",
	} {
		if strings.Contains(body, secret) {
			t.Errorf("payload leaks %q: the bundle cannot be shared", secret)
		}
	}

	// Nothing address-shaped at all, beyond firmware versions.
	for _, m := range ipv4Literal.FindAllStringSubmatch(body, -1) {
		if !firmwareVersionish(m[1]) {
			t.Errorf("payload carries an IPv4-shaped value %q", m[1])
		}
	}
	for _, pat := range []struct {
		name string
		re   *regexp.Regexp
	}{
		{"CIDR", cidrLiteral},
		{"IPv6", ipv6Literal},
		{"MAC", macLiteral},
		{"GUID", guidLiteral},
	} {
		if got := pat.re.FindAllString(body, -1); len(got) > 0 {
			t.Errorf("payload carries %s-shaped values: %v", pat.name, got[:min(len(got), 5)])
		}
	}
}

// TestFindingProofIsNotCarried pins the specific channel that would defeat the
// rest: a finding's proof string routinely quotes the host it was taken from, so
// proofs must not reach the payload even in aggregate.
func TestFindingProofIsNotCarried(t *testing.T) {
	src := loadOne(t, "proof",
		`{"host":"203.0.113.9","identity":{"class":"bmc","vendor":"dell"},"findings":[{"check":"ipmi.v20.cipherZero","risk":"critical","fields":{"proof":"203.0.113.9 opened suite 0 as Administrator"}}]}`,
	)
	payload, err := json.Marshal(Build("2026-01-01 00:00 UTC", []*Source{src}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(payload), "opened suite 0 as Administrator") {
		t.Error("payload carries a finding proof string; proofs quote host addresses")
	}
	// The finding itself must still be counted -- the point is aggregate-only, not
	// blind.
	v := src.view()
	if got := exposureHosts(v.Compromise, "cipher_zero"); got != 1 {
		t.Errorf("cipher_zero = %d, want 1: the finding must still count", got)
	}
}

// TestRecoveredSecretsAreRedacted pins the credential gate. A recovered plaintext
// built from a company name identifies the victim, and this bundle is meant to be
// shared: the shared-credential head really did carry values like these.
func TestRecoveredSecretsAreRedacted(t *testing.T) {
	orgSecrets := []string{"BOBCATBOBCAT", "Nokia2018", "b@dp@ssw0rd", "Contoso!2024", "acmecorp99"}
	for _, pw := range orgSecrets {
		if !isOrgAttributable(pw) {
			t.Errorf("%q is published verbatim; an org-attributable secret must be masked", pw)
		}
	}
	// Vendor defaults and universally-common weak passwords stay legible: masking
	// them would destroy the finding ("this fleet still runs shipped defaults")
	// while protecting nobody.
	for _, pw := range []string{"admin", "ADMIN", "calvin", "superuser", "0penBmc", "password", "12345678"} {
		if isOrgAttributable(pw) {
			t.Errorf("%q is masked; a vendor default or top-1000 password carries no attribution", pw)
		}
	}
	// The crack-method token is not a password at all.
	if got := redactSecret("common"); got != "<common>" {
		t.Errorf("redactSecret(common) = %q, want <common> to mark it a placeholder", got)
	}
	if got := redactSecret(""); got != "<empty>" {
		t.Errorf("redactSecret(empty) = %q, want <empty>", got)
	}
	// A masked value keeps its shape so the family is still readable.
	if got := redactSecret("BOBCATBOBCAT"); got != "<redacted:AAAAAAAAAAAA>" {
		t.Errorf("redactSecret(BOBCATBOBCAT) = %q, want the shape mask", got)
	}
}

// TestPasswordViewsCarryNoOrgSecrets asserts the gate is wired into every channel
// that reaches the payload, not just available as a helper.
func TestPasswordViewsCarryNoOrgSecrets(t *testing.T) {
	// Twelve hosts sharing one org-specific credential: enough to clear the
	// shared-credential ceiling and reach the head of every histogram.
	lines := []string{}
	for i := 1; i <= 12; i++ {
		lines = append(lines, `{"host":"10.0.0.`+itoa(i)+`","identity":{"class":"bmc","vendor":"hpe"},"rakp":[{"username":"ADMIN","authAlgo":1,"cracked":"BOBCATBOBCAT"}]}`)
	}
	src := loadOne(t, "secrets", lines...)
	payload, err := jsonMarshal(Build("2026-01-01 00:00 UTC", []*Source{src}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(payload), "BOBCATBOBCAT") {
		t.Error("payload carries the org-specific plaintext BOBCATBOBCAT")
	}
	if !strings.Contains(string(payload), "redacted:AAAAAAAAAAAA") {
		t.Error("payload lost the masked form too; the shape must survive so the row is still readable")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
