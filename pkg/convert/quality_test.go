package convert

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// TestQualityFixture writes a small JSONL fixture carrying each documented
// failure mode and asserts the audit surfaces every one. If a future edit
// re-introduces a NUL byte in communityString or drops the proof field on a
// critical finding, this fails.
func TestQualityFixture(t *testing.T) {
	records := []map[string]any{
		{
			"host": "10.0.0.1",
			"findings": []map[string]any{
				{
					"check": "ipmi.v20.rakpHash", "risk": "critical",
					"fields": map[string]string{
						"user": "root", "hash": "deadbeef:cafebabe", "hash_algo": "hmac-sha1",
					},
				},
			},
			"ipmiPostAuth": map[string]any{
				"lan": map[string]string{
					// Deliberately dirty: trips both the null-byte and the U+FFFD rule.
					"communityString": "public\x00\x00�",
				},
			},
		},
		{
			"host": "10.0.0.2",
			"findings": []map[string]any{
				// Critical with no proof field at all.
				{
					"check": "http.idrac.defaultCreds", "risk": "critical",
					"fields": map[string]string{"user": "root", "pass": "calvin"},
				},
			},
		},
		{
			"host": "10.0.0.3",
			"findings": []map[string]any{
				{
					"check": "http.exposure", "risk": "high",
					"fields": map[string]string{"url": "/page/a", "match": "preAuthReadable", "response": "<html>"},
				},
				{
					"check": "http.exposure", "risk": "high",
					"fields": map[string]string{"url": "/page/b", "match": "preAuthReadable", "response": "<html>"},
				},
			},
		},
		{
			"host": "10.0.0.4",
			"findings": []map[string]any{
				{"check": "ssh.version", "risk": "info", "fields": map[string]string{"hostkeyFingerprint": "SHA256:shared"}},
				{"check": "tls.selfSigned", "risk": "low", "fields": map[string]string{"sha256": "AA:BB"}},
			},
		},
		{
			"host": "10.0.0.5",
			"findings": []map[string]any{
				{"check": "ssh.version", "risk": "info", "fields": map[string]string{"hostkeyFingerprint": "SHA256:shared"}},
				{"check": "tls.selfSigned", "risk": "low", "fields": map[string]string{"sha256": "AA:BB"}},
			},
		},
	}

	in := writeFixture(t, "quality.jsonl", records)
	st, err := Run(Options{Format: FormatOOBScan, Input: in, Quality: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	q := st.Quality
	if q == nil {
		t.Fatal("no quality report")
	}
	if q.Records != 5 {
		t.Errorf("Records = %d, want 5", q.Records)
	}
	if !q.Dirty() {
		t.Error("Dirty() = false, want true")
	}
	if _, ok := q.NullByte["ipmiPostAuth.lan.communityString"]; !ok {
		t.Errorf("null byte in communityString not reported: %v", q.NullByte)
	}
	if _, ok := q.ReplacementChar["ipmiPostAuth.lan.communityString"]; !ok {
		t.Errorf("U+FFFD in communityString not reported: %v", q.ReplacementChar)
	}
	if _, ok := q.MissingProof["http.idrac.defaultCreds"]; !ok {
		t.Errorf("proofless critical finding not reported: %v", q.MissingProof)
	}
	if got := q.DuplicateURL["http.exposure|preAuthReadable"]; got != 1 {
		t.Errorf("uncollapsed duplicate count = %d, want 1", got)
	}
	if hosts := q.ReusedSSHKey["SHA256:shared"]; len(hosts) != 2 {
		t.Errorf("reused SSH key hosts = %v, want 2", hosts)
	}
	if hosts := q.ReusedTLSCert["AA:BB"]; len(hosts) != 2 {
		t.Errorf("reused TLS cert hosts = %v, want 2", hosts)
	}
	// The rakpHash finding carries a `hash` field, which counts as proof.
	if _, ok := q.MissingProof["ipmi.v20.rakpHash"]; ok {
		t.Error("rakpHash finding with a hash field was reported as proofless")
	}
}

// TestQualityAuditsPreRedactionRecords pins the ordering guarantee: redaction
// replaces the very values the hygiene rules inspect, so auditing has to happen
// on what the source said, not on what we are about to write.
func TestQualityAuditsPreRedactionRecords(t *testing.T) {
	// The post-auth captures are the right probe for this: unlike finding
	// fields, whose values are sanitized as they decode, a raw capture reaches
	// the audit exactly as the source wrote it.
	in := writeFixture(t, "dirty.jsonl", []map[string]any{{
		"host": "192.0.2.10",
		"ipmiPostAuth": map[string]any{
			"lan": map[string]string{"communityString": "public\x00"},
		},
	}})
	out := filepath.Join(t.TempDir(), "out.jsonl")

	st, err := Run(Options{Format: FormatOOBScan, Input: in, Output: out, Redact: true, Quality: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(st.Quality.NullByte) == 0 {
		t.Error("redaction hid the null byte from the audit")
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "public") {
		t.Errorf("redaction left the community string in the output: %s", body)
	}
}

func TestDarkChecksCanonicalMatching(t *testing.T) {
	registered := map[string]bool{
		"ipmi.v20.rakpHash":          true,
		"ipmi.postAuthEnum":          true,
		"kvm.usbAnywhere":            true,
		"tcp.telnetBanner":           true,
		"http.redfish.authPathError": true,
	}
	histogram := map[string]int{
		"ipmi.20.rakp_hash":            5,
		"ipmi.postauth_enum":           4,
		"kvm.usbanywhere":              3,
		"tcp.telnet_banner":            2,
		"http.redfish.auth_path_error": 1,
	}
	if dark := darkChecks(registered, histogram); len(dark) != 0 {
		t.Fatalf("darkChecks should treat canonical variants as emitted, got: %v", dark)
	}
}

func TestRegisteredCheckIDsExcludeDisabledAndNonEmittingNames(t *testing.T) {
	registered := RegisteredCheckIDs()
	for _, id := range []string{"udp.moxa.dsciConfig", "udp.vertiv.velocityDiscovery", "http.redfish.authPathProbe"} {
		if registered[engine.CanonicalCheckID(id)] {
			t.Errorf("RegisteredCheckIDs includes non-emitting or disabled check %q", id)
		}
	}
	if !registered[engine.CanonicalCheckID("http.redfish.authPathError")] {
		t.Error("RegisteredCheckIDs missing emitted http.redfish.authPathError")
	}
}

// writeFixture writes records as NDJSON into a temp file and returns its path.
func writeFixture(t *testing.T, name string, records []map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			t.Fatalf("encode fixture: %v", err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// writeLines writes raw NDJSON lines into a temp file and returns its path.
func writeLines(t *testing.T, name string, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// TestQualityFindsMangledFindingFieldsOnDisk pins the reason the audit reads
// the raw line: engine.Fields sanitizes values as it decodes them, so a NUL
// that a producer actually wrote into a finding field is already gone by the
// time the typed record exists. Auditing the decoded value would report the
// file clean.
func TestQualityFindsMangledFindingFieldsOnDisk(t *testing.T) {
	in := writeFixture(t, "mangled.jsonl", []map[string]any{{
		"host": "192.0.2.60",
		"findings": []map[string]any{{
			"check": "ipmi.v20.rakpHash", "risk": "high",
			"fields": map[string]string{"hash": "deadbeef\x00", "proof": "sane"},
		}},
	}})

	st, err := Run(Options{Format: FormatOOBScan, Input: in, Quality: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, ok := st.Quality.NullByte["ipmi.v20.rakpHash.hash"]; !ok {
		t.Errorf("null byte in a finding field went unreported: %v", st.Quality.NullByte)
	}
}
