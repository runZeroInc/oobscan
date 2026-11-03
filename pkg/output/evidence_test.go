package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// A key that is not a canonical evidence spelling looks fine but matches nothing:
// t.Evidenced canonicalizes its argument, so a misspelled entry serializes no data.
// A reason per key is required too, since this list is the contract for what survives.
func TestSerializedEvidenceKeysAreCanonical(t *testing.T) {
	for key, why := range serializedEvidenceKeys {
		if got := engine.CanonicalEvidenceKey(key); got != key {
			t.Errorf("serializedEvidenceKeys key %q is not canonical (canonicalises to %q), so it would match no evidence", key, got)
		}
		if strings.TrimSpace(why) == "" {
			t.Errorf("serializedEvidenceKeys[%q] has no reason recorded", key)
		}
	}
}

// The bag must not carry handles that would balloon the record or duplicate data
// already serialized elsewhere.
func TestSerializedEvidenceKeysExcludeRedundantAndHuge(t *testing.T) {
	for _, key := range []string{
		"http",      // full httpscan report incl. a retained body per endpoint
		"ipmi.auth", // RAKP hash material + recovered passwords, already in rakp[]
		"tls",       // already in services[].attributes
		"ssh.hostKeys",
		"ssh.banner",
		"ipmi.postAuth",    // already the top-level ipmiPostAuth field
		"redfish.postAuth", // already the top-level redfishPostAuth field
		"ilo",              // already the top-level ilo field
	} {
		if why, present := serializedEvidenceKeys[key]; present {
			t.Errorf("%q is in the evidence bag (%q) but is redundant or too large", key, why)
		}
	}
}

// Only allowlisted evidence is serialized, and it round-trips as real JSON.
func TestEvidenceForRecordSerializesAllowlistedOnly(t *testing.T) {
	tg := &engine.Target{Host: "192.0.2.1"}
	tg.SetEvidence("ipmi.smc.rakpUnordered", map[string]any{"rakp4Status": 8, "sidEchoed": true})
	tg.SetEvidence("ipmi.openBmcDefaultUserKey", map[string]any{"winBmcRand": "abcd"})
	// Not allowlisted: must not appear.
	tg.SetEvidence("http", map[string]any{"body": strings.Repeat("x", 1000)})

	got := evidenceForRecord(tg)
	if _, ok := got["ipmi.smc.rakpUnordered"]; !ok {
		t.Error("allowlisted ipmi.smc.rakpUnordered was not serialized")
	}
	if _, ok := got["ipmi.openBmcDefaultUserKey"]; !ok {
		t.Error("allowlisted ipmi.openBmcDefaultUserKey was not serialized")
	}
	if _, ok := got["http"]; ok {
		t.Error("non-allowlisted `http` evidence leaked into the record")
	}
	// Every value must be valid JSON so a reader can pass it through untouched.
	for k, raw := range got {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Errorf("evidence[%q] is not valid JSON: %v", k, err)
		}
	}
}

// A host with no evidence must not gain an empty `evidence` object.
func TestEvidenceForRecordOmitsWhenEmpty(t *testing.T) {
	if got := evidenceForRecord(&engine.Target{Host: "192.0.2.1"}); got != nil {
		t.Errorf("evidenceForRecord = %v, want nil so the key is omitted", got)
	}
}

// An oversized blob is reported as omitted-with-a-reason, never silently dropped:
// a missing key would read as "the probe did not run".
func TestEvidenceForRecordNotesOversizedBlob(t *testing.T) {
	tg := &engine.Target{Host: "192.0.2.1"}
	tg.SetEvidence("ipmi.preAuthMap", map[string]any{"blob": strings.Repeat("x", maxEvidenceBytes+1)})

	raw, ok := evidenceForRecord(tg)["ipmi.preAuthMap"]
	if !ok {
		t.Fatal("oversized evidence was dropped entirely; that reads as 'the probe never ran'")
	}
	var note struct {
		Omitted string `json:"omitted"`
		Bytes   int    `json:"bytes"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &note); err != nil {
		t.Fatalf("oversized placeholder is not valid JSON: %v", err)
	}
	if note.Omitted == "" || note.Bytes <= maxEvidenceBytes || note.Reason == "" {
		t.Errorf("placeholder must state what was omitted, how big it was and why the key matters: %+v", note)
	}
}

// The record must actually carry the bag end to end.
func TestResultCarriesEvidence(t *testing.T) {
	tg := &engine.Target{Host: "192.0.2.1"}
	tg.SetEvidence("ipmi.v15", map[string]any{"authNoneOk": true})

	b, err := json.Marshal(resultFrom(tg))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"evidence"`) {
		t.Fatalf("record has no evidence object: %s", b)
	}
	if !strings.Contains(string(b), `"ipmi.v15"`) {
		t.Errorf("evidence handle missing from record: %s", b)
	}
}
