package scanfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func writeFile(t *testing.T, name string, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func readBack(t *testing.T, path string) []Record {
	t.Helper()
	r, err := Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer r.Close()
	var out []Record
	for r.Next() {
		out = append(out, *r.Record())
	}
	if err := r.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return out
}

// TestPostAuthBlobsSurviveUnchanged is why the post-auth captures are held as
// raw JSON rather than decoded into their probe-side structs: a read-modify-
// write cycle must not be able to drop a field nobody thought to model.
func TestPostAuthBlobsSurviveUnchanged(t *testing.T) {
	const blob = `{"lan":{"ipAddress":"192.0.2.1"},"someFutureField":{"nested":[1,2,3]}}`
	in := writeFile(t, "in.jsonl", `{"host":"192.0.2.1","ipmiPostAuth":`+blob+`}`)

	recs := readBack(t, in)
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	var got, want any
	if err := json.Unmarshal(recs[0].IPMIPost, &got); err != nil {
		t.Fatalf("decode captured blob: %v", err)
	}
	if err := json.Unmarshal([]byte(blob), &want); err != nil {
		t.Fatal(err)
	}
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("post-auth blob changed:\n got %s\nwant %s", gotJSON, wantJSON)
	}
}

// TestLegacyKeysMigrate covers the top-level renames that happened after data
// had already shipped.
func TestLegacyKeysMigrate(t *testing.T) {
	in := writeFile(t, "legacy.jsonl",
		`{"host":"192.0.2.2","ts":1700000000,"ipmi_postauth":{"lan":{}},"web_login":{"steps":[]}}`)
	recs := readBack(t, in)
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	rec := recs[0]
	if !rawPresent(rec.IPMIPost) {
		t.Error("legacy ipmi_postauth did not migrate to ipmiPostAuth")
	}
	if !rawPresent(rec.WebLogin) {
		t.Error("legacy web_login did not migrate to webLogin")
	}
	if rec.TS != 1700000000 {
		t.Errorf("legacy ts = %d, want it migrated to timestamp", rec.TS)
	}
}

// TestMigrateFoldsCleanFindings checks the rule change that moved "none"-risk
// results out of the findings array and into attemptedChecks.
func TestMigrateFoldsCleanFindings(t *testing.T) {
	rec := &Record{
		AttemptedChecks: "ssh.exposure",
		Findings: []engine.Finding{
			{Check: "ipmi.rmcpPing", Risk: "info"},
			{Check: "tls.expired", Risk: "none"},
			{Check: "ipmi.v20.cipherZero", Risk: "critical"},
			{Check: "", Risk: "high"}, // no check id: dropped
		},
	}
	rec.Migrate()

	if got := len(rec.Findings); got != 2 {
		t.Fatalf("findings = %d, want 2: %+v", got, rec.Findings)
	}
	if rec.Findings[0].Check != "ipmi.v20.cipherZero" {
		t.Errorf("findings not sorted most-severe-first: %+v", rec.Findings)
	}
	if rec.AttemptedChecks != "ssh.exposure,tls.expired" {
		t.Errorf("attemptedChecks = %q, want the clean check folded in", rec.AttemptedChecks)
	}

	// Idempotent: a second pass changes nothing.
	before := rec.AttemptedChecks
	rec.Migrate()
	if rec.AttemptedChecks != before || len(rec.Findings) != 2 {
		t.Errorf("Migrate is not idempotent: %q / %+v", rec.AttemptedChecks, rec.Findings)
	}
}

// TestReaderSkipsMalformedLines checks that a corrupt or half-written line
// costs one record rather than the whole file -- scan outputs are appended live
// and a truncated tail is normal.
func TestReaderSkipsMalformedLines(t *testing.T) {
	in := writeFile(t, "mixed.jsonl",
		`{"host":"192.0.2.3"}`,
		`not json at all`,
		``,
		`{"host":"192.0.2.4"}`,
		`{"host":"192.0.2.5"`,
	)
	r, err := Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var hosts []string
	for r.Next() {
		hosts = append(hosts, r.Record().Host)
	}
	if err := r.Err(); err != nil {
		t.Fatalf("Err = %v, want nil", err)
	}
	if len(hosts) != 2 {
		t.Errorf("hosts = %v, want the 2 well-formed records", hosts)
	}
	if r.Skipped() != 2 {
		t.Errorf("Skipped = %d, want 2", r.Skipped())
	}
}

// TestWriterGzipByExtension checks that compression follows the output path.
func TestWriterGzipByExtension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.jsonl.gz")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(&Record{Host: "192.0.2.6"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		t.Fatalf("output is not gzipped: % x", raw)
	}
	if recs := readBack(t, path); len(recs) != 1 || recs[0].Host != "192.0.2.6" {
		t.Errorf("gzip round trip lost the record: %+v", recs)
	}
}
