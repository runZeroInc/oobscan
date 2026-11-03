package cmd

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/correlate"
)

// An iLO whose /xmldata names its server: one NIC entry is the iLO itself (the address
// the scan reached), the other is the machine it manages.
const iloLine = `{"host":"192.0.2.10","finalIdentity":{"class":"bmc"},"attributes":{"vendor":"hpe"},` +
	`"ilo":{"hsi":{"serverModel":"ProLiant DL360 Gen10","chassisSerial":"CZ12345678","nics":{"nic":[` +
	`{"description":"iLO 5","macAddress":"00:11:22:33:44:03","ipAddress":"192.0.2.10"},` +
	`{"description":"HPE Ethernet 1Gb","macAddress":"00:11:22:33:44:00","ipAddress":"192.0.2.20"}]}}}}`

const plainLine = `{"host":"192.0.2.30","ports":{"tcp":[22]}}`

// A line this build cannot parse. The rewrite is the only copy of the scan, so it has
// to survive: an older build's shape, or a tail cut off mid-write, is not garbage to
// throw away.
const brokenLine = `{"host":"192.0.2.99","truncat`

func writeScan(t *testing.T, name string, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCorrelateAnnotatesTheDevicesOwnRecord(t *testing.T) {
	// No trailing newline: the last line of an interrupted scan has none, and adding
	// one would be a change to a file the pass is only supposed to annotate.
	path := writeScan(t, "scan.jsonl", iloLine, plainLine, brokenLine)

	sum, out, err := runCorrelateStageTo(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if out != path {
		t.Fatalf("wrote %q, want the input rewritten in place", out)
	}
	if sum.Annotated != 1 || sum.Described != 1 || sum.Stated != 1 {
		t.Fatalf("summary = %+v", sum)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasSuffix(b, []byte("\n")) {
		t.Fatal("pass added a trailing newline the scan did not have")
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3: %q", len(lines), b)
	}
	if lines[1] != plainLine {
		t.Fatalf("a record with nothing to add was rewritten:\n%s", lines[1])
	}
	if lines[2] != brokenLine {
		t.Fatalf("an unparseable line was not copied through:\n%s", lines[2])
	}

	var rec struct {
		Host    string                 `json:"host"`
		Managed *correlate.ManagedHost `json:"managedHost"`
		ILO     *map[string]any        `json:"ilo"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("annotated line does not decode: %v\n%s", err, lines[0])
	}
	if rec.ILO == nil {
		t.Fatal("annotation dropped the record's own contents")
	}
	if rec.Managed == nil {
		t.Fatalf("no managedHost on the iLO record: %s", lines[0])
	}
	if len(rec.Managed.Addresses) != 1 || rec.Managed.Addresses[0].Value != "192.0.2.20" {
		t.Fatalf("addresses = %+v, want the server the iLO named", rec.Managed.Addresses)
	}
	if rec.Managed.Confidence != correlate.Stated {
		t.Fatalf("confidence = %q", rec.Managed.Confidence)
	}
	// The record already says which device this is; the annotation must not restate it.
	if rec.Managed.BMC != "" || rec.Managed.BMCVendor != "" || len(rec.Managed.BMCMACs) != 0 {
		t.Fatalf("annotation restated the device's own identity: %+v", rec.Managed)
	}
}

// Correlation logic changes more often than collection does, so re-running the pass
// over a scan it already annotated has to replace the key rather than append a second
// one -- a duplicate key is valid JSON that different decoders resolve differently.
func TestCorrelateIsIdempotent(t *testing.T) {
	path := writeScan(t, "scan.jsonl", iloLine, plainLine)
	for range 3 {
		if _, _, err := runCorrelateStageTo(path, ""); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(b, []byte(managedKey)); n != 1 {
		t.Fatalf("managedHost appears %d times after three passes:\n%s", n, b)
	}
	if !json.Valid(bytes.SplitN(b, []byte("\n"), 2)[0]) {
		t.Fatalf("re-annotated line is not valid JSON:\n%s", b)
	}
}

func TestCorrelateToSeparateOutputLeavesInputAlone(t *testing.T) {
	path := writeScan(t, "scan.jsonl", iloLine)
	dst := filepath.Join(filepath.Dir(path), "annotated.jsonl")

	if _, out, err := runCorrelateStageTo(path, dst); err != nil || out != dst {
		t.Fatalf("out = %q, err = %v", out, err)
	}
	in, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(in) != iloLine {
		t.Fatalf("input was modified:\n%s", in)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(managedKey)) {
		t.Fatalf("copy was not annotated:\n%s", got)
	}
}

// A gzipped scan has to come back gzipped, and the temporary the rewrite goes through
// must not be left behind next to it.
func TestCorrelateRewritesGzipInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.jsonl.gz")
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	if _, err := gz.Write([]byte(iloLine + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	sum, out, err := runCorrelateStageTo(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if out != path || sum.Annotated != 1 {
		t.Fatalf("out = %q, summary = %+v", out, sum)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "scan.jsonl.gz" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %v, want the scan alone", names)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("rewritten file is not gzip: %v", err)
	}
	body, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(managedKey)) {
		t.Fatalf("gzipped scan was not annotated:\n%s", body)
	}
}
