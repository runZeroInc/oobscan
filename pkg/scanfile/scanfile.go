// Package scanfile is the read side of the NDJSON schema: a streaming reader and
// writer for scan output files, plus the migration that brings a record written by
// an older build up to the current rules. pkg/output owns the write side; both
// halves share the schema types so the format has one definition.
//
// Record keeps the three post-auth captures (ipmiPostAuth, redfishPostAuth,
// webLogin) as raw JSON rather than decoding them into their probe-side structs.
// Those structs are built to be produced by a live probe, not to survive a
// decode/encode round trip, so passing the bytes through is what guarantees a
// read-modify-write cycle cannot silently drop a field.
package scanfile

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ilo"
	"github.com/runZeroInc/oobscan/pkg/output"
)

// initialReadBuf is the starting size of the line reader's buffer. It is only a
// hint: bufio.Reader.ReadBytes grows to hold a whole line however long, so a
// record with a large post-auth capture or preserved runZero service_data is
// read intact instead of tripping a fixed scan-token cap.
const initialReadBuf = 1 << 20

// Record is one line of an oobscan NDJSON file. The field order, JSON tags and
// types mirror output.Result exactly -- re-encoding an unmodified Record
// reproduces the same key order a live scan emits -- except that the post-auth
// captures are held as raw JSON (see the package comment).
type Record struct {
	Host            string                 `json:"host"`
	TS              int64                  `json:"timestamp,omitempty"`
	Ports           engine.OpenPorts       `json:"ports,omitempty"`
	Identity        *engine.Identity       `json:"identity,omitempty"`
	Final           *engine.Final          `json:"finalIdentity,omitempty"`
	Findings        []engine.Finding       `json:"findings,omitempty"`
	AttemptedChecks string                 `json:"attemptedChecks,omitempty"`
	Services        []output.ServiceRecord `json:"services,omitempty"`
	Attributes      map[string]string      `json:"attributes,omitempty"`
	RAKP            []output.RAKPRecord    `json:"rakp,omitempty"`
	// ILO is the pre-auth /xmldata RIMP document. It is decoded rather than held raw
	// because its NIC list is the only channel in a scan that states a managed
	// server's address, and a reader that drops it silently loses that: this field
	// was missing while the doc comment above claimed an exact mirror of output.Result.
	ILO      *ilo.XMLData    `json:"ilo,omitempty"`
	IPMIPost json.RawMessage `json:"ipmiPostAuth,omitempty"`
	RFPost   json.RawMessage `json:"redfishPostAuth,omitempty"`
	WebLogin json.RawMessage `json:"webLogin,omitempty"`
	// Evidence is the probe-result bag (see output.serializedEvidenceKeys), kept as
	// raw JSON like the other nested blobs so a reader never has to depend on the
	// probe structs to round-trip a record. Its position mirrors output.Result so an
	// unmodified record re-encodes with the same key order a live scan emits.
	Evidence map[string]json.RawMessage `json:"evidence,omitempty"`
	Error    string                     `json:"error,omitempty"`
	// Managed is what this device disclosed about the server it manages, filled in by
	// the post-scan correlation pass (pkg/correlate) rather than by a live probe. It is
	// held raw both to keep the nested-blob rule above and because pkg/correlate reads
	// this package: a typed field here would be an import cycle. It sits last because
	// nothing on the write side produces it, so a record a scan just emitted and a
	// record the correlation pass annotated differ only by a key appended at the end.
	Managed json.RawMessage `json:"managedHost,omitempty"`
}

// UnmarshalJSON decodes a record, accepting the pre-canonicalization spellings
// of the top-level keys that were renamed after data had already shipped.
// Everything below the top level migrates itself: engine.Finding.UnmarshalJSON
// folds legacy check ids, field keys, `ts` and the array form of `cves`.
func (r *Record) UnmarshalJSON(b []byte) error {
	// The embedded Record must not re-enter this method, hence the alias.
	type plain Record
	var raw struct {
		plain
		LegacyIPMIPost json.RawMessage `json:"ipmi_postauth,omitempty"`
		LegacyRFPost   json.RawMessage `json:"redfish_postauth,omitempty"`
		LegacyWebLogin json.RawMessage `json:"web_login,omitempty"`
		LegacyFinal    *engine.Final   `json:"final_identity,omitempty"`
		LegacyTS       int64           `json:"ts,omitempty"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*r = Record(raw.plain)
	if !rawPresent(r.IPMIPost) {
		r.IPMIPost = raw.LegacyIPMIPost
	}
	if !rawPresent(r.RFPost) {
		r.RFPost = raw.LegacyRFPost
	}
	if !rawPresent(r.WebLogin) {
		r.WebLogin = raw.LegacyWebLogin
	}
	if r.Final == nil {
		r.Final = raw.LegacyFinal
	}
	if r.TS == 0 {
		r.TS = raw.LegacyTS
	}
	return nil
}

// rawPresent reports whether a raw JSON field holds an actual value.
func rawPresent(m json.RawMessage) bool {
	s := strings.TrimSpace(string(m))
	return s != "" && s != "null"
}

// Migrate brings a decoded record up to the current emission rules, in place. It is
// idempotent, so re-converting an already-current file changes nothing beyond
// re-serialization. It folds "none"-risk findings into attemptedChecks, re-sorts the
// remaining findings most-severe-first under the current per-field caps, and drops
// findings with no check id. Check ids, finding field keys and identity/flag
// attribute keys are already canonicalized by the engine types on decode and encode.
func (r *Record) Migrate() {
	attempted := splitCSV(r.AttemptedChecks)
	seen := make(map[string]struct{}, len(attempted))
	for _, c := range attempted {
		seen[c] = struct{}{}
	}

	kept := r.Findings[:0]
	for _, f := range r.Findings {
		if f.Check == "" {
			continue
		}
		risk := f.Risk
		if risk == "" {
			risk = "none"
		}
		if engine.RiskRank(risk) < engine.RiskRank("info") {
			if _, dup := seen[f.Check]; !dup {
				seen[f.Check] = struct{}{}
				attempted = append(attempted, f.Check)
			}
			continue
		}
		f.Risk = risk
		f.Fields = output.CapFindingFields(f.Fields)
		kept = append(kept, f)
	}
	r.Findings = kept
	if len(r.Findings) == 0 {
		r.Findings = nil
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return engine.RiskRank(r.Findings[i].Risk) > engine.RiskRank(r.Findings[j].Risk)
	})
	r.AttemptedChecks = engine.SortedCSV(attempted)
}

func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Reader streams records out of an oobscan NDJSON file. A line that will not
// decode is counted in Skipped and stepped over rather than aborting the run:
// scan outputs are appended live and a truncated tail is normal.
type Reader struct {
	closers []io.Closer
	br      *bufio.Reader
	rec     Record
	raw     []byte
	err     error
	skipped int
	total   int
}

// Open opens path for reading, transparently decompressing a .gz file.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r := &Reader{closers: []io.Closer{f}}
	var src io.Reader = f
	if isGzipPath(path) {
		gz, gerr := gzip.NewReader(f)
		if gerr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("%s: gzip: %w", path, gerr)
		}
		r.closers = append([]io.Closer{gz}, r.closers...)
		src = gz
	}
	r.br = bufio.NewReaderSize(src, initialReadBuf)
	return r, nil
}

// Next decodes the next record, returning false at end of input or on a hard
// read error (check Err). Malformed lines are skipped, not returned. A truncated
// final line (no trailing newline, or a cut-off gzip stream) is not an error:
// the records read before the cut are still good.
func (r *Reader) Next() bool {
	for {
		line, rerr := r.br.ReadBytes('\n')
		fatal := rerr != nil && rerr != io.EOF && !isTruncation(rerr)
		if fatal {
			r.err = rerr
		}
		if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
			var rec Record
			if err := json.Unmarshal(trimmed, &rec); err != nil {
				r.skipped++
			} else {
				r.total++
				r.rec = rec
				// ReadBytes may reuse its buffer on the next call, so hand callers
				// a private copy of the raw line (Raw() is held past Next()).
				r.raw = append([]byte(nil), trimmed...)
				return true
			}
		}
		if rerr != nil {
			return false
		}
	}
}

// Record returns the record decoded by the last successful Next.
func (r *Reader) Record() *Record { return &r.rec }

// Raw returns the undecoded JSON line behind the last successful Next.
func (r *Reader) Raw() []byte { return r.raw }

// Err returns the first hard read error, if any. A truncated final line or
// gzip stream is not an error: the records already read are still good.
func (r *Reader) Err() error { return r.err }

// Total returns the number of records decoded so far.
func (r *Reader) Total() int { return r.total }

// Skipped returns the number of malformed lines stepped over so far.
func (r *Reader) Skipped() int { return r.skipped }

// Close releases the underlying file (and gzip reader).
func (r *Reader) Close() error {
	var err error
	for _, c := range r.closers {
		if cerr := c.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

// LineReader streams the raw lines of a scan file without decoding them, gzip-aware
// like Open. It exists for rewrites that must preserve the file: Reader skips a line
// that will not decode, which is the right behaviour for a consumer and the wrong one
// for a producer -- a rewrite built on it would silently drop the truncated tail of a
// scan that was still in flight, or a line an older build wrote in a shape this one
// cannot parse.
type LineReader struct {
	closers []io.Closer
	br      *bufio.Reader
	line    []byte
	err     error
}

// OpenLines opens path for raw line reading, transparently decompressing a .gz file.
func OpenLines(path string) (*LineReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r := &LineReader{closers: []io.Closer{f}}
	var src io.Reader = f
	if isGzipPath(path) {
		gz, gerr := gzip.NewReader(f)
		if gerr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("%s: gzip: %w", path, gerr)
		}
		r.closers = append([]io.Closer{gz}, r.closers...)
		src = gz
	}
	r.br = bufio.NewReaderSize(src, initialReadBuf)
	return r, nil
}

// Next reads the next line, returning false at end of input. A cut-off input is not
// an error, matching Reader: the bytes read before the cut are still good.
func (r *LineReader) Next() bool {
	line, rerr := r.br.ReadBytes('\n')
	if rerr != nil && rerr != io.EOF && !isTruncation(rerr) {
		r.err = rerr
	}
	r.line = line
	return len(line) > 0
}

// Line returns the line read by the last Next, exactly as it appeared on disk,
// including its trailing newline when it had one. The slice is only valid until the
// next call to Next.
func (r *LineReader) Line() []byte { return r.line }

// Err returns the first hard read error, if any.
func (r *LineReader) Err() error { return r.err }

// Close releases the underlying file (and gzip reader).
func (r *LineReader) Close() error {
	var err error
	for _, c := range r.closers {
		if cerr := c.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

// isTruncation reports whether a scan error is just a cut-off input (an
// interrupted export, a partial download, a scan still in flight).
func isTruncation(err error) bool {
	return errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "unexpected EOF")
}

func isGzipPath(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".gz")
}

// Writer streams records into an oobscan NDJSON file, gzipping when the path
// ends in .gz.
type Writer struct {
	f     *os.File
	gz    *gzip.Writer
	bw    *bufio.Writer
	enc   *json.Encoder
	count int
}

// Create creates (or truncates) path and its parent directory. A path of "-"
// writes plain NDJSON to stdout.
func Create(path string) (*Writer, error) {
	w := &Writer{}
	var sink io.Writer
	if path == "-" {
		sink = os.Stdout
	} else {
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, err
			}
		}
		f, err := os.Create(path)
		if err != nil {
			return nil, err
		}
		w.f = f
		sink = f
		if isGzipPath(path) {
			w.gz = gzip.NewWriter(f)
			sink = w.gz
		}
	}
	w.bw = bufio.NewWriterSize(sink, 1<<20)
	w.enc = json.NewEncoder(w.bw)
	// Scan output is machine-read, not embedded in HTML: keep <, > and & literal
	// so a captured banner reads the same on disk as it did on the wire.
	w.enc.SetEscapeHTML(false)
	return w, nil
}

// Write appends one record. json.Encoder emits a trailing newline per value,
// which is exactly the NDJSON framing.
func (w *Writer) Write(rec *Record) error {
	w.count++
	return w.enc.Encode(rec)
}

// WriteLine appends a pre-encoded NDJSON line (including its trailing newline).
// It exists for the parallel convert pipeline, where records are marshalled on
// worker goroutines (with MarshalRecord) and only the byte write is serialized
// through the single writer. The bytes must be produced by MarshalRecord so the
// escaping matches Write's.
func (w *Writer) WriteLine(line []byte) error {
	w.count++
	_, err := w.bw.Write(line)
	return err
}

// MarshalRecord encodes one record to a single NDJSON line (with the trailing
// newline), using the same HTML-literal escaping as Write. It is safe to call
// concurrently; each call uses its own encoder.
func MarshalRecord(rec *Record) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Count returns the number of records written.
func (w *Writer) Count() int { return w.count }

// Close flushes and closes the whole pipeline.
func (w *Writer) Close() error {
	if err := w.bw.Flush(); err != nil {
		return err
	}
	if w.gz != nil {
		if err := w.gz.Close(); err != nil {
			return err
		}
	}
	if w.f != nil {
		return w.f.Close()
	}
	return nil
}
