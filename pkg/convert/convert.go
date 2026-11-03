// Package convert turns scan-adjacent corpora into the native NDJSON format and
// re-serializes native files under the current rules, so foreign and scanned data
// can be compared in one schema. The conversion is lossless-first: source attributes
// are carried through verbatim, and only then is the native view (identity,
// findings, RAKP rows) derived on top.
//
// Three transforms hang off the same pipeline: migration (always on, see
// scanfile.Record.Migrate), redaction, and the quality audit.
package convert

import (
	"fmt"
	"slices"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

// Format names an input format.
type Format string

const (
	// FormatOOBScan is the native oobscan NDJSON output. Converting it to itself
	// migrates and re-serializes it, which is how a redaction or a re-audit of an
	// existing scan file is done.
	FormatOOBScan Format = "oobscan"
	// FormatRZSQL is the runZero SQL export: one asset with its services per line.
	FormatRZSQL Format = "rzsql"
	// FormatRZServices is the runZero services export: one service per line with
	// its asset denormalized alongside it.
	FormatRZServices Format = "rzservices"
)

// Formats lists the supported input formats in help order.
var Formats = []Format{FormatOOBScan, FormatRZSQL, FormatRZServices}

// ParseFormat resolves a --format value.
func ParseFormat(v string) (Format, error) {
	f := Format(strings.ToLower(strings.TrimSpace(v)))
	if f == "" {
		return FormatOOBScan, nil
	}
	if slices.Contains(Formats, f) {
		return f, nil
	}
	return "", fmt.Errorf("unknown format %q (want one of: %s)", v, FormatList())
}

// FormatList renders the supported formats for help and error text.
func FormatList() string {
	names := make([]string, len(Formats))
	for i, f := range Formats {
		names[i] = string(f)
	}
	return strings.Join(names, ", ")
}

// Options configures one conversion.
type Options struct {
	Format Format
	Input  string
	// Output is the destination NDJSON path; "-" writes to stdout and "" writes
	// nothing (an audit-only run). Both the input and the output are gzipped
	// transparently when the path ends in .gz.
	Output string
	// Redact renumbers every address and strips the values that identify a
	// specific asset. See redact.go for exactly what is rewritten.
	Redact bool
	// Quality runs the data-hygiene / coverage / proof audit over the records as
	// they were read, before any redaction, and returns it in Stats.
	Quality bool
	// Progress, when set, is called with the running count of records processed
	// so far. It fires per record, so the callback is responsible for its own
	// throttling; a large rzsql import can call it millions of times. The
	// streaming formats (oobscan, rzsql) report progress live; rzservices groups
	// its whole input in memory first, so it reports only during the emit phase.
	Progress func(processed int)
	// Workers sets the size of the parallel transform pool. 0 uses the CPU count.
	// The parallel path runs the per-record work (migrate, redact, marshal) on
	// several goroutines and writes results back in input order; it engages only
	// when there is real per-record CPU work to spread (redaction, or a runZero
	// projection) and the audit is off, since the audit must stay serial. A plain
	// oobscan->oobscan re-serialize stays single-threaded (it is I/O bound).
	Workers int
}

// sourceStats counts what came out of the input.
type sourceStats struct {
	Read      int  // records (or, for rzservices, service rows) decoded
	Skipped   int  // lines that would not parse
	Grouped   int  // assets after grouping (rzservices only)
	Truncated bool // input ended mid-record
}

// Stats reports what a conversion did.
type Stats struct {
	Format    Format
	Read      int
	Skipped   int
	Grouped   int
	Truncated bool
	Written   int
	Redaction *RedactionStats
	// Mapping holds the "original -> replacement" address lines from a redacting
	// run. It reverses the redaction, so it is handed back to the caller rather
	// than written anywhere by default.
	Mapping []string
	Quality *QualityReport
}

// Run executes a conversion end to end.
func Run(opts Options) (*Stats, error) {
	if opts.Input == "" {
		return nil, fmt.Errorf("no input file")
	}
	format := opts.Format
	if format == "" {
		format = FormatOOBScan
	}

	st := &Stats{Format: format}

	var w *scanfile.Writer
	if opts.Output != "" {
		var err error
		if w, err = scanfile.Create(opts.Output); err != nil {
			return nil, err
		}
		defer func() {
			if w != nil {
				_ = w.Close()
			}
		}()
	}

	var (
		audit    *qualityAuditor
		redactor *Redactor
	)
	if opts.Quality {
		audit = newQualityAuditor()
	}
	if opts.Redact {
		redactor = NewRedactor()
	}

	// One record at a time: migrate, audit what the source actually said, then
	// redact, then write. The audit runs before redaction on purpose -- redaction
	// replaces the very banner and proof values the hygiene checks inspect, so
	// auditing afterwards would report a clean file no matter what went in.
	// raw is the undecoded input line when there is one (a native input) and nil
	// for a synthesized record; the audit needs it to see bytes that the typed
	// decode sanitizes away.
	processed := 0
	emit := func(rec *scanfile.Record, raw []byte) error {
		rec.Migrate()
		if audit != nil {
			audit.observe(rec, raw)
		}
		if redactor != nil {
			redactor.Record(rec)
		}
		processed++
		if opts.Progress != nil {
			opts.Progress(processed)
		}
		if w == nil {
			return nil
		}
		if err := w.Write(rec); err != nil {
			return err
		}
		st.Written++
		return nil
	}

	// The parallel path spreads the per-record CPU work (redaction, projection)
	// across a worker pool. It cannot run the stateful audit, and it only pays
	// off when there is real per-record work, so it engages for a redaction or a
	// runZero projection with the audit off; everything else stays serial.
	parallel := audit == nil && (opts.Redact || format != FormatOOBScan) && resolveWorkers(opts.Workers) > 1

	var err error
	switch {
	case parallel:
		var ss sourceStats
		ss, st.Written, err = runParallel(producerFor(format, opts.Input), w, redactor, opts.Workers, opts.Progress)
		st.apply(ss)
	case format == FormatOOBScan:
		err = runNative(opts.Input, emit, st)
	case format == FormatRZSQL:
		var ss sourceStats
		ss, err = streamRZSQL(opts.Input, func(h *rzHost) error { return emit(h.record(), nil) })
		st.apply(ss)
	case format == FormatRZServices:
		var ss sourceStats
		ss, err = streamRZServices(opts.Input, func(h *rzHost) error { return emit(h.record(), nil) })
		st.apply(ss)
	default:
		err = fmt.Errorf("unknown format %q (want one of: %s)", format, FormatList())
	}
	if err != nil {
		return st, err
	}

	if w != nil {
		if cerr := w.Close(); cerr != nil {
			return st, cerr
		}
		w = nil
	}
	if audit != nil {
		st.Quality = audit.report()
	}
	if redactor != nil {
		st.Redaction = redactor.Stats()
		st.Mapping = redactor.Mapping()
	}
	return st, nil
}

// runNative streams an existing oobscan NDJSON file back through the pipeline.
func runNative(path string, emit func(*scanfile.Record, []byte) error, st *Stats) error {
	r, err := scanfile.Open(path)
	if err != nil {
		return err
	}
	defer r.Close()
	// Recorded via defer so a mid-stream failure still reports how far it got.
	defer func() {
		st.Read = r.Total()
		st.Skipped = r.Skipped()
	}()
	for r.Next() {
		if err := emit(r.Record(), r.Raw()); err != nil {
			return err
		}
	}
	return r.Err()
}

func (s *Stats) apply(ss sourceStats) {
	s.Read = ss.Read
	s.Skipped = ss.Skipped
	s.Grouped = ss.Grouped
	s.Truncated = ss.Truncated
}
