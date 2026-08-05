package convert

import (
	"fmt"
	"slices"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

type Format string

const (
	FormatOOBScan Format = "oobscan"

	FormatRZSQL Format = "rzsql"

	FormatRZServices Format = "rzservices"
)

var Formats = []Format{FormatOOBScan, FormatRZSQL, FormatRZServices}

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

func FormatList() string {
	names := make([]string, len(Formats))
	for i, f := range Formats {
		names[i] = string(f)
	}
	return strings.Join(names, ", ")
}

type Options struct {
	Format Format
	Input  string

	Output string

	Redact bool

	Quality bool

	Progress func(processed int)

	Workers int
}

type sourceStats struct {
	Read      int
	Skipped   int
	Grouped   int
	Truncated bool
}

type Stats struct {
	Format    Format
	Read      int
	Skipped   int
	Grouped   int
	Truncated bool
	Written   int
	Redaction *RedactionStats

	Mapping []string
	Quality *QualityReport
}

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

func runNative(path string, emit func(*scanfile.Record, []byte) error, st *Stats) error {
	r, err := scanfile.Open(path)
	if err != nil {
		return err
	}
	defer r.Close()

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
