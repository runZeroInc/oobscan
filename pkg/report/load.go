package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

// Input names one source file for the report.
type Input struct {
	Name string // display name
	Path string // oobscan NDJSON file (optionally .gz)
	// PotCheck, when set, returns the cracks the oobscan potfile already holds
	// for a record's captured RAKP hashes (nil/empty = none), one entry per
	// cracked hash so the count is len(). It yields the plaintexts and the
	// account they belong to, not just a tally: the password-pattern analysis has
	// to see offline recoveries (they are the bulk of what a mature potfile
	// knows), and the account name decides whether the recovery is a usable
	// credential. Supplied by the caller so this package stays free of the
	// hashcrack/potfile dependency.
	PotCheck func(rec *scanfile.Record) []PotCrack
	// PotLabel names the crack run behind the potfile (e.g. "one-day session").
	// The legacy potfile carries no timestamps, so this is an asserted label,
	// not an inferred one; empty means the generic "potfile" wording is used.
	PotLabel string
	// Observe, when set, is called with every record as it is read, alongside
	// the aggregate. It lets the CLI accumulate the side-artifact tree (RAKP
	// hashes, CSVs) in the same streaming pass without a second read of the file.
	Observe func(rec *scanfile.Record)
}

// ParseInput parses a "Name=path" argument. A bare path (no '=') uses the
// file's base name as the display name, so `oobscan report scan.jsonl` works
// without ceremony.
func ParseInput(arg string) (Input, error) {
	name, path, ok := strings.Cut(arg, "=")
	if !ok {
		return Input{Name: baseName(arg), Path: arg}, nil
	}
	name = strings.TrimSpace(name)
	path = strings.TrimSpace(path)
	if name == "" || path == "" {
		return Input{}, fmt.Errorf("invalid source %q: want Name=path", arg)
	}
	return Input{Name: name, Path: path}, nil
}

// baseName strips the directory and a trailing .jsonl/.gz from a path for use
// as a default display name.
func baseName(path string) string {
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
		path = path[i+1:]
	}
	for _, suffix := range []string{".gz", ".jsonl", ".ndjson", ".json"} {
		path = strings.TrimSuffix(path, suffix)
	}
	if path == "" {
		return "source"
	}
	return path
}

// LoadStats reports what LoadSource read.
type LoadStats struct {
	Records int
	Skipped int
}

// LoadSource streams one input file into a finalized Source.
func LoadSource(in Input) (*Source, LoadStats, error) {
	return LoadSourceProgress(in, nil)
}

// LoadSourceProgress is LoadSource with a progress callback invoked with the
// running record count. It reads native oobscan NDJSON only: a runZero export
// must be run through `oobscan convert` first (report does not project it).
func LoadSourceProgress(in Input, progress func(records int)) (*Source, LoadStats, error) {
	r, err := scanfile.Open(in.Path)
	if err != nil {
		return nil, LoadStats{}, err
	}
	defer r.Close()

	s := NewSource(in.Name)
	s.potCheck = in.PotCheck
	s.potLabel = in.PotLabel

	n := 0
	for r.Next() {
		// Guard against the common mistake of pointing report at a raw runZero
		// export: report reads oobscan output, so a `{asset,services}` line would
		// parse into an empty record and silently poison every total. Reject it
		// with the fix rather than producing a garbage report.
		if n == 0 && looksLikeRunZeroExport(r.Raw()) {
			return nil, LoadStats{}, fmt.Errorf(
				"input looks like a runZero export, not oobscan output; convert it first:\n  oobscan convert --format rzsql %s out.jsonl",
				in.Path)
		}
		rec := r.Record()
		normalizeServiceRecord(rec)
		s.Add(rec)
		if in.Observe != nil {
			in.Observe(rec)
		}
		n++
		if progress != nil {
			progress(n)
		}
	}
	if err := r.Err(); err != nil {
		return nil, LoadStats{}, fmt.Errorf("read %s: %w", in.Path, err)
	}
	s.Finalize()
	return s, LoadStats{Records: r.Total(), Skipped: r.Skipped()}, nil
}

// looksLikeRunZeroExport reports whether a line is a runZero SQL export
// (`{"asset":...,"services":...}` with no `host`) or services export
// (`service_asset_id`) rather than an oobscan result.
func looksLikeRunZeroExport(raw []byte) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	if _, ok := m["service_asset_id"]; ok {
		return true
	}
	_, host := m["host"]
	_, asset := m["asset"]
	_, services := m["services"]
	return asset && services && !host
}
