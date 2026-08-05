package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

type Input struct {
	Name string
	Path string

	PotCheck func(rec *scanfile.Record) []PotCrack

	PotLabel string

	Observe func(rec *scanfile.Record)
}

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

type LoadStats struct {
	Records int
	Skipped int
}

func LoadSource(in Input) (*Source, LoadStats, error) {
	return LoadSourceProgress(in, nil)
}

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
