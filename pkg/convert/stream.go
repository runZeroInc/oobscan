package convert

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

func forEachLine(path string, fn func(line []byte) error) (truncated bool, err error) {
	f, ferr := os.Open(path)
	if ferr != nil {
		return false, ferr
	}
	defer f.Close()

	var src io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, gerr := gzip.NewReader(f)
		if gerr != nil {
			return false, gerr
		}
		defer gz.Close()
		src = gz
	}

	br := bufio.NewReaderSize(src, 1<<20)
	for {
		line, rerr := br.ReadBytes('\n')
		if t := bytes.TrimSpace(line); len(t) > 0 {
			if e := fn(t); e != nil {
				return false, e
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return false, nil
			}
			if errors.Is(rerr, io.ErrUnexpectedEOF) || strings.Contains(rerr.Error(), "unexpected EOF") {
				return true, nil
			}
			return false, rerr
		}
	}
}

func DetectFormat(path string) (Format, error) {
	format := FormatOOBScan
	errStop := errors.New("stop")
	_, err := forEachLine(path, func(line []byte) error {
		var probe map[string]json.RawMessage
		if json.Unmarshal(line, &probe) != nil {

			if _, ok := parseProbe(unescapeCopyText(string(line))); ok {
				format = FormatRZSQL
			} else {
				format = FormatOOBScan
			}
			return errStop
		}
		format = classifyProbe(probe)
		return errStop
	})
	if err != nil && !errors.Is(err, errStop) {
		return "", err
	}
	return format, nil
}

func parseProbe(line string) (map[string]json.RawMessage, bool) {
	var probe map[string]json.RawMessage
	if json.Unmarshal([]byte(line), &probe) != nil {
		return nil, false
	}
	return probe, true
}

func classifyProbe(probe map[string]json.RawMessage) Format {
	if _, ok := probe["service_asset_id"]; ok {
		return FormatRZServices
	}
	_, hasAsset := probe["asset"]
	_, hasServices := probe["services"]
	_, hasHost := probe["host"]
	if hasAsset && hasServices && !hasHost {
		return FormatRZSQL
	}
	return FormatOOBScan
}

type StreamStats struct {
	Read      int
	Skipped   int
	Truncated bool
}

func StreamRecords(format Format, path string, fn func(*scanfile.Record)) (StreamStats, error) {
	switch format {
	case FormatRZSQL:
		ss, err := streamRZSQL(path, func(h *rzHost) error { fn(h.record()); return nil })
		return StreamStats{Read: ss.Read, Skipped: ss.Skipped, Truncated: ss.Truncated}, err
	case FormatRZServices:
		ss, err := streamRZServices(path, func(h *rzHost) error { fn(h.record()); return nil })
		return StreamStats{Read: ss.Grouped, Skipped: ss.Skipped, Truncated: ss.Truncated}, err
	default:
		r, err := scanfile.Open(path)
		if err != nil {
			return StreamStats{}, err
		}
		defer r.Close()
		for r.Next() {
			rec := r.Record()
			rec.Migrate()
			fn(rec)
		}
		return StreamStats{Read: r.Total(), Skipped: r.Skipped()}, r.Err()
	}
}
