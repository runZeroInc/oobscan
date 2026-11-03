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

// forEachLine opens path (transparently decompressing a .gz), and calls fn for
// every non-empty line with no line-length cap: bufio.Reader grows to hold a
// whole line, so a runZero asset carrying dozens of services with large HTTP
// bodies / cert chains / screenshots is read intact rather than tripping a
// fixed scan-token cap (bufio.Scanner: token too long). It reports whether the
// input ended truncated (an interrupted export / cut-off gzip); fn's error
// aborts the walk. The []byte passed to fn is only valid for the call.
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

// This file exposes the format detection and record projection that `oobscan
// report` needs to read any of the three corpora, not just native oobscan. A
// runZero SQL or services export is projected onto the oobscan schema on the
// fly (identity, findings and RAKP derived), so the report sees the same
// resolved records a `convert` would have written -- which is what pulls the
// "unknown" vendor/class rate down to what bmc-stats produced.

// DetectFormat sniffs a corpus's format from its first record: a runZero SQL
// export is one `{"asset":...,"services":...}` object per line, a services
// export carries a `service_asset_id`, and everything else is native oobscan.
func DetectFormat(path string) (Format, error) {
	format := FormatOOBScan // empty input: treat as native (nothing to project)
	errStop := errors.New("stop")
	_, err := forEachLine(path, func(line []byte) error {
		var probe map[string]json.RawMessage
		if json.Unmarshal(line, &probe) != nil {
			// A COPY-escaped SQL export won't parse raw; that shape is SQL.
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

// StreamStats reports what StreamRecords read.
type StreamStats struct {
	Read      int  // records (native/rzsql) or assets (rzservices)
	Skipped   int  // malformed lines
	Truncated bool // input ended mid-record
}

// StreamRecords streams a corpus of the given format, invoking fn for each
// record already projected onto the oobscan schema. For rz formats fn receives
// a freshly projected, caller-owned record; for the native format fn receives
// the reader's record, which is reused on the next call -- copy anything
// retained past the callback.
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
