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

const initialReadBuf = 1 << 20

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

	ILO      *ilo.XMLData    `json:"ilo,omitempty"`
	IPMIPost json.RawMessage `json:"ipmiPostAuth,omitempty"`
	RFPost   json.RawMessage `json:"redfishPostAuth,omitempty"`
	WebLogin json.RawMessage `json:"webLogin,omitempty"`

	Evidence map[string]json.RawMessage `json:"evidence,omitempty"`
	Error    string                     `json:"error,omitempty"`
}

func (r *Record) UnmarshalJSON(b []byte) error {

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

func rawPresent(m json.RawMessage) bool {
	s := strings.TrimSpace(string(m))
	return s != "" && s != "null"
}

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

type Reader struct {
	closers []io.Closer
	br      *bufio.Reader
	rec     Record
	raw     []byte
	err     error
	skipped int
	total   int
}

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

				r.raw = append([]byte(nil), trimmed...)
				return true
			}
		}
		if rerr != nil {
			return false
		}
	}
}

func (r *Reader) Record() *Record { return &r.rec }

func (r *Reader) Raw() []byte { return r.raw }

func (r *Reader) Err() error { return r.err }

func (r *Reader) Total() int { return r.total }

func (r *Reader) Skipped() int { return r.skipped }

func (r *Reader) Close() error {
	var err error
	for _, c := range r.closers {
		if cerr := c.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

func isTruncation(err error) bool {
	return errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "unexpected EOF")
}

func isGzipPath(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".gz")
}

type Writer struct {
	f     *os.File
	gz    *gzip.Writer
	bw    *bufio.Writer
	enc   *json.Encoder
	count int
}

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

	w.enc.SetEscapeHTML(false)
	return w, nil
}

func (w *Writer) Write(rec *Record) error {
	w.count++
	return w.enc.Encode(rec)
}

func (w *Writer) WriteLine(line []byte) error {
	w.count++
	_, err := w.bw.Write(line)
	return err
}

func MarshalRecord(rec *Record) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (w *Writer) Count() int { return w.count }

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
