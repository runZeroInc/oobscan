package httpx

import (
	"bytes"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Recording HTTP capture for default-login checks.
//
// A default-credential login decides success/failure from a device's HTTP
// responses, and embedded management web tiers are quirky enough that a heuristic
// can misfire (a false positive, or the wrong device behind an ambiguous
// fingerprint). To make those field problems debuggable, a Recorder transport
// captures the full request/response transcript of each login exchange so the
// raw data ends up in the scan output.

// recordBodyCeiling bounds how much of any single body is buffered in memory
// (the caller still receives the full-but-capped body). Login pages / JSON auth
// responses are small; this only guards against a pathological large body.
const recordBodyCeiling = 256 << 10

// recordBodyStored is how much of each body is kept in the transcript (matches
// the NDJSON raw-field cap elsewhere).
const recordBodyStored = 16 << 10

// Exchange is one captured HTTP request/response.
type Exchange struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	RequestHeaders  map[string]string `json:"requestHeaders,omitempty"`
	RequestBody     string            `json:"requestBody,omitempty"`
	Status          int               `json:"status,omitempty"`
	ResponseHeaders map[string]string `json:"responseHeaders,omitempty"`
	Body            string            `json:"body,omitempty"`
	BodyBytes       int               `json:"bodyBytes,omitempty"` // full body length before truncation
	Truncated       bool              `json:"truncated,omitempty"`
	DurationMs      int64             `json:"durationMs,omitempty"`
	Error           string            `json:"error,omitempty"`
}

// Transcript is the full capture for one default-login check against a target,
// stashed on the target's evidence and emitted verbatim in the scan record.
type Transcript struct {
	Vendor    string     `json:"vendor,omitempty"`
	Port      int        `json:"port,omitempty"`
	Scheme    string     `json:"scheme,omitempty"`
	Mechanism string     `json:"mechanism,omitempty"` // e.g. http.form.moxa, http.basic
	Result    string     `json:"result"`              // success | no-match | error
	Username  string     `json:"username,omitempty"`  // credential that authenticated, if any
	Exchanges []Exchange `json:"exchanges,omitempty"`
}

// Recorder is an http.RoundTripper that records every request/response it sees
// (bounded) and then transparently passes the response through to the caller.
// It is safe for concurrent use.
type Recorder struct {
	Base         http.RoundTripper // nil => http.DefaultTransport
	MaxExchanges int               // 0 => 16
	mu           sync.Mutex
	exchanges    []Exchange
}

// NewRecordingClient wraps an existing client's transport with a Recorder,
// returning the client (now recording) and the Recorder to read afterward.
func NewRecordingClient(c *http.Client) (*http.Client, *Recorder) {
	rec := &Recorder{Base: c.Transport}
	c.Transport = rec
	return c, rec
}

// Exchanges returns a copy of the captured exchanges.
func (r *Recorder) Exchanges() []Exchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Exchange(nil), r.exchanges...)
}

func (r *Recorder) maxExch() int {
	if r.MaxExchanges > 0 {
		return r.MaxExchanges
	}
	return 16
}

func (r *Recorder) add(ex Exchange) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.exchanges) >= r.maxExch() {
		return
	}
	r.exchanges = append(r.exchanges, ex)
}

// RoundTrip records the request, delegates to the base transport, records the
// response, and restores a re-readable body so the caller is unaffected.
func (r *Recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	ex := Exchange{Method: req.Method, URL: req.URL.String(), RequestHeaders: flattenHeaders(req.Header)}
	if req.Body != nil {
		ex.RequestBody = captureRequestBody(req)
	}
	base := r.Base
	if base == nil {
		base = http.DefaultTransport
	}
	start := time.Now()
	resp, err := base.RoundTrip(req)
	ex.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		ex.Error = err.Error()
		r.add(ex)
		return resp, err
	}
	ex.Status = resp.StatusCode
	ex.ResponseHeaders = flattenHeaders(resp.Header)
	full, _ := io.ReadAll(io.LimitReader(resp.Body, recordBodyCeiling))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(full)) // restore for the caller
	ex.BodyBytes = len(full)
	if len(full) > recordBodyStored {
		ex.Body = string(full[:recordBodyStored])
		ex.Truncated = true
	} else {
		ex.Body = string(full)
	}
	r.add(ex)
	return resp, nil
}

// captureRequestBody reads the request body for the transcript and restores it
// so the base transport still sends it. Bodies here are small login payloads.
func captureRequestBody(req *http.Request) string {
	if req.GetBody != nil {
		if rc, err := req.GetBody(); err == nil {
			b, _ := io.ReadAll(io.LimitReader(rc, recordBodyStored))
			rc.Close()
			return string(b)
		}
	}
	b, _ := io.ReadAll(req.Body)
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(b))
	if len(b) > recordBodyStored {
		return string(b[:recordBodyStored])
	}
	return string(b)
}

// flattenHeaders renders a header map as sorted "key: comma-joined-values",
// keeping the full auth material (the default credential under test) so a
// reviewer can see exactly what was sent.
func flattenHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out[k] = strings.Join(h[k], ", ")
	}
	return out
}
