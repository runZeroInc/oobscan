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

const recordBodyCeiling = 256 << 10

const recordBodyStored = 16 << 10

type Exchange struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	RequestHeaders  map[string]string `json:"requestHeaders,omitempty"`
	RequestBody     string            `json:"requestBody,omitempty"`
	Status          int               `json:"status,omitempty"`
	ResponseHeaders map[string]string `json:"responseHeaders,omitempty"`
	Body            string            `json:"body,omitempty"`
	BodyBytes       int               `json:"bodyBytes,omitempty"`
	Truncated       bool              `json:"truncated,omitempty"`
	DurationMs      int64             `json:"durationMs,omitempty"`
	Error           string            `json:"error,omitempty"`
}

type Transcript struct {
	Vendor    string     `json:"vendor,omitempty"`
	Port      int        `json:"port,omitempty"`
	Scheme    string     `json:"scheme,omitempty"`
	Mechanism string     `json:"mechanism,omitempty"`
	Result    string     `json:"result"`
	Username  string     `json:"username,omitempty"`
	Exchanges []Exchange `json:"exchanges,omitempty"`
}

type Recorder struct {
	Base         http.RoundTripper
	MaxExchanges int
	mu           sync.Mutex
	exchanges    []Exchange
}

func NewRecordingClient(c *http.Client) (*http.Client, *Recorder) {
	rec := &Recorder{Base: c.Transport}
	c.Transport = rec
	return c, rec
}

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
	resp.Body = io.NopCloser(bytes.NewReader(full))
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
