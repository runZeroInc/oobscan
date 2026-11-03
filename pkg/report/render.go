package report

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// reportHTML is the self-contained interactive shell. The token __REPORT_DATA__
// is replaced at render time with the gzip+base64-encoded JSON payload; the page
// decompresses it at load via DecompressionStream. Compression matters because
// the per-host explorer detail is large but highly repetitive (~10x), so a
// corpus that would be a 250 MB raw payload ships as a ~25 MB bundle. All CSS
// and JS are inlined so the bundle opens offline with no external requests.
//
//go:embed report.html
var reportHTML string

// Render returns the complete HTML document for a report payload.
func Render(r Report) (string, error) {
	payload, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	// json.Marshal escapes <, > and & by default; the base64 encoding below has
	// no HTML metacharacters anyway, so it is safe inside a <script> element.
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if _, err := zw.Write(payload); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	return strings.Replace(reportHTML, "__REPORT_DATA__", encoded, 1), nil
}
