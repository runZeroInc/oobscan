package report

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"strings"
)

//go:embed report.html
var reportHTML string

func Render(r Report) (string, error) {
	payload, err := json.Marshal(r)
	if err != nil {
		return "", err
	}

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
