package ilo

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

var reCpqKey = regexp.MustCompile(`(?is)<KEY>\s*([^<\s][^<]*?)\s*</KEY>`)

type LicenseKey struct {
	Name string
	Type string
	Key  string

	Scheme string
	Port   int
}

func FetchLicenseKey(host string, timeout time.Duration) (*LicenseKey, bool) {
	client := httpx.Client(timeout)
	for _, scheme := range []string{"https", "http"} {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+netaddr.URLAuthority(host)+"/xmldata?item=CpqKey", nil)
		if err != nil {
			cancel()
			continue
		}
		res, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		res.Body.Close()
		cancel()
		if res.StatusCode != http.StatusOK {
			continue
		}
		m := reCpqKey.FindSubmatch(body)
		if m == nil {
			continue
		}
		key := strings.TrimSpace(string(m[1]))

		if key == "" || strings.EqualFold(key, "NONE") {
			continue
		}
		port := 443
		if scheme == "http" {
			port = 80
		}
		return &LicenseKey{
			Name:   tagText(body, "LNAME"),
			Type:   tagText(body, "LTYPE"),
			Key:    key,
			Scheme: scheme,
			Port:   port,
		}, true
	}
	return nil, false
}

func tagText(body []byte, tag string) string {
	re := regexp.MustCompile(`(?is)<` + tag + `>\s*([^<]*?)\s*</` + tag + `>`)
	if m := re.FindSubmatch(body); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}
