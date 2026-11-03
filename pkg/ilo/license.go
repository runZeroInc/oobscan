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

// The /xmldata?item=CpqKey endpoint is served unauthenticated on every iLO and
// returns the licensed feature set as an XML document:
//
//	<PROLIANT><CpqKey><LNAME>iLO Advanced</LNAME><LTYPE>..</LTYPE>
//	<KEY>XXXXX-XXXXX-XXXXX-XXXXX-XXXXX</KEY></CpqKey></PROLIANT>
//
// The <KEY> is the iLO activation/license key: a per-purchase secret an attacker
// can reuse to license their own iLO units, and a fingerprint of the licensed
// feature tier. This asserts only on a KEY value actually returned, not on the
// product fingerprint.

var reCpqKey = regexp.MustCompile(`(?is)<KEY>\s*([^<\s][^<]*?)\s*</KEY>`)

// LicenseKey is the disclosed iLO license/activation key and its label.
type LicenseKey struct {
	Name string // <LNAME>, e.g. "iLO Advanced"
	Type string // <LTYPE>
	Key  string // <KEY> activation key
	// Scheme and Port record where the key was actually read. The fetch tries
	// https then http on each scheme's default port, so a caller that stamps the
	// finding with the host's identified web port can attribute a disclosure to a
	// port it was never read from.
	Scheme string
	Port   int
}

// FetchLicenseKey retrieves /xmldata?item=CpqKey and returns the disclosed
// license key when the endpoint served one pre-auth. ok is false when the
// endpoint is absent/denied or no <KEY> value is present. Read-only (GET),
// HTTPS first then HTTP, matching Fetch.
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
		// An unlicensed iLO returns an empty/placeholder <KEY></KEY>; only a real
		// activation key (dashed 25-char HPE format) is a disclosure.
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

// tagText pulls the trimmed text of a simple <tag>..</tag> pair, or "".
func tagText(body []byte, tag string) string {
	re := regexp.MustCompile(`(?is)<` + tag + `>\s*([^<]*?)\s*</` + tag + `>`)
	if m := re.FindSubmatch(body); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}
