package check

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// errNotThisDevice is returned by an adapter's login when the pre-flight shows
// the vendor's login flow is not actually present on this port (e.g. the login
// page/nonce is missing). The driver stops the attempt loop rather than trying
// further credentials against a device that is not what identify claimed.
var errNotThisDevice = errors.New("weblogin: vendor login flow not present")

// webLoginAdapter drives a vendor-specific web login that the generic HTTP Basic
// path cannot -- a form POST with an obfuscated credential (Moxa), a CGI login
// that mints a URL/cookie session (Opengear), or a JSON-RPC auth call (Raritan).
//
// Implementations limit each attempt to a pre-flight GET (to obtain a
// login-page nonce/CSRF token) plus one credentialed login request per attempt,
// and best-effort session teardown. They must not change device configuration;
// authentication can still create session state, logs, or failure counters.
type webLoginAdapter interface {
	// mechanism is the short label recorded on the finding's loginVia field,
	// e.g. "http.form.moxa" / "http.jsonrpc.raritan".
	mechanism() string

	// login attempts exactly one credential against base ("scheme://host:port").
	// It returns ok=true only on positive proof of an authenticated session
	// (never on an ambiguous response). proof is a short human-readable marker.
	// A transport error is returned as err so the caller can stop early.
	login(ctx context.Context, client *http.Client, base, user, pass string) (ok bool, proof string, err error)
}

// webLoginAdapters maps a vendor slug to its bespoke web-login adapter. A vendor
// with no entry uses the self-scoping HTTP Basic path in web_basic_creds.go.
//
// Adapters are registered from their own files (web_login_<vendor>.go) via
// registerWebLoginAdapter in an init(), so each vendor's protocol lives beside
// its emulator test.
var webLoginAdapters = map[string]webLoginAdapter{}

// registerWebLoginAdapter records an adapter for a vendor slug. Duplicate
// registration panics (a build-time wiring bug).
func registerWebLoginAdapter(vendor string, a webLoginAdapter) {
	if _, dup := webLoginAdapters[vendor]; dup {
		panic("duplicate web-login adapter for vendor " + vendor)
	}
	webLoginAdapters[vendor] = a
}

// webVendorFP is a live web-fingerprint gate for a vendor: the served Server
// header or page <title> must positively match this vendor, and must not match
// an exclude marker, before any login is attempted (case-insensitive
// substring). This guards against vendor misattribution from a UDP discovery
// collision (Lantronix UDP/30718, Moxa UDP/4800 also match unrelated devices
// like Cradlepoint or TEXECOM), which would otherwise spray a wrong-vendor
// default (e.g. Lantronix `sysadmin`/`PASS`) at the wrong device.
type webVendorFP struct {
	server  []string // any-of substrings expected in the Server header
	title   []string // any-of substrings expected in the <title>
	exclude []string // none-of substrings (server or title) that veto the match
}

// webVendorFPs are keyed by vendor slug. Strings are drawn from the observed
// server/title distribution (see TestWebLoginReplayCorpus). A vendor with no
// entry is not fingerprint-gated (the check falls back to the identify-stage
// vendor attribution alone).
var webVendorFPs = map[string]webVendorFP{
	"moxa":       {server: []string{"moxahttp"}, title: []string{"nport"}, exclude: []string{"d-link", "dlink"}},
	"opengear":   {server: []string{"cherokee"}, title: []string{"opengear"}},
	"digi":       {server: []string{"rompager"}, title: []string{"portserver", "digi", "connect", "web service"}},
	"servertech": {server: []string{"servertech"}, title: []string{"protected object", "sentry", "switched cdu"}},
	// Lantronix SLC web tier is mini_httpd (xwsd fork); older SLC/Spider units and
	// the SNMP-fallback path still surface GoAhead, so accept both. Exclude the
	// UDP/30718 discovery false positives.
	"lantronix": {server: []string{"mini_httpd", "goahead"}, title: []string{"spider", "lantronix", "securelinx", "serial server", "slc"}, exclude: []string{"cradlepoint", "texecom", "d-link", "dlink"}},
	"perle":     {server: []string{"mini_httpd"}, title: []string{"iolan"}},
	// The Network-M2/M3 SPA ships an empty <title> over the wire (Angular fills it
	// client-side), so a title-only gate skips the adapter; the tntnet web server
	// sends "Server: Tntnet/3.0" -- accept that. (Identify attributes the vendor
	// from the favicon; see bmcfp.)
	"eaton":     {server: []string{"tntnet"}, title: []string{"network-m", "power xpert", "eaton"}, exclude: []string{"cradlepoint"}},
	"tripplite": {title: []string{"poweralert", "tripp"}},
	// RMCARD's login <title> is runtime-composed and resolves to a brandless "UPS
	// Remote Management | Login" (no vendor word), so title-only gating fails on
	// real cards; key on the "Server: HTTPsrv" banner instead (identify attributes
	// the vendor from the OU=RMCARD TLS cert). The PowerPanel Enterprise SPA still
	// matches via title.
	"cyberpower": {server: []string{"httpsrv"}, title: []string{"powerpanel", "rmcard", "cyberpower"}},
	"advantech":  {server: []string{"boa"}, title: []string{"advantech", "eki"}},
	// raritan is intentionally not fingerprint-gated: the Xerus firmware (PX3
	// 3.6.1) root is HTTP 200 from BusyBox httpd with no Server header and an
	// empty <title>, so the JSON-RPC adapter self-confirms via the POST /session
	// (newSession) response shape instead.
	"pikvm":   {title: []string{"pikvm"}},
	"redlion": {title: []string{"red lion", "sixnet"}},
}

// confirmVendorWeb reports whether an observed Server header + page title
// corroborate the identified vendor. A vendor with no fingerprint entry is
// allowed (returns true) so coverage never regresses below the identify-stage
// attribution; a vendor with an entry must positively match and must not hit an
// exclude marker.
func confirmVendorWeb(server, title, vendor string) bool {
	fp, ok := webVendorFPs[vendor]
	if !ok {
		return true
	}
	s, ti := strings.ToLower(server), strings.ToLower(title)
	for _, x := range fp.exclude {
		if strings.Contains(s, x) || strings.Contains(ti, x) {
			return false
		}
	}
	for _, m := range fp.server {
		if strings.Contains(s, m) {
			return true
		}
	}
	for _, m := range fp.title {
		if strings.Contains(ti, m) {
			return true
		}
	}
	return false
}
