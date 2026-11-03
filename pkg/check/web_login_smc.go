package check

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/creds"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

// Supermicro ATEN web-login check. The pre-OpenBMC SMC stack (X9-X13 / H13) logs in
// with a form POST to /cgi/login.cgi carrying name=<user>&pwd=<pass>&check=00.
//
// Only the minted SID session cookie is a valid success signal: login.cgi can return
// a byte-identical body on success and failure, so the adapter verifies the SID
// against an authenticated endpoint rather than matching on the response body.
type smcATENAdapter struct{}

func (smcATENAdapter) mechanism() string { return "httpForm" }

// smcMaxAttempts caps ATEN login attempts per host (well under lockout).
const smcMaxAttempts = 4

// smcFormEncoding describes how an ATEN firmware generation expects the login.cgi
// name/pwd fields on the wire. The success signal is the same either way, so both
// are tried:
//
//   - "plaintext": X9/X10-era firmware reads name/pwd verbatim and sends no check
//     field. base64-encoding here yields a bogus username and fails silently (no
//     SID), so the plaintext form is required to reach those hosts at all.
//   - "base64": X11+ base64-decodes name/pwd server-side, gated by check=00.
type smcFormEncoding struct {
	label string
	enc   func(string) string
	check bool // send check=00 to gate the server-side base64 decode
}

// smcFormEncodings is tried in order per credential; plaintext first so a legacy
// X10 succeeds on its first POST, base64 second for X11+. Stops on the first
// minted SID, so a default-cred host costs 1-2 POSTs.
var smcFormEncodings = []smcFormEncoding{
	{label: "plaintext", enc: func(s string) string { return s }, check: false},
	{label: "base64", enc: func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }, check: true},
}

// smcWebAttempts bounds transport-error retries per request. Old ATEN web servers
// accept only a few concurrent connections and briefly wedge when a scan's HTTP lane
// saturates them, so a request can fail at the transport layer while the host is up
// and the credentials valid; a short backoff rides that out. Retries fire only on
// transport errors (no HTTP response), never on a credential rejection, so no extra
// login attempt is charged toward the ATEN lockout counter.
const smcWebAttempts = 4

// smcHTTPDo runs build() and retries on transport error (no HTTP response) with
// a linear backoff, returning the first response received or the last error.
func smcHTTPDo(ctx context.Context, client *http.Client, build func() (*http.Request, error)) (*http.Response, error) {
	var lastErr error
	for i := range smcWebAttempts {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		req, err := build()
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(i+1) * 500 * time.Millisecond):
		}
	}
	return nil, lastErr
}

func (smcATENAdapter) login(ctx context.Context, client *http.Client, base, user, pass string, encd smcFormEncoding) (ok bool, proof string, err error) {
	form := url.Values{
		"name": {encd.enc(user)},
		"pwd":  {encd.enc(pass)},
	}
	if encd.check {
		form.Set("check", "00")
	}
	body := form.Encode()
	resp, err := smcHTTPDo(ctx, client, func() (*http.Request, error) {
		r, e := http.NewRequestWithContext(ctx, http.MethodPost, base+"/cgi/login.cgi", strings.NewReader(body))
		if e != nil {
			return nil, e
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r, nil
	})
	if err != nil {
		return false, "", err
	}
	defer func() { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192)); resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return false, "", nil // rejected credential
	}
	// A redirect marker can appear in rejected pages, so require a minted SID.
	for _, c := range resp.Cookies() {
		if strings.EqualFold(c.Name, "SID") && smcValidSID(c.Value) {
			// Prove the session works by pulling a concise device fingerprint from
			// authenticated-only ATEN endpoints (firmware version, session user/priv,
			// hostname). A valid reply doubles as the authorization check.
			if info, ok := smcSessionInfo(ctx, client, base, c.Value); ok {
				return true, info, nil
			}
			// Fallback for generations that don't serve those opcodes: confirm the
			// token authorizes access via a generic authenticated endpoint.
			if authed, ep := smcVerifySID(ctx, client, base, c.Value); authed {
				return true, "authenticated session via " + ep, nil
			}
			return true, fmt.Sprintf("minted SID session cookie (len=%d)", len(c.Value)), nil
		}
	}
	return false, "", nil
}

// smcSessionInfo pulls a concise device fingerprint from an authenticated ATEN
// session -- firmware version/build (GENERIC_INFO.XML) plus the session user,
// privilege, and BMC hostname (Get_PlatformInfo.XML). Both opcodes are served by
// the ATEN /cgi/ipmi.cgi across the X10..H13 stack. A valid GENERIC_INFO reply
// doubles as the authorization proof: logged out, /cgi/ipmi.cgi returns the login
// redirect, not this XML. Returns the concise proof and true when authenticated;
// "", false otherwise (e.g. a generation that does not serve these opcodes).
func smcSessionInfo(ctx context.Context, client *http.Client, base, sid string) (string, bool) {
	gi := smcPostAuthedXML(ctx, client, base, sid, "GENERIC_INFO.XML=(0,0)")
	fw := smcXMLAttr(gi, "IPMIFW_VERSION")
	if fw == "" {
		return "", false // not authenticated via this endpoint / unsupported generation
	}
	parts := []string{"fw=" + smcFormatFWVersion(fw)}
	if bld := strings.TrimSpace(smcXMLAttr(gi, "IPMIFW_BLDTIME")); bld != "" {
		parts = append(parts, "build="+bld)
	}
	if pi := smcPostAuthedXML(ctx, client, base, sid, "Get_PlatformInfo.XML=(0,0)"); pi != "" {
		if u := strings.TrimSpace(smcXMLAttr(pi, "SESS_USER_NAME")); u != "" {
			parts = append(parts, "user="+u)
		}
		if pr := smcPrivName(smcXMLAttr(pi, "USER_ACCESS")); pr != "" {
			parts = append(parts, "priv="+pr)
		}
		if h := strings.TrimSpace(smcXMLAttr(pi, "HOSTNAME")); h != "" {
			parts = append(parts, "host="+h)
		}
	}
	return strings.Join(parts, " "), true
}

// smcPostAuthedXML POSTs an ATEN ipmi.cgi opcode with the session cookie and
// returns the response body (empty on transport error).
func smcPostAuthedXML(ctx context.Context, client *http.Client, base, sid, cmd string) string {
	resp, err := smcHTTPDo(ctx, client, func() (*http.Request, error) {
		r, e := http.NewRequestWithContext(ctx, http.MethodPost, base+"/cgi/ipmi.cgi", strings.NewReader(cmd))
		if e != nil {
			return nil, e
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: "SID", Value: sid})
		return r, nil
	})
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()
	return string(body)
}

// smcXMLAttr extracts an ATEN XML attribute value (name="value") from body.
func smcXMLAttr(body, name string) string {
	key := name + `="`
	_, after, ok := strings.Cut(body, key)
	if !ok {
		return ""
	}
	rest := after
	before, _, ok := strings.Cut(rest, "\"")
	if !ok {
		return ""
	}
	return before
}

// smcFormatFWVersion renders the ATEN 4-digit BMC revision ("0353") as "3.53".
func smcFormatFWVersion(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) == 4 && isAllDigits(raw) {
		maj := strings.TrimLeft(raw[:2], "0")
		if maj == "" {
			maj = "0"
		}
		return maj + "." + raw[2:]
	}
	return raw
}

// smcPrivName maps the ATEN USER_ACCESS hex privilege nibble to a name.
func smcPrivName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	v, err := strconv.ParseUint(raw, 16, 8)
	if err != nil {
		return ""
	}
	switch v & 0x0f {
	case 1:
		return "callback"
	case 2:
		return "user"
	case 3:
		return "operator"
	case 4:
		return "admin"
	case 5:
		return "oem"
	}
	return ""
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// smcValidSID rejects empty / placeholder SID values (a real ATEN session token
// is a non-trivial string; "0" and "" are the logged-out / rejected sentinels).
func smcValidSID(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && v != "0" && len(v) >= 4
}

// smcVerifySID does one authenticated GET with the SID and reports whether an
// ATEN authenticated-only endpoint returns real content (not the login page /
// a redirect back to it). Best-effort: a network error or an unrecognized
// firmware layout leaves the SID-cookie proof standing on its own.
func smcVerifySID(ctx context.Context, client *http.Client, base, sid string) (bool, string) {
	for _, ep := range []string{"/cgi/url_redirect.cgi?url_name=mainmenu", "/cgi/CheckUserPriv.cgi"} {
		resp, err := smcHTTPDo(ctx, client, func() (*http.Request, error) {
			r, e := http.NewRequestWithContext(ctx, http.MethodGet, base+ep, nil)
			if e != nil {
				return nil, e
			}
			r.AddCookie(&http.Cookie{Name: "SID", Value: sid})
			return r, nil
		})
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		low := strings.ToLower(string(body))
		if resp.StatusCode == http.StatusOK && !strings.Contains(low, "login.cgi") && !strings.Contains(low, "url_name=login") {
			return true, ep
		}
	}
	return false, ""
}

func init() {
	Register(Check{
		Name:        "http.smc.webDefaultCreds",
		Description: "Active Supermicro ATEN web-UI default-credential login (POST /cgi/login.cgi, base64 creds) -- vendor-targeted, online only",
		Category:    "creds",
		Applies:     Applicability{CrossVendor: true}, // ATEN is BMC-class; the generic web check excludes BMC
		Enabled:     true,
		Run:         runSMCWebDefaultCreds,
	})
	RegisterExplain("http.smc.webDefaultCreds", explainSMCWebDefaultCreds)
}

func runSMCWebDefaultCreds(ctx context.Context, t *engine.Target) []engine.Finding {
	if t.DisableLogins { // active login; online-gated
		return nil
	}
	if identityVendor(t) != "supermicro" {
		return nil
	}
	return smcWebLoginWith(ctx, t, smcWebCandidates(t), smcMaxAttempts)
}

// smcWebLoginWith runs the ATEN web-UI fingerprint gate, then tries each credential
// under both wire encodings against /cgi/login.cgi, returning a default-cred finding
// for the first that mints a verified SID. Shared by the default-cred check and the
// IPMI-recovered-cred post-check; callers own the vendor and DisableLogins gating.
// maxPOSTs caps login POSTs, each credential costing up to two.
func smcWebLoginWith(ctx context.Context, t *engine.Target, cands []smcCred, maxPOSTs int) []engine.Finding {
	if len(cands) == 0 {
		return nil
	}
	port := webPort(t)
	proto := webProto(t)
	if port <= 0 {
		return nil
	}
	base := hostPortURL(proto, t.Host, port, "") // scheme://host:port
	per := smcPerRequestTimeout(t.Timeout)
	client := insecureWebClient(per)

	// Fingerprint gate: only proceed against a genuine ATEN web UI, so a
	// Supermicro host that is X14 OpenBMC (bmcweb/Redfish) or otherwise not the
	// ATEN form is left alone.
	if !smcIsATENWeb(ctx, client, base) {
		return nil
	}

	adapter := smcATENAdapter{}
	// attempts counts login POSTs (not credential pairs): each credential is
	// tried under both wire encodings, so the cap bounds total failed logins on
	// a non-default host at smcMaxAttempts -- staying under the ATEN lockout.
	attempts := 0
	for _, c := range cands {
		for _, encd := range smcFormEncodings {
			if ctx.Err() != nil {
				return nil
			}
			if attempts >= maxPOSTs {
				return nil
			}
			attempts++
			okAuth, proof, err := adapter.login(ctx, client, base, c.user, c.pass, encd)
			if err != nil {
				return nil
			}
			if !okAuth {
				continue
			}
			t.MarkOpen(port, "tcp", proto)
			passField := c.pass
			if passField == "" {
				passField = "(blank)"
			}
			return []engine.Finding{{
				Check: httpCredCheckName("supermicro"), Category: "creds", Risk: "critical",
				Port: port, Transport: "tcp", Protocol: proto,
				Fields: engine.F(
					"vendor", "supermicro",
					"username", c.user,
					"password", passField,
					"loginVia", adapter.mechanism(),
					"formEncoding", encd.label,
					"source", c.source,
					"evidenceEndpoint", "/cgi/login.cgi",
					"proof", proof),
				CVE: cveOrNil(c.cve),
			}}
		}
	}
	return nil
}

type smcCred struct{ user, pass, source, cve string }

// smcWebCandidates returns operator-supplied creds first, then the documented
// Supermicro defaults (ADMIN/ADMIN, ADMIN/blank), de-duplicated, username required.
func smcWebCandidates(t *engine.Target) []smcCred {
	seen := map[[2]string]struct{}{}
	var out []smcCred
	add := func(u, p, src, cve string) {
		if u == "" {
			return
		}
		k := [2]string{u, p}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, smcCred{u, p, src, cve})
	}
	for _, c := range suppliedCreds(t) {
		add(c.User, c.Pass, "cli", "")
	}
	for _, c := range creds.VendorCredsFor("supermicro", creds.ClassHTTP) {
		add(c.Username, c.Password, c.Source, c.CVE)
	}
	return out
}

// smcIsATENWeb reports whether the root (or the ATEN login page) shows the ATEN
// web fingerprint -- the "Supermicro BMC Login" title or the "ATEN" marker -- so we
// never POST a login to a non-ATEN Supermicro surface (e.g. X14 bmcweb).
func smcIsATENWeb(ctx context.Context, client *http.Client, base string) bool {
	for _, path := range []string{"/", "/page/login.www"} {
		resp, err := smcHTTPDo(ctx, client, func() (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		})
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		resp.Body.Close()
		low := strings.ToLower(string(body))
		if strings.Contains(low, "supermicro bmc login") ||
			strings.Contains(low, "aten international") ||
			(strings.Contains(low, "supermicro") && strings.Contains(low, "login.cgi")) {
			return true
		}
	}
	return false
}

func smcPerRequestTimeout(scanTimeout time.Duration) time.Duration {
	if scanTimeout <= 0 || scanTimeout > 4*time.Second {
		return 4 * time.Second
	}
	if scanTimeout < time.Second {
		return time.Second
	}
	return scanTimeout
}

func explainSMCWebDefaultCreds(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 443)
	user := explainField(f, "username")
	pass := explainField(f, "password")
	baseURL := explainBaseURL(host, f, port, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nThe Supermicro ATEN web UI accepted the default credential **%s / %s** via /cgi/login.cgi.\n", user, pass))
	// The wire encoding differs by firmware generation: legacy X9/X10 reads the
	// fields verbatim; X11+ base64-decodes them (gated by check=00). Show the
	// exact form that was accepted.
	if explainField(f, "formEncoding") == "plaintext" {
		b.WriteString("\n**Validate (legacy ATEN -- plaintext creds):**\n")
		b.WriteString(explainSh(
			fmt.Sprintf("curl -sk -c - -X POST %s/cgi/login.cgi -d \"name=%s&pwd=%s\"", baseURL, user, pass),
		))
	} else {
		b.WriteString("\n**Validate (base64 the creds, then POST):**\n")
		b.WriteString(explainSh(
			fmt.Sprintf("U=$(printf '%s' | base64); P=$(printf '%s' | base64)", user, pass),
			fmt.Sprintf("curl -sk -c - -X POST %s/cgi/login.cgi -d \"name=$U&pwd=$P&check=00\"", baseURL),
		))
	}
	b.WriteString("\n\n**Impact:** Full ATEN BMC web access -- KVM/vMedia, power control, user management.\n")
	return b.String()
}
