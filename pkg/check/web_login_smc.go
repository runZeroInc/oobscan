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

type smcATENAdapter struct{}

func (smcATENAdapter) mechanism() string { return "httpForm" }

const smcMaxAttempts = 4

type smcFormEncoding struct {
	label string
	enc   func(string) string
	check bool
}

var smcFormEncodings = []smcFormEncoding{
	{label: "plaintext", enc: func(s string) string { return s }, check: false},
	{label: "base64", enc: func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }, check: true},
}

const smcWebAttempts = 4

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
		return false, "", nil
	}

	for _, c := range resp.Cookies() {
		if strings.EqualFold(c.Name, "SID") && smcValidSID(c.Value) {

			if info, ok := smcSessionInfo(ctx, client, base, c.Value); ok {
				return true, info, nil
			}

			if authed, ep := smcVerifySID(ctx, client, base, c.Value); authed {
				return true, "authenticated session via " + ep, nil
			}
			return true, fmt.Sprintf("minted SID session cookie (len=%d)", len(c.Value)), nil
		}
	}
	return false, "", nil
}

func smcSessionInfo(ctx context.Context, client *http.Client, base, sid string) (string, bool) {
	gi := smcPostAuthedXML(ctx, client, base, sid, "GENERIC_INFO.XML=(0,0)")
	fw := smcXMLAttr(gi, "IPMIFW_VERSION")
	if fw == "" {
		return "", false
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

func smcValidSID(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && v != "0" && len(v) >= 4
}

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
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runSMCWebDefaultCreds,
	})
	RegisterExplain("http.smc.webDefaultCreds", explainSMCWebDefaultCreds)
}

func runSMCWebDefaultCreds(ctx context.Context, t *engine.Target) []engine.Finding {
	if t.DisableLogins {
		return nil
	}
	if identityVendor(t) != "supermicro" {
		return nil
	}
	return smcWebLoginWith(ctx, t, smcWebCandidates(t), smcMaxAttempts)
}

func smcWebLoginWith(ctx context.Context, t *engine.Target, cands []smcCred, maxPOSTs int) []engine.Finding {
	if len(cands) == 0 {
		return nil
	}
	port := webPort(t)
	proto := webProto(t)
	if port <= 0 {
		return nil
	}
	base := hostPortURL(proto, t.Host, port, "")
	per := smcPerRequestTimeout(t.Timeout)
	client := insecureWebClient(per)

	if !smcIsATENWeb(ctx, client, base) {
		return nil
	}

	adapter := smcATENAdapter{}

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
