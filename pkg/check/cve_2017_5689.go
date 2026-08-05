package check

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/amt"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
	"github.com/runZeroInc/oobscan/pkg/wsman"
)

var amtVersionRe = regexp.MustCompile(`([0-9]+(?:\.[0-9]+){1,3})`)

func init() {
	Register(Check{
		Name:        "amt.authBypass",
		Description: "Intel AMT empty-digest authentication bypass (CVE-2017-5689), actively confirmed",
		Category:    "creds",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runAMTAuthBypass,
	})
}

func amtOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func runAMTAuthBypass(_ context.Context, t *engine.Target) []engine.Finding {
	if !likelyAMT(t) {
		return nil
	}
	r, err := amt.Probe(t.Host, t.Timeout)
	if err != nil || r == nil || !r.Present {
		return nil
	}
	if r.Version == "" {
		if v := wsmanAMTVersion(t); v != "" {
			r.Version = v
			r.VersionSource = "wsman_productversion"
			r.VersionInRange = amtVersionInRange(v)
		}
	}
	t.SetEvidence("amt", r)
	port, transport := r.Port, "tcp"
	if port == 0 {
		port = amt.CleartextPort
		if !r.Cleartext && r.TLS {
			port = amt.TLSPort
		}
	}
	t.MarkOpen(port, transport, "amt")

	if !t.DisableLogins {
		amt.VerifyEmptyDigest(r, t.Timeout)
	}
	if r.AuthBypass {
		return []engine.Finding{{
			Check: "amt.authBypass", Category: "creds", Risk: "critical",
			Port: r.BypassPort, Transport: "tcp", Protocol: "amt",
			Fields: engine.F("username", "admin", "version", r.Version, "versionSource", r.VersionSource,
				"proof", proofKV(
					"path", amtOr(r.BypassPath, "/index.htm"),
					"baselineStatus", "401",
					"bypassStatus", "200",
					"responseBytes", "0",
					"port", strconv.Itoa(r.BypassPort),
					"realm", r.BypassRealm)),
			CVE: []string{"CVE-2017-5689"},
		}}
	}

	return []engine.Finding{amtDetectedFinding(r, port)}
}

func amtDetectedFinding(r *amt.Result, port int) engine.Finding {
	fields := engine.F(
		"version", r.Version,
		"versionSource", r.VersionSource,
		"detectionSource", r.DetectionSource,
		"fingerprint", r.Fingerprint,
		"httpStatus", strconv.Itoa(r.HTTPStatus),
		"server", r.ServerHdr,
	)
	var cves []string
	if r.VersionInRange {
		cves = []string{"CVE-2017-5689"}
	}
	return engine.Finding{
		Check: "amt.detected", Category: "discovery", Risk: "info",
		Port: port, Transport: "tcp", Protocol: "amt",
		Fields: fields, CVE: cves,
	}
}

func likelyAMT(t *engine.Target) bool {
	if t.Identity != nil {
		if t.Identity.Class == engine.ClassAMT {
			return true
		}
		if strings.EqualFold(t.Identity.Vendor, "intel") {
			return true
		}
		if t.Identity.Attributes != nil {
			for _, k := range []string{"wsman.vendor", "wsman.product", "wsman.raw", "http.title", "http.server"} {
				v := strings.ToLower(strings.TrimSpace(t.Identity.Attributes[k]))
				if strings.Contains(v, "intel") || strings.Contains(v, "active management") || strings.Contains(v, "standard manageability") {
					return true
				}
			}
		}
	}
	return false
}

func wsmanAMTVersion(t *engine.Target) string {
	v, ok := t.Evidenced("wsman")
	if !ok {
		return ""
	}
	id, ok := v.(*wsman.Identity)
	if !ok || id == nil {
		return ""
	}
	if m := amtVersionRe.FindStringSubmatch(id.ProductVersion); m != nil {
		return m[1]
	}
	return ""
}

func amtVersionInRange(ver string) bool {
	major, minor := parseMajorMinor(ver)
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

func parseMajorMinor(ver string) (int, int) {
	parts := strings.Split(ver, ".")
	if len(parts) < 2 {
		return 0, 0
	}
	return parseLeadingInt(parts[0]), parseLeadingInt(parts[1])
}

func parseLeadingInt(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = (n * 10) + int(c-'0')
	}
	return n
}

func init() {
	RegisterExplain("amt.authBypass", explainAMTAuthBypass)
	RegisterExplain("amt.detected", explainAMTDetected)
}

func explainAMTAuthBypass(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 16992)
	version := explainField(f, "version")
	versionSource := explainField(f, "versionSource")
	scheme := "http"
	if port == 16993 {
		scheme = "https"
	}
	baseURL := netaddr.URL(scheme, host, port, "")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nIntel AMT accepts an empty Digest auth response -- the password check is\n")
	b.WriteString("bypassed entirely (CVE-2017-5689 / INTEL-SA-00075).\n")
	if version != "" {
		b.WriteString(fmt.Sprintf("\n**AMT version:** `%s`\n", version))
		if versionSource != "" {
			b.WriteString(fmt.Sprintf("**Version source:** `%s`\n", versionSource))
		}
	}
	b.WriteString("\n**Confirm the bypass:**\n")
	b.WriteString(explainSh(
		"# Send a Digest response with an empty HA1:",
		fmt.Sprintf("curl -sk --digest -u 'admin:' %s/index.htm", baseURL),
		"",
		"# Public PoC: https://github.com/bartblaze/CVE-2017-5689",
	))
	b.WriteString("\n\n**Impact:** Unauthenticated Intel AMT access -- remote KVM, power control,\n")
	b.WriteString("network traffic redirection, and OS-level command execution.\n")
	b.WriteString("\n**CVE:** CVE-2017-5689 / INTEL-SA-00075\n")
	return b.String()
}

func explainAMTDetected(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 16992)
	version := explainField(f, "version")
	versionSource := explainField(f, "versionSource")
	scheme := "http"
	if port == 16993 {
		scheme = "https"
	}
	baseURL := netaddr.URL(scheme, host, port, "")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nIntel AMT (vPro) management interface detected.\n")
	if version != "" {
		b.WriteString(fmt.Sprintf("**Version:** `%s`", version))
		if versionSource != "" {
			b.WriteString(fmt.Sprintf(" (source: `%s`)", versionSource))
		}
		if len(f.CVE) > 0 {
			b.WriteString(" -- in the CVE-2017-5689 vulnerable range (< 11.6)")
		}
		b.WriteString("\n")
	}
	b.WriteString("\n**Enumerate the AMT surface:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk %s/index.htm", baseURL),
		fmt.Sprintf("oobscan scan --checks amt.authBypass %s:%d", host, port),
	))
	return b.String()
}
