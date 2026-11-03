package identify

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/bmcfp"
	"github.com/runZeroInc/oobscan/pkg/cim"
	"github.com/runZeroInc/oobscan/pkg/digi"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/guid"
	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/idrac"
	"github.com/runZeroInc/oobscan/pkg/ilo"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/lantronix"
	"github.com/runZeroInc/oobscan/pkg/mdns"
	"github.com/runZeroInc/oobscan/pkg/moxa"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
	"github.com/runZeroInc/oobscan/pkg/redfish"
	"github.com/runZeroInc/oobscan/pkg/sanitize"
	"github.com/runZeroInc/oobscan/pkg/slp"
	"github.com/runZeroInc/oobscan/pkg/snmp"
	"github.com/runZeroInc/oobscan/pkg/ssh"
	"github.com/runZeroInc/oobscan/pkg/tlscert"
	"github.com/runZeroInc/oobscan/pkg/wsdiscovery"
	"github.com/runZeroInc/oobscan/pkg/wsman"
)

// preferredHTTPSMgmtPorts is ranked for common OOB/PDU HTTPS management ports,
// so we prefer them before any HTTP fallback.
var preferredHTTPSMgmtPorts = []int{443, 444, 8443, 9443, 4443, 4433, 10443, 7443, 6443, 4444, 8083, 7548, 9898, 4434, 8081}

// preferredHTTPFallbackPorts are HTTP-native or mixed web ports where plain HTTP is
// common enough to probe directly after the HTTPS candidates. The tail (81..55000)
// covers HTTP-only OOB web ports: Moxa web (55000/81/82), Tripp Lite PowerAlert
// (805), CyberPower RMCARD (3052), Advantech EKI (8090), NanoKVM/PiKVM (5000/8888).
var preferredHTTPFallbackPorts = []int{80, 8080, 8000, 81, 82, 805, 3052, 5000, 8090, 8888, 55000}

// httpsPort returns the target's HTTPS port (443 unless another tcp/https-ish
// port is configured), used by the TLS/Redfish/iLO/iDRAC collectors.
func httpsPort(t *engine.Target) int {
	ports := likelyHTTPSPorts(t)
	if len(ports) == 0 {
		return 443
	}
	return ports[0]
}

// likelyHTTPSPorts returns OOB/PDU-relevant HTTPS management ports in priority
// order, keeping probes deterministic and TLS-first.
func likelyHTTPSPorts(t *engine.Target) []int {
	out := make([]int, 0, len(preferredHTTPSMgmtPorts)+1)
	seen := map[int]struct{}{}
	hasTCP := map[int]bool{}
	for _, p := range t.Ports {
		if p.Proto == engine.ProtoTCP {
			hasTCP[p.Num] = true
		}
	}
	add := func(port int) {
		if _, ok := seen[port]; ok {
			return
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	// An explicit host:port (or --web-port) names the exact web port; probe it
	// first (both https and http, since the scheme is unknown) so the web/TLS
	// collectors reach a non-standard port like 8643 and record it as web.port.
	if t.WebPort > 0 {
		add(t.WebPort)
	}
	for _, p := range preferredHTTPSMgmtPorts {
		if hasTCP[p] || p == 443 {
			add(p)
		}
	}
	if len(out) == 0 {
		add(443)
	}
	return out
}

// likelyHTTPFallbackPorts returns plain-HTTP ports to try after TLS candidates.
func likelyHTTPFallbackPorts(t *engine.Target) []int {
	out := make([]int, 0, len(preferredHTTPFallbackPorts))
	seen := map[int]struct{}{}
	hasTCP := map[int]bool{}
	for _, p := range t.Ports {
		if p.Proto == engine.ProtoTCP {
			hasTCP[p.Num] = true
		}
	}
	add := func(port int) {
		if _, ok := seen[port]; ok {
			return
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	for _, p := range preferredHTTPFallbackPorts {
		if hasTCP[p] || p == 80 {
			add(p)
		}
	}
	if len(out) == 0 {
		add(80)
	}
	return out
}

// faviconHashes fetches the site favicon and returns the Shodan-style mmh3 hash
// and the hex MD5 (both "" on any failure), which feed the bmcfp fold so
// favicon-only OOB panels get a vendor during identify.
//
// It tries the root /favicon.ico first, then the icon declared by the page's
// <link rel="...icon"> href: some devices 404 the root and serve the icon only at
// a non-root path (Raritan Xerus uses /faviconit/favicon.ico), leaving the
// favicon rules with no data. htmlBody is the already-fetched root page.
func faviconHashes(client *http.Client, scheme, hostPort string, htmlBody []byte) (mmh3, md5hex string) {
	base := &url.URL{Scheme: scheme, Host: hostPort, Path: "/"}
	candidates := []string{base.ResolveReference(&url.URL{Path: "/favicon.ico"}).String()}
	if href := faviconHref(htmlBody); href != "" {
		if ref, err := url.Parse(href); err == nil {
			abs := base.ResolveReference(ref)
			// Only follow a same-host http(s) icon and avoid a duplicate root fetch.
			if abs.Host == hostPort && (abs.Scheme == "http" || abs.Scheme == "https") && abs.String() != candidates[0] {
				candidates = append(candidates, abs.String())
			}
		}
	}
	for _, u := range candidates {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || len(body) == 0 {
			continue
		}
		sum := md5.Sum(body)
		return bmcfp.FaviconHashString(body), hex.EncodeToString(sum[:])
	}
	return "", ""
}

// faviconLinkTagRe / faviconRelRe / faviconHrefRe parse the page's favicon
// <link>. faviconRelRe accepts only rel "icon" / "shortcut icon"; apple-touch-icon
// and mask-icon point at differently-hashed assets.
var (
	faviconLinkTagRe = regexp.MustCompile(`(?i)<link\b[^>]*>`)
	faviconRelRe     = regexp.MustCompile(`(?i)\brel\s*=\s*["']?\s*(?:shortcut\s+)?icon\s*["'\s/>]`)
	faviconHrefRe    = regexp.MustCompile(`(?i)\bhref\s*=\s*["']([^"']+)["']`)
)

// faviconHref returns the href of the page's <link rel="...icon"> declaration
// (the browser/Shodan favicon), or "" if none is present.
func faviconHref(body []byte) string {
	for _, tag := range faviconLinkTagRe.FindAll(body, -1) {
		if !faviconRelRe.Match(tag) {
			continue
		}
		if m := faviconHrefRe.FindSubmatch(tag); m != nil {
			return strings.TrimSpace(string(m[1]))
		}
	}
	return ""
}

// webIdentifyTimeout is the whole-request budget for the HTTP/TLS fingerprint
// probes. It sits above the per-probe check timeout so a slow-but-alive BMC web
// tier still gets fingerprinted, while staying small enough that a rate-limited
// board fails fast. identifyBudget is the real upper bound; this only sizes an
// individual probe. Paired with httpx.IdentifyClient, which lifts the per-phase
// handshake ceiling so the handshake is not clipped.
func webIdentifyTimeout(t *engine.Target) time.Duration {
	return min(max(t.Timeout, 8*time.Second), 10*time.Second)
}

// identifyBudget bounds the wall clock Identify spends on one host across phase 1
// and phase 2 combined. A rate-limited board can leave every web and IPMI probe
// hanging to its own timeout, which compounds to minutes; past this deadline
// Identify abandons stragglers and resolves with the evidence it has. The budget
// has to be generous enough to reach phase 2, which owns the vendor-specific
// generation probes, but it applies to every host, so it stays bounded and is
// paired with bounding the collectors that waste it (see wsmanConnectTimeout).
//
// It is deliberately tight. Raising it is the most expensive knob in the scanner:
// it applies to every host, so it multiplies straight into total scan time, and a
// previous increase bought no measurable reduction in hosts that skipped phase 2.
// Widen the collectors that waste the budget before widening the budget.
func identifyBudget(t *engine.Target) time.Duration {
	return min(max(t.Timeout*5, 20*time.Second), 30*time.Second)
}

// collectIPMI probes UDP/623 for the sessionless fingerprint. It tries Get
// Channel Auth Caps (OEM ID) and Get Channel Cipher Suites (the most
// reliable "IPMI 2.0 present" signal - it works even on BMCs like OpenBMC that
// ignore the 1.5 auth-caps probe). Get Device ID (IANA PEN + firmware) and Get
// System GUID are only attempted once one of those confirmed a BMC, so a
// filtered UDP/623 on a non-BMC host doesn't pay extra probe timeouts.
// ipmiUDPRetries is how many times the sessionless UDP probes are attempted.
// IPMI is UDP with no delivery guarantee, so a single dropped request/reply makes
// a live BMC look dead; retries recover transient packet loss.
const ipmiUDPRetries = 3

// udpPerAttempt splits the per-probe budget across retries so N attempts fit
// inside the overall timeout instead of multiplying wall-clock on dead hosts.
func udpPerAttempt(total time.Duration) time.Duration {
	per := max(total/ipmiUDPRetries, 700*time.Millisecond)
	return per
}

func collectIPMI(t *engine.Target, a *acc) {
	port := t.IPMIPort()
	responded := false
	per := udpPerAttempt(t.Timeout)

	var raw []byte
	var err error
	for range ipmiUDPRetries {
		if raw, err = ipmi.GetChannelAuthCaps15(t.Host, port, 0x0e, 0x04, per); err == nil {
			break
		}
	}
	if err != nil {
		a.log(fmt.Sprintf("authcaps udp/%d: %v (after %d tries)", port, err, ipmiUDPRetries))
	} else {
		responded = true
		if ac, perr := ipmi.ParseAuthCapsReply(raw); perr != nil {
			a.log(fmt.Sprintf("authcaps parse (%d bytes): %v", len(raw), perr))
		} else {
			a.markIPMI()
			t.SetEvidence("ipmi.authCaps", ac)
			a.log(fmt.Sprintf("authcaps ok: ipmi20=%v oem=%d", ac.IPMI20, ac.OEMID))
			if ac.OEMID != 0 {
				if name := ipmi.ManufacturerNameFor(ac.OEMID); name != "" {
					a.addVendor(name, "", "", engine.ConfMedium, "ipmi.authCaps")
				}
			}
		}
	}

	var ids []int
	var cerr error
	for range ipmiUDPRetries {
		if ids, _, cerr = ipmi.EnumCipherSuites15(t.Host, port, per); cerr == nil {
			break
		}
	}
	if cerr != nil {
		a.log(fmt.Sprintf("cipher-suites: %v (after %d tries)", cerr, ipmiUDPRetries))
	} else {
		responded = true
		if len(ids) > 0 {
			a.markIPMI()
			t.SetEvidence("ipmi.ciphers", ids)
			a.log(fmt.Sprintf("cipher-suites: %v", ids))
			if openBMCCipherSuiteOnly(ids) {
				a.setAttr("ipmi.openbmcCandidate", "suite17Only")
			}
		}
	}

	// Fallback cipher-suite capture via an RMCP+ Open Session. OpenBMC and the
	// stacks derived from it ignore the sessionless 1.5 Get Channel Cipher Suites
	// enumeration but answer this, so without the capture ipmi.ciphers stays empty
	// on those hosts and every downstream 2.0 check has no suite to probe.
	//
	// Gated on: no suite list yet, and the host is plausibly 2.0 (either IPMI is not
	// yet confirmed because auth-caps was unparseable, or auth-caps set the 2.0
	// bit). That covers the OpenBMC case while skipping a legacy 1.5-only host, and
	// skipping when nothing responded keeps a filtered UDP/623 host from paying two
	// more timeouts.
	_, haveCiphers := t.Evidenced("ipmi.ciphers")
	looks20 := !a.isIPMI()
	if v, ok := t.Evidenced("ipmi.authCaps"); ok {
		if ac, ok := v.(*ipmi.AuthCaps); ok && ac != nil && ac.IPMI20 {
			looks20 = true
		}
	}
	if responded && !haveCiphers && looks20 {
		for _, algo := range []byte{ipmi.RAKPHMACSHA256, ipmi.RAKPHMACSHA1} {
			r, oerr := ipmi.DoRAKP12(t.Host, port, "", algo, ipmi.IntegrityNone, ipmi.ConfNone, t.Timeout)
			if r != nil && r.BMCSID != 0 {
				a.markIPMI()
				// Record the confirmed working suite so downstream 2.0 checks have a
				// suite to probe. SetEvidenceIfAbsent so a later real enumeration (or a
				// concurrent probe) always wins over this single-suite fallback.
				if suiteIDs := rmcpPlusSuiteForAlgo(algo); len(suiteIDs) > 0 {
					t.SetEvidenceIfAbsent("ipmi.ciphers", suiteIDs)
					a.log(fmt.Sprintf("open-session ok (algo 0x%02x, bmc_sid=0x%08x); recorded cipher suite %v", algo, r.BMCSID, suiteIDs))
				} else {
					a.log(fmt.Sprintf("open-session ok (algo 0x%02x, bmc_sid=0x%08x)", algo, r.BMCSID))
				}
				break
			}
			a.log(fmt.Sprintf("open-session algo 0x%02x: %v", algo, oerr))
		}
	}
	if a.isIPMI() {
		t.MarkOpen(port, "udp", "ipmi")
	}

	// Only worth a Get Device ID once IPMI is confirmed present.
	if !a.isIPMI() {
		return
	}
	if dev, derr := ipmi.GetDeviceID15(t.Host, port, t.Timeout); derr == nil && dev != nil {
		t.SetEvidence("ipmi.deviceId", dev)
		if name := ipmi.ManufacturerNameFor(dev.ManufacturerID); name != "" {
			a.addVendor(name, "", "", engine.ConfMedium, "ipmi.deviceId")
		}
		a.setAttr("ipmi.fw", ipmi.FormatFirmwareRevision(dev.FirmwareMajor, dev.FirmwareMinor))
		if full := dev.FirmwareRevisionFull(); full != "" {
			a.setAttr("ipmi.firmwareVersionFull", full)
		}
	}
	var rawGUID []byte
	for range ipmiUDPRetries {
		if rawGUID, err = ipmi.GetSystemGUID15(t.Host, port, per); err == nil {
			break
		}
	}
	if len(rawGUID) == 16 {
		g := guid.Decode(rawGUID)
		t.SetEvidence("guid", g)
		if g.Vendor != "" {
			a.addVendor(g.Vendor, "", "", engine.ConfLow, "guid")
		}
		if g.Family != "" {
			a.setAttr("guid.family", g.Family)
		}
	}

	// Get DCMI Capabilities Info (Group Extension 0x2C, group 0xDC) - answered
	// pre-session by DCMI-capable BMCs. Presence + spec version is a useful
	// sessionless fingerprint (many datacenter servers implement DCMI power/
	// thermal management).
	var dcmi *ipmi.DCMICapabilities
	for range ipmiUDPRetries {
		var derr error
		if dcmi, derr = ipmi.GetDCMICapabilities15(t.Host, port, per); derr == nil {
			break
		}
	}
	if dcmi != nil {
		t.SetEvidence("ipmi.dcmi", dcmi)
		a.setAttr("ipmi.dcmiVersion", dcmi.Version())
		a.log(fmt.Sprintf("dcmi: supported, version %s (param rev %d)", dcmi.Version(), dcmi.ParamRevision))
	}
}

func openBMCCipherSuiteOnly(ids []int) bool {
	return len(ids) == 1 && ids[0] == 17
}

// rmcpPlusSuiteForAlgo maps a confirmed-working RAKP authentication algorithm
// (from an accepted RMCP+ Open Session) to the standard cipher suite ID that
// carries it. It lets a host that ignores the sessionless Get Channel Cipher
// Suites enumeration -- OpenBMC and its derivatives -- still record a usable
// suite in ipmi.ciphers. SHA256 -> suite 17, SHA1 -> suite 3; other algorithms
// (e.g. MD5) have no strong standard suite we want to advertise here.
func rmcpPlusSuiteForAlgo(authAlgo byte) []int {
	switch authAlgo {
	case ipmi.RAKPHMACSHA256:
		return []int{17}
	case ipmi.RAKPHMACSHA1:
		return []int{3}
	default:
		return nil
	}
}

// collectTLS inspects the HTTPS certificate for a vendor identity and feeds the
// subject/issuer DNs to the fingerprint engine.
func collectTLS(t *engine.Target, a *acc) {
	ito := webIdentifyTimeout(t)
	for _, port := range likelyHTTPSPorts(t) {
		ci, err := tlscert.Inspect(t.Host, port, ito)
		if err != nil || ci == nil {
			a.log(fmt.Sprintf("tls tcp/%d: %v", port, err))
			continue
		}
		t.SetEvidence("tls", ci)
		t.MarkOpen(port, "tcp", "https")
		a.log(fmt.Sprintf("tls:%d cn=%q issuer=%q vendor=%q", port, ci.SubjectCN, ci.IssuerCN, ci.Vendor))
		a.addFP(bmcfp.TLSSubjectCN, ci.SubjectCN)
		a.addFP(bmcfp.TLSIssuerCN, ci.IssuerCN)
		if ci.SubjectCN != "" || ci.SubjectO != "" {
			a.addFP(bmcfp.TLSSubjectDN, fmt.Sprintf("CN=%s,O=%s", ci.SubjectCN, ci.SubjectO))
		}
		if vendor, serviceTag, _ := tlscert.ClassifyIdentity(ci.SubjectCN, ci.IssuerCN); vendor == "dell" {
			a.addVendor("dell", "iDRAC", "", engine.ConfHigh, "tls-cn")
			a.setAttrIfUnset("dell.service_tag", serviceTag)
		}
		if ci.Vendor != "" {
			a.addVendor(ci.Vendor, ci.Product, "", engine.ConfMedium, "tls")
		}
		return
	}
}

// collectWeb fetches the root page and feeds the HTML <title> and Server header
// to the fingerprint engine (bmcfp already carries the rules that key off them,
// e.g. the OpenBMC "OpenBMC Web UI" title). This is the signal httpscan
// computes internally but does not surface, and it is what lets a JS-only SPA
// like OpenBMC's bmcweb be attributed correctly.
func collectWeb(t *engine.Target, a *acc) {
	client := httpx.IdentifyClient(webIdentifyTimeout(t))
	httpsPreferred := map[int]bool{}
	httpPreferred := map[int]bool{}
	orderedPorts := make([]int, 0, len(likelyHTTPSPorts(t))+len(likelyHTTPFallbackPorts(t)))
	seenPort := map[int]struct{}{}
	for _, p := range likelyHTTPSPorts(t) {
		httpsPreferred[p] = true
		if _, ok := seenPort[p]; !ok {
			seenPort[p] = struct{}{}
			orderedPorts = append(orderedPorts, p)
		}
	}
	for _, p := range likelyHTTPFallbackPorts(t) {
		httpPreferred[p] = true
		if _, ok := seenPort[p]; !ok {
			seenPort[p] = struct{}{}
			orderedPorts = append(orderedPorts, p)
		}
	}

	for _, port := range orderedPorts {
		schemes := []string{"https", "http"}
		if httpPreferred[port] && !httpsPreferred[port] {
			schemes = []string{"http", "https"}
		}
		for _, scheme := range schemes {
			// Retry once on a transient error: embedded OOB web servers (APC NMC's
			// RomPager especially) have a tiny connection pool, so collectWeb's GET
			// can be dropped/reset when it races the other collectors' concurrent
			// connects - which intermittently left an HTTP-only NMC unidentified.
			var resp *http.Response
			var err error
			for range 2 {
				if resp, err = client.Get(netaddr.URL(scheme, t.Host, port, "/")); err == nil {
					break
				}
			}
			if err != nil {
				continue
			}
			if scheme == "https" {
				t.MarkOpen(port, "tcp", "https")
			} else {
				t.MarkOpen(port, "tcp", "http")
			}
			a.setAttr("web.port", strconv.Itoa(port))
			a.setAttr("web.scheme", scheme)
			server := resp.Header.Get("Server")
			csp := resp.Header.Get("Content-Security-Policy")
			wwwAuth := resp.Header.Get("WWW-Authenticate")
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 96*1024))
			resp.Body.Close()
			title := htmlTitle(body)
			if server != "" {
				a.addFP(bmcfp.HTTPServerHeader, server)
				a.setAttr("http.server", server) // kept for generation heuristics (e.g. WPCM450 == SMC X9)
			}
			if csp != "" {
				a.addFP(bmcfp.ContentSecurityPolicy, csp)
			}
			// The 401 Basic-auth challenge realm is often the strongest passive tell
			// for an embedded OOB web tier whose Server header is generic/shared: e.g.
			// an Advantech EKI serial server fronts Boa/0.93.15 (shared with the old
			// SMC X10 ATEN stack and many embedded devices) but challenges with
			// realm="EKI-1524-CE", and Fujitsu/Dell/Opengear/Lantronix likewise name
			// themselves in the realm. Feed it so bmcfp's WWWAuthenticate rules can
			// disambiguate; without this the realm rules never fire during identify.
			if wwwAuth != "" {
				a.addFP(bmcfp.WWWAuthenticate, wwwAuth)
				a.setAttr("http.wwwauth", wwwAuth)
			}
			if title != "" {
				a.addFP(bmcfp.HTMLTitle, title)
				a.setAttr("http.title", title) // reused by the web.service check (avoids a second GET)
			}
			// Feed the favicon into the fold once per host: some OOB UIs (bare
			// Opengear/JetKVM/NanoKVM, rebranded panels) identify only by their
			// baked-in icon, and the mmh3/md5 favicon rules would otherwise be dead
			// during identify (they only ran in the check phase, too late to pick a
			// class/vendor-scoped check set).
			if mmh3, md5hex := faviconHashes(client, scheme, netaddr.URLHostPort(t.Host, port), body); mmh3 != "" {
				a.addFP(bmcfp.FaviconMMH3, mmh3)
				if md5hex != "" {
					a.addFP(bmcfp.FaviconMD5, md5hex)
				}
			}
			a.log(fmt.Sprintf("web %s:%d: title=%q server=%q", scheme, port, title, server))
			// OpenBMC's SPA identifies only by its title/body; catch it explicitly so
			// it outranks generic endpoint-list guesses.
			if strings.Contains(strings.ToLower(title), "openbmc") ||
				strings.Contains(strings.ToLower(string(body)), "openbmc") {
				a.addVendor("openbmc", "OpenBMC", "", engine.ConfHigh, "http.title")
			}
			// APC / Schneider Network Management Card (NMC): the RomPager web tier
			// emits a nonstandard, usually empty "WebServer:" response header on every
			// reply and 303-redirects unauthenticated clients to
			// /NMC/<token>/logon.htm. Its "Server:" header is empty and the login
			// title is a generic "Log On", so neither the Server-header nor the
			// title bmcfp rule fires - key off these NMC-specific tells directly.
			_, hasWebServer := resp.Header[http.CanonicalHeaderKey("WebServer")]
			finalPath := ""
			if resp.Request != nil && resp.Request.URL != nil {
				finalPath = strings.ToLower(resp.Request.URL.Path)
			}
			lowBody := strings.ToLower(string(body))
			if hasWebServer || strings.Contains(finalPath, "/nmc/") ||
				(strings.Contains(lowBody, "se_logo") && strings.Contains(lowBody, "logon.htm")) {
				a.addVendor("apc", "NMC", "", engine.ConfHigh, "http.apc-nmc")
				a.setAttr("http.apc_nmc", "webserver-header/nmc-path")
			}
			return
		}
	}
}

// mgmtSoftwareProbe returns a phase-1 collector that fingerprints an OOB
// management web application on a dedicated port, rather than an appliance BMC on
// 443/80: CyberPower PowerPanel Enterprise (53568/https) and Eaton Intelligent
// Power Manager (4679/http, 4680/https). It is gated on a quick TCP connect so a
// host without the port pays at most one connect timeout; one collector per port
// keeps the set concurrent rather than serialized. A responding port feeds its
// title/Server to the fingerprint engine and is recorded open so the webapp CVE
// checks (cyberpower.ppe / eaton.ipm_lfi) resolve it.
func mgmtSoftwareProbe(port int, scheme string) func(*engine.Target, *acc) {
	return func(t *engine.Target, a *acc) {
		if !tcpOpen(t.Host, port, t.Timeout) {
			return
		}
		t.MarkOpen(port, "tcp", scheme)
		client := httpx.ClientWithRedirect(t.Timeout, func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse })
		resp, err := client.Get(netaddr.URL(scheme, t.Host, port, "/"))
		if err != nil {
			return
		}
		server := resp.Header.Get("Server")
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 96*1024))
		resp.Body.Close()
		title := htmlTitle(body)
		if server != "" {
			a.addFP(bmcfp.HTTPServerHeader, server)
		}
		if title != "" {
			a.addFP(bmcfp.HTMLTitle, title)
		}
		// Point downstream checks/output at this port unless the main web
		// collector already claimed a primary web port on 443/80.
		a.setAttrIfUnset("web.port", strconv.Itoa(port))
		a.setAttrIfUnset("web.scheme", scheme)
		a.log(fmt.Sprintf("mgmt-software %s:%d: title=%q server=%q", scheme, port, title, server))
	}
}

// htmlTitle extracts the text of the first <title> element (case-insensitive).
func htmlTitle(body []byte) string {
	s := string(body)
	low := strings.ToLower(s)
	i := strings.Index(low, "<title")
	if i < 0 {
		return ""
	}
	gt := strings.IndexByte(s[i:], '>')
	if gt < 0 {
		return ""
	}
	start := i + gt + 1
	end := strings.Index(low[start:], "</title>")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(s[start : start+end])
}

// collectRedfish fetches the unauthenticated Redfish service root.
func collectRedfish(t *engine.Target, a *acc) {
	res, port, err := probeRedfishOnLikelyPorts(t, a)
	if err != nil || res == nil || res.Status == 0 {
		a.log(fmt.Sprintf("redfish: %v", err))
		return // no HTTP response from the Redfish endpoint
	}
	t.SetEvidence("redfish", res)
	t.MarkOpen(port, "tcp", "redfish")
	rv, rp := redfishVendor(res)
	a.log(fmt.Sprintf("redfish:%d status=%d vendor=%q iloGen=%d rootVendor=%q", port, res.Status, res.Vendor, res.ILOGeneration, rv))
	if res.ServiceRoot != nil {
		a.setAttr("redfish.version", res.ServiceRoot.RedfishVersion)
		a.setAttr("redfish.uuid", res.ServiceRoot.UUID)
		a.setAttr("redfish.vendor", res.ServiceRoot.Vendor)
		a.setAttr("redfish.product", res.ServiceRoot.Product)
	}
	switch {
	case res.ILOGeneration > 0:
		a.addVendor("hpe", "iLO"+strconv.Itoa(res.ILOGeneration), strconv.Itoa(res.ILOGeneration), engine.ConfHigh, "redfish")
	case res.DellFWVersion != "":
		a.addVendor("dell", "iDRAC", "", engine.ConfHigh, "redfish")
		a.setAttr("idrac.fw", res.DellFWVersion)
	case rv != "":
		// Vendor from the service-root Oem key or the manager id (e.g. OpenBMC's
		// /redfish/v1/Managers/bmc) - the most reliable Redfish vendor signals.
		a.addVendor(rv, rp, "", engine.ConfHigh, "redfish")
	case res.Vendor != "":
		a.addVendor(res.Vendor, "", "", engine.ConfMedium, "redfish")
	}
	if res.AMICVE {
		a.setAttr("redfish.ami_cve_2024_54085", "candidate")
	}
	// BMC firmware version from the Manager resource, unauthenticated where the
	// BMC allows it (many do for the Manager object). This is the most portable
	// firmware source for vendors whose IPMI Get Device ID is session-gated
	// (Supermicro/ATEN) or absent.
	if res.ServiceRoot != nil {
		if id := managerODataID(res.ServiceRoot.Links); id != "" {
			if fw := fetchRedfishManagerFW(t.Host, port, id, t.Timeout); fw != "" {
				a.setAttr("redfish.fw", fw)
			}
		}
	}
}

// probeRedfishOnLikelyPorts tries Redfish on the discovered web/tls ports in
// priority order and returns the first responsive service root.
func probeRedfishOnLikelyPorts(t *engine.Target, a *acc) (*redfish.Result, int, error) {
	ports := []int{}
	seen := map[int]struct{}{}
	add := func(p int) {
		if p <= 0 {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		ports = append(ports, p)
	}
	if s := a.attrVal("web.port"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			add(n)
		}
	}
	add(httpsPort(t))
	for _, p := range t.Ports {
		if p.Proto != engine.ProtoTCP {
			continue
		}
		add(p.Num)
	}
	add(443)
	add(8443)
	add(4443)

	var lastErr error
	ito := webIdentifyTimeout(t)
	for _, port := range ports {
		res, err := redfish.ProbeAt(t.Host, port, ito)
		if err != nil {
			lastErr = err
			continue
		}
		if res != nil && res.Status != 0 {
			return res, port, nil
		}
	}
	return nil, 0, lastErr
}

// fetchRedfishManagerFW does one unauthenticated GET of a Redfish Manager
// resource and returns its FirmwareVersion, or "" on 401/parse failure.
func fetchRedfishManagerFW(host string, port int, managerPath string, timeout time.Duration) string {
	client := httpx.Client(timeout)
	url := netaddr.URL("https", host, port, managerPath)
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	var mgr struct {
		FirmwareVersion string `json:"FirmwareVersion"`
	}
	if json.Unmarshal(body, &mgr) != nil {
		return ""
	}
	return strings.TrimSpace(mgr.FirmwareVersion)
}

// redfishVendor derives a vendor/product from the Redfish service root: first the
// Oem extension key, then the manager id referenced by Links (OpenBMC's bmcweb
// uses the id "bmc"). Falls back to scanning the raw root for OpenBMC markers.
func redfishVendor(res *redfish.Result) (vendor, product string) {
	if sr := res.ServiceRoot; sr != nil {
		// The Oem extension key covers every typed vendor plus the long tail
		// (cisco, fujitsu, huawei, quanta, tyan, gigabyte, asus, ...) in one shot.
		if v, p := sr.OemVendor(); v != "" {
			return v, p
		}
		if id := managerODataID(sr.Links); strings.Contains(strings.ToLower(id), "/managers/bmc") {
			return "openbmc", "OpenBMC"
		}
	}
	low := strings.ToLower(string(res.RawRoot))
	if strings.Contains(low, "openbmc") || strings.Contains(low, "/managers/bmc") {
		return "openbmc", "OpenBMC"
	}
	return "", ""
}

// managerODataID digs the @odata.id out of Links.ManagerProvidingService.
func managerODataID(links map[string]any) string {
	mps, ok := links["ManagerProvidingService"].(map[string]any)
	if !ok {
		return ""
	}
	id, _ := mps["@odata.id"].(string)
	return id
}

// iloXMLDataProbeCap bounds how many candidate web ports collectILO probes for
// /xmldata. likelyHTTPSPorts/likelyHTTPFallbackPorts already filter to ports the
// target actually has open (plus 443/80), so the realistic cost is 1-2 requests;
// the cap only stops a wide-open host from turning identify into a port sweep.
const iloXMLDataProbeCap = 3

// collectILO fetches HPE iLO's pre-auth /xmldata. It probes the target's
// discovered web ports, not just 443/80: iLOs published on 8443/4443/8083 are
// common behind NAT, and a router web UI occupying 443 in front of a forwarded
// iLO would otherwise hide it.
func collectILO(t *engine.Target, a *acc) {
	client := httpx.IdentifyClient(webIdentifyTimeout(t))
	x, err := ilo.FetchPorts(client, t.Host,
		capPorts(likelyHTTPSPorts(t), iloXMLDataProbeCap),
		capPorts(likelyHTTPFallbackPorts(t), iloXMLDataProbeCap))
	if err != nil || x == nil {
		return
	}
	// FetchPorts parses /xmldata into a RIMP doc; a non-iLO host returning 200 to
	// /xmldata yields an empty doc. Require populated iLO identity before claiming
	// HPE, otherwise generic web servers get mislabeled. This must not test
	// Generation() == "": Generation falls back to a bare "iLO" and never returns
	// empty, so that form of the guard is dead code.
	if !x.Populated() {
		return
	}
	gen := x.Generation()
	t.SetEvidence("ilo", x)
	a.addVendor("hpe", gen, gen, engine.ConfHigh, "ilo")
	if x.MP.FWRI != "" {
		a.setAttr("ilo.fw", x.MP.FWRI)
	}
	if x.HSI.SBSN != "" {
		a.setAttr("ilo.serial", x.HSI.SBSN)
	}
	// The pre-auth RIMP doc also names the host platform. Promote it: Redfish is
	// the only other source of a server model and it is absent or gated on most
	// internet-exposed iLOs, so without these the model is parsed and discarded.
	if x.HSI.SPN != "" {
		a.setAttr("ilo.model", x.HSI.SPN)
	}
	if x.HSI.PN != "" {
		a.setAttr("ilo.productId", x.HSI.PN)
	}
	if x.HSI.UUID != "" {
		a.setAttr("ilo.uuid", x.HSI.UUID)
	}
	// MP.PN and MP.ST are the only two inputs to Generation(). Surfacing them
	// flat makes a fall-through (gen == "iLO", no digit) diagnosable with a
	// single grep over the scan output instead of a re-scan; the full RIMP doc
	// is also serialized as the record's `ilo` object.
	if x.MP.PN != "" {
		a.setAttr("ilo.mpProduct", x.MP.PN)
	}
	if x.MP.ST != "" {
		a.setAttr("ilo.mpFamily", x.MP.ST)
	}
}

// capPorts returns at most n ports, preserving the caller's priority order.
func capPorts(ports []int, n int) []int {
	if len(ports) <= n {
		return ports
	}
	return ports[:n]
}

// collectIDRAC hits Dell iDRAC's pre-auth endpoints.
func collectIDRAC(t *engine.Target, a *acc) {
	port := httpsPort(t)
	if s := a.attrVal("web.port"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			port = n
		}
	}
	info, err := idrac.ProbeAt(t.Host, port, webIdentifyTimeout(t))
	if err != nil || info == nil {
		return
	}
	// idrac.Probe always returns non-nil and appends endpoints even on generic
	// 401s, so len(Endpoints)>0 is not sufficient (a plain nginx/NX-OS/Synology
	// gets mislabeled iDRAC). Require a Dell-specific tell: a parsed generation,
	// firmware, service tag, the default-cred indicator, or a Dell/iDRAC server
	// banner.
	dellTell := info.Generation > 0 || info.FWVersion != "" || info.ServiceTag != "" ||
		info.DefaultCredKnown || info.Model != "" ||
		strings.Contains(strings.ToLower(info.ServerBanner), "idrac") ||
		strings.Contains(strings.ToLower(info.ServerBanner), "dell")
	if !dellTell {
		return
	}
	t.SetEvidence("idrac", info)
	product := "iDRAC"
	generation := ""
	if info.Generation > 0 {
		product = "iDRAC" + strconv.Itoa(info.Generation)
		generation = strconv.Itoa(info.Generation)
	}
	a.addVendor("dell", product, generation, engine.ConfHigh, "idrac")
	if info.ServiceTag != "" {
		a.setAttr("dell.service_tag", info.ServiceTag)
	}
	if info.FWVersion != "" {
		a.setAttr("idrac.fw", info.FWVersion)
	}
	if info.Version != "" {
		a.setAttr("idrac.version", info.Version)
	}
	if info.Hostname != "" {
		a.setAttr("idrac.hostname", info.Hostname)
	}
	if info.OEMHostname != "" {
		a.setAttr("idrac.oem.hostname", info.OEMHostname)
	}
	if info.SysDesc != "" {
		a.setAttr("idrac.sysDesc", info.SysDesc)
	}
	if info.Status != "" {
		a.setAttr("idrac.status", info.Status)
	}
	if info.TitleBar != "" {
		a.setAttr("idrac.gui.titleBar", info.TitleBar)
	}
	if info.ADEnabled != "" {
		a.setAttr("idrac.adEnabled", info.ADEnabled)
	}
	if info.IsOEMBranded != "" {
		a.setAttr("idrac.isOemBranded", info.IsOEMBranded)
	}
	if info.License != "" {
		a.setAttr("idrac.license", info.License)
	}
	if info.SSOEnabled != "" {
		a.setAttr("idrac.ssoEnabled", info.SSOEnabled)
	}
	if info.ServerGen != "" {
		a.setAttr("idrac.serverGen", info.ServerGen)
	}
	if info.SystemLockdown != "" {
		a.setAttr("idrac.systemLockdown", info.SystemLockdown)
	}
	if info.SystemModel != "" {
		a.setAttr("idrac.systemModelName", info.SystemModel)
	}
	if info.TFAEnabled != "" {
		a.setAttr("idrac.tfaEnabled", info.TFAEnabled)
	}
	if info.Name != "" {
		a.setAttr("idrac.name", info.Name)
	}
}

// wsmanConnectTimeout bounds the per-port reachability test in collectWSMAN. WS-Man
// runs on a fixed six-port candidate list and a filtered port costs a full connect
// timeout, so this is what keeps one collector from consuming identify's entire
// budget on a host that does not speak WS-Man at all.
const wsmanConnectTimeout = 1500 * time.Millisecond

// collectWSMAN sends WS-Man Identify (AMT / some BMCs).
func collectWSMAN(t *engine.Target, a *acc) {
	ports := []int{5986, 5985, 16993, 16992, 443}
	if p := httpsPort(t); p > 0 {
		ports = append(ports, p)
	}
	// A short reachability budget per candidate port. Six fixed ports at the full probe
	// timeout is up to 24s of connect waits on a host with no WS-Man, which is more than
	// identify's whole budget -- see ProbeWithConnectTimeout.
	id, err := wsman.ProbeWithConnectTimeout(t.Host, ports, wsmanConnectTimeout, t.Timeout)
	if err != nil || id == nil {
		return
	}
	t.SetEvidence("wsman", id)
	if id.ProductVendor != "" {
		a.setAttr("wsman.vendor", id.ProductVendor)
	}
	if id.ProductVersion != "" {
		a.setAttr("wsman.product", id.ProductVersion)
	}
	if id.ProtocolVersion != "" {
		a.setAttr("wsman.protocol_version", id.ProtocolVersion)
	}
	if len(id.SecurityProfile) > 0 {
		a.setAttr("wsman.security_profiles", strings.Join(id.SecurityProfile, ","))
	}
	if id.URL != "" {
		a.setAttr("wsman.url", id.URL)
	}
	slug := id.VendorSlug()
	if slug == "intel-amt" {
		a.forceClass(engine.ClassAMT)
		a.addVendor("intel", "AMT", "", engine.ConfHigh, "wsman")
		return
	}
	if slug != "" {
		a.addVendor(slug, id.ProductVersion, "", engine.ConfMedium, "wsman")
	}
}

// collectLantronix queries the UDP/30718 setup protocol (serial-to-Ethernet).
func collectLantronix(t *engine.Target, a *acc) {
	r, err := lantronix.Query(t.Host, t.Timeout)
	if err != nil || r == nil {
		return
	}
	t.SetEvidence("lantronix", r)
	t.MarkOpen(30718, "udp", "lantronix")
	a.forceClass(engine.ClassSerialConsole)
	a.addVendor("lantronix", r.Model, "", engine.ConfHigh, "lantronix")
	// Firmware is a version, not a device generation - record it as device.fw
	// (feeds finalIdentity.version) so it never lands in the generation field.
	if r.Firmware != "" {
		a.setAttr("device.fw", r.Firmware)
	}
	if r.MAC != "" {
		a.setAttr("mac", r.MAC)
	}
	if banner, _, ok, err := lantronix.ProbeSetupTelnet(t.Host, t.Timeout); err == nil && banner != "" {
		t.MarkOpen(lantronix.SetupTelnetPort, "tcp", "telnet")
		cleanBanner := sanitizeIdentityText(banner)
		// Only record the banner as Lantronix evidence when it actually looks
		// Lantronix-flavored. Some Moxa NPorts and honeypots listen on 9999/tcp
		// with an unrelated (HTTP or binary) service; storing that reply as
		// `lantronix.setup_telnet` cross-contaminates identity for those hosts.
		if cleanBanner != "" && (ok || looksLantronixTelnetBanner(cleanBanner)) {
			t.SetEvidence("lantronix.telnet", cleanBanner)
			a.setAttr("lantronix.setup_telnet", cleanBanner)
		}
		if ok {
			a.addVendor("lantronix", r.Model, "", engine.ConfHigh, "lantronix.telnet")
		}
	}
}

// collectLantronixTelnet probes TCP/9999 directly for Lantronix setup banners.
// Only banners that look Lantronix-flavored (`looksLantronix` heuristic or a
// printable serial-ish prompt) are recorded as identity evidence; a raw HTTP
// error reply or binary noise on 9999/tcp is left off the Identity so it
// doesn't contaminate Moxa/honeypot fingerprints.
func collectLantronixTelnet(t *engine.Target, a *acc) {
	banner, _, ok, err := lantronix.ProbeSetupTelnet(t.Host, t.Timeout)
	if err != nil || banner == "" {
		return
	}
	cleanBanner := sanitizeIdentityText(banner)
	if cleanBanner == "" {
		return
	}
	t.MarkOpen(lantronix.SetupTelnetPort, "tcp", "telnet")
	if !ok && !looksLantronixTelnetBanner(cleanBanner) {
		// Non-Lantronix responder (HTTP server / honeypot / binary probe reply).
		// Do not surface the banner as identity evidence.
		return
	}
	t.SetEvidence("lantronix.telnet", cleanBanner)
	a.setAttr("lantronix.setup_telnet", cleanBanner)
	if !ok {
		return
	}
	a.forceClass(engine.ClassSerialConsole)
	a.addVendor("lantronix", "Serial Server", "", engine.ConfMedium, "lantronix.telnet")
}

// sanitizeIdentityText removes non-printable control bytes from collector text
// attributes and ensures the result is valid UTF-8 for JSON output.
func sanitizeIdentityText(raw string) string {
	if raw == "" {
		return ""
	}
	return strings.TrimSpace(string(sanitize.Bytes([]byte(raw))))
}

// looksLantronixTelnetBanner is a defensive gate that decides whether a banner
// captured from TCP/9999 is plausibly the Lantronix setup-mode prompt. It
// rejects HTTP responses (Nginx / Moxa embedded HTTP / honeypot Citrix
// Gateway) and non-printable garbage that some Moxa builds emit on 9999/tcp.
// A banner passes only when it has at least a few printable characters and
// does not open with an HTTP status line.
func looksLantronixTelnetBanner(banner string) bool {
	trim := strings.TrimSpace(banner)
	if trim == "" {
		return false
	}
	low := strings.ToLower(trim)
	if strings.HasPrefix(low, "http/1.") || strings.HasPrefix(low, "<html") {
		return false
	}
	// An SSH daemon on 9999/tcp (some devices relocate sshd there) is not a
	// Lantronix setup service; its RFC 4253 "SSH-<proto>-<software>" banner must
	// not be recorded as setup evidence or the tcp.lantronix.setupBanner check
	// picks it up via the evidence path and escalates it.
	if strings.HasPrefix(low, "ssh-") {
		return false
	}
	printable := 0
	for _, r := range trim {
		if (r >= 0x20 && r < 0x7f) || r == '\r' || r == '\n' || r == '\t' {
			printable++
		}
	}
	return printable >= 4
}

// collectMoxa queries the UDP/4800 DeviceSearch protocol (serial-to-Ethernet).
func collectMoxa(t *engine.Target, a *acc) {
	r, err := moxa.Query(t.Host, t.Timeout)
	if err != nil || r == nil {
		return
	}
	t.SetEvidence("moxa", r)
	t.MarkOpen(4800, "udp", "moxa")
	a.forceClass(engine.ClassSerialConsole)
	a.addVendor("moxa", r.Model, "", engine.ConfHigh, "moxa")
	if r.Model != "" {
		a.setAttr("moxa.model", r.Model)
	}
	if r.Firmware != "" {
		a.setAttr("moxa.firmware", r.Firmware)
		a.setAttr("device.fw", r.Firmware) // firmware is a version, not a generation
	}
	if r.MAC != "" {
		a.setAttr("mac", r.MAC)
	}
	if r.IP != "" {
		a.setAttr("moxa.ip", r.IP)
	}
	if r.Ports > 0 {
		a.setAttr("moxa.serial_ports", strconv.Itoa(r.Ports))
	}
	if r.Serial != "" {
		a.setAttr("moxa.serial", r.Serial)
	}
}

// collectDigiADDP queries Digi ADDP discovery on UDP/2362.
func collectDigiADDP(t *engine.Target, a *acc) {
	r, err := digi.Query(t.Host, t.Timeout)
	if err != nil || r == nil {
		return
	}
	t.SetEvidence("digi.addp", r)
	t.MarkOpen(digi.ADDPPort, "udp", "digi-addp")
	a.forceClass(engine.ClassSerialConsole)
	product := strings.TrimSpace(r.HWName)
	if product == "" {
		product = "PortServer"
	}
	a.addVendor("digi", product, "", engine.ConfHigh, "digi.addp")
	// ADDP firmware is a version string ("Version 82000774_U 11/09/2007"), not a
	// device generation - record it as device.fw (feeds finalIdentity.version)
	// instead of letting it pollute the generation field.
	if r.Firmware != "" {
		a.setAttr("device.fw", r.Firmware)
	}
	if r.MAC != "" {
		a.setAttr("mac", r.MAC)
	}
	if r.Hostname != "" {
		a.setAttr("digi.hostname", r.Hostname)
	}
	if r.RealPort > 0 {
		a.setAttr("digi.realport_port", strconv.Itoa(r.RealPort))
	}
	if r.Ports > 0 {
		a.setAttr("digi.serial_ports", strconv.Itoa(r.Ports))
	}
}

// collectDigiRealPort probes Digi RealPort service on TCP/771 and TCP/1027(TLS).
func collectDigiRealPort(t *engine.Target, a *acc) {
	candidates := []struct {
		port int
		tls  bool
	}{
		{digi.RealPortPort, false},
		{digi.RealPortTLSPort, true},
	}
	for _, c := range candidates {
		if !hasPort(t, c.port, engine.ProtoTCP) {
			continue
		}
		ri, err := digi.ProbeRealPort(t.Host, c.port, c.tls, t.Timeout)
		if err != nil || ri == nil {
			continue
		}
		t.SetEvidence("digi.realport", ri)
		t.MarkOpen(c.port, "tcp", "digi-realport")
		a.forceClass(engine.ClassSerialConsole)
		a.addVendor("digi", ri.Name, "", engine.ConfHigh, "digi.realport")
		a.setAttr("digi.realport_name", ri.Name)
		a.setAttr("digi.realport_ports", strconv.Itoa(ri.PortCount))
		if c.tls {
			a.setAttr("digi.realport_tls", "true")
		}
		return
	}
}

// collectSLP performs SLPv2 (RFC 2608) unicast Service Requests on UDP/427.
func collectSLP(t *engine.Target, a *acc) {
	// service:service-agent elicits a reply from any SLP SA/DA; service:wbem and
	// the Intel DCIM hardware type carry the vendor-bearing management URLs.
	var urls []string
	seen := map[string]struct{}{}
	for _, svc := range []string{"service:service-agent", "service:wbem", "service:management-hardware.intel-dcim"} {
		r, err := slp.Probe(t.Host, svc, t.Timeout)
		if err != nil || r == nil {
			continue
		}
		for _, u := range r.URLs {
			u = sanitizeIdentityText(u)
			if u == "" {
				continue
			}
			if _, ok := seen[u]; ok {
				continue
			}
			seen[u] = struct{}{}
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		return
	}
	t.SetEvidence("slp", urls)
	t.MarkOpen(427, "udp", "slp")
	a.setAttr("slp.services", strings.Join(urls, " "))
	// Only claim a vendor when a URL actually names one; a bare
	// service:service-agent reply confirms SLP but not the device family.
	if v := slp.VendorFromURLs(urls); v != "" {
		a.addVendor(v, "", "", engine.ConfMedium, "slp")
	}
}

// sshIdentifyPorts are the ports collectSSH grabs a banner from: 22 standard,
// 2222 the most common alt-SSH on OOB gear (HPE iLO mpSSH, APC AOS cryptlib).
var sshIdentifyPorts = []int{22, 2222}

// collectSSH grabs the SSH banner and feeds it to the bmcfp fold so the
// SSHBanner rules (iLO mpSSH, Oracle ILOM, APC cryptlib, ServerTech, OpenBMC
// dropbear, CyberPower) contribute to identity -- otherwise those rules are dead
// weight, evaluated by MatchAll but never fed a value. The banner + port are
// stashed as evidence so the always-on ssh.exposure check reuses them instead
// of re-dialing 22.
func collectSSH(t *engine.Target, a *acc) {
	for _, p := range sshIdentifyPorts {
		banner, err := ssh.Banner(t.Host, p, t.Timeout)
		if err != nil || banner == "" {
			continue
		}
		t.MarkOpen(p, "tcp", "ssh")
		t.SetEvidence("ssh.banner", banner)
		t.SetEvidence("ssh.port", p)
		a.setAttr("ssh.banner", banner)
		// bmcfp's SSHBanner rules are anchored to the RFC 4253 softwareversion
		// field, so the "SSH-2.0-" prefix must be stripped before the fold. The
		// raw line stays in the attribute/evidence above for reporting.
		a.addFP(bmcfp.SSHBanner, ssh.SoftwareVersion(banner))
		return
	}
}

// collectCIM detects a CIM-XML / WBEM CIMOM on 5989 (https) or 5988 (http) with
// a read-only intrinsic and records the broker/server (older IBM/HP/Dell/VMware
// management stacks and Linux sblim/OpenPegasus expose WBEM here).
func collectCIM(t *engine.Target, a *acc) {
	for _, pc := range []struct {
		port   int
		scheme string
	}{{cim.PortHTTPS, "https"}, {cim.PortHTTP, "http"}} {
		if !tcpOpen(t.Host, pc.port, min(t.Timeout, 900*time.Millisecond)) {
			continue
		}
		res := cim.Probe(httpx.Client(t.Timeout), pc.scheme, netaddr.URLHostPort(t.Host, pc.port))
		if res == nil {
			continue
		}
		res.Port, res.Scheme = pc.port, pc.scheme
		t.MarkOpen(pc.port, "tcp", "cim-xml")
		t.SetEvidence("cim", res)
		a.setAttr("cim.port", strconv.Itoa(pc.port))
		if res.Broker != "" {
			a.setAttr("cim.broker", res.Broker)
		}
		if res.Server != "" {
			a.addFP(bmcfp.HTTPServerHeader, res.Server) // a known CIMOM Server may name the vendor
		}
		a.log(fmt.Sprintf("cim %s:%d broker=%q server=%q", pc.scheme, pc.port, res.Broker, res.Server))
		return
	}
}

// collectMDNS enumerates DNS-SD service types via a unicast mDNS query on 5353.
func collectMDNS(t *engine.Target, a *acc) {
	r := mdns.Query(t.Host, udpPerAttempt(t.Timeout))
	if r == nil {
		return
	}
	t.MarkOpen(mdns.Port, "udp", "mdns")
	t.SetEvidence("mdns", r)
	a.setAttr("mdns.services", strings.Join(r.Services, " "))
	if r.Vendor != "" {
		a.addVendor(r.Vendor, "", "", engine.ConfMedium, "mdns")
	}
	a.log(fmt.Sprintf("mdns %s: %d service(s) vendor=%q", t.Host, len(r.Services), r.Vendor))
}

// collectWSDiscovery sends a unicast WS-Discovery Probe on 3702 and records the
// advertised device Types / transport addresses.
func collectWSDiscovery(t *engine.Target, a *acc) {
	r := wsdiscovery.Probe(t.Host, udpPerAttempt(t.Timeout))
	if r == nil {
		return
	}
	t.MarkOpen(wsdiscovery.Port, "udp", "ws-discovery")
	t.SetEvidence("wsdiscovery", r)
	if len(r.Types) > 0 {
		a.setAttr("wsdiscovery.types", strings.Join(r.Types, " "))
	}
	if len(r.XAddrs) > 0 {
		a.setAttr("wsdiscovery.xaddrs", strings.Join(r.XAddrs, " "))
	}
	a.log(fmt.Sprintf("ws-discovery %s: types=%v", t.Host, r.Types))
}

// collectSNMP reads sysDescr/sysObjectID for a vendor guess (PDUs, consoles) and
// performs SNMPv3 USM engine-ID discovery. It runs on every target; the results
// feed both identity and the snmp check, which renders findings from this evidence
// and adds the active v3 default-credential test. The private community is only
// tried once public confirms SNMP responds.
func collectSNMP(t *engine.Target, a *acc) {
	per := udpPerAttempt(t.Timeout)
	found := false

	// Public community (v2c then v1). A reply at all confirms the community is
	// accepted, because a v1/v2c agent stays silent on one it refuses. Requiring
	// a non-empty sysDescr here discarded working communities on agents that
	// restrict that one object, which is common on iDRAC.
	var pub *snmp.Result
	for _, ver := range []int{1, 0} {
		if r, err := snmp.Probe(t.Host, 161, "public", ver, per); err == nil && r != nil && r.Responded {
			pub = r
			break
		}
	}
	if pub != nil {
		found = true
		t.SetEvidence("snmp", pub)
		if pub.VendorGuess != "" {
			a.addVendor(pub.VendorGuess, "", "", engine.ConfLow, "snmp")
		}
		// A distinctive sysDescr product string is a stronger tell than the bare
		// enterprise arc, so attribute it at medium confidence (enough to clear the
		// class floor in resolve). Catches e.g. Red Lion/Sixnet RTUs.
		if v := snmp.VendorBySysDescr(pub.SysDescr); v != "" {
			a.addVendor(v, "", "", engine.ConfMedium, "snmp.sysdescr")
		}
		// Probe the conventional 'private' community after SNMP is confirmed. The
		// check separately uses an idempotent SET to determine whether it is writable.
		for _, ver := range []int{1, 0} {
			if r, err := snmp.Probe(t.Host, 161, "private", ver, per); err == nil && r != nil && r.Responded {
				t.SetEvidence("snmp.private", r)
				break
			}
		}

		// The same agent that answers the system group often serves the
		// neighbour cache and a vendor inventory of the machine the controller
		// is attached to, which is what ties a controller to its host.
		collectSNMPHostInventory(t, a, pub)
	}

	// SNMPv3 engine-ID discovery - always attempted (the engine ID is an
	// identification signal even when no community is readable).
	if v3, err := snmp.ProbeV3(t.Host, 161, per); err == nil && v3 != nil {
		found = true
		t.SetEvidence("snmpv3", v3)
		a.setAttr("snmp.engine_id", v3.EngineID)
		// The engine ID's RFC 3411 enterprise number is a pre-auth vendor tell
		// independent of sysObjectID, and vendors often stash a product/serial
		// string in the format-4/5 suffix (e.g. HPE iLO): both are worth
		// attributing during identify, not just echoing in the finding.
		if info, err := snmp.DecodeEngineIDHex(v3.EngineID); err == nil && info.Enterprise != 0 {
			if info.Vendor != "" {
				a.addVendor(info.Vendor, "", "", engine.ConfLow, "snmp.v3.engineId")
			}
			a.setAttr("snmp.v3.engineIdEnterprise", fmt.Sprintf("%d", info.Enterprise))
			if info.Suffix != "" {
				a.setAttr("snmp.v3.engineIdSuffix", info.Suffix)
			}
		}
	}

	if found {
		t.MarkOpen(161, "udp", "snmp")
	}
}

// collectSNMPHostInventory walks the neighbour cache, the interface tables and
// the vendor inventory scalars with the community that already answered. The
// managed-machine NIC list joined against the neighbour cache resolves the
// controller-to-host pair without inference, and because a MAC is globally
// unique the pair holds when the two sit in different segments.
func collectSNMPHostInventory(t *engine.Target, a *acc, pub *snmp.Result) {
	if pub == nil {
		return
	}
	inv, err := snmp.CollectHostInventory(t.Host, 161, pub.Community, pub.Version, udpPerAttempt(t.Timeout))
	if err != nil || inv.Empty() {
		return
	}
	t.SetEvidence("snmp.hostinv", inv)

	if len(inv.OwnMACs) > 0 {
		a.setAttr("snmp.host.agentMACs", strings.Join(inv.OwnMACs, ","))
	}
	if len(inv.ServerNICs) > 0 {
		a.setAttr("snmp.host.serverNICs", strings.Join(inv.ServerNICs, ","))
	}
	if n := len(inv.ARP); n > 0 {
		a.setAttr("snmp.host.arpEntries", fmt.Sprintf("%d", n))
		peers := make([]string, 0, n)
		for _, e := range inv.ARP {
			peers = append(peers, e.IP+"="+e.MAC)
		}
		a.setAttr("snmp.host.arpCache", strings.Join(peers, ","))
	}
	if len(inv.ManagedIPs) > 0 {
		a.setAttr("snmp.host.managedIPs", strings.Join(inv.ManagedIPs, ","))
	}
	if inv.ServiceTag != "" {
		a.setAttr("snmp.host.serviceTag", inv.ServiceTag)
	}
	if inv.Model != "" {
		a.setAttr("snmp.host.model", inv.Model)
	}
	if inv.HostOS != "" {
		a.setAttr("snmp.host.os", inv.HostOS)
	}
	if inv.HostSerial != "" {
		a.setAttr("snmp.host.serial", inv.HostSerial)
	}
}
