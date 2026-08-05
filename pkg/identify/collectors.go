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

var preferredHTTPSMgmtPorts = []int{443, 444, 8443, 9443, 4443, 4433, 10443, 7443, 6443, 4444, 8083, 7548, 9898, 4434, 8081}

var preferredHTTPFallbackPorts = []int{80, 8080, 8000, 81, 82, 805, 3052, 5000, 8090, 8888, 55000}

func httpsPort(t *engine.Target) int {
	ports := likelyHTTPSPorts(t)
	if len(ports) == 0 {
		return 443
	}
	return ports[0]
}

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

func faviconHashes(client *http.Client, scheme, hostPort string, htmlBody []byte) (mmh3, md5hex string) {
	base := &url.URL{Scheme: scheme, Host: hostPort, Path: "/"}
	candidates := []string{base.ResolveReference(&url.URL{Path: "/favicon.ico"}).String()}
	if href := faviconHref(htmlBody); href != "" {
		if ref, err := url.Parse(href); err == nil {
			abs := base.ResolveReference(ref)

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

var (
	faviconLinkTagRe = regexp.MustCompile(`(?i)<link\b[^>]*>`)
	faviconRelRe     = regexp.MustCompile(`(?i)\brel\s*=\s*["']?\s*(?:shortcut\s+)?icon\s*["'\s/>]`)
	faviconHrefRe    = regexp.MustCompile(`(?i)\bhref\s*=\s*["']([^"']+)["']`)
)

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

func webIdentifyTimeout(t *engine.Target) time.Duration {
	return min(max(t.Timeout, 8*time.Second), 10*time.Second)
}

func identifyBudget(t *engine.Target) time.Duration {
	return min(max(t.Timeout*5, 20*time.Second), 30*time.Second)
}

const ipmiUDPRetries = 3

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
				a.setAttr("http.server", server)
			}
			if csp != "" {
				a.addFP(bmcfp.ContentSecurityPolicy, csp)
			}

			if wwwAuth != "" {
				a.addFP(bmcfp.WWWAuthenticate, wwwAuth)
				a.setAttr("http.wwwauth", wwwAuth)
			}
			if title != "" {
				a.addFP(bmcfp.HTMLTitle, title)
				a.setAttr("http.title", title)
			}

			if mmh3, md5hex := faviconHashes(client, scheme, netaddr.URLHostPort(t.Host, port), body); mmh3 != "" {
				a.addFP(bmcfp.FaviconMMH3, mmh3)
				if md5hex != "" {
					a.addFP(bmcfp.FaviconMD5, md5hex)
				}
			}
			a.log(fmt.Sprintf("web %s:%d: title=%q server=%q", scheme, port, title, server))

			if strings.Contains(strings.ToLower(title), "openbmc") ||
				strings.Contains(strings.ToLower(string(body)), "openbmc") {
				a.addVendor("openbmc", "OpenBMC", "", engine.ConfHigh, "http.title")
			}

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

		a.setAttrIfUnset("web.port", strconv.Itoa(port))
		a.setAttrIfUnset("web.scheme", scheme)
		a.log(fmt.Sprintf("mgmt-software %s:%d: title=%q server=%q", scheme, port, title, server))
	}
}

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

func collectRedfish(t *engine.Target, a *acc) {
	res, port, err := probeRedfishOnLikelyPorts(t, a)
	if err != nil || res == nil || res.Status == 0 {
		a.log(fmt.Sprintf("redfish: %v", err))
		return
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

		a.addVendor(rv, rp, "", engine.ConfHigh, "redfish")
	case res.Vendor != "":
		a.addVendor(res.Vendor, "", "", engine.ConfMedium, "redfish")
	}
	if res.AMICVE {
		a.setAttr("redfish.ami_cve_2024_54085", "candidate")
	}

	if res.ServiceRoot != nil {
		if id := managerODataID(res.ServiceRoot.Links); id != "" {
			if fw := fetchRedfishManagerFW(t.Host, port, id, t.Timeout); fw != "" {
				a.setAttr("redfish.fw", fw)
			}
		}
	}
}

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

func redfishVendor(res *redfish.Result) (vendor, product string) {
	if sr := res.ServiceRoot; sr != nil {

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

func managerODataID(links map[string]any) string {
	mps, ok := links["ManagerProvidingService"].(map[string]any)
	if !ok {
		return ""
	}
	id, _ := mps["@odata.id"].(string)
	return id
}

const iloXMLDataProbeCap = 3

func collectILO(t *engine.Target, a *acc) {
	client := httpx.IdentifyClient(webIdentifyTimeout(t))
	x, err := ilo.FetchPorts(client, t.Host,
		capPorts(likelyHTTPSPorts(t), iloXMLDataProbeCap),
		capPorts(likelyHTTPFallbackPorts(t), iloXMLDataProbeCap))
	if err != nil || x == nil {
		return
	}

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

	if x.HSI.SPN != "" {
		a.setAttr("ilo.model", x.HSI.SPN)
	}
	if x.HSI.PN != "" {
		a.setAttr("ilo.productId", x.HSI.PN)
	}
	if x.HSI.UUID != "" {
		a.setAttr("ilo.uuid", x.HSI.UUID)
	}

	if x.MP.PN != "" {
		a.setAttr("ilo.mpProduct", x.MP.PN)
	}
	if x.MP.ST != "" {
		a.setAttr("ilo.mpFamily", x.MP.ST)
	}
}

func capPorts(ports []int, n int) []int {
	if len(ports) <= n {
		return ports
	}
	return ports[:n]
}

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

const wsmanConnectTimeout = 1500 * time.Millisecond

func collectWSMAN(t *engine.Target, a *acc) {
	ports := []int{5986, 5985, 16993, 16992, 443}
	if p := httpsPort(t); p > 0 {
		ports = append(ports, p)
	}

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

func collectLantronix(t *engine.Target, a *acc) {
	r, err := lantronix.Query(t.Host, t.Timeout)
	if err != nil || r == nil {
		return
	}
	t.SetEvidence("lantronix", r)
	t.MarkOpen(30718, "udp", "lantronix")
	a.forceClass(engine.ClassSerialConsole)
	a.addVendor("lantronix", r.Model, "", engine.ConfHigh, "lantronix")

	if r.Firmware != "" {
		a.setAttr("device.fw", r.Firmware)
	}
	if r.MAC != "" {
		a.setAttr("mac", r.MAC)
	}
	if banner, _, ok, err := lantronix.ProbeSetupTelnet(t.Host, t.Timeout); err == nil && banner != "" {
		t.MarkOpen(lantronix.SetupTelnetPort, "tcp", "telnet")
		cleanBanner := sanitizeIdentityText(banner)

		if cleanBanner != "" && (ok || looksLantronixTelnetBanner(cleanBanner)) {
			t.SetEvidence("lantronix.telnet", cleanBanner)
			a.setAttr("lantronix.setup_telnet", cleanBanner)
		}
		if ok {
			a.addVendor("lantronix", r.Model, "", engine.ConfHigh, "lantronix.telnet")
		}
	}
}

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

func sanitizeIdentityText(raw string) string {
	if raw == "" {
		return ""
	}
	return strings.TrimSpace(string(sanitize.Bytes([]byte(raw))))
}

func looksLantronixTelnetBanner(banner string) bool {
	trim := strings.TrimSpace(banner)
	if trim == "" {
		return false
	}
	low := strings.ToLower(trim)
	if strings.HasPrefix(low, "http/1.") || strings.HasPrefix(low, "<html") {
		return false
	}

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
		a.setAttr("device.fw", r.Firmware)
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

func collectSLP(t *engine.Target, a *acc) {

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

	if v := slp.VendorFromURLs(urls); v != "" {
		a.addVendor(v, "", "", engine.ConfMedium, "slp")
	}
}

var sshIdentifyPorts = []int{22, 2222}

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

		a.addFP(bmcfp.SSHBanner, ssh.SoftwareVersion(banner))
		return
	}
}

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
			a.addFP(bmcfp.HTTPServerHeader, res.Server)
		}
		a.log(fmt.Sprintf("cim %s:%d broker=%q server=%q", pc.scheme, pc.port, res.Broker, res.Server))
		return
	}
}

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

func collectSNMP(t *engine.Target, a *acc) {
	per := udpPerAttempt(t.Timeout)
	found := false

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

		if v := snmp.VendorBySysDescr(pub.SysDescr); v != "" {
			a.addVendor(v, "", "", engine.ConfMedium, "snmp.sysdescr")
		}

		for _, ver := range []int{1, 0} {
			if r, err := snmp.Probe(t.Host, 161, "private", ver, per); err == nil && r != nil && r.Responded {
				t.SetEvidence("snmp.private", r)
				break
			}
		}

		collectSNMPHostInventory(t, a, pub)
	}

	if v3, err := snmp.ProbeV3(t.Host, 161, per); err == nil && v3 != nil {
		found = true
		t.SetEvidence("snmpv3", v3)
		a.setAttr("snmp.engine_id", v3.EngineID)

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
