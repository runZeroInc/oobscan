package check

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/httpscan"
	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

var (
	httpSurfaceMinPerRequest = 3 * time.Second

	httpSurfaceMinCanary = 8 * time.Second
	httpSurfaceMaxCanary = 10 * time.Second

	httpSurfaceCanaryBudget = 20 * time.Second
)

func httpSurfaceCanaryTimeout(t *engine.Target) time.Duration {
	return min(max(t.Timeout, httpSurfaceMinCanary), httpSurfaceMaxCanary)
}

func init() {
	Register(Check{
		Name:        "http.surface",
		Description: "Firmware-derived HTTP/CGI endpoint sweep (pre-auth readable data, upload surfaces)",
		Category:    "http",
		Applies:     Applicability{Classes: []engine.DeviceClass{engine.ClassBMC}},
		Enabled:     true,
		Run:         runHTTPSurface,
	})
}

func runHTTPSurface(ctx context.Context, t *engine.Target) []engine.Finding {
	port := webPort(t)
	proto := webProto(t)

	per := max(t.Timeout, httpSurfaceMinPerRequest)

	sweepCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	rep, err := httpscan.ProbeHostCtxForVendorsScheme(sweepCtx, t.Host, port, proto, per, httpSurfaceVendorScope(t)...)
	if err != nil || rep == nil {
		return nil
	}
	t.SetEvidence("http", rep)

	if s := rep.HTTPSummary; s.RequestsAttempted > 0 && s.RequestsFailed == s.RequestsAttempted {

		if identifyReadWebSurface(t, port) {
			return nil
		}

		if r := iloSurface(t); r != nil && r.port == port {
			return nil
		}

		canaryTimeout := httpSurfaceCanaryTimeout(t)
		if httpSurfaceCanaryReachable(ctx, t.Host, port, proto, canaryTimeout) {
			return nil
		}

		return []engine.Finding{{
			Check: "http.surfaceUnreachable", Category: "http", Risk: "info",
			Port: port, Transport: "tcp", Protocol: proto,
			Fields: engine.F(
				"endpointsTested", fmt.Sprintf("%d", s.EndpointsTested),
				"requestsFailed", fmt.Sprintf("%d/%d", s.RequestsFailed, s.RequestsAttempted),
				"scheme", proto,
				"sweepBudget", per.String(),
				"canaryPaths", fmt.Sprintf("%d", len(httpSurfaceCanaryPaths)),
				"canaryStatus", "noReply",
				"canaryBudget", canaryTimeout.String()),
		}}
	}

	var out []engine.Finding
	const maxEndpoints = 25
	for _, ef := range rep.HTTPFindings {
		if len(out) >= maxEndpoints {
			break
		}
		rr := pickHTTPRequest(ef)
		interesting := normalizeHTTPSurfaceInteresting(rr.URL, rr.Interest)
		if suppressHTTPSurfaceEndpoint(rr.URL, interesting) {
			continue
		}
		switch {
		case exposureConfirmed(rr, interesting):
			fields := engine.F(
				"url", rr.URL,
				"method", rr.Method,
				"httpStatus", fmt.Sprintf("%d", rr.Status),
				"match", strings.Join(interesting, ","),
				"response", describeResponse(rr))
			out = append(out, engine.Finding{
				Check: "http.exposure", Category: "http", Risk: httpRisk(interesting),
				Port: port, Transport: "tcp", Protocol: proto,
				Fields: append(fields, fingerprintFields(rr.Fingerprint)...),
			})
		case rr.Status >= 200 && rr.Status < 300 && (strings.TrimSpace(rr.Snippet) != "" || !rr.Fingerprint.Empty()):
			fields := engine.F(
				"url", rr.URL,
				"method", rr.Method,
				"httpStatus", fmt.Sprintf("%d", rr.Status),
				"response", describeResponse(rr))
			out = append(out, engine.Finding{
				Check: "http.endpoint", Category: "http", Risk: "info",
				Port: port, Transport: "tcp", Protocol: proto,
				Fields: append(fields, fingerprintFields(rr.Fingerprint)...),
			})
		}
	}
	return collapseHTTPExposureDuplicates(out)
}

var httpSurfaceCanaryPaths = []string{"/xmldata?item=all", "/redfish/v1/", "/", "/login.html"}

func httpSurfaceCanaryReachable(ctx context.Context, host string, port int, scheme string, timeout time.Duration) bool {
	if host == "" || port <= 0 {
		return false
	}

	client := httpx.NewClient(httpx.ClientOptions{Timeout: timeout, PhaseCeiling: timeout})
	base := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
	deadline := time.Now().Add(httpSurfaceCanaryBudget)
	for i, path := range httpSurfaceCanaryPaths {
		if i > 0 && time.Now().After(deadline) {
			break
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode > 0 {
			return true
		}
	}
	return false
}

func httpSurfaceVendorScope(t *engine.Target) []string {
	if t == nil || t.Identity == nil {
		return nil
	}
	vendor := strings.ToLower(strings.TrimSpace(t.Identity.Vendor))
	switch vendor {
	case "dell", "hpe", "lenovo", "cisco", "huawei", "intel", "fujitsu":
		return []string{vendor}
	default:
		return nil
	}
}

func suppressHTTPSurfaceEndpoint(rawURL string, interesting []string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.TrimSpace(u.Path)
	if path == "/page/topmenu.www" || path == "/cgi/url_redirect.cgi" {
		return true
	}
	if len(interesting) == 0 && (path == "/redfish/v1" || path == "/redfish/v1/") {

		return false
	}
	return false
}

func normalizeHTTPSurfaceInteresting(rawURL string, tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return tags
	}
	path := strings.TrimSpace(u.Path)
	switch {
	case path == "/redfish" || path == "/redfish/" ||
		path == "/redfish/v1" || path == "/redfish/v1/" ||
		path == "/$metadata" || strings.HasSuffix(path, "/$metadata"):
		return dropTags(tags, "possibleDataLeak", "preAuthReadable", "staticDisclosure")
	case isLogoutPath(path):
		return dropTags(tags, "possibleDataLeak")
	}
	return tags
}

func isLogoutPath(path string) bool {
	base := path
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	return strings.EqualFold(base, "logout")
}

func dropTags(tags []string, drop ...string) []string {
	if len(tags) == 0 {
		return tags
	}
	dropset := make(map[string]struct{}, len(drop))
	for _, d := range drop {
		dropset[d] = struct{}{}
	}
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		if _, ok := dropset[tag]; ok {
			continue
		}
		out = append(out, tag)
	}
	return out
}

func collapseHTTPExposureDuplicates(in []engine.Finding) []engine.Finding {
	if len(in) == 0 {
		return in
	}
	type bucket struct {
		idx  int
		urls []string
	}
	out := make([]engine.Finding, 0, len(in))
	buckets := map[string]*bucket{}
	for _, f := range in {
		if f.Check != "http.exposure" {
			out = append(out, f)
			continue
		}
		match := findingField(f, "match")
		key := match
		if match == "" {

			out = append(out, f)
			continue
		}
		if b, ok := buckets[key]; ok {
			if u := findingField(f, "url"); u != "" {
				b.urls = append(b.urls, u)
			}
			continue
		}
		buckets[key] = &bucket{idx: len(out)}
		out = append(out, f)
	}
	for _, b := range buckets {
		if len(b.urls) == 0 {
			continue
		}
		primary := &out[b.idx]
		primaryURL := findingField(*primary, "url")
		urls := append([]string{primaryURL}, b.urls...)
		primary.Fields = append(primary.Fields,
			engine.Field{Key: "urlCount", Val: strconv.Itoa(len(urls))},
			engine.Field{Key: "extraUrls", Val: strings.Join(b.urls, ",")},
		)
	}
	return out
}

func findingField(f engine.Finding, key string) string {
	want := engine.CanonicalFieldKey(key)
	for _, kv := range f.Fields {
		if engine.CanonicalFieldKey(kv.Key) == want {
			return kv.Val
		}
	}
	return ""
}

func exposureConfirmed(rr httpscan.RequestResult, interesting []string) bool {
	return hasHTTPExposureProof(interesting) &&
		rr.Status >= 200 && rr.Status < 300 &&
		strings.TrimSpace(rr.Snippet) != ""
}

func hasHTTPExposureProof(tags []string) bool {
	for _, tag := range tags {
		switch tag {
		case "possibleDataLeak", "preAuthReadable", "staticDisclosure", "kvm.launchTokenLeak":
			return true
		}
	}
	return false
}

func pickHTTPRequest(ef httpscan.EndpointResult) httpscan.RequestResult {

	hasBody := func(rr httpscan.RequestResult) bool { return strings.TrimSpace(rr.Snippet) != "" }
	for _, rr := range ef.Requests {
		if len(rr.Interest) > 0 && hasBody(rr) {
			return rr
		}
	}
	for _, rr := range ef.Requests {
		if len(rr.Interest) > 0 {
			return rr
		}
	}
	for _, rr := range ef.Requests {
		if rr.Status >= 200 && rr.Status < 300 && hasBody(rr) {
			return rr
		}
	}
	for _, rr := range ef.Requests {
		if hasBody(rr) {
			return rr
		}
	}
	for _, rr := range ef.Requests {
		if rr.Status >= 200 && rr.Status < 300 {
			return rr
		}
	}
	if len(ef.Requests) > 0 {
		return ef.Requests[0]
	}
	return httpscan.RequestResult{}
}

func fingerprintFields(fp httpscan.Fingerprint) engine.Fields {
	archiveCount := ""
	if fp.ArchiveCount > 0 {
		archiveCount = strconv.Itoa(fp.ArchiveCount)
	}
	return engine.F(
		"version", fp.Version,
		"redfishVersion", fp.RedfishVersion,
		"odataVersion", fp.ODataVersion,
		"product", fp.Product,
		"model", fp.Model,
		"serial", fp.Serial,
		"firmware", fp.Firmware,
		"manufacturer", fp.Manufacturer,
		"fingerprint", fp.Fingerprint,
		"archiveCount", archiveCount,
		"archiveContents", sampleCSV(fp.ArchiveContents, 12),
	)
}

func sampleCSV(s string, n int) string {
	if s == "" {
		return s
	}
	parts := strings.Split(s, ",")
	if len(parts) <= n {
		return s
	}
	return strings.Join(parts[:n], ",") + ",…"
}

func httpRisk(tags []string) string {
	rank := 0
	for _, tag := range tags {
		switch tag {
		case "possibleDataLeak", "kvm.launchTokenLeak":
			if rank < 2 {
				rank = 2
			}
		case "preAuthReadable", "staticDisclosure":
			if rank < 1 {
				rank = 1
			}
		}
	}
	switch rank {
	case 3:
		return "high"
	case 2:
		return "medium"
	case 1:
		return "low"
	default:
		return "info"
	}
}

var binaryMagics = []struct{ magic, kind string }{
	{"7zXZ", "xz"},
	{"PK\x03\x04", "zip/jar"},
	{"hsqs", "squashfs"},
	{"sqsh", "squashfs"},
	{"PNG", "png"},
	{"ELF", "elf"},
	{"ustar", "tar"},
	{"JFIF", "jpeg"},
	{"CrAU", "chromeos-update"},
	{"UBI#", "ubi"},

	{"\x1f\x8b\x08", "gzip"},
	{"\x28\xb5\x2f\xfd", "zstd"},
}

func binarySnippetDescriptor(s string) string {
	kind, pct, ok := binarySnippetKind(s, "")
	if !ok {
		return ""
	}
	return fmt.Sprintf("<%s body, %d snippet bytes, %d%% printable>", kind, len(s), pct)
}

func binaryMagicKind(s string) string {
	head := s[:min(len(s), 32)]
	for _, m := range binaryMagics {
		if strings.Contains(head, m.magic) {
			return m.kind
		}
	}
	return ""
}

func declaredTextBody(contentType string) bool {
	ct := strings.ToLower(responseContentType(contentType))
	if ct == "" {
		return false
	}
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	switch ct {
	case "application/json", "application/xml", "application/xhtml+xml",
		"application/javascript", "application/x-javascript", "application/ecmascript":
		return true
	}
	return strings.HasSuffix(ct, "+json") || strings.HasSuffix(ct, "+xml")
}

const binarySnippetMinNonPrintablePct = 15

func replacementRuneBytes(s string) int {
	return strings.Count(s, string(utf8.RuneError)) * len(string(utf8.RuneError))
}

func printableASCIIBytes(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f) {
			n++
		}
	}
	return n
}

const binarySnippetMinTextResidue = 16

func decodedTextResidue(s string) bool {
	residue := strings.ReplaceAll(s, string(utf8.RuneError), "")
	if len(residue) < binarySnippetMinTextResidue {
		return false
	}
	return printableASCIIBytes(residue)*100/len(residue) >= 100-binarySnippetMinNonPrintablePct
}

func binarySnippetKind(s, contentType string) (kind string, pct int, ok bool) {
	if len(s) < 16 {
		return "", 0, false
	}
	magic := binaryMagicKind(s)

	if magic == "" && declaredTextBody(contentType) {
		return "", 0, false
	}

	if utf8.ValidString(s) && replacementRuneBytes(s)*100/len(s) < binarySnippetMinNonPrintablePct {
		return "", 0, false
	}

	if magic == "" && decodedTextResidue(s) {
		return "", 0, false
	}
	pct = printableASCIIBytes(s) * 100 / len(s)

	if pct >= 100-binarySnippetMinNonPrintablePct {
		return "", 0, false
	}
	kind = magic
	if kind == "" {
		kind = "binary"
	}
	return kind, pct, true
}

func describeResponse(rr httpscan.RequestResult) string {
	kind, pct, ok := binarySnippetKind(rr.Snippet, rr.ContentType)
	if !ok {

		return quoteSnippet(rr.Snippet)
	}
	size := rr.BodyBytes
	if size <= 0 {
		size = len(rr.Snippet)
	}
	if ct := responseContentType(rr.ContentType); ct != "" {
		return fmt.Sprintf("<%s body, %s, %d bytes, %d%% printable>", kind, ct, size, pct)
	}
	return fmt.Sprintf("<%s body, %d bytes, %d%% printable>", kind, size, pct)
}

func responseContentType(ct string) string {
	ct, _, _ = strings.Cut(ct, ";")
	b := make([]byte, 0, len(ct))
	for i := 0; i < len(ct) && len(b) < 48; i++ {
		if c := ct[i]; c > 0x20 && c < 0x7f && c != '<' && c != '>' && c != ',' {
			b = append(b, c)
		}
	}
	return string(b)
}

func cleanSnippet(s string) string {
	if d := binarySnippetDescriptor(s); d != "" {
		return d
	}
	return quoteSnippet(s)
}

func quoteSnippet(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			b = append(b, ' ')
		case c >= 0x20 && c < 0x7f:
			b = append(b, c)
		}

	}
	out := strings.Join(strings.Fields(string(b)), " ")
	if len(out) > 160 {
		out = out[:160]
	}
	return out
}

func httpsPort(t *engine.Target) int {
	preferred := []int{443, 444, 8443, 9443, 4443, 4433, 10443, 7443, 6443, 4444, 8083, 7548, 9898, 4434, 8081}
	hasTCP := map[int]bool{}
	for _, p := range t.Ports {
		if p.Proto == engine.ProtoTCP {
			hasTCP[p.Num] = true
		}
	}
	for _, p := range preferred {
		if p == 443 || hasTCP[p] {
			return p
		}
	}
	return 443
}

func webPort(t *engine.Target) int {
	if t.Identity != nil && t.Identity.Attributes != nil {
		if s := t.Identity.Attributes["web.port"]; s != "" {
			if n, err := strconv.Atoi(s); err == nil && n > 0 {
				return n
			}
		}
	}
	return httpsPort(t)
}

func identifyReadWebSurface(t *engine.Target, port int) bool {
	if t == nil || t.Identity == nil || port <= 0 {
		return false
	}
	attrs := t.Identity.Attributes

	if wp := attrs["web.port"]; wp != "" && wp != strconv.Itoa(port) {
		return false
	}
	if strings.TrimSpace(attrs["http.server"]) != "" || strings.TrimSpace(attrs["http.title"]) != "" {
		return true
	}

	for _, s := range t.Identity.Signals {
		if s.Source == "ilo" {
			return true
		}
	}
	return false
}

func webProto(t *engine.Target) string {
	if t.Identity != nil && t.Identity.Attributes != nil {
		if s := t.Identity.Attributes["web.scheme"]; s == "http" || s == "https" {
			return s
		}
	}
	return netaddr.DefaultScheme(webPort(t))
}

func init() {
	RegisterExplain("http.surface", explainHTTPSurface)
}

func explainHTTPSurface(host string, f engine.Finding) string {
	url := explainField(f, "url")
	baseURL := explainBaseURL(host, f, 443, "https")
	if url == "" {
		url = "/"
	}
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nA pre-auth readable HTTP endpoint was confirmed.\n")
	b.WriteString("\n**Retrieve:**\n")
	b.WriteString(explainSh(fmt.Sprintf("curl -sk %s%s | head -40", baseURL, url)))
	return b.String()
}
