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

// These are the sweep and canary budgets. They are variables rather than constants
// so a test can scale them down together and keep the relationships between them:
// a test that waits out the production budgets spends a minute of wall clock proving
// something a tenth of that would prove just as well.
var (
	// httpSurfaceMinPerRequest is the floor on the sweep's per-request timeout. A
	// BMC TLS handshake alone can take multiple seconds; anything tighter reports
	// transport failures that are the scanner's, not the target's.
	httpSurfaceMinPerRequest = 3 * time.Second
	// httpSurfaceMinCanary and httpSurfaceMaxCanary bound the sequential reachability
	// canary, and together mirror the fingerprint stage's web budget. The canary exists
	// to second-guess the sweep, so budgeting it like the sweep made it agree with the
	// sweep by construction: a BMC that needs several seconds just to finish a TLS
	// handshake is read fine during fingerprinting and then fails every sweep request,
	// and the port was reported dead on a surface that demonstrably answers. Matching
	// the stage that did read it is what makes the second opinion worth taking.
	httpSurfaceMinCanary = 8 * time.Second
	httpSurfaceMaxCanary = 10 * time.Second
	// httpSurfaceCanaryBudget bounds the whole canary loop. Each path gets the full
	// per-request budget, but a host that stalls every path must not hold the check
	// for the sum of them; a new path is only started while this remains.
	httpSurfaceCanaryBudget = 20 * time.Second
)

// httpSurfaceCanaryTimeout mirrors identify's webIdentifyTimeout so the canary
// measures the surface on the same budget the fingerprint stage did.
func httpSurfaceCanaryTimeout(t *engine.Target) time.Duration {
	return min(max(t.Timeout, httpSurfaceMinCanary), httpSurfaceMaxCanary)
}

// The HTTP surface sweep walks the firmware-derived endpoint list looking for
// pre-auth readable data and upload surfaces, bounded by a short per-request timeout
// and a hard wall-clock cap so a hanging web UI cannot stall the scan.
//
// ClassBMC only: managed PDUs and console servers front their UI with a
// tiny-connection-pool embedded server that buckles under concurrent connects, so
// their pre-auth endpoints are confirmed sequentially by pdu.confirm instead.
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
	// The per-request budget has to cover a slow embedded TLS handshake: iLO4 and
	// iDRAC routinely need seconds just for the handshake, and a tighter cap reports
	// transport failures the target never had. The sweep deadline below is what bounds
	// the sweep.
	per := max(t.Timeout, httpSurfaceMinPerRequest)

	// Bound the whole endpoint sweep with a wall-clock deadline. ProbeHostCtx honors
	// the deadline and returns the partial results gathered so far rather than
	// nothing, so a large endpoint list or a slow BMC still surfaces the endpoints it
	// reached instead of the sweep being silently discarded.
	sweepCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	// Use the observed scheme rather than guessing from the port, since an
	// HTTP-only web tier on a non-standard port would otherwise be swept as HTTPS.
	rep, err := httpscan.ProbeHostCtxForVendorsScheme(sweepCtx, t.Host, port, proto, per, httpSurfaceVendorScope(t)...)
	if err != nil || rep == nil {
		return nil
	}
	t.SetEvidence("http", rep)

	// If every request failed at the transport layer, the sweep found nothing but
	// never really ran -- record that distinctly rather than reporting a clean host.
	if s := rep.HTTPSummary; s.RequestsAttempted > 0 && s.RequestsFailed == s.RequestsAttempted {
		// A completed HTTP read of this surface is already on file, taken on a budget
		// the sweep does not match. That read is the stronger measurement, so a sweep
		// that failed says the sweep's bounds were too tight, not that the port is dead.
		if identifyReadWebSurface(t, port) {
			return nil
		}
		// The iLO disclosure checks publish against this port from a pre-auth
		// /xmldata read of their own, and they run alongside this one. Resolve that
		// read here, through the helper they publish from, so the outcome does not
		// depend on which check got there first: the first caller performs the one
		// read and every later caller is handed that same answer. A read that
		// answered on this port is what those findings rest on, and it settles the
		// claim about to be made here.
		if r := iloSurface(t); r != nil && r.port == port {
			return nil
		}
		// A saturated/slow embedded web tier can time out the concurrent sweep while
		// still serving normal requests. Before claiming the whole surface is
		// unreachable, verify with a direct sequential request on a larger budget.
		canaryTimeout := httpSurfaceCanaryTimeout(t)
		if httpSurfaceCanaryReachable(ctx, t.Host, port, proto, canaryTimeout) {
			return nil
		}
		// Scoped to the sweep, not to the port: this records that the endpoint list
		// this sweep walked produced no answers on the stated budget, and names that
		// budget so the reader can tell a slow surface from a dead one. requestsFailed
		// always equals requestsAttempted inside this branch, so report them as one
		// ratio rather than two fields that can never disagree.
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

	// One finding per endpoint. A response with proof-bearing data tags is an
	// http.exposure; route reachability and static UI fingerprints remain an
	// informational http.endpoint. 401/403/404/redirects with no body are skipped.
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

// httpSurfaceCanaryPaths are the cheap static routes the canary tries. Root ("/")
// alone is not a usable reachability oracle: on an iLO4 or iDRAC it serves the heavy
// single-page app and frequently stalls while the small static handlers on the same
// port answer instantly. Ordered cheapest-first so the common case exits after one
// request.
var httpSurfaceCanaryPaths = []string{"/xmldata?item=all", "/redfish/v1/", "/", "/login.html"}

// httpSurfaceCanaryReachable reports whether the web surface answers any of a
// handful of cheap routes. Any HTTP status counts, including 401/403/404: the
// question is whether the transport and web tier are alive, not whether the route
// exists. Only a total failure across every path justifies surfaceUnreachable.
func httpSurfaceCanaryReachable(ctx context.Context, host string, port int, scheme string, timeout time.Duration) bool {
	if host == "" || port <= 0 {
		return false
	}
	// PhaseCeiling moves with the timeout, as the fingerprint stage's client does. Each
	// phase is derived from the whole-request timeout and then clamped by the ceiling,
	// so a canary handed a longer budget without it silently keeps the shorter handshake
	// the default ceiling allows and reproduces the sweep's failure instead of testing
	// it.
	client := httpx.NewClient(httpx.ClientOptions{Timeout: timeout, PhaseCeiling: timeout})
	base := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
	deadline := time.Now().Add(httpSurfaceCanaryBudget)
	for i, path := range httpSurfaceCanaryPaths {
		if i > 0 && time.Now().After(deadline) {
			break
		}
		// GET only. HEAD is unimplemented or silently dropped on a good share of
		// embedded BMC web tiers, so a HEAD failure says nothing about reachability.
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
		// Keep Redfish service-root as an informational endpoint, not a leak exposure.
		return false
	}
	return false
}

// normalizeHTTPSurfaceInteresting drops leak-implying interest tags from endpoints
// that carry no device data, so they collapse to informational while keeping any
// structured fingerprint the body yielded. possibleDataLeak matches a bare
// "serial"/"session"/"firmware" substring, which two classes of endpoint trip
// without leaking anything:
//
//   - the Redfish service root and the OData $metadata document, static spec-defined
//     schemas whose property names are type names, never values.
//   - logout CGIs, session-teardown stubs where the word "session" is expected.
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

// isLogoutPath reports whether path is a logout/session-teardown navigation stub
// (e.g. /cgi/logout.cgi, /logout, /logout.html). Its body reliably contains the
// word "session", which the possibleDataLeak heuristic would otherwise flag as a
// data leak.
func isLogoutPath(path string) bool {
	base := path
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	if i := strings.IndexByte(base, '.'); i >= 0 { // drop trailing extension
		base = base[:i]
	}
	return strings.EqualFold(base, "logout")
}

// dropTags returns tags with every value in drop removed, preserving order.
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

// collapseHTTPExposureDuplicates merges http.exposure findings that share the
// same match signature. Firmware often maps many URLs to equivalent pre-auth
// surfaces; grouping by match keeps one primary finding while preserving
// additional URLs in extraUrls/urlCount.
func collapseHTTPExposureDuplicates(in []engine.Finding) []engine.Finding {
	if len(in) == 0 {
		return in
	}
	type bucket struct {
		idx  int      // index in `out` for the primary finding
		urls []string // additional URLs (excluding the primary)
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
			// Without a match signature we cannot safely collapse.
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

// findingField returns the first field value matching key (empty string when
// absent). Kept package-private and small to avoid importing engine helpers.
func findingField(f engine.Finding, key string) string {
	want := engine.CanonicalFieldKey(key)
	for _, kv := range f.Fields {
		if engine.CanonicalFieldKey(kv.Key) == want {
			return kv.Val
		}
	}
	return ""
}

// exposureConfirmed reports whether an endpoint result is a proof-carrying
// http.exposure: an interesting endpoint whose representative response is a 2xx
// that actually served a body. A non-2xx (401/403 auth-gated, 404 absent, 3xx
// redirect) proves the opposite - the resource is protected or absent - and an
// empty body (e.g. a HEAD probe that only proves the route exists) demonstrates
// nothing readable. Dropping both is what keeps an auth-gated upload CGI from
// over-rated and an empty HEAD 200 from being flagged "preAuthReadable".
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

// pickHTTPRequest chooses the representative request for an endpoint: one that
// triggered an interest tag, else a 2xx, else the first.
func pickHTTPRequest(ef httpscan.EndpointResult) httpscan.RequestResult {
	// Prefer, in order: an interesting request that carries a body, any
	// interesting request, a 2xx with a body, any body-bearing request, a 2xx,
	// then the first. Preferring a body-bearing method (GET/POST over HEAD) means
	// the response snippet is populated whenever the endpoint returns one.
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

// fingerprintFields renders the structured identity/version data scraped from a
// response body (see httpscan.FingerprintBody) as ordered finding fields. Every
// field is optional and engine.F drops the empties, so a body that yielded nothing
// adds no fields. These are added alongside the existing url/method/http_status/
// match/response fields, never replacing them, so schema consumers stay intact.
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

// sampleCSV returns the first n comma-separated items of s with a ",…" suffix
// when more remain. The exact count is carried in archiveCount, so the full
// list (up to ~10 KB of standard Redfish schema filenames) need not be dumped.
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

// httpRisk maps proof-bearing tags to risk: credential/token data is medium,
// readable data is low, and mere route reachability is informational. An upload
// route is not write proof and therefore does not raise risk by itself.
func httpRisk(tags []string) string {
	rank := 0 // 0 info, 1 low, 2 medium, 3 high
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

// binaryMagics maps the printable part of a container magic to its label, for
// naming a binary body instead of quoting bytes from it.
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
	// gzip and zstd are what a web tier most often hands back for a log or config
	// download, and mislabelling one as text is common. Their magics are non-ASCII,
	// so the substring match below cannot trip on prose that merely mentions them --
	// which is why the ASCII-magic entries above stay a short, deliberate list.
	{"\x1f\x8b\x08", "gzip"},
	{"\x28\xb5\x2f\xfd", "zstd"},
}

// binarySnippetDescriptor returns a compact description when the snippet is a binary
// body rather than the HTML/XML/JSON a BMC web tier normally serves, or "" when it is
// text and should be quoted as-is. Dropping the non-printable bytes and keeping the
// surviving ASCII yields a husk that reads as text but cannot be verified; a type and
// a size can.
func binarySnippetDescriptor(s string) string {
	kind, pct, ok := binarySnippetKind(s, "")
	if !ok {
		return ""
	}
	return fmt.Sprintf("<%s body, %d snippet bytes, %d%% printable>", kind, len(s), pct)
}

// binaryMagicKind names the container whose magic opens the snippet, or "" for
// none. Only the head is inspected: a magic further in is a mention, not a body.
func binaryMagicKind(s string) string {
	head := s[:min(len(s), 32)]
	for _, m := range binaryMagics {
		if strings.Contains(head, m.magic) {
			return m.kind
		}
	}
	return ""
}

// declaredTextBody reports whether a Content-Type names a media type whose body is
// text. Charset is irrelevant here: the question is what the device says it served,
// not how it encoded it.
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

// binarySnippetMinNonPrintablePct is the share of a snippet that has to be bytes no
// text body would carry before it is called binary.
const binarySnippetMinNonPrintablePct = 15

// replacementRuneBytes returns how many of s's bytes encode U+FFFD.
func replacementRuneBytes(s string) int {
	return strings.Count(s, string(utf8.RuneError)) * len(string(utf8.RuneError))
}

// printableASCIIBytes counts the bytes of s a text body is made of: printable
// ASCII plus the three whitespace controls.
func printableASCIIBytes(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f) {
			n++
		}
	}
	return n
}

// binarySnippetMinTextResidue is how many decoded bytes a snippet has to have left
// before their shape is allowed to answer the question. Below it there is too
// little to read either way.
const binarySnippetMinTextResidue = 16

// decodedTextResidue reports whether what is left of a snippet once the replacement
// runes are dropped reads as text. A dense run of replacement runes is what any
// undecodable byte sequence leaves behind, so on its own it separates nothing: a
// page in a legacy charset and a truncated archive both produce one. The bytes that
// did decode do separate them. A page keeps the ASCII skeleton its markup is made
// of -- tags, attribute names, punctuation -- while an archive keeps the raw control
// bytes that happened to be valid UTF-8 and read as nothing. Deciding on those bytes
// is what covers a device that declares no content type at all, and the callers that
// have no header to pass.
func decodedTextResidue(s string) bool {
	residue := strings.ReplaceAll(s, string(utf8.RuneError), "")
	if len(residue) < binarySnippetMinTextResidue {
		return false
	}
	return printableASCIIBytes(residue)*100/len(residue) >= 100-binarySnippetMinNonPrintablePct
}

// binarySnippetKind classifies a response snippet, returning the container kind and
// the printable-byte percentage when it is binary, and ok=false when it is text.
// contentType is the type the response declared, "" when the caller has none.
func binarySnippetKind(s, contentType string) (kind string, pct int, ok bool) {
	if len(s) < 16 {
		return "", 0, false
	}
	magic := binaryMagicKind(s)
	// What the response said it served settles it, so long as the bytes do not
	// contradict the declaration. It is the one thing that still speaks for a body
	// with no ASCII left to judge -- a page whose text is entirely non-ASCII in a
	// legacy charset such as Shift_JIS, GBK or windows-1251 is undecodable as UTF-8
	// and comes out of the rune-wise truncation below dense in replacement runes,
	// exactly like a truncated archive, and calling it binary discards readable
	// evidence and prints a descriptor that names a text media type. A container
	// magic at the head outranks the declaration: a device that labels a jar
	// text/html is wrong about its own body.
	// What the response said it served settles it, so long as the bytes do not
	// contradict the declaration. Byte shape cannot take this decision: the snippet
	// arrives after a rune-wise truncation that rewrites every undecodable byte as
	// U+FFFD, so a page in a legacy charset and a truncated archive are identical
	// here -- both are replacement runes end to end. Calling that binary discards
	// readable evidence and prints a descriptor naming a text media type. A container
	// magic at the head does contradict the declaration and outranks it: a device
	// that labels a jar text/html is wrong about its own body. A binary body with no
	// recognised magic and a text label is not separable from prose at this point and
	// is knowingly left as text.
	if magic == "" && declaredTextBody(contentType) {
		return "", 0, false
	}
	// Nothing to go on but byte shape from here, and validity alone cannot separate
	// text from binary. The snippet reaches this function after a rune-wise truncation
	// that re-encodes every byte it could not decode as U+FFFD, so any body longer than
	// the truncation length arrives valid UTF-8 whatever it held, and treating validity
	// as proof of text lets every truncated archive through. What survives that rewrite
	// is the replacement runes: each one stands for a byte that did not decode. A
	// valid-UTF-8 snippet is text unless they cover a large enough share of it, which
	// keeps a page that is legitimately low on printable ASCII -- and free to carry the
	// odd replacement glyph of its own -- out of the binary bucket. The share matches
	// the non-printable margin the ratio test below allows. Their bytes are
	// non-printable and count against that ratio too.
	if utf8.ValidString(s) && replacementRuneBytes(s)*100/len(s) < binarySnippetMinNonPrintablePct {
		return "", 0, false
	}
	// Replacement runes are dense. A declared type is not always there to appeal to
	// -- an embedded CGI often sends no Content-Type, and the snippet cleaner has no
	// header to pass on at all -- so fall back to the shape of the bytes that did
	// decode. A container magic at the head still outranks them.
	if magic == "" && decodedTextResidue(s) {
		return "", 0, false
	}
	pct = printableASCIIBytes(s) * 100 / len(s)
	// BMC text bodies are all but entirely printable. Below this, the body is an
	// archive, an image or a firmware blob.
	if pct >= 100-binarySnippetMinNonPrintablePct {
		return "", 0, false
	}
	kind = magic
	if kind == "" {
		kind = "binary"
	}
	return kind, pct, true
}

// describeResponse renders a response for a finding's `response` field. A binary body
// is named -- container kind, served content type, full body size -- rather than
// quoted: the printable residue of a compressed body reads like text but proves
// nothing, while a type and a size can be rechecked. Text is quoted as before.
// Unlike cleanSnippet this reports the whole body's size, not the snippet's, since
// the request result still carries it.
func describeResponse(rr httpscan.RequestResult) string {
	kind, pct, ok := binarySnippetKind(rr.Snippet, rr.ContentType)
	if !ok {
		// Quote directly rather than through cleanSnippet: cleanSnippet reclassifies
		// with no content type to hand, and would call this body binary again.
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

// responseContentType reduces a Content-Type header to its bare media type, keeping
// only printable ASCII and a short cap. The header is target-controlled and is being
// placed inside a descriptor, so it is bounded rather than echoed.
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

// cleanSnippet renders a response snippet as one readable field value. A binary
// body is described rather than quoted (see binarySnippetDescriptor); text keeps
// only printable ASCII, then collapses whitespace and caps the length. Operating
// byte-wise avoids the U+FFFD noise produced when invalid UTF-8 is decoded
// rune-wise.
func cleanSnippet(s string) string {
	if d := binarySnippetDescriptor(s); d != "" {
		return d
	}
	return quoteSnippet(s)
}

// quoteSnippet renders a snippet already judged to be text: printable ASCII only,
// whitespace collapsed, length capped.
func quoteSnippet(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			b = append(b, ' ')
		case c >= 0x20 && c < 0x7f: // printable ASCII (incl. space)
			b = append(b, c)
		}
		// everything else (control + high/binary bytes) is dropped
	}
	out := strings.Join(strings.Fields(string(b)), " ")
	if len(out) > 160 {
		out = out[:160]
	}
	return out
}

// httpsPort mirrors identify's port selection: 443 unless the target lists an
// alternate TLS port.
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

// webPort returns the web port identify actually found reachable (HTTP or
// HTTPS), recorded on the Identity as "web.port". Follow-up HTTP sweeps use it
// so they reach HTTP-only devices - many managed PDUs and legacy console/NMC
// cards disable HTTPS, and probing 443 alone returned nothing. Falls back to
// the TLS-port default when identify recorded no web port. Reading
// Identity.Attributes is race-free: the Identity is fixed before checks run.
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

// identifyReadWebSurface reports whether a completed pre-auth HTTP read of the
// surface this port names is already on file. The fingerprint stage allows a slow
// embedded TLS handshake the whole request budget, where the check battery clamps
// every phase to a fast-fail ceiling, so a weak-SoC BMC is routinely read there and
// then fails every request here. Callers use it to avoid reporting a surface as
// unreachable when it has demonstrably been read.
func identifyReadWebSurface(t *engine.Target, port int) bool {
	if t == nil || t.Identity == nil || port <= 0 {
		return false
	}
	attrs := t.Identity.Attributes
	// A recorded web port that is not this one describes a different surface and says
	// nothing here. No recorded web port at all means the fingerprint stage never
	// established one and this port came from webPort's fallback -- the same fallback
	// every other HTTP check on this target stamps its findings with, so a read on
	// file does bear on the claim about to be made.
	if wp := attrs["web.port"]; wp != "" && wp != strconv.Itoa(port) {
		return false
	}
	if strings.TrimSpace(attrs["http.server"]) != "" || strings.TrimSpace(attrs["http.title"]) != "" {
		return true
	}
	// A Server header and an HTML title are only the evidence a root-page fetch
	// leaves. iLO's root serves a heavy single-page app that stalls while the small
	// static handlers on the same port answer at once, so on iLO that fetch is the one
	// that fails while /xmldata is read cleanly. A signal sourced from that read is
	// recorded by the fingerprint stage and fixed before any check runs, so it is a
	// witness for this port on the same terms as the two attributes above.
	//
	// A read by a sibling check is deliberately not consulted here. Evidence left by
	// one is not a witness that this port answered: the fetch behind it falls back to
	// a second port, and whether it has landed yet depends on which check the battery
	// scheduled first. The caller resolves that read through iloSurface instead, which
	// answers once for the whole target and names the port it read.
	for _, s := range t.Identity.Signals {
		if s.Source == "ilo" {
			return true
		}
	}
	return false
}

// webProto returns the URL scheme ("http"/"https") for the web port identify
// used, so findings are labelled with the transport actually observed instead
// of a hardcoded "https" (an HTTP-only PDU/NMC serves on tcp/80).
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
