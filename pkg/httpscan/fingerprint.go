package httpscan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/ulikunitz/xz"
)

// This file turns the raw body of a warranted endpoint into a small structured
// Fingerprint. For endpoints that carry a version/identity signal, it decompresses
// archives and/or scrapes a version, model, serial, firmware, and product marker
// out of the body, then attaches them to the finding.
//
// Everything here is bounded:
//   - Decompression is capped at maxDecompressed bytes via an io.LimitReader on the
//     decompressor, guarding against a decompression bomb.
//   - Tar iteration is capped at maxTarEntries so an archive of tiny headers cannot
//     spin the CPU.
//   - Decompression and heavy parsing are attempted only for bodies whose
//     Content-Type or URL suffix warrant it (see ShouldDecompress /
//     wantsFingerprint upstream), so an ordinary HTML page never reaches them.

const (
	// maxDecompressed caps the number of bytes we will read out of any
	// decompressor. A few MB is plenty to enumerate a Redfish schema/metadata
	// tar's member list and read a version header; past that we stop reading
	// (the archive is still "seen", we just don't inflate the whole thing).
	maxDecompressed = 4 << 20 // 4 MiB
	// maxTarEntries caps how many tar members we iterate. Real Redfish schema
	// tars carry a few hundred files; this leaves generous headroom while
	// bounding a hostile header flood.
	maxTarEntries = 4096
)

// Fingerprint is the structured identity/version data scraped from one response
// body. Every field is optional; an all-empty Fingerprint marshals to nothing
// useful and the caller drops the empties (engine.F skips empty values). The
// fields deliberately mirror the finding field names emitted by the check.
type Fingerprint struct {
	// Version is a best-effort firmware / UI / schema version string.
	Version string `json:"version,omitempty"`
	// RedfishVersion is the RedfishVersion reported by a Redfish service root.
	RedfishVersion string `json:"redfishVersion,omitempty"`
	// ODataVersion is the OData/EDMX version declared by a $metadata document.
	ODataVersion string `json:"odataVersion,omitempty"`
	// Product / Model / Serial / Firmware / Manufacturer are the usual identity
	// fields when a body exposes them (Redfish JSON, iLO XML, UPnP descriptor).
	Product      string `json:"product,omitempty"`
	Model        string `json:"model,omitempty"`
	Serial       string `json:"serial,omitempty"`
	Firmware     string `json:"firmware,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	// Fingerprint is a short human-readable identity tag we could derive even
	// when no explicit version was present (e.g. the ATEN copyright META marker,
	// or "redfish-schema tar (N files)").
	Fingerprint string `json:"fingerprint,omitempty"`
	// ArchiveContents is a comma-joined full member list from a decompressed
	// archive. Only set for archive bodies.
	ArchiveContents string `json:"archiveContents,omitempty"`
	// ArchiveCount is the total number of archive members recorded in
	// ArchiveContents.
	ArchiveCount int `json:"archiveCount,omitempty"`
}

// Empty reports whether nothing was extracted (so the caller can skip attaching
// any of the structured fields).
func (fp Fingerprint) Empty() bool {
	return fp == Fingerprint{}
}

// ShouldDecompress reports whether a body should be run through the decompress +
// archive-fingerprint path, based on the URL path suffix, the endpoint tags, and
// the Content-Type. Kept narrow on purpose: only archive/schema/metadata bodies
// (or an explicit compressed suffix / content-type) get decompressed, so an
// ordinary HTML/JSON page never balloons memory in the decompressor.
func ShouldDecompress(path string, tags []string, contentType string) bool {
	lp := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lp, ".tar.xz"),
		strings.HasSuffix(lp, ".xz"),
		strings.HasSuffix(lp, ".tar.gz"),
		strings.HasSuffix(lp, ".tgz"),
		strings.HasSuffix(lp, ".gz"),
		strings.HasSuffix(lp, ".squashfs"):
		return true
	}
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "gzip") || strings.Contains(ct, "x-xz") || strings.Contains(ct, "x-tar") || strings.Contains(ct, "octet-stream") {
		// octet-stream alone is weak, so require an archive/schema/metadata tag to
		// avoid decompressing arbitrary binary blobs (images, firmware).
		return hasAny(tags, "archive", "schema", "metadata")
	}
	return false
}

// bodyCapFor returns the read cap doRequest should apply for a given endpoint.
// Archive/schema/metadata/redfish bodies need the full stream so decompression
// and version scraping have something to work with; the default 4 KiB cap
// truncates a .tar.xz mid-stream and defeats the decompressor. Everything else
// keeps the small default cap so we don't buffer a big HTML app on every hit.
func bodyCapFor(path string, tags []string) int64 {
	lp := strings.ToLower(path)
	if strings.HasSuffix(lp, ".tar.xz") || strings.HasSuffix(lp, ".xz") ||
		strings.HasSuffix(lp, ".tar.gz") || strings.HasSuffix(lp, ".tgz") ||
		strings.HasSuffix(lp, ".gz") || strings.HasSuffix(lp, ".squashfs") ||
		hasAny(tags, "archive", "schema", "metadata", "redfish") {
		return archiveBodyCap
	}
	return defaultBodyCap
}

const (
	// defaultBodyCap is how much of an ordinary response we read and retain.
	// Larger login pages, Redfish JSON replies, and vendor SPAs can carry
	// fingerprintable version/model/serial data beyond small headers. Finding
	// output still shows only a trimmed snippet (see cleanSnippet in
	// http_surface.go), so the large body never lands in the NDJSON finding stream.
	defaultBodyCap = 256 << 10 // 256 KiB
	// archiveBodyCap is the larger cap used only for compressed / schema /
	// metadata / redfish endpoints so the decompressor gets the whole stream.
	// This gives Redfish schema archives headroom while still bounding a hostile
	// oversized body.
	archiveBodyCap = 2 << 20 // 2 MiB
)

// FingerprintBody is the single entry point: given the endpoint path, its tags,
// the response Content-Type and the raw body, it returns whatever structured
// identity/version data it could extract. It never errors - a body it can't
// parse just yields an empty Fingerprint.
func FingerprintBody(path string, tags []string, contentType string, body []byte) Fingerprint {
	if len(body) == 0 {
		return Fingerprint{}
	}
	// Compressed / archive bodies: decompress (bounded) and fingerprint the
	// contents. This is the path that rescues .tar.xz / .gz artifacts from being
	// captured as useless mojibake.
	if ShouldDecompress(path, tags, contentType) {
		if fp, ok := fingerprintArchive(path, body); ok {
			return fp
		}
		// fall through: if it wasn't actually a recognised archive (e.g. a soft
		// 404 HTML error body served at a .gz path), try the text scrapers below.
	}
	return fingerprintText(contentType, body)
}

// fingerprintArchive handles a compressed body. It sniffs the magic bytes rather
// than trusting the path suffix (a mislabelled .gz can really be xz, and a soft
// error page served at an archive path is neither), decompresses up to
// maxDecompressed bytes, and - if the decompressed stream is a tar - summarises
// the member list and pulls a schema/OData version out of the names/contents.
func fingerprintArchive(path string, body []byte) (Fingerprint, bool) {
	// .squashfs has no pure-Go decompressor available here; the best we can do is
	// confirm the magic and report size. Never crash on it.
	if bytes.HasPrefix(body, squashfsMagicLE) || bytes.HasPrefix(body, squashfsMagicBE) {
		return Fingerprint{
			Fingerprint: "squashfs image (" + humanSize(len(body)) + ", not decompressed)",
		}, true
	}

	dec, kind := openDecompressor(body)
	if dec == nil {
		return Fingerprint{}, false
	}
	// Bomb guard: never read more than maxDecompressed bytes out of any
	// decompressor, regardless of how small the compressed input was.
	limited := io.LimitReader(dec, maxDecompressed+1)
	raw, err := io.ReadAll(limited)
	if err != nil && len(raw) == 0 {
		return Fingerprint{}, false
	}
	truncated := int64(len(raw)) > maxDecompressed
	if truncated {
		raw = raw[:maxDecompressed]
	}

	// If the decompressed stream is a tar, fingerprint the archive as a whole
	// (member list + versions). Otherwise it's a single decompressed file (e.g.
	// Fujitsu Disclaimer.txt.gz) -> scrape it as text.
	if fp, ok := fingerprintTar(raw); ok {
		if fp.Fingerprint != "" && kind != "" {
			fp.Fingerprint = kind + " " + fp.Fingerprint
		}
		return fp, true
	}
	fp := fingerprintText("", raw)
	if fp.Empty() {
		// At least record that we decompressed it and roughly how big it was.
		fp.Fingerprint = kind + " payload (" + humanSize(len(raw)) + " decompressed)"
	}
	return fp, true
}

// openDecompressor returns a reader that inflates body, sniffing the magic bytes.
// kind is a short label ("xz"/"gzip") used in the fingerprint text.
func openDecompressor(body []byte) (io.Reader, string) {
	switch {
	case bytes.HasPrefix(body, xzMagic):
		r, err := xz.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, ""
		}
		return r, "xz"
	case bytes.HasPrefix(body, gzipMagic):
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, ""
		}
		return r, "gzip"
	}
	return nil, ""
}

// fingerprintTar walks a (bounded) tar stream and derives an identity from the
// member names: the highest Redfish schema version tag (v1_X_Y) seen, whether a
// vendor-specific schema is present (SMCRAKP.json => Supermicro), the member
// count, and a short sample of the names. ok is false if the stream isn't a tar.
func fingerprintTar(raw []byte) (Fingerprint, bool) {
	tr := tar.NewReader(bytes.NewReader(raw))
	// Read the first header; a non-tar stream fails here and we bail with ok=false.
	first, err := tr.Next()
	if err != nil {
		return Fingerprint{}, false
	}

	var (
		names       []string
		count       int
		vendorTag   string
		maxVerMajor int
		maxVerMinor int
		maxVerPatch int
		maxVerStr   string
	)
	consider := func(name string) {
		base := name
		if i := strings.LastIndexByte(base, '/'); i >= 0 {
			base = base[i+1:]
		}
		if base == "" {
			return // directory entry: don't count it as a "file"
		}
		count++
		names = append(names, base)
		if strings.EqualFold(base, "SMCRAKP.json") || strings.HasPrefix(base, "SMC") {
			vendorTag = "supermicro"
		}
		if m := redfishVerTagRE.FindStringSubmatch(base); m != nil {
			maj, min, pat := atoi(m[1]), atoi(m[2]), atoi(m[3])
			if maj > maxVerMajor ||
				(maj == maxVerMajor && min > maxVerMinor) ||
				(maj == maxVerMajor && min == maxVerMinor && pat > maxVerPatch) {
				maxVerMajor, maxVerMinor, maxVerPatch = maj, min, pat
				maxVerStr = m[1] + "." + m[2] + "." + m[3]
			}
		}
	}
	consider(first.Name)
	// iterated bounds the number of tar headers we read (the hard anti-flood
	// guard), independent of how many of them turn out to be files vs dirs.
	for iterated := 1; iterated < maxTarEntries; iterated++ {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		consider(hdr.Name)
	}

	fp := Fingerprint{}
	// Describe the archive. Distinguish a Redfish JSON-schema tar from an OData
	// metadata tar from the member names.
	kind := "tar archive"
	switch {
	case anyHasSuffix(names, ".json"):
		kind = "redfish-schema tar"
	case anyHasSuffix(names, ".xml"):
		kind = "redfish-metadata tar"
	}
	sort.Strings(names)
	fp.ArchiveContents = strings.Join(names, ", ")
	fp.ArchiveCount = count
	fp.Fingerprint = kind + " (" + itoa(count) + " files"
	if vendorTag != "" {
		fp.Fingerprint += ", " + vendorTag
	}
	fp.Fingerprint += ")"
	if maxVerStr != "" {
		// The highest schema version tag present is the closest thing a schema tar
		// has to a "version". Report it as version.
		fp.Version = "redfish-schema " + maxVerStr
	}
	return fp, true
}

// fingerprintText scrapes identity/version markers out of a text body: Redfish
// JSON (RedfishVersion / Model / SerialNumber / FirmwareVersion / Manufacturer),
// an OData $metadata EDMX version, an iLO/UPnP XML descriptor, and the ATEN /
// Insyde HTML copyright META marker. Returns the empties it couldn't find.
func fingerprintText(contentType string, body []byte) Fingerprint {
	// Cap the scan window so a huge HTML app doesn't cost a full-body regex sweep;
	// every marker we look for lives near the top of the document anyway.
	scan := body
	if len(scan) > 64<<10 {
		scan = scan[:64<<10]
	}
	s := string(scan)
	fp := Fingerprint{}

	// --- Redfish service-root / resource JSON --------------------------------
	// e.g. {"RedfishVersion":"1.15.0", "Model":"...", "SerialNumber":"...", ...}
	fp.RedfishVersion = firstJSONString(s, "RedfishVersion")
	fp.Model = firstNonEmpty(firstJSONString(s, "Model"), firstJSONString(s, "SystemType"))
	fp.Serial = firstNonEmpty(firstJSONString(s, "SerialNumber"), firstJSONString(s, "SKU"))
	fp.Firmware = firstNonEmpty(firstJSONString(s, "FirmwareVersion"), firstJSONString(s, "BiosVersion"), firstJSONString(s, "fwVersion"))
	fp.Manufacturer = firstJSONString(s, "Manufacturer")
	fp.Product = firstNonEmpty(firstJSONString(s, "Product"), firstJSONString(s, "ProductName"))
	// The @odata.type on a service root carries the ServiceRoot version, e.g.
	// "#ServiceRoot.v1_15_0.ServiceRoot" - a good version tell even when
	// RedfishVersion itself is absent.
	if fp.RedfishVersion == "" {
		if m := odataTypeVerRE.FindStringSubmatch(s); m != nil {
			fp.RedfishVersion = m[1] + "." + m[2] + "." + m[3]
		}
	}

	// --- OData $metadata (EDMX) ----------------------------------------------
	// <edmx:Edmx Version="4.0" ...>
	if m := edmxVersionRE.FindStringSubmatch(s); m != nil {
		fp.ODataVersion = m[1]
	}

	// --- iLO / UPnP style XML descriptors ------------------------------------
	// <manufacturer>..</manufacturer><modelNumber>..</modelNumber><serialNumber>..
	if fp.Model == "" {
		fp.Model = firstNonEmpty(firstXMLText(s, "modelNumber"), firstXMLText(s, "modelName"), firstXMLText(s, "SPN"))
	}
	if fp.Serial == "" {
		fp.Serial = firstNonEmpty(firstXMLText(s, "serialNumber"), firstXMLText(s, "sn"))
	}
	if fp.Manufacturer == "" {
		fp.Manufacturer = firstXMLText(s, "manufacturer")
	}
	if fp.Firmware == "" {
		fp.Firmware = firstNonEmpty(firstXMLText(s, "fwVersion"), firstXMLText(s, "spVersion"))
	}

	// --- ATEN / Insyde / Intel HTML copyright META marker --------------------
	// Supermicro/ATEN and Insyde BMC UI pages carry a
	//   <META NAME="ATEN International Co Ltd." CONTENT="(c) ATEN ...">
	// (or Insyde/Intel Corporation) marker. That NAME/CONTENT pair is a durable
	// vendor + copyright-year fingerprint for the ATEN/Insyde web stack that
	// otherwise returns an anonymous HTML page or a bare refresh redirect.
	if fp.Fingerprint == "" {
		if m := metaNameRE.FindStringSubmatch(s); m != nil {
			vendor := strings.TrimSpace(m[1])
			content := ""
			if cm := metaContentRE.FindStringSubmatch(s); cm != nil {
				content = strings.TrimSpace(cm[1])
			}
			if vendor != "" {
				fp.Fingerprint = "html-meta " + vendor
				if content != "" && content != vendor {
					fp.Fingerprint += " / " + content
				}
			}
		}
	}

	// --- ATEN <LOGIN> XML default-credential indicator -----------------------
	// The ATEN /cgi/login.cgi surface returns
	//   <LOGIN><RESP>...<DEFCRED>2</DEFCRED></RESP></LOGIN>
	// DEFCRED signals whether the factory default credentials are still active -
	// a strong ATEN tell and a security-relevant datum. Surface it in the
	// fingerprint when present.
	if m := defcredRE.FindStringSubmatch(s); m != nil {
		tag := "aten-login DEFCRED=" + m[1]
		if fp.Fingerprint == "" {
			fp.Fingerprint = tag
		} else {
			fp.Fingerprint += "; " + tag
		}
	}

	// --- Supermicro web-UI generation marker --------------------------------
	// On an ATEN Supermicro login page (identified by the copyright META above),
	// the JS stack splits the generations: the coreui/kendo + jquery-3 UI ("Super-
	// micro BMC Login") is X11 or newer, while the legacy prototype.js/YUI UI (with
	// an empty <title>) is X10. Recording which UI the page uses lets the engine
	// upgrade the coarse "X10 ATEN" cert baseline that mislabels X11/X12/X13 as X10.
	if strings.Contains(fp.Fingerprint, "ATEN") {
		uiTag := ""
		switch {
		case strings.Contains(s, "coreui"):
			uiTag = "smc-ui:coreui" // modern X11+ UI (coreui)
		case strings.Contains(s, "kendo"):
			uiTag = "smc-ui:kendo" // modern X11+ UI (kendo; some X13/X14 builds)
		case strings.Contains(s, "prototype.js"), strings.Contains(s, "/yui/"), strings.Contains(s, "yui-min.js"),
			strings.Contains(s, "<title></title>"):
			// Legacy X10 ATEN UI: prototype.js/YUI, and the signature empty <title>
			// on its login page (modern logins set "Supermicro BMC Login").
			uiTag = "smc-ui:legacy"
		}
		if uiTag != "" {
			fp.Fingerprint += "; " + uiTag
		}
	}

	// Fujitsu iRMCVersionInfo.txt and similar plain "Name: value" version files.
	if fp.Version == "" {
		if m := versionLineRE.FindStringSubmatch(s); m != nil {
			fp.Version = strings.TrimSpace(m[1])
		}
	}
	return fp
}

// --- regexes and magic bytes -------------------------------------------------

var (
	xzMagic         = []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}
	gzipMagic       = []byte{0x1F, 0x8B}
	squashfsMagicLE = []byte("hsqs")
	squashfsMagicBE = []byte("sqsh")

	// redfishVerTagRE matches the DMTF schema version tag embedded in a schema
	// file name, e.g. "MemoryMetrics.v1_1_3.json" -> 1,1,3.
	redfishVerTagRE = regexp.MustCompile(`\.v(\d+)_(\d+)_(\d+)\b`)
	// odataTypeVerRE matches the version in a Redfish @odata.type, e.g.
	// "#ServiceRoot.v1_15_0.ServiceRoot" -> 1,15,0.
	odataTypeVerRE = regexp.MustCompile(`@odata\.type"\s*:\s*"#[^"]*\.v(\d+)_(\d+)_(\d+)\.`)
	// edmxVersionRE matches the OData EDMX version attribute.
	edmxVersionRE = regexp.MustCompile(`(?i)<edmx:Edmx[^>]*\bVersion="([0-9.]+)"`)
	// metaNameRE / metaContentRE pull the vendor and copyright out of the ATEN /
	// Insyde HTML META marker. Anchored on the NAME= we don't want the generic
	// http-equiv/viewport metas, so require a NAME with a letter+space (a vendor
	// name) rather than "Pragma"/"viewport".
	metaNameRE    = regexp.MustCompile(`(?i)<META\s+NAME="([^"]*(?:Co Ltd|Software|Corporation|Inc|Technolog|Computer)[^"]*)"`)
	metaContentRE = regexp.MustCompile(`(?i)<META\s+NAME="[^"]*(?:Co Ltd|Software|Corporation|Inc|Technolog|Computer)[^"]*"\s+CONTENT="([^"]*)"`)
	// defcredRE pulls the ATEN <DEFCRED>N</DEFCRED> default-credential flag.
	defcredRE = regexp.MustCompile(`(?i)<DEFCRED>\s*([0-9]+)\s*</DEFCRED>`)
	// versionLineRE matches a plain "<something>Version[: ]<value>" line as seen
	// in Fujitsu iRMCVersionInfo.txt and similar version text files.
	versionLineRE = regexp.MustCompile(`(?i)(?:iRMC|BMC|Firmware|SP)\s*Version[:=\s]+([0-9][0-9A-Za-z._-]{1,32})`)
)

// firstJSONString returns the value of the first `"key":"value"` pair in s. It's
// a deliberately shallow scraper (no full JSON parse) so it works on truncated
// bodies too; it only accepts a string value and stops at the closing quote.
func firstJSONString(s, key string) string {
	re := jsonKeyRE(key)
	if m := re.FindStringSubmatch(s); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// jsonKeyRE builds (and the small cache reuses) a regex for a JSON string field.
//
// The cache is sync.Map, not a bare map: FingerprintBody is called concurrently
// from many sweep goroutines, and a plain map here would be a concurrent
// read/write, which Go turns into an unrecoverable fatal error rather than a
// recoverable panic.
var jsonKeyReCache sync.Map // map[string]*regexp.Regexp

func jsonKeyRE(key string) *regexp.Regexp {
	if re, ok := jsonKeyReCache.Load(key); ok {
		return re.(*regexp.Regexp)
	}
	re := regexp.MustCompile(`(?i)"` + regexp.QuoteMeta(key) + `"\s*:\s*"([^"]{1,128})"`)
	// LoadOrStore, not Store: two goroutines racing on the same key must end up
	// sharing one compiled regex rather than each installing its own.
	actual, _ := jsonKeyReCache.LoadOrStore(key, re)
	return actual.(*regexp.Regexp)
}

// firstXMLText returns the text of the first <tag>text</tag> element in s.
func firstXMLText(s, tag string) string {
	re := xmlTagRE(tag)
	if m := re.FindStringSubmatch(s); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// Concurrency-safe for the same reason as jsonKeyReCache above.
var xmlTagReCache sync.Map // map[string]*regexp.Regexp

func xmlTagRE(tag string) *regexp.Regexp {
	if re, ok := xmlTagReCache.Load(tag); ok {
		return re.(*regexp.Regexp)
	}
	re := regexp.MustCompile(`(?is)<` + regexp.QuoteMeta(tag) + `[^>]*>([^<]{1,128})</` + regexp.QuoteMeta(tag) + `>`)
	actual, _ := xmlTagReCache.LoadOrStore(tag, re)
	return actual.(*regexp.Regexp)
}

// --- small helpers -----------------------------------------------------------

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func anyHasSuffix(names []string, suffix string) bool {
	for _, n := range names {
		if strings.HasSuffix(strings.ToLower(n), suffix) {
			return true
		}
	}
	return false
}

func humanSize(n int) string {
	switch {
	case n >= 1<<20:
		return itoa(n>>20) + " MiB"
	case n >= 1<<10:
		return itoa(n>>10) + " KiB"
	default:
		return itoa(n) + " B"
	}
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return n
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
