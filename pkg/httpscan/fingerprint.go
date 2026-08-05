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

const (
	maxDecompressed = 4 << 20

	maxTarEntries = 4096
)

type Fingerprint struct {
	Version string `json:"version,omitempty"`

	RedfishVersion string `json:"redfishVersion,omitempty"`

	ODataVersion string `json:"odataVersion,omitempty"`

	Product      string `json:"product,omitempty"`
	Model        string `json:"model,omitempty"`
	Serial       string `json:"serial,omitempty"`
	Firmware     string `json:"firmware,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`

	Fingerprint string `json:"fingerprint,omitempty"`

	ArchiveContents string `json:"archiveContents,omitempty"`

	ArchiveCount int `json:"archiveCount,omitempty"`
}

func (fp Fingerprint) Empty() bool {
	return fp == Fingerprint{}
}

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

		return hasAny(tags, "archive", "schema", "metadata")
	}
	return false
}

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
	defaultBodyCap = 256 << 10

	archiveBodyCap = 2 << 20
)

func FingerprintBody(path string, tags []string, contentType string, body []byte) Fingerprint {
	if len(body) == 0 {
		return Fingerprint{}
	}

	if ShouldDecompress(path, tags, contentType) {
		if fp, ok := fingerprintArchive(path, body); ok {
			return fp
		}

	}
	return fingerprintText(contentType, body)
}

func fingerprintArchive(path string, body []byte) (Fingerprint, bool) {

	if bytes.HasPrefix(body, squashfsMagicLE) || bytes.HasPrefix(body, squashfsMagicBE) {
		return Fingerprint{
			Fingerprint: "squashfs image (" + humanSize(len(body)) + ", not decompressed)",
		}, true
	}

	dec, kind := openDecompressor(body)
	if dec == nil {
		return Fingerprint{}, false
	}

	limited := io.LimitReader(dec, maxDecompressed+1)
	raw, err := io.ReadAll(limited)
	if err != nil && len(raw) == 0 {
		return Fingerprint{}, false
	}
	truncated := int64(len(raw)) > maxDecompressed
	if truncated {
		raw = raw[:maxDecompressed]
	}

	if fp, ok := fingerprintTar(raw); ok {
		if fp.Fingerprint != "" && kind != "" {
			fp.Fingerprint = kind + " " + fp.Fingerprint
		}
		return fp, true
	}
	fp := fingerprintText("", raw)
	if fp.Empty() {

		fp.Fingerprint = kind + " payload (" + humanSize(len(raw)) + " decompressed)"
	}
	return fp, true
}

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

func fingerprintTar(raw []byte) (Fingerprint, bool) {
	tr := tar.NewReader(bytes.NewReader(raw))

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
			return
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

	for iterated := 1; iterated < maxTarEntries; iterated++ {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		consider(hdr.Name)
	}

	fp := Fingerprint{}

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

		fp.Version = "redfish-schema " + maxVerStr
	}
	return fp, true
}

func fingerprintText(contentType string, body []byte) Fingerprint {

	scan := body
	if len(scan) > 64<<10 {
		scan = scan[:64<<10]
	}
	s := string(scan)
	fp := Fingerprint{}

	fp.RedfishVersion = firstJSONString(s, "RedfishVersion")
	fp.Model = firstNonEmpty(firstJSONString(s, "Model"), firstJSONString(s, "SystemType"))
	fp.Serial = firstNonEmpty(firstJSONString(s, "SerialNumber"), firstJSONString(s, "SKU"))
	fp.Firmware = firstNonEmpty(firstJSONString(s, "FirmwareVersion"), firstJSONString(s, "BiosVersion"), firstJSONString(s, "fwVersion"))
	fp.Manufacturer = firstJSONString(s, "Manufacturer")
	fp.Product = firstNonEmpty(firstJSONString(s, "Product"), firstJSONString(s, "ProductName"))

	if fp.RedfishVersion == "" {
		if m := odataTypeVerRE.FindStringSubmatch(s); m != nil {
			fp.RedfishVersion = m[1] + "." + m[2] + "." + m[3]
		}
	}

	if m := edmxVersionRE.FindStringSubmatch(s); m != nil {
		fp.ODataVersion = m[1]
	}

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

	if m := defcredRE.FindStringSubmatch(s); m != nil {
		tag := "aten-login DEFCRED=" + m[1]
		if fp.Fingerprint == "" {
			fp.Fingerprint = tag
		} else {
			fp.Fingerprint += "; " + tag
		}
	}

	if strings.Contains(fp.Fingerprint, "ATEN") {
		uiTag := ""
		switch {
		case strings.Contains(s, "coreui"):
			uiTag = "smc-ui:coreui"
		case strings.Contains(s, "kendo"):
			uiTag = "smc-ui:kendo"
		case strings.Contains(s, "prototype.js"), strings.Contains(s, "/yui/"), strings.Contains(s, "yui-min.js"),
			strings.Contains(s, "<title></title>"):

			uiTag = "smc-ui:legacy"
		}
		if uiTag != "" {
			fp.Fingerprint += "; " + uiTag
		}
	}

	if fp.Version == "" {
		if m := versionLineRE.FindStringSubmatch(s); m != nil {
			fp.Version = strings.TrimSpace(m[1])
		}
	}
	return fp
}

var (
	xzMagic         = []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}
	gzipMagic       = []byte{0x1F, 0x8B}
	squashfsMagicLE = []byte("hsqs")
	squashfsMagicBE = []byte("sqsh")

	redfishVerTagRE = regexp.MustCompile(`\.v(\d+)_(\d+)_(\d+)\b`)

	odataTypeVerRE = regexp.MustCompile(`@odata\.type"\s*:\s*"#[^"]*\.v(\d+)_(\d+)_(\d+)\.`)

	edmxVersionRE = regexp.MustCompile(`(?i)<edmx:Edmx[^>]*\bVersion="([0-9.]+)"`)

	metaNameRE    = regexp.MustCompile(`(?i)<META\s+NAME="([^"]*(?:Co Ltd|Software|Corporation|Inc|Technolog|Computer)[^"]*)"`)
	metaContentRE = regexp.MustCompile(`(?i)<META\s+NAME="[^"]*(?:Co Ltd|Software|Corporation|Inc|Technolog|Computer)[^"]*"\s+CONTENT="([^"]*)"`)

	defcredRE = regexp.MustCompile(`(?i)<DEFCRED>\s*([0-9]+)\s*</DEFCRED>`)

	versionLineRE = regexp.MustCompile(`(?i)(?:iRMC|BMC|Firmware|SP)\s*Version[:=\s]+([0-9][0-9A-Za-z._-]{1,32})`)
)

func firstJSONString(s, key string) string {
	re := jsonKeyRE(key)
	if m := re.FindStringSubmatch(s); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

var jsonKeyReCache sync.Map

func jsonKeyRE(key string) *regexp.Regexp {
	if re, ok := jsonKeyReCache.Load(key); ok {
		return re.(*regexp.Regexp)
	}
	re := regexp.MustCompile(`(?i)"` + regexp.QuoteMeta(key) + `"\s*:\s*"([^"]{1,128})"`)

	actual, _ := jsonKeyReCache.LoadOrStore(key, re)
	return actual.(*regexp.Regexp)
}

func firstXMLText(s, tag string) string {
	re := xmlTagRE(tag)
	if m := re.FindStringSubmatch(s); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

var xmlTagReCache sync.Map

func xmlTagRE(tag string) *regexp.Regexp {
	if re, ok := xmlTagReCache.Load(tag); ok {
		return re.(*regexp.Regexp)
	}
	re := regexp.MustCompile(`(?is)<` + regexp.QuoteMeta(tag) + `[^>]*>([^<]{1,128})</` + regexp.QuoteMeta(tag) + `>`)
	actual, _ := xmlTagReCache.LoadOrStore(tag, re)
	return actual.(*regexp.Regexp)
}

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
