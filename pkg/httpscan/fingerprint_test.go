package httpscan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"
)

// makeTarXZ builds a small tar.xz in memory from name->contents, mirroring the
// shape of a Supermicro /JsonSchemas.tar.xz.
func makeTarXZ(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for name, body := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}
		if strings.HasSuffix(name, "/") {
			hdr.Typeflag = tar.TypeDir
			hdr.Size = 0
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var xzBuf bytes.Buffer
	xw, err := xz.NewWriter(&xzBuf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xw.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := xw.Close(); err != nil {
		t.Fatal(err)
	}
	return xzBuf.Bytes()
}

func makeGZ(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestFingerprintSMCLoginUI proves the login-page HTML scraper tags the coreui
// (X11+) vs legacy prototype.js/YUI (X10) Supermicro ATEN web UI, gated on the
// ATEN copyright META so it never fires on a generic coreui page. The snippets
// mirror the real firmware login pages (X10 = empty <title> + prototype.js;
// X13/coreui = "Supermicro BMC Login" + coreui-docs.min.css).
func TestFingerprintSMCLoginUI(t *testing.T) {
	const legacyX10 = `<html><head>
<META NAME="ATEN International Co Ltd." CONTENT="(c) ATEN International Co Ltd. 2010">
<title></title>
<script language="JavaScript" src="../js/prototype.js"></script>
<link rel="stylesheet" href="../yui/build/base.css"></head><body></body></html>`
	const coreui = `<html><head>
<META NAME="ATEN International Co Ltd." CONTENT="(c) ATEN International Co Ltd. 2010">
<title>Supermicro BMC Login</title>
<link rel="stylesheet" href="../css/coreui-docs.min.css">
<script src="../js/jquery-3.5.1.min.js"></script></head><body></body></html>`
	// A generic coreui page without the ATEN META must not be tagged.
	const generic = `<html><head><title>Some App</title>
<link rel="stylesheet" href="/coreui.min.css"></head><body></body></html>`

	cases := []struct{ name, body, wantContains, wantNot string }{
		{"legacy X10", legacyX10, "smc-ui:legacy", "smc-ui:coreui"},
		{"coreui X11+", coreui, "smc-ui:coreui", "smc-ui:legacy"},
		{"generic coreui not tagged", generic, "", "smc-ui"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fp := FingerprintBody("/cgi/url_redirect.cgi?url_name=login", []string{"login", "fingerprint"}, "text/html", []byte(c.body))
			if c.wantContains != "" && !strings.Contains(fp.Fingerprint, c.wantContains) {
				t.Errorf("fingerprint = %q, want it to contain %q", fp.Fingerprint, c.wantContains)
			}
			if c.wantNot != "" && strings.Contains(fp.Fingerprint, c.wantNot) {
				t.Errorf("fingerprint = %q, must not contain %q", fp.Fingerprint, c.wantNot)
			}
		})
	}
}

// TestFingerprintJsonSchemasTarXZ feeds a synthetic Supermicro /JsonSchemas.tar.xz
// through the decompress+fingerprint path and asserts we recover the schema
// version, the vendor tell, the file count and the member list - i.e. exactly
// the "version or fingerprint derived from the contents" demanded, instead of a
// mojibake blob.
func TestFingerprintJsonSchemasTarXZ(t *testing.T) {
	archive := makeTarXZ(t, map[string]string{
		"json_schema/":                          "",
		"json_schema/ServiceRoot.v1_5_0.json":   `{"title":"#ServiceRoot"}`,
		"json_schema/MemoryMetrics.v1_1_3.json": `{"title":"#MemoryMetrics"}`,
		"json_schema/SMCRAKP.json":              `{"title":"#SMCRAKP"}`,
		"json_schema/Thermal.json":              `{"title":"#Thermal"}`,
	})
	fp := FingerprintBody("/JsonSchemas.tar.xz", []string{"static", "schema", "redfish"}, "application/octet-stream", archive)
	if fp.Empty() {
		t.Fatal("expected a non-empty fingerprint from JsonSchemas.tar.xz")
	}
	if !strings.Contains(fp.Version, "1.5.0") {
		t.Errorf("expected highest schema version 1.5.0, got version=%q", fp.Version)
	}
	if !strings.Contains(fp.Fingerprint, "redfish-schema tar") {
		t.Errorf("expected redfish-schema tar fingerprint, got %q", fp.Fingerprint)
	}
	if !strings.Contains(fp.Fingerprint, "supermicro") {
		t.Errorf("expected supermicro vendor tell (SMCRAKP.json), got %q", fp.Fingerprint)
	}
	if !strings.Contains(fp.Fingerprint, "xz") {
		t.Errorf("expected xz codec tag in fingerprint, got %q", fp.Fingerprint)
	}
	if !strings.Contains(fp.ArchiveContents, "SMCRAKP.json") {
		t.Errorf("expected member list to include SMCRAKP.json, got %q", fp.ArchiveContents)
	}
}

// TestFingerprintMetadataTarXZ mirrors the /Metadata.tar.xz shape (OData XML
// members) and asserts it is classified as a metadata tar.
func TestFingerprintMetadataTarXZ(t *testing.T) {
	archive := makeTarXZ(t, map[string]string{
		"metadata/":                     "",
		"metadata/MemoryMetrics_v1.xml": `<?xml version="1.0"?><edmx:Edmx Version="4.0"></edmx:Edmx>`,
		"metadata/ServiceRoot_v1.xml":   `<?xml version="1.0"?>`,
	})
	fp := FingerprintBody("/Metadata.tar.xz", []string{"static", "metadata", "redfish"}, "application/octet-stream", archive)
	if !strings.Contains(fp.Fingerprint, "redfish-metadata tar") {
		t.Errorf("expected redfish-metadata tar fingerprint, got %q", fp.Fingerprint)
	}
	if !strings.Contains(fp.ArchiveContents, "MemoryMetrics_v1.xml") {
		t.Errorf("expected member list to include the metadata xml, got %q", fp.ArchiveContents)
	}
}

// TestFingerprintDisclaimerGZ feeds a single-file .gz (Fujitsu Disclaimer.txt.gz
// shape) and asserts the decompressed text is scraped rather than left as a blob.
func TestFingerprintDisclaimerGZ(t *testing.T) {
	body := makeGZ(t, "iRMC S6 ServerView\niRMC Version: 3.37P\nCopyright Fujitsu")
	fp := FingerprintBody("/Disclaimer.txt.gz", []string{"static", "docs"}, "application/gzip", body)
	if fp.Empty() {
		t.Fatal("expected a non-empty fingerprint from the decompressed .gz")
	}
	if !strings.Contains(fp.Version, "3.37P") {
		t.Errorf("expected iRMC version 3.37P from decompressed text, got version=%q fingerprint=%q", fp.Version, fp.Fingerprint)
	}
}

// TestFingerprintATENPage feeds a captured ATEN /page/*.www / /cgi/*.cgi body and
// asserts the vendor + copyright META marker is turned into a fingerprint (the
// marker HD Moore called out: <META NAME="ATEN International Co Ltd." ...>).
func TestFingerprintATENPage(t *testing.T) {
	body := []byte(`<html><head>` +
		`<META HTTP-EQUIV="refresh" CONTENT="0;URL=/">` +
		`<META HTTP-EQUIV="Pragma" CONTENT="no_cache">` +
		`<META NAME="ATEN International Co Ltd." CONTENT="(c) ATEN International Co Ltd. 2021">` +
		`</head><body></body></html>`)
	fp := FingerprintBody("/cgi/bios_upload.cgi", []string{"dynamic", "cgi", "upload"}, "text/html", body)
	if fp.Empty() {
		t.Fatal("expected a non-empty fingerprint from the ATEN page")
	}
	if !strings.Contains(fp.Fingerprint, "ATEN International Co Ltd.") {
		t.Errorf("expected ATEN vendor marker in fingerprint, got %q", fp.Fingerprint)
	}
	if !strings.Contains(fp.Fingerprint, "2021") {
		t.Errorf("expected the copyright year in the fingerprint, got %q", fp.Fingerprint)
	}
}

// TestFingerprintATENLoginDefcred asserts the ATEN <LOGIN> XML default-credential
// indicator is surfaced (a security-relevant datum from /cgi/login.cgi).
func TestFingerprintATENLoginDefcred(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?><LOGIN><RESP><RC>0x10</RC><SID></SID><STATE>0x0000000a</STATE><STATENAME>SESSION_INVALID</STATENAME><DEFCRED>2</DEFCRED></RESP></LOGIN>`)
	fp := FingerprintBody("/cgi/login.cgi", []string{"dynamic", "cgi", "login"}, "text/xml", body)
	if !strings.Contains(fp.Fingerprint, "DEFCRED=2") {
		t.Errorf("expected DEFCRED=2 in fingerprint, got %q", fp.Fingerprint)
	}
}

// TestFingerprintRedfishServiceRoot asserts a Redfish service-root JSON yields a
// redfishVersion, and that the @odata.type version is used as a fallback.
func TestFingerprintRedfishServiceRoot(t *testing.T) {
	// Explicit RedfishVersion present.
	body := []byte(`{"@odata.type":"#ServiceRoot.v1_15_0.ServiceRoot","RedfishVersion":"1.15.0","Product":"Super Server","Vendors":{}}`)
	fp := FingerprintBody("/redfish/v1/", []string{"info", "redfish", "static"}, "application/json", body)
	if fp.RedfishVersion != "1.15.0" {
		t.Errorf("expected redfishVersion 1.15.0, got %q", fp.RedfishVersion)
	}
	if fp.Product != "Super Server" {
		t.Errorf("expected product from JSON, got %q", fp.Product)
	}
	// No explicit RedfishVersion -> fall back to @odata.type version.
	body2 := []byte(`{"@odata.context":"/redfish/v1/$metadata#ServiceRoot.ServiceRoot","@odata.type":"#ServiceRoot.v1_12_0.ServiceRoot"}`)
	fp2 := FingerprintBody("/redfish/v1/", []string{"info", "redfish", "static"}, "application/json", body2)
	if fp2.RedfishVersion != "1.12.0" {
		t.Errorf("expected @odata.type fallback redfishVersion 1.12.0, got %q", fp2.RedfishVersion)
	}
}

// TestFingerprintODataMetadata asserts the OData EDMX version is scraped from a
// bare $metadata document (not a tar).
func TestFingerprintODataMetadata(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx"><!--Dell--></edmx:Edmx>`)
	fp := FingerprintBody("/redfish/v1/$metadata", []string{"info", "redfish", "static"}, "application/xml", body)
	if fp.ODataVersion != "4.0" {
		t.Errorf("expected odata_version 4.0, got %q", fp.ODataVersion)
	}
}

// TestFingerprintUPnPDescriptor asserts an iLO/UPnP XML descriptor yields
// manufacturer/model/serial.
func TestFingerprintUPnPDescriptor(t *testing.T) {
	body := []byte(`<root><device>` +
		`<manufacturer>HP</manufacturer>` +
		`<modelNumber>iLO 5</modelNumber>` +
		`<serialNumber>ABC123</serialNumber>` +
		`</device></root>`)
	fp := FingerprintBody("/upnp/BasicDevice.xml", []string{"info", "xml", "static", "fingerprint"}, "text/xml", body)
	if fp.Manufacturer != "HP" || fp.Model != "iLO 5" || fp.Serial != "ABC123" {
		t.Errorf("expected HP/iLO 5/ABC123, got mfr=%q model=%q serial=%q", fp.Manufacturer, fp.Model, fp.Serial)
	}
}

// TestFingerprintSquashfsGraceful asserts a squashfs body is fingerprinted by
// magic bytes / size and never crashes (no pure-Go squashfs decompressor here).
func TestFingerprintSquashfsGraceful(t *testing.T) {
	body := append([]byte("hsqs"), bytes.Repeat([]byte{0x00}, 4096)...)
	fp := FingerprintBody("/ThirdPartyLicenseReadme.squashfs", []string{"static", "fingerprint", "archive"}, "application/octet-stream", body)
	if !strings.Contains(fp.Fingerprint, "squashfs") {
		t.Errorf("expected squashfs fingerprint, got %q", fp.Fingerprint)
	}
}

// TestDecompressBombGuard asserts the decompressor stops at maxDecompressed even
// when a tiny compressed input inflates enormously.
func TestDecompressBombGuard(t *testing.T) {
	// Highly-compressible payload larger than the cap; gzip shrinks it to a few
	// hundred bytes on the wire but it inflates past maxDecompressed.
	huge := bytes.Repeat([]byte("A"), maxDecompressed+(1<<20))
	body := makeGZ(t, string(huge))
	if len(body) > 64<<10 {
		t.Fatalf("fixture not compressible enough (%d bytes); test is meaningless", len(body))
	}
	// Should not hang / OOM: fingerprintArchive reads at most maxDecompressed+1.
	fp, ok := fingerprintArchive("/x.gz", body)
	if !ok {
		t.Fatal("expected the gz to be recognised")
	}
	// A wall of 'A' is neither tar nor a recognised text marker; we still return
	// a bounded "gzip payload (...)" fingerprint rather than the whole blob.
	if fp.Empty() {
		t.Error("expected a bounded fingerprint for the decompressed blob")
	}
}

// TestShouldDecompressNarrow asserts we do not enter the decompressor for an
// ordinary HTML page (only archive/compressed bodies qualify).
func TestShouldDecompressNarrow(t *testing.T) {
	if ShouldDecompress("/page/topmenu.www", []string{"static", "fingerprint"}, "text/html") {
		t.Error("plain HTML page should not be decompressed")
	}
	if !ShouldDecompress("/JsonSchemas.tar.xz", []string{"static", "schema", "redfish"}, "application/octet-stream") {
		t.Error(".tar.xz should be decompressed")
	}
	if !ShouldDecompress("/Disclaimer.txt.gz", []string{"static", "docs"}, "application/gzip") {
		t.Error(".gz should be decompressed")
	}
}

// TestBodyCapForArchive asserts archive/schema/metadata/redfish endpoints get the
// larger read cap so the full stream reaches the decompressor.
func TestBodyCapForArchive(t *testing.T) {
	if got := bodyCapFor("/JsonSchemas.tar.xz", []string{"schema"}); got != archiveBodyCap {
		t.Errorf("tar.xz cap = %d, want %d", got, archiveBodyCap)
	}
	if got := bodyCapFor("/redfish/v1/", []string{"redfish"}); got != archiveBodyCap {
		t.Errorf("redfish cap = %d, want %d", got, archiveBodyCap)
	}
	if got := bodyCapFor("/page/topmenu.www", []string{"static", "fingerprint"}); got != defaultBodyCap {
		t.Errorf("html cap = %d, want %d", got, defaultBodyCap)
	}
}
