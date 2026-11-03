package check

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// looksBinaryHusk mirrors pkg/convert.looksBinary, the audit rule that reads the
// emitted records back. pkg/convert imports this package, so it cannot be imported
// here; keeping the predicate identical is what makes the scanner and the auditor
// agree about which stored values are binary residue.
func looksBinaryHusk(v string) bool {
	if len(v) < 16 {
		return false
	}
	for _, magic := range []string{"7zXZ", "PK\x03\x04", "hsqs", "sqsh", "\x1f\x8b", "\x7fELF", "%PDF"} {
		if strings.HasPrefix(v, magic) {
			return true
		}
	}
	return strings.HasPrefix(v, "PK") && strings.Contains(v[:min(len(v), 64)], "META-INF")
}

// jarBody returns a deflated-JAR-shaped body longer than the snippet truncation
// length, the size at which the defect appeared: the truncation is rune-wise and
// re-encodes every undecodable byte as U+FFFD, so a longer body reaches the emitter
// as valid UTF-8 and a validity test alone reads it as text.
func jarBody() []byte {
	b := []byte{'P', 'K', 0x03, 0x04, 0x14, 0x00, 0x08, 0x08, 0x08, 0x00,
		0x72, 0x54, 0x45, 0x55, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x04, 0x00}
	b = append(b, []byte("META-INF/MANIFEST.MF")...)
	for i := 0; i < 512; i++ { // stand-in for the deflate stream
		b = append(b, byte(0x80+(i*7)%0x7f))
	}
	return b
}

// A binary body served by a real endpoint must reach the finding as a descriptor.
// The emitters see the body only after a rune-wise truncation has already replaced
// its undecodable bytes, so a test that hands raw container bytes straight to the
// snippet cleaner exercises a path production never takes.
func TestHTTPSurfaceDescribesBinaryResponseBodies(t *testing.T) {
	body := jarBody()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/java-archive")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}

	fs := runHTTPSurface(context.Background(), bmcTargetAt(host, port, "http"))
	if len(fs) == 0 {
		t.Fatal("no findings from a responding endpoint sweep")
	}
	checked := 0
	for _, f := range fs {
		got := findingField(f, "response")
		if got == "" {
			continue
		}
		checked++
		if looksBinaryHusk(got) {
			t.Errorf("%s stored the printable residue of a binary body as proof: %q", f.Check, got)
			continue
		}
		if !strings.HasPrefix(got, "<zip/jar body,") {
			t.Errorf("%s response = %q, want a <zip/jar body, ...> descriptor", f.Check, got)
		}
		if !strings.Contains(got, "application/java-archive") {
			t.Errorf("descriptor should name the served content type: %q", got)
		}
		if !strings.Contains(got, strconv.Itoa(len(body))+" bytes") {
			t.Errorf("descriptor should report the full body size %d: %q", len(body), got)
		}
	}
	if checked == 0 {
		t.Fatal("no finding carried a response field; the test proves nothing")
	}
}

// legacyCharsetPage builds an HTML page whose markup is ASCII and whose text is
// encoded in a non-UTF-8 charset, the shape a Japanese/Chinese BMC web tier serves.
// The high bytes sit near the front and the page is longer than the snippet
// truncation length, so the emitter sees it after the rune-wise truncation has
// rewritten each undecodable byte as U+FFFD.
func legacyCharsetPage(text []byte) []byte {
	b := []byte("<html><head><title>")
	b = append(b, text...)
	b = append(b, []byte("</title></head><body><form action=\"/cgi/login.cgi\" method=\"post\">"+
		"<input name=\"name\"><input name=\"pwd\" type=\"password\">"+
		"<input type=\"submit\" value=\"login\"></form>"+
		"<script src=\"/js/login.js\"></script><link rel=\"stylesheet\" href=\"/css/login.css\">"+
		"<div id=\"footer\">firmware 01.09.16</div></body></html>")...)
	return b
}

// A page in a legacy charset decodes to a high replacement-rune density, which is a
// charset signal and not a binary one. Describing it as binary throws away readable
// evidence the scan used to report -- and produces the self-refuting "<binary body,
// text/html, ...>", a body called binary by a descriptor that names its text type.
func TestHTTPSurfaceKeepsLegacyCharsetTextBodies(t *testing.T) {
	cases := []struct {
		name, contentType string
		text              []byte
	}{
		{
			name:        "shift_jis",
			contentType: "text/html; charset=Shift_JIS",
			text: []byte{0x8A, 0xC7, 0x97, 0x9D, 0x83, 0x52, 0x83, 0x93, 0x83, 0x5C,
				0x81, 0x5B, 0x83, 0x8B, 0x82, 0xC9, 0x82, 0xE6, 0x82, 0xA4, 0x82, 0xB1,
				0x82, 0xBB, 0x81, 0x41, 0x83, 0x8D, 0x83, 0x4F, 0x83, 0x43, 0x83, 0x93},
		},
		{
			name:        "gbk",
			contentType: "text/html; charset=GBK",
			text: []byte{0xD4, 0xB6, 0xB3, 0xCC, 0xB9, 0xDC, 0xC0, 0xED, 0xBF, 0xD8,
				0xD6, 0xC6, 0xCC, 0xA8, 0xB5, 0xC7, 0xC2, 0xBC, 0xD3, 0xC3, 0xBB, 0xA7,
				0xC3, 0xFB, 0xC3, 0xDC, 0xC2, 0xEB, 0xC7, 0xEB, 0xCA, 0xE4, 0xC8, 0xEB},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := legacyCharsetPage(tc.text)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				_, _ = w.Write(body)
			}))
			defer srv.Close()

			host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
			if err != nil {
				t.Fatalf("split: %v", err)
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				t.Fatalf("port: %v", err)
			}

			fs := runHTTPSurface(context.Background(), bmcTargetAt(host, port, "http"))
			checked := 0
			for _, f := range fs {
				got := findingField(f, "response")
				if got == "" {
					continue
				}
				checked++
				if strings.Contains(got, "% printable>") {
					t.Errorf("%s described a %s page as binary: %q", f.Check, tc.contentType, got)
					continue
				}
				if !strings.Contains(got, "<html><head><title>") {
					t.Errorf("%s response = %q, want the page's readable markup", f.Check, got)
				}
			}
			if checked == 0 {
				t.Fatal("no finding carried a response field; the test proves nothing")
			}
		})
	}
}

// A container magic at the head of the body outranks the declared type: a body a
// device labels text/html but serves as a jar is still binary, and quoting its
// printable residue would be the original defect back again.
func TestHTTPSurfaceDescribesBinaryBodyDeclaredAsText(t *testing.T) {
	body := jarBody()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}

	fs := runHTTPSurface(context.Background(), bmcTargetAt(host, port, "http"))
	checked := 0
	for _, f := range fs {
		got := findingField(f, "response")
		if got == "" {
			continue
		}
		checked++
		if looksBinaryHusk(got) {
			t.Errorf("%s stored the printable residue of a binary body as proof: %q", f.Check, got)
			continue
		}
		if !strings.HasPrefix(got, "<zip/jar body,") {
			t.Errorf("%s response = %q, want a <zip/jar body, ...> descriptor despite the text/html label", f.Check, got)
		}
	}
	if checked == 0 {
		t.Fatal("no finding carried a response field; the test proves nothing")
	}
}

// Dropping the non-printable bytes of a binary body and keeping the surviving ASCII
// yields a plausible-looking but meaningless string. A type and a size can be checked;
// that husk cannot.
func TestCleanSnippetDescribesBinaryBodies(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantKind string
	}{
		{
			name:     "xz tar archive",
			body:     "\xfd7zXZ\x00\x00\x04\xe6\xd6\xb4F\x02\x00!\x01\x16\x00\x00\x00t/\xe5\xa3\xe0\x07\xff\x00\x8f]\x00\x39\x48\x3e\x36\x22\x48\x36\x2c\x3b\x21\x4e\x71",
			wantKind: "xz",
		},
		{
			name:     "jar (a KVM applet served pre-auth)",
			body:     "PK\x03\x04\x14\x00\x08\x08\x08\x00rTEU\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x04\x00META-INF/MANIFEST.MF\xfe\xca\x00\x00",
			wantKind: "zip/jar",
		},
		{
			name:     "squashfs image",
			body:     "hsqs\x0c\x03\x00\x00\x8b\x1f\x9dd\x00\x00\x02\x00\x01\x00\x00\x00\x04\x00\x11\x00\xc0\x00\x04\x00\x00\x00\x00\x00\x00\x00\xff\xfe\xfd\xfc",
			wantKind: "squashfs",
		},
		{
			name:     "unrecognized binary blob still gets described, not quoted",
			body:     "\x01\x02\x03\x04\xde\xad\xbe\xef\x00\x00\x00\x00\xff\xfe\xfd\xfc\x11\x22\x33\x44\x99\x88\x77\x66\xaa\xbb\xcc\xdd",
			wantKind: "binary",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cleanSnippet(tc.body)
			if !strings.HasPrefix(got, "<"+tc.wantKind+" body,") {
				t.Fatalf("cleanSnippet = %q, want a <%s body, ...> descriptor", got, tc.wantKind)
			}
			if !strings.Contains(got, "printable>") {
				t.Errorf("descriptor should report the printable ratio: %q", got)
			}
			// The point of the fix: no bytes lifted out of the compressed stream.
			if strings.Contains(got, "META-INF") || strings.Contains(got, "7zXZ") {
				t.Errorf("descriptor quotes bytes from the binary body: %q", got)
			}
		})
	}
}

// Text bodies must be quoted exactly as before -- including non-ASCII text, which
// is legitimately low on printable ASCII but is not binary.
func TestCleanSnippetKeepsTextBodies(t *testing.T) {
	cases := []struct{ name, body, wantSub string }{
		{
			name:    "html with attribute quotes preserved",
			body:    `<html> <head> <META HTTP-EQUIV="refresh" CONTENT="0;URL=/cgi/url_redirect.cgi">`,
			wantSub: `HTTP-EQUIV="refresh"`,
		},
		{
			name:    "idrac discover xml",
			body:    `<?xml version="1.0" encoding="UTF-8"?><DISCOVER><RESP><RC>0x0</RC></RESP></DISCOVER>`,
			wantSub: `version="1.0"`,
		},
		{
			name:    "redfish json",
			body:    `{"@odata.id":"/redfish/v1/","RedfishVersion":"1.11.0"}`,
			wantSub: `"RedfishVersion"`,
		},
		{
			name:    "valid utf-8 CJK text is not binary",
			body:    "<html><title>管理コンソールへようこそ、ログインしてください</title></html>",
			wantSub: "<html>",
		},
		{
			// A page that already carried a replacement glyph, e.g. a mis-encoded
			// character the device itself served. One of those is not the trace of a
			// truncated binary body, and the page is still text.
			name:    "CJK text with a stray replacement glyph is not binary",
			body:    "<html><title>管理コンソール�へようこそ、ログインしてください</title></html>",
			wantSub: "<html>",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cleanSnippet(tc.body)
			if strings.HasPrefix(got, "<binary body,") || strings.Contains(got, "% printable>") {
				t.Fatalf("text body was described as binary: %q", got)
			}
			if !strings.Contains(got, tc.wantSub) {
				t.Errorf("cleanSnippet = %q, want it to contain %q", got, tc.wantSub)
			}
		})
	}
}

// A short body is never worth describing; quoting it is cheaper and more useful.
func TestCleanSnippetLeavesShortBodiesAlone(t *testing.T) {
	if got := cleanSnippet("\x00\x01\x02"); strings.Contains(got, "printable>") {
		t.Errorf("a 3-byte body should not get a descriptor, got %q", got)
	}
}
