package check

import (
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/sanitize"
)

// truncateLikeProbe reproduces the one transformation a response body goes through
// before any classifier sees it: the rune-wise truncation the HTTP prober applies
// (sanitize.TruncateString at the snippet length). It re-encodes every byte it could
// not decode as U+FFFD, so a body longer than the cap arrives valid UTF-8 whatever it
// held. A test that hands raw bytes straight to the classifier never reaches the
// state production is in.
func truncateLikeProbe(body []byte) string {
	return sanitize.TruncateString(string(body), 200)
}

// charsetPage builds a page whose markup is ASCII and whose text is in a non-UTF-8
// charset, long enough to be truncated.
func charsetPage(text []byte) []byte {
	b := append([]byte("<html><head><title>"), text...)
	return append(b, []byte("</title></head><body><form action=\"/cgi/login.cgi\" method=\"post\">"+
		"<input name=\"name\"><input name=\"pwd\" type=\"password\">"+
		"<input type=\"submit\" value=\"login\"></form>"+
		"<div id=\"footer\">firmware 01.09.16</div></body></html>")...)
}

var (
	shiftJISText = []byte{0x8A, 0xC7, 0x97, 0x9D, 0x83, 0x52, 0x83, 0x93, 0x83, 0x5C,
		0x81, 0x5B, 0x83, 0x8B, 0x82, 0xC9, 0x82, 0xE6, 0x82, 0xA4, 0x82, 0xB1,
		0x82, 0xBB, 0x81, 0x41, 0x83, 0x8D, 0x83, 0x4F, 0x83, 0x43, 0x83, 0x93}
	gbkText = []byte{0xD4, 0xB6, 0xB3, 0xCC, 0xB9, 0xDC, 0xC0, 0xED, 0xBF, 0xD8,
		0xD6, 0xC6, 0xCC, 0xA8, 0xB5, 0xC7, 0xC2, 0xBC, 0xD3, 0xC3, 0xBB, 0xA7,
		0xC3, 0xFB, 0xC3, 0xDC, 0xC2, 0xEB, 0xC7, 0xEB, 0xCA, 0xE4, 0xC8, 0xEB}
	latin1Text = []byte("Anmeldung f\xfcr die Ger\xe4teverwaltung \xfcber gesch\xfctzte " +
		"Verbindung \xc4nderungen an der Netzwerkkonfiguration erfordern " +
		"Administratorrechte \xd6ffnen Sie das Men\xfc Systemzustand \xdcbersicht")
)

// A page in a legacy charset is text. It reaches the classifier dense in replacement
// runes, exactly like a truncated archive does, and a rule that reads only that
// density calls it binary and throws away the readable markup. Nothing outside the
// endpoint sweep can appeal to the declared type: the snippet cleaner has no header
// to pass on, and an embedded CGI often sends none.
func TestClassifyLegacyCharsetPageWithNoDeclaredType(t *testing.T) {
	cases := []struct {
		name string
		text []byte
	}{
		{"shift_jis", shiftJISText},
		{"gbk", gbkText},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snippet := truncateLikeProbe(charsetPage(tc.text))
			if _, _, binary := binarySnippetKind(snippet, ""); binary {
				t.Errorf("a %s page with no declared type was classified binary", tc.name)
			}
			got := cleanSnippet(snippet)
			if strings.Contains(got, "% printable>") {
				t.Fatalf("cleanSnippet described a %s page as binary: %q", tc.name, got)
			}
			if !strings.Contains(got, "<html><head><title>") {
				t.Errorf("cleanSnippet = %q, want the page's readable markup", got)
			}
		})
	}
}

// A single-byte legacy charset never reaches the density rule at all, and pinning
// that down is what keeps it from being cited as a case the rule decides. Every
// accented character in a Latin-1 page is one byte among the ASCII the markup and
// the prose are otherwise made of, so the replacement runes stay well under the
// threshold and the page is text on the density arm alone. It is the multi-byte
// charsets, where nearly every character is two high bytes, that cross it.
func TestClassifyLatin1PageNeverReachesTheDensityRule(t *testing.T) {
	snippet := truncateLikeProbe(charsetPage(latin1Text))
	density := replacementRuneBytes(snippet) * 100 / len(snippet)
	if density >= binarySnippetMinNonPrintablePct {
		t.Fatalf("replacement density = %d%%, at or above the %d%% threshold: the fixture no "+
			"longer shows what it claims to", density, binarySnippetMinNonPrintablePct)
	}
	if _, _, binary := binarySnippetKind(snippet, ""); binary {
		t.Error("a Latin-1 page was classified binary")
	}
}

// The declared type must still be honoured where it is the only evidence: a body
// whose text is entirely non-ASCII leaves no markup behind to judge.
func TestClassifyDeclaredTextWithNoASCIIResidue(t *testing.T) {
	snippet := truncateLikeProbe(append([]byte{}, strings.Repeat(string(shiftJISText), 8)...))
	if _, _, binary := binarySnippetKind(snippet, "text/plain; charset=Shift_JIS"); binary {
		t.Error("a declared text/plain body was classified binary")
	}
}

// The original defect must stay fixed: a body that really is binary has to become a
// descriptor. Its bytes reach the classifier in the same replacement-rune-dense state
// a legacy-charset page does, so what separates them is what survives the decode --
// a page keeps its ASCII skeleton, an archive keeps raw control bytes.
func TestClassifyBinaryBodiesAfterTruncation(t *testing.T) {
	blob := make([]byte, 0, 600)
	for i := 0; i < 600; i++ {
		blob = append(blob, byte((i*37)%256))
	}
	cases := []struct {
		name, wantKind string
		body           []byte
	}{
		{name: "unrecognized blob", wantKind: "binary", body: blob},
		{name: "jar", wantKind: "zip/jar", body: jarBody()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snippet := truncateLikeProbe(tc.body)
			kind, _, binary := binarySnippetKind(snippet, "")
			if !binary {
				t.Fatalf("a %s body was quoted as text: %q", tc.name, cleanSnippet(snippet))
			}
			if kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", kind, tc.wantKind)
			}
			if got := cleanSnippet(snippet); !strings.Contains(got, "% printable>") {
				t.Errorf("cleanSnippet = %q, want a descriptor", got)
			}
		})
	}
}

// A snippet with almost nothing left once the replacement runes are removed cannot
// be read either way, and the handful of surviving bytes must not carry the
// decision: a blob whose few decodable bytes happen to be printable would otherwise
// be quoted as text.
func TestDecodedTextResidueNeedsSomethingToRead(t *testing.T) {
	highBytes := func(n int) []byte {
		b := make([]byte, 0, n)
		for i := 0; i < n; i++ {
			b = append(b, 0x80|byte(i%0x40))
		}
		return b
	}
	cases := []struct {
		name string
		body []byte
	}{
		{"a few printable bytes among undecodable ones", append([]byte("abcdefgh"), highBytes(400)...)},
		{"nothing decoded at all", highBytes(400)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snippet := truncateLikeProbe(tc.body)
			if decodedTextResidue(snippet) {
				t.Errorf("%s was called text", tc.name)
			}
			if got := cleanSnippet(snippet); !strings.Contains(got, "% printable>") {
				t.Errorf("cleanSnippet = %q, want a descriptor", got)
			}
		})
	}
}
