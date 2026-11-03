package check

import (
	"strings"
	"testing"
)

// The declaration decides only when the bytes do not contradict it, and container
// magic is the contradiction. This pins both halves, because a change to either one
// silently costs something: dropping the declaration check describes prose in a
// legacy charset as an archive, and dropping the magic check hands every mislabelled
// container a free pass.
func TestBinaryClassifierUsesDeclarationOnlyWhenBytesAgree(t *testing.T) {
	// A page in a legacy charset: undecodable end to end, but it is prose and the
	// server says so.
	legacy := strings.Repeat("�", 200)
	if kind, _, ok := binarySnippetKind(legacy, "text/html; charset=Shift_JIS"); ok {
		t.Errorf("legacy-charset text/html described as %q; that discards readable evidence", kind)
	}
	if _, _, ok := binarySnippetKind(legacy, "application/json"); ok {
		t.Error("a declared JSON body was described as binary")
	}

	// The same byte shape with no declaration is binary: nothing speaks for it.
	if _, _, ok := binarySnippetKind(legacy, ""); !ok {
		t.Error("an undeclared body of pure replacement runes was not described as binary")
	}

	// Container magic contradicts the declaration and outranks it.
	for _, tc := range []struct{ name, body string }{
		{"zip", "PK\x03\x04" + strings.Repeat("\x00\xff", 100)},
		{"gzip", "\x1f\x8b\x08" + strings.Repeat("\x00\xff", 100)},
	} {
		if _, _, ok := binarySnippetKind(tc.body, "text/html"); !ok {
			t.Errorf("%s served as text/html was not described as binary; magic must outrank the declaration", tc.name)
		}
	}
}

// A body the response declared as text, with no container magic, is knowingly left
// as text even when its bytes look binary: after the rune-wise truncation a legacy
// charset and a truncated archive are the same bytes, so there is nothing left to
// judge. This documents the accepted gap rather than pretending it is closed.
func TestUnrecognisedBinaryUnderATextLabelIsAcceptedAsText(t *testing.T) {
	// No magic in the recognised set, all undecodable, labelled text.
	body := "\x8b\x71" + strings.Repeat("\x00\xff", 120)
	if _, _, ok := binarySnippetKind(body, "text/plain"); ok {
		t.Error("classifier now calls an unrecognised binary body binary under a text label; " +
			"if that is intended, the legacy-charset case above needs a new way to stay text")
	}
}
