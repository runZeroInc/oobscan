package check

import (
	"strings"
	"unicode/utf8"
)

// sanitizeBanner cleans a raw banner captured from a TCP/UDP probe (which may
// contain NULs, non-UTF8 tails, or ANSI escapes) for the `banner` field on a
// finding: it trims whitespace, preserves CR/LF/TAB, drops NUL and other
// C0/C1 control bytes, and falls back to printable-ASCII only when the
// residue is not valid UTF-8. Callers should also emit the raw bytes
// hex-encoded under `raw` alongside the clean banner for forensic review.
func sanitizeBanner(raw string) string {
	if raw == "" {
		return ""
	}
	b := []byte(raw)
	// First pass: drop C0 controls (except TAB/CR/LF) and 0x7f.
	filtered := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0x00 || c == 0x7f {
			continue
		}
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			continue
		}
		filtered = append(filtered, c)
	}
	// UTF-8 validity: if invalid, downgrade to printable-ASCII only.
	if !utf8.Valid(filtered) {
		ascii := make([]byte, 0, len(filtered))
		for _, c := range filtered {
			if (c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r' {
				ascii = append(ascii, c)
			}
		}
		filtered = ascii
	}
	return strings.TrimSpace(string(filtered))
}

// countPrintableRunes returns the count of printable ASCII bytes plus TAB/CR/LF
// in a raw banner. Used to gate risk on empty or near-empty captures.
func countPrintableRunes(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r' {
			n++
		}
	}
	return n
}
