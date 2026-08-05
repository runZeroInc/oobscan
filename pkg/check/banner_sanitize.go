package check

import (
	"strings"
	"unicode/utf8"
)

func sanitizeBanner(raw string) string {
	if raw == "" {
		return ""
	}
	b := []byte(raw)

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
