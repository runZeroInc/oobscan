// Package sanitize normalizes untrusted device strings for storage and output.
package sanitize

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// nullByteSlice is the literal NUL byte we look for in [Bytes].
// Pre-allocated so callers don't pay for a fresh literal on every call.
var nullByteSlice = []byte{0}

// nullEscapeSlice is the textual JSON-style null escape "\\u0000" we strip
// in [Bytes]. PostgreSQL jsonb cannot store this either.
var nullEscapeSlice = []byte{'\\', 'u', '0', '0', '0', '0'}

// Name removes null bytes and trims leading and trailing spaces from a string.
func Name(name string) string {
	return strings.TrimSpace(strings.ReplaceAll(name, "\x00", ""))
}

// String scrubs a given string of invalid UTF8 and nulls.
func String(s string) string {
	// Fast path: clean inputs (no NUL, valid UTF-8) are returned as-is to
	// avoid the strings.ToValidUTF8 / strings.ReplaceAll copies.
	if !strings.ContainsRune(s, 0) && utf8.ValidString(s) {
		return s
	}
	// Remove invalid UTF-8 sequences.
	s = strings.ToValidUTF8(s, "")
	// Remove null bytes that break PostgreSQL jsonb.
	return strings.ReplaceAll(s, "\x00", "")
}

func StringSlice(slice []string) []string {
	for i, s := range slice {
		slice[i] = String(s)
	}
	return slice
}

// Bytes scrubs a given byte array of invalid UTF8 and nulls.
func Bytes(s []byte) []byte {
	// Fast path: if the input has no NULs, no JSON null escape, and is
	// already valid UTF-8, return it unchanged.
	if bytes.IndexByte(s, 0) == -1 &&
		!bytes.Contains(s, nullEscapeSlice) &&
		utf8.Valid(s) {
		return s
	}

	// Loop until all invalid bytes are scrubbed.
	plen := len(s)
	for {
		// Remove invalid UTF-8 sequences and return a new array.
		s = bytes.ToValidUTF8(s, nil)
		// Remove null bytes that break PostgreSQL jsonb.
		s = bytes.ReplaceAll(s, nullByteSlice, nil)
		// remove null bytes unicode sequence.
		s = bytes.ReplaceAll(s, nullEscapeSlice, nil)
		if len(s) == plen {
			break
		}
		plen = len(s)
	}
	return s
}

// TruncateString returns a version of the input string no bigger than l bytes.
// If passed a valid UTF-8 string, it returns a valid UTF-8 string.
func TruncateString(s string, l int) string {
	if len(s) <= l {
		return s
	}
	var ns strings.Builder
	ns.Grow(l)
	i := 0
	for _, c := range s {
		scl := len(string(c))
		if scl+i > l {
			break
		}
		ns.WriteRune(c)
		i += scl
	}
	return ns.String()
}
