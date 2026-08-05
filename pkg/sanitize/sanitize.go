package sanitize

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

var nullByteSlice = []byte{0}

var nullEscapeSlice = []byte{'\\', 'u', '0', '0', '0', '0'}

func Name(name string) string {
	return strings.TrimSpace(strings.ReplaceAll(name, "\x00", ""))
}

func String(s string) string {

	if !strings.ContainsRune(s, 0) && utf8.ValidString(s) {
		return s
	}

	s = strings.ToValidUTF8(s, "")

	return strings.ReplaceAll(s, "\x00", "")
}

func StringSlice(slice []string) []string {
	for i, s := range slice {
		slice[i] = String(s)
	}
	return slice
}

func Bytes(s []byte) []byte {

	if bytes.IndexByte(s, 0) == -1 &&
		!bytes.Contains(s, nullEscapeSlice) &&
		utf8.Valid(s) {
		return s
	}

	plen := len(s)
	for {

		s = bytes.ToValidUTF8(s, nil)

		s = bytes.ReplaceAll(s, nullByteSlice, nil)

		s = bytes.ReplaceAll(s, nullEscapeSlice, nil)
		if len(s) == plen {
			break
		}
		plen = len(s)
	}
	return s
}

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
