package sanitize

import "testing"

func TestBytes(t *testing.T) {
	got := string(Bytes([]byte{'A', 0x00, 'B'}))
	if got != "AB" {
		t.Fatalf("Bytes NUL = %q, want %q", got, "AB")
	}

	got = string(Bytes([]byte{0xff, 'A', 0x00, 'B'}))
	if got != "AB" {
		t.Fatalf("Bytes invalid utf8 = %q, want %q", got, "AB")
	}

	got = string(Bytes([]byte{'A', '\\', 'u', '0', '0', '0', '0', 'B'}))
	if got != "AB" {
		t.Fatalf("Bytes escaped null = %q, want %q", got, "AB")
	}
}
