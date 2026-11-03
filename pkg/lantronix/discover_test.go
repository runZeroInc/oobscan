package lantronix

import "testing"

func TestLantronixMAC(t *testing.T) {
	cases := []struct {
		name string
		mac  []byte
		want string
	}{
		{"valid Lantronix OUI 00:20:4a", []byte{0x00, 0x20, 0x4a, 0x11, 0x22, 0x33}, "00:20:4a:11:22:33"},
		{"valid Lantronix OUI 00:80:a3", []byte{0x00, 0x80, 0xa3, 0xaa, 0xbb, 0xcc}, "00:80:a3:aa:bb:cc"},
		// A non-Lantronix OUI (e.g. trailing padding) must not be trusted.
		{"foreign OUI rejected", []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}, ""},
		{"all zero padding rejected", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ""},
		{"wrong length", []byte{0x00, 0x20, 0x4a}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := lantronixMAC(c.mac); got != c.want {
				t.Errorf("lantronixMAC(%v) = %q, want %q", c.mac, got, c.want)
			}
		})
	}
}

func TestStripTelnetIAC(t *testing.T) {
	in := []byte{0xff, 0xfb, 0x01, 'L', 'a', 'n', 't', 'r', 'o', 'n', 'i', 'x', '\r', '\n'}
	got := stripTelnetIAC(in)
	if got != "Lantronix\r\n" {
		t.Fatalf("stripTelnetIAC()=%q", got)
	}
}
