package ipmi

import "testing"

func TestParseCipherSuiteIDs(t *testing.T) {
	// Three standard records (0xC0): suite 3, suite 17 (0x11), suite 0, each
	// followed by tagged algorithm bytes (auth 0x00-0x03, integ 0x40+, conf 0x80+).
	raw := []byte{
		0xC0, 0x03, 0x01, 0x41, 0x82,
		0xC0, 0x11, 0x03, 0x43, 0x82,
		0xC0, 0x00, 0x00, 0x40, 0x80,
	}
	got := parseCipherSuiteIDs(raw)
	if len(got) != 3 || got[0] != 0 || got[1] != 3 || got[2] != 17 {
		t.Fatalf("parseCipherSuiteIDs = %v, want [0 3 17]", got)
	}
	if !CipherSuiteWeak(0) || !CipherSuiteWeak(1) {
		t.Errorf("cipher 0 and 1 should be weak")
	}
	if CipherSuiteWeak(3) || CipherSuiteWeak(17) {
		t.Errorf("cipher 3 and 17 should not be weak")
	}
}
