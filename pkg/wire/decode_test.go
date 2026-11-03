package wire

import "testing"

func TestExtractors(t *testing.T) {
	raw := []byte("EKI-1524\x00v1.35\x00ip=192.168.1.50 mac=00:0a:35:1c:2d:3e\xff\xff")
	if got := Printable(raw); len(got) == 0 {
		t.Fatalf("Printable found nothing")
	}
	if ips := IPv4s(raw); len(ips) != 1 || ips[0] != "192.168.1.50" {
		t.Fatalf("IPv4s = %v", ips)
	}
	if macs := MACs(raw); len(macs) != 1 || macs[0] != "00:0a:35:1c:2d:3e" {
		t.Fatalf("MACs = %v", macs)
	}
}

func TestMACFromBytes(t *testing.T) {
	if got := MACFromBytes([]byte{0x00, 0x0a, 0x35, 0x01, 0x02, 0x03}); got != "00:0a:35:01:02:03" {
		t.Fatalf("MACFromBytes = %q", got)
	}
	if got := MACFromBytes([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}); got != "" {
		t.Fatalf("broadcast MAC should be empty, got %q", got)
	}
	if got := MACFromBytes([]byte{0, 0, 0, 0, 0, 0}); got != "" {
		t.Fatalf("zero MAC should be empty, got %q", got)
	}
}
