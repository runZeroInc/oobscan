package digi

import "testing"

func TestParseADDPReply(t *testing.T) {
	// DIGI + CMD_CONF_REP + TLVs:
	// 0x01 MAC, 0x04 hostname, 0x08 fwrev, 0x0d hwname, 0x0e realport, 0x12 ports
	payload := []byte{
		0x01, 0x06, 0x00, 0x40, 0x9d, 0xaa, 0xbb, 0xcc,
		0x04, 0x06, 'd', 'i', 'g', 'i', '0', '1',
		0x08, 0x06, '8', '.', '2', '.', '1', '0',
		0x0d, 0x0d, 'P', 'o', 'r', 't', 'S', 'e', 'r', 'v', 'e', 'r', ' ', 'T', 'S',
		0x0e, 0x04, 0x00, 0x00, 0x03, 0x03,
		0x12, 0x01, 0x10,
	}
	b := make([]byte, 8+len(payload))
	copy(b[:4], []byte("DIGI"))
	b[5] = 0x02
	b[7] = byte(len(payload))
	copy(b[8:], payload)

	r, ok := parseADDPReply(b)
	if !ok {
		t.Fatal("expected valid ADDP reply")
	}
	if r.Magic != "DIGI" {
		t.Fatalf("magic=%q want DIGI", r.Magic)
	}
	if r.MAC != "00:40:9d:aa:bb:cc" {
		t.Fatalf("mac=%q", r.MAC)
	}
	if r.Hostname != "digi01" {
		t.Fatalf("hostname=%q", r.Hostname)
	}
	if r.Firmware != "8.2.10" {
		t.Fatalf("firmware=%q", r.Firmware)
	}
	if r.HWName != "PortServer TS" {
		t.Fatalf("hwname=%q", r.HWName)
	}
	if r.RealPort != 771 {
		t.Fatalf("realport=%d", r.RealPort)
	}
	if r.Ports != 16 {
		t.Fatalf("ports=%d", r.Ports)
	}
}

func TestParseADDPReplyIgnoresInvalidRealPort(t *testing.T) {
	// AnywhereUSB/14 responses have been observed returning 0x03030000 in the
	// RealPort TLV. It is not a valid TCP port and must not become 50528256.
	payload := []byte{
		0x01, 0x06, 0x00, 0x40, 0x9d, 0xb6, 0x3b, 0x11,
		0x0d, 0x0e, 'A', 'n', 'y', 'w', 'h', 'e', 'r', 'e', 'U', 'S', 'B', '/', '1', '4',
		0x08, 0x14, 'b', 'u', 'i', 'l', 'd', ' ', '8', '2', '0', '0', '2', '0', '8', '1', '_', 'P', ' ', 'e', 'o', 's',
		0x12, 0x01, 0x01,
		0x0e, 0x04, 0x03, 0x03, 0x00, 0x00,
	}
	b := make([]byte, 8+len(payload))
	copy(b[:4], []byte("DIGI"))
	b[5] = 0x02
	b[7] = byte(len(payload))
	copy(b[8:], payload)

	r, ok := parseADDPReply(b)
	if !ok {
		t.Fatal("expected valid ADDP reply")
	}
	if r.HWName != "AnywhereUSB/14" || r.Firmware != "build 82002081_P eos" || r.Ports != 1 {
		t.Fatalf("identity fields = product %q firmware %q ports %d", r.HWName, r.Firmware, r.Ports)
	}
	if r.RealPort != 0 {
		t.Fatalf("realport=%d, want unset for out-of-range value", r.RealPort)
	}
}

func TestParseADDPReplyRejectsBadMagic(t *testing.T) {
	b := []byte("NOPE\x00\x01\x00\x00")
	if _, ok := parseADDPReply(b); ok {
		t.Fatal("expected non-ADDP payload to be rejected")
	}
}

func TestIsADDPMagic(t *testing.T) {
	if !isADDPMagic([]byte("DIGI")) || !isADDPMagic([]byte("DVKT")) || !isADDPMagic([]byte("DGDP")) {
		t.Fatal("expected all three Digi magic prefixes")
	}
	if isADDPMagic([]byte("ABCD")) {
		t.Fatal("unexpected magic accepted")
	}
}
