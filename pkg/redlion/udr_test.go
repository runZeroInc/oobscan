package redlion

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestIsConnRefused(t *testing.T) {
	if !isConnRefused(fmt.Errorf("UDP read: %w", syscall.ECONNREFUSED)) {
		t.Error("wrapped ECONNREFUSED was not recognized")
	}
	if isConnRefused(errors.New("permission denied")) {
		t.Error("generic network error was classified as connection refused")
	}
}

// TestCRCUDR locks in the recovered UDR wire-CRC parameters (CCITT-FALSE init
// 0xFFFF, poly 0x1021, no reflection, xorout 0xFFFF - i.e. CRC-16/GENIBUS)
// against the standard check vector: CRC of "123456789" is 0xD64E.
func TestCRCUDR(t *testing.T) {
	if got := crcUDR([]byte("123456789")); got != 0xD64E {
		t.Errorf("UDR wire CRC check vector = 0x%04x, want 0xD64E", got)
	}
}

// TestVersionFrame verifies the safe, state-free probe frame: it must start
// with 0x29, carry command 0x03 (version/identify, no operands), and match the
// recovered verified-good reference frame 29 07 FF FF 00 00 03 25 A2 - in
// particular the trailing wire CRC bytes must equal 25 A2 (little-endian).
func TestVersionFrame(t *testing.T) {
	f := versionFrame()
	want := []byte{0x29, 0x07, 0xFF, 0xFF, 0x00, 0x00, 0x03, 0x25, 0xA2}
	if len(f) != len(want) {
		t.Fatalf("frame length = %d, want %d", len(f), len(want))
	}
	for i := range want {
		if f[i] != want[i] {
			t.Fatalf("frame = % 02x, want % 02x", f, want)
		}
	}
	// Explicitly assert the trailing CRC bytes are 25 A2 for the 0x03 frame.
	crc := f[len(f)-2:]
	if crc[0] != 0x25 || crc[1] != 0xA2 {
		t.Errorf("CRC trailer = %02x %02x, want 25 a2", crc[0], crc[1])
	}
	if f[6] != cmdUDRVersion {
		t.Errorf("command = 0x%02x, want 0x%02x (version/identify)", f[6], cmdUDRVersion)
	}
	if !validUDRReply(f) {
		t.Error("versionFrame did not pass validUDRReply (bad CRC framing)")
	}
	// A frame with a corrupted CRC must be rejected.
	bad := append([]byte(nil), f...)
	bad[len(bad)-1] ^= 0xff
	if validUDRReply(bad) {
		t.Error("validUDRReply accepted a frame with a corrupted CRC")
	}
}
