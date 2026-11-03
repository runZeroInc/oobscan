package advantech

import (
	"encoding/binary"
	"testing"
)

func TestBuildRequestLayout(t *testing.T) {
	b := buildRequest(opNetworkRead, prodEKI1524)
	if len(b) != reqLen {
		t.Fatalf("request length = %d, want %d", len(b), reqLen)
	}
	if binary.BigEndian.Uint32(b[offMagic:]) != magic {
		t.Fatalf("magic not set")
	}
	if binary.BigEndian.Uint16(b[offProd:]) != prodEKI1524 {
		t.Fatalf("product code not set")
	}
	for i := range 6 {
		if b[offMAC+i] != 0xFF {
			t.Fatalf("target MAC byte %d not broadcast", i)
		}
	}
	if binary.BigEndian.Uint16(b[offOpcode:]) != opNetworkRead {
		t.Fatalf("opcode not set")
	}
	// Token area must be empty (unauthenticated read).
	if b[0x14] != 0x00 {
		t.Fatalf("token area not empty")
	}
}

func TestDecodeReply(t *testing.T) {
	// Synthetic reply: echoed ADAM magic, a real MAC at 0x0C, and model/fw/ip
	// tokens elsewhere in the datagram.
	raw := make([]byte, reqLen)
	binary.BigEndian.PutUint32(raw[offMagic:], magic)
	copy(raw[offMAC:], []byte{0x00, 0x0a, 0x35, 0x11, 0x22, 0x33})
	tail := []byte("EKI-1524\x00v1.35\x00192.168.10.20")
	raw = append(raw, tail...)

	r := decode(raw)
	if r == nil {
		t.Fatal("decode returned nil")
	}
	if !r.MagicOK {
		t.Fatal("magic not recognized")
	}
	if r.MAC != "00:0a:35:11:22:33" {
		t.Fatalf("MAC = %q", r.MAC)
	}
	if r.Model != "EKI-1524" {
		t.Fatalf("Model = %q", r.Model)
	}
	if r.Firmware == "" {
		t.Fatalf("Firmware not extracted")
	}
	if len(r.IPv4) != 1 || r.IPv4[0] != "192.168.10.20" {
		t.Fatalf("IPv4 = %v", r.IPv4)
	}
}
