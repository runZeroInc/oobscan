package ipmi

import (
	"bytes"
	"testing"
)

// TestBuildDCMICapabilitiesRequest locks in the on-the-wire framing of the
// sessionless Get DCMI Capabilities Info request: NetFn Group (0x2C), Cmd 0x01,
// data = [0xDC group id, 0x01 parameter selector]. The 0xDC group byte is what
// the BMC's sessionless allow-list gates on, so it must be present and first.
func TestBuildDCMICapabilitiesRequest(t *testing.T) {
	// netfn 0x2C -> 0xB0 in the netfn/lun byte; 9-byte body =
	// 20 b0 30(csum1) 81 00 01 dc 01 a1(csum2).
	want := []byte{
		0x06, 0x00, 0xff, 0x07, // RMCP header, class IPMI
		0x00,                   // auth type = none
		0x00, 0x00, 0x00, 0x00, // session seq = 0
		0x00, 0x00, 0x00, 0x00, // session ID = 0
		0x09,                                                 // msg len (9)
		0x20, 0xb0, 0x30, 0x81, 0x00, 0x01, 0xdc, 0x01, 0xa1, // body
	}
	got := buildSessionlessMsg(NetFnGroup, CmdDCMIGetCapabilities,
		[]byte{DCMIGroupExtID, DCMIParamSupportedCaps})
	if !bytes.Equal(got, want) {
		t.Errorf("DCMI Get Capabilities framing changed\n got=%x\nwant=%x", got, want)
	}
}

func TestParseDCMICapabilitiesReply(t *testing.T) {
	// Response data after CC: group=0xDC, major=1, minor=5, paramRev=2, then
	// 4 bytes of supported-caps parameter data.
	data := []byte{0xdc, 0x01, 0x05, 0x02, 0x00, 0x01, 0x03, 0x00}
	reply := buildDCMIReply(0x00, data)

	dc, err := ParseDCMICapabilitiesReply(reply)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if dc.Version() != "1.5" {
		t.Errorf("version = %q, want 1.5", dc.Version())
	}
	if dc.ParamRevision != 2 {
		t.Errorf("paramRevision = %d, want 2", dc.ParamRevision)
	}
	if dc.SupportedCapsHex() != "00010300" {
		t.Errorf("supportedCaps = %q, want 00010300", dc.SupportedCapsHex())
	}
}

func TestParseDCMICapabilitiesReply_WrongGroup(t *testing.T) {
	// A Group Extension reply that is not DCMI (group != 0xDC) must be rejected
	// rather than mis-reported as DCMI-capable.
	reply := buildDCMIReply(0x00, []byte{0x00, 0x01, 0x05, 0x02})
	if _, err := ParseDCMICapabilitiesReply(reply); err == nil {
		t.Fatal("expected error for non-DCMI group id, got nil")
	}
}

func TestParseDCMICapabilitiesReply_BadCompletion(t *testing.T) {
	// Non-zero completion code (e.g. 0xC1 invalid command) must be an error.
	reply := buildDCMIReply(0xc1, nil)
	if _, err := ParseDCMICapabilitiesReply(reply); err == nil {
		t.Fatal("expected error for non-zero completion code, got nil")
	}
}

func TestParseDCMICapabilitiesReply_Short(t *testing.T) {
	// Group byte present but fewer than the 4 mandatory data bytes.
	reply := buildDCMIReply(0x00, []byte{0xdc, 0x01})
	if _, err := ParseDCMICapabilitiesReply(reply); err == nil {
		t.Fatal("expected error for short response, got nil")
	}
}

// buildDCMIReply frames a minimal IPMB response the parser can anchor on:
// rsAddr(0x81) netfn rqAddr(0x20) seq cmd cc <data...>. Only the anchor bytes
// (0x81 ... 0x20 at +3) and the completion code at +6 matter to the parser.
func buildDCMIReply(cc byte, data []byte) []byte {
	b := []byte{0x81, (NetFnGroup | 1) << 2, 0x00, 0x20, 0x00, CmdDCMIGetCapabilities, cc}
	return append(b, data...)
}
