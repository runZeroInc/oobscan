package ipmi

import (
	"bytes"
	"context"
	"testing"
)

// TestBuildSessionlessMsgWireBytes locks the on-the-wire framing of the sessionless
// IPMI 1.5 request builder against captured lab bytes. Both vectors come from the
// same builder path, differing only in cmd plus two data bytes, and the auth-caps
// one is answered: a Get Device ID timeout is the BMC gating 0x01 behind a session
// (only 0x38 and 0x54 are spec-mandated sessionless), never a framing bug, so do
// not "fix" buildSessionlessMsg to chase it.
func TestBuildSessionlessMsgWireBytes(t *testing.T) {
	// Captured device-id request from a lab BMC: no reply -> timeout.
	// RMCP(0600ff07) authType(00) seq(00000000) SID(00000000) len(07) body(2018c88100017e)
	wantDeviceID := []byte{
		0x06, 0x00, 0xff, 0x07, // RMCP header, class IPMI
		0x00,                   // auth type = none
		0x00, 0x00, 0x00, 0x00, // session seq = 0
		0x00, 0x00, 0x00, 0x00, // session ID = 0
		0x07,                                     // msg len
		0x20, 0x18, 0xc8, 0x81, 0x00, 0x01, 0x7e, // rsAddr,netfn,csum1,rqAddr,seq,cmd,csum2
	}
	if got := buildSessionlessMsg(NetFnApp, CmdGetDeviceID, nil); !bytes.Equal(got, wantDeviceID) {
		t.Errorf("Get Device ID framing changed\n got=%x\nwant=%x", got, wantDeviceID)
	}

	// Captured auth-caps request from the same lab BMC, which did reply.
	// ...len(09) body(2018c88100380e0435), data = channel 0x0e, priv 0x04.
	wantAuthCaps := []byte{
		0x06, 0x00, 0xff, 0x07,
		0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x09,
		0x20, 0x18, 0xc8, 0x81, 0x00, 0x38, 0x0e, 0x04, 0x35,
	}
	if got := buildSessionlessMsg(NetFnApp, CmdGetChannelAuthCaps, []byte{0x0e, 0x04}); !bytes.Equal(got, wantAuthCaps) {
		t.Errorf("Get Channel Auth Caps framing changed\n got=%x\nwant=%x", got, wantAuthCaps)
	}
}

func TestParseDeviceIDReply(t *testing.T) {
	// Device ID data: ID,Rev,FwMaj,FwMin(BCD 59),IPMIver(BCD 2.0),AddSupport,
	// mfr=674 (Dell) LE, product=16 LE, aux.
	data := []byte{
		0x20, 0x81, 0x03, 0x59, 0x02, 0xbf,
		0xa2, 0x02, 0x00, // manufacturer 674
		0x10, 0x00, // product 16
		0x01, 0x02, 0x03, 0x04, // aux firmware
	}
	// IPMB response: rsAddr(0x81) netfn|lun csum rqAddr(0x20) seq cmd CC data csum
	body := []byte{0x81, 0x1c, 0x00, 0x20, 0x00, 0x01, 0x00}
	body = append(body, data...)
	body = append(body, 0x00)
	// Sessionless 1.5 wrapper: RMCP(4) authType(1) seq(4) SID(4) msglen(1) body
	reply := []byte{0x06, 0x00, 0xff, 0x07, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, byte(len(body))}
	reply = append(reply, body...)

	dev, err := ParseDeviceIDReply(reply)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if dev.ManufacturerID != 674 {
		t.Errorf("ManufacturerID=%d, want 674", dev.ManufacturerID)
	}
	if dev.ManufacturerName() != "Dell Inc." {
		t.Errorf("ManufacturerName=%q, want Dell Inc.", dev.ManufacturerName())
	}
	if dev.ProductID != 16 {
		t.Errorf("ProductID=%d, want 16", dev.ProductID)
	}
	a := dev.Attributes()
	if a["ipmi.firmwareRevision"] != "3.59" {
		t.Errorf("firmwareRevision=%q, want 3.59", a["ipmi.firmwareRevision"])
	}
	if a["ipmi.ipmiVersion"] != "2.0" {
		t.Errorf("ipmiVersion=%q, want 2.0", a["ipmi.ipmiVersion"])
	}

	// A reply with no IPMB header must error, not panic.
	if _, err := ParseDeviceIDReply([]byte{0x06, 0x00, 0xff, 0x07}); err == nil {
		t.Errorf("expected error on headerless reply")
	}
}

func TestParseSystemGUIDReply(t *testing.T) {
	guid := []byte{0x44, 0x45, 0x4c, 0x4c, 0x53, 0x00, 0x10, 0x48, 0x80, 0x4b, 0xca, 0xc0, 0x4f, 0x4b, 0x58, 0x58}
	body := []byte{0x81, 0x1c, 0x00, 0x20, 0x00, CmdGetSystemGUID, 0x00}
	body = append(body, guid...)
	body = append(body, 0x00)
	reply := []byte{0x06, 0x00, 0xff, 0x07, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, byte(len(body))}
	reply = append(reply, body...)

	got, err := ParseSystemGUIDReply(reply)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(got, guid) {
		t.Fatalf("guid mismatch: got=%x want=%x", got, guid)
	}

	if _, err := ParseSystemGUIDReply([]byte{0x06, 0x00, 0xff, 0x07}); err == nil {
		t.Errorf("expected error on headerless reply")
	}
	short := []byte{0x06, 0x00, 0xff, 0x07, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x17,
		0x81, 0x1c, 0x00, 0x20, 0x00, CmdGetSystemGUID, 0x00,
		0x01, 0x02, 0x03, 0x04, 0x00}
	if _, err := ParseSystemGUIDReply(short); err == nil {
		t.Errorf("expected error on short GUID payload")
	}
}

// TestFirmwareRevisionRendering locks the two-component rendering. Firmware
// Revision 2 is BCD, so its nibbles are the decimal digits and print as hex
// digits. The 0xff case is the one that matters: arithmetic BCD decoding turned
// an out-of-spec byte into "165", which reads as a real minor revision.
func TestFirmwareRevisionRendering(t *testing.T) {
	cases := []struct {
		major, minor byte
		want         string
	}{
		{0x03, 0x19, "3.19"}, // Supermicro X10-era
		{0x04, 0x00, "4.00"}, // Supermicro X10 4.00
		{0x01, 0x74, "1.74"}, // Supermicro X11 01.74.x
		{0x03, 0x59, "3.59"},
		{0x83, 0x59, "3.59"}, // bit 7 of Firmware Revision 1 is device-available
		{0x00, 0xff, "0.ff"}, // not valid BCD: stays visibly wrong
	}
	for _, c := range cases {
		if got := FormatFirmwareRevision(c.major, c.minor); got != c.want {
			t.Errorf("FormatFirmwareRevision(0x%02x, 0x%02x) = %q, want %q",
				c.major, c.minor, got, c.want)
		}
	}
}

// TestFirmwareRevisionFull checks the reconstruction against the DevIdTbl
// entries in etc/conf/version.xml of shipped Supermicro images, so the rendered
// string equals the version Supermicro publishes for that image.
func TestFirmwareRevisionFull(t *testing.T) {
	const smc, dell = 10876, 674
	cases := []struct {
		name         string
		mfr          uint32
		major, minor byte
		aux          [4]byte
		want         string
	}{
		{"X13 2401MS 01.07.01", smc, 0x01, 0x07, [4]byte{0x01, 0x02, 0x00, 0x00}, "01.07.01"},
		{"X13 C301MS 01.08.08", smc, 0x01, 0x08, [4]byte{0x08, 0x01, 0x00, 0x00}, "01.08.08"},
		{"H13 E401MS 01.09.16", smc, 0x01, 0x09, [4]byte{0x16, 0x00, 0x00, 0x00}, "01.09.16"},
		// X14 publishes a fourth component (01.06.07.00). Only three are
		// rendered: the second aux byte is not a published component on every
		// generation, so appending it would invent one.
		{"X14 5601MS 01.06.07.00", smc, 0x01, 0x06, [4]byte{0x07, 0x00, 0x00, 0x00}, "01.06.07"},
		// X10 4.00 ships no auxiliary revision.
		{"X10 4.00", smc, 0x04, 0x00, [4]byte{}, ""},
		// Auxiliary encoding is vendor-defined; do not invent a version for a
		// vendor whose encoding has not been confirmed against an image.
		{"unconfirmed vendor", dell, 0x03, 0x59, [4]byte{0x01, 0x02, 0x03, 0x04}, ""},
	}
	for _, c := range cases {
		got := FormatFirmwareRevisionFull(c.mfr, c.major, c.minor, c.aux)
		if got != c.want {
			t.Errorf("%s: FormatFirmwareRevisionFull = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestDeviceIDAuxAttributes checks that the auxiliary bytes reach reported
// output. They were parsed but dropped before reporting, which left the
// reported version unmatchable against a vendor advisory.
func TestDeviceIDAuxAttributes(t *testing.T) {
	smc := &DeviceID{
		FirmwareMajor: 0x01, FirmwareMinor: 0x09, IPMIVersion: 0x02,
		ManufacturerID: 10876, AuxFirmwareVersion: [4]byte{0x16, 0x00, 0x00, 0x00},
	}
	a := smc.Attributes()
	if a["ipmi.firmwareRevision"] != "1.09" {
		t.Errorf("firmwareRevision=%q, want 1.09", a["ipmi.firmwareRevision"])
	}
	if a["ipmi.firmwareRevisionFull"] != "01.09.16" {
		t.Errorf("firmwareRevisionFull=%q, want 01.09.16", a["ipmi.firmwareRevisionFull"])
	}
	if a["ipmi.auxFirmwareRev"] != "16000000" {
		t.Errorf("auxFirmwareRev=%q, want 16000000", a["ipmi.auxFirmwareRev"])
	}

	// Unconfirmed vendor: raw auxiliary bytes still reported, no reconstruction.
	other := &DeviceID{
		FirmwareMajor: 0x02, FirmwareMinor: 0x75, ManufacturerID: 674,
		AuxFirmwareVersion: [4]byte{0x01, 0x02, 0x03, 0x04},
	}
	a = other.Attributes()
	if _, ok := a["ipmi.firmwareRevisionFull"]; ok {
		t.Errorf("firmwareRevisionFull set for an unconfirmed vendor: %q", a["ipmi.firmwareRevisionFull"])
	}
	if a["ipmi.auxFirmwareRev"] != "01020304" {
		t.Errorf("auxFirmwareRev=%q, want 01020304", a["ipmi.auxFirmwareRev"])
	}
}

// fakeRunner replays a fixed Get Device ID response.
type fakeRunner struct{ data []byte }

func (f *fakeRunner) Exec(netfn, cmd byte, _ []byte) (byte, []byte, error) {
	if netfn == NetFnApp && cmd == CmdGetDeviceID {
		return 0x00, f.data, nil
	}
	return 0xc1, nil, nil
}
func (f *fakeRunner) Close() {}

// TestCollectMCInfoAuxRoundTrip runs the real Get Device ID response bytes
// captured from an X13 unit running 01.07.01 through the post-auth collector,
// and checks the collector reproduces the version Supermicro publishes for that
// firmware. The bytes are the ones quoted in CVE-2026-18449 and CVE-2026-18450.
func TestCollectMCInfoAuxRoundTrip(t *testing.T) {
	// 20 01 01 07 02 bf | 7c 2a 00 (mfr 10876) | 00 00 (product) | 01 02 00 00 (aux)
	data := []byte{
		0x20, 0x01, 0x01, 0x07, 0x02, 0xbf,
		0x7c, 0x2a, 0x00,
		0x00, 0x00,
		0x01, 0x02, 0x00, 0x00,
	}
	mi, err := collectMCInfo(context.Background(), &fakeRunner{data: data})
	if err != nil {
		t.Fatalf("collectMCInfo: %v", err)
	}
	if mi.ManufacturerID != 10876 {
		t.Errorf("ManufacturerID=%d, want 10876", mi.ManufacturerID)
	}
	if mi.FirmwareRevision != "1.07" {
		t.Errorf("FirmwareRevision=%q, want 1.07", mi.FirmwareRevision)
	}
	if mi.FirmwareRevisionFull != "01.07.01" {
		t.Errorf("FirmwareRevisionFull=%q, want 01.07.01 (the published version)", mi.FirmwareRevisionFull)
	}
	if mi.AuxFirmwareHex != "01020000" {
		t.Errorf("AuxFirmwareHex=%q, want 01020000", mi.AuxFirmwareHex)
	}
}
