package ipmi

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// DeviceID holds the parsed Get Device ID (NetFn App / Cmd 0x01) response. This
// unauthenticated command is one of the strongest BMC fingerprints: it returns
// the IANA manufacturer ID, product ID, firmware version, and IPMI version
// without any session.
type DeviceID struct {
	ID                 byte
	Revision           byte
	FirmwareMajor      byte
	FirmwareMinor      byte
	IPMIVersion        byte
	AdditionalSupport  byte
	ManufacturerID     uint32
	ProductID          uint16
	AuxFirmwareVersion [4]byte
}

// manufacturerNames maps IANA enterprise (PEN) numbers to vendor names for the
// manufacturer IDs commonly seen in BMC Get Device ID responses. Values are
// checked against the IANA Private Enterprise Number registry.
var manufacturerNames = map[uint32]string{
	2:     "IBM",
	11:    "Hewlett-Packard",
	42:    "Sun Microsystems",
	211:   "Fujitsu Limited",
	259:   "Accton Technology",
	343:   "Intel Corporation",
	674:   "Dell Inc.",
	802:   "National Semiconductor (Intel mBMC/Sahalee)", // Intel SE7xxx-era boards, IPMI 1.5, fw 2.40
	2011:  "Huawei",
	2050:  "Windward Technologies (BMC firmware)", // seen on Intel SE7320VP2
	2623:  "ASUSTek Computer",
	4413:  "Broadcom",
	4542:  "Alerting Specifications Forum",
	5771:  "Cisco Systems",
	6653:  "Tyan Computer",
	7244:  "Quanta Computer",
	10437: "Peppercon / Raritan (IPMI-KVM)",
	10876: "Super Micro Computer",
	11129: "Google",
	12290: "Celestica", // ODM for Dell/Silicom VEP-4600 uCPE
	19046: "Lenovo Group",
	20301: "IBM eServer",
	20569: "Inventec",
	20974: "American Megatrends (AMI)",
	21317: "ATEN International (Supermicro OEM)",
	25506: "H3C",
	37945: "Inspur",
	47196: "Hewlett Packard Enterprise", // Gen11+/iLO6; distinct from PEN 11 legacy HP
	47488: "Nedam Engineering",
	49622: "ASRock Rack",
	58132: "xFusion Digital Technologies", // Huawei x86-server spinoff
}

// ManufacturerNameFor maps an IANA enterprise (PEN) number to a BMC vendor name,
// returning "" when unknown. Shared by Get Device ID and the Get Channel Auth
// Caps OEM-ID fingerprint (both carry an IANA manufacturer number).
func ManufacturerNameFor(id uint32) string { return manufacturerNames[id] }

// ManufacturerName returns the vendor name for the manufacturer ID, or "".
func (d *DeviceID) ManufacturerName() string { return ManufacturerNameFor(d.ManufacturerID) }

// FormatFirmwareRevision renders the two-component firmware revision carried in
// the Get Device ID Firmware Revision 1 and Firmware Revision 2 bytes.
//
// Firmware Revision 2 is BCD, so its nibbles are printed as hex digits (0x19 ->
// "19"). Arithmetic-decoding an out-of-spec byte would turn it into a
// plausible-looking revision, so print it verbatim instead ("ff").
func FormatFirmwareRevision(major, minor byte) string {
	return fmt.Sprintf("%d.%02x", major&0x7f, minor)
}

// auxVersionVendors lists the IANA enterprise numbers whose auxiliary firmware
// revision encoding is confirmed against shipped firmware; the bytes are
// vendor-defined, so an unknown encoding cannot be reconstructed. Supermicro/ATEN
// publish Firmware Revision 1, Firmware Revision 2 and the first auxiliary byte as
// hex digits, and only those three: the second auxiliary byte is not part of the
// published string on every generation, so appending it would invent one.
var auxVersionVendors = map[uint32]bool{
	10876: true, // Super Micro Computer
	21317: true, // ATEN International (the Supermicro OEM stack)
}

// FormatFirmwareRevisionFull reconstructs the vendor-published firmware version
// from the two revision bytes plus the auxiliary revision bytes, or returns ""
// when the vendor's auxiliary encoding is not confirmed or no auxiliary
// revision is present. Callers should report the raw auxiliary bytes as well,
// since "" here means "cannot be reconstructed", not "no data".
func FormatFirmwareRevisionFull(manufacturerID uint32, major, minor byte, aux [4]byte) string {
	if !auxVersionVendors[manufacturerID] || aux[0] == 0 {
		return ""
	}
	return fmt.Sprintf("%02x.%02x.%02x", major&0x7f, minor, aux[0])
}

// FirmwareRevisionFull reconstructs the vendor-published firmware version, or
// "" when it cannot be reconstructed. See FormatFirmwareRevisionFull.
func (d *DeviceID) FirmwareRevisionFull() string {
	return FormatFirmwareRevisionFull(d.ManufacturerID, d.FirmwareMajor, d.FirmwareMinor, d.AuxFirmwareVersion)
}

// Attributes renders the decoded fields for reporting. Firmware minor and IPMI
// version are BCD-encoded per the IPMI spec.
func (d *DeviceID) Attributes() map[string]string {
	m := map[string]string{
		"ipmi.deviceID":         fmt.Sprintf("%d", d.ID),
		"ipmi.deviceRevision":   fmt.Sprintf("%d", d.Revision&0x0f),
		"ipmi.firmwareRevision": FormatFirmwareRevision(d.FirmwareMajor, d.FirmwareMinor),
		"ipmi.ipmiVersion":      fmt.Sprintf("%d.%d", d.IPMIVersion&0x0f, (d.IPMIVersion>>4)&0x0f),
		"ipmi.manufacturerID":   fmt.Sprintf("%d", d.ManufacturerID),
		"ipmi.productID":        fmt.Sprintf("%d", d.ProductID),
	}
	if n := d.ManufacturerName(); n != "" {
		m["ipmi.manufacturerName"] = n
	}
	if d.AuxFirmwareVersion != [4]byte{} {
		m["ipmi.auxFirmwareRev"] = hex.EncodeToString(d.AuxFirmwareVersion[:])
	}
	if full := d.FirmwareRevisionFull(); full != "" {
		m["ipmi.firmwareRevisionFull"] = full
	}
	return m
}

// Summary is a one-line human-readable fingerprint.
func (d *DeviceID) Summary() string {
	vendor := d.ManufacturerName()
	if vendor == "" {
		vendor = fmt.Sprintf("mfrID=%d", d.ManufacturerID)
	}
	fw := FormatFirmwareRevision(d.FirmwareMajor, d.FirmwareMinor)
	if full := d.FirmwareRevisionFull(); full != "" {
		fw = full
	}
	return fmt.Sprintf("%s product=%d fw=%s ipmi=%d.%d",
		vendor, d.ProductID, fw,
		d.IPMIVersion&0x0f, (d.IPMIVersion>>4)&0x0f)
}

// GetDeviceID15 sends an unauthenticated Get Device ID (NetFn App/0x06, Cmd 0x01)
// over the sessionless IPMI 1.5 wrapper and parses the reply. The spec does not
// require this command be processed without a session (only Get Channel Auth Caps
// 0x38, Get Channel Cipher Suites 0x54 and session setup), so a BMC may drop the
// session-zero request: a timeout here says nothing about framing or whether IPMI
// 1.5 is enabled. Use GetChannelAuthCaps15 for a dependable pre-session fingerprint.
func GetDeviceID15(host string, port int, timeout time.Duration) (*DeviceID, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	reply, err := c.Send(buildSessionlessMsg(NetFnApp, CmdGetDeviceID, nil))
	if err != nil {
		return nil, err
	}
	return ParseDeviceIDReply(reply)
}

// GetSystemGUID15 sends an unauthenticated Get System GUID (NetFn App/0x06,
// Cmd 0x37) over the sessionless IPMI 1.5 wrapper and returns the 16-byte GUID
// from the reply.
func GetSystemGUID15(host string, port int, timeout time.Duration) ([]byte, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	reply, err := c.Send(buildSessionlessMsg(NetFnApp, CmdGetSystemGUID, nil))
	if err != nil {
		return nil, err
	}
	return ParseSystemGUIDReply(reply)
}

// ParseDeviceIDReply parses a Get Device ID reply. It anchors on the IPMB
// response header (rsAddr=0x81 followed by rqAddr=0x20) - the same anchoring as
// ParseAuthCapsReply - reads the completion code at start+6, and decodes the
// Device ID fields that begin at start+7.
func ParseDeviceIDReply(reply []byte) (*DeviceID, error) {
	start := -1
	for i := 0; i+7 < len(reply); i++ {
		if (reply[i] == 0x81 || reply[i] == 0x8c) && i+3 < len(reply) && reply[i+3] == 0x20 {
			start = i
			break
		}
	}
	if start < 0 || start+7 >= len(reply) {
		return nil, errors.New("device-id: IPMB response header not found")
	}
	if cc := reply[start+6]; cc != 0x00 {
		return nil, fmt.Errorf("device-id: completion code 0x%02x", cc)
	}
	d := reply[start+7:]
	if len(d) < 11 {
		return nil, errors.New("device-id: short response")
	}
	dev := &DeviceID{
		ID:                d[0],
		Revision:          d[1],
		FirmwareMajor:     d[2],
		FirmwareMinor:     d[3],
		IPMIVersion:       d[4],
		AdditionalSupport: d[5],
		ManufacturerID:    uint32(d[6]) | uint32(d[7])<<8 | uint32(d[8])<<16,
		ProductID:         uint16(d[9]) | uint16(d[10])<<8,
	}
	if len(d) >= 15 {
		copy(dev.AuxFirmwareVersion[:], d[11:15])
	}
	return dev, nil
}

// ParseSystemGUIDReply parses a Get System GUID reply and returns the 16-byte
// GUID payload.
func ParseSystemGUIDReply(reply []byte) ([]byte, error) {
	start := -1
	for i := 0; i+7 < len(reply); i++ {
		if (reply[i] == 0x81 || reply[i] == 0x8c) && i+3 < len(reply) && reply[i+3] == 0x20 {
			start = i
			break
		}
	}
	if start < 0 || start+7 >= len(reply) {
		return nil, errors.New("system-guid: IPMB response header not found")
	}
	if cc := reply[start+6]; cc != 0x00 {
		return nil, fmt.Errorf("system-guid: completion code 0x%02x", cc)
	}
	d := reply[start+7:]
	if len(d) < 16 {
		return nil, errors.New("system-guid: short response")
	}
	return append([]byte(nil), d[:16]...), nil
}
