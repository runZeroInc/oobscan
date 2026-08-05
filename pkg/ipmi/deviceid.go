package ipmi

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

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

var manufacturerNames = map[uint32]string{
	2:     "IBM",
	11:    "Hewlett-Packard",
	42:    "Sun Microsystems",
	211:   "Fujitsu Limited",
	259:   "Accton Technology",
	343:   "Intel Corporation",
	674:   "Dell Inc.",
	802:   "National Semiconductor (Intel mBMC/Sahalee)",
	2011:  "Huawei",
	2050:  "Windward Technologies (BMC firmware)",
	2623:  "ASUSTek Computer",
	4413:  "Broadcom",
	4542:  "Alerting Specifications Forum",
	5771:  "Cisco Systems",
	6653:  "Tyan Computer",
	7244:  "Quanta Computer",
	10437: "Peppercon / Raritan (IPMI-KVM)",
	10876: "Super Micro Computer",
	11129: "Google",
	12290: "Celestica",
	19046: "Lenovo Group",
	20301: "IBM eServer",
	20569: "Inventec",
	20974: "American Megatrends (AMI)",
	21317: "ATEN International (Supermicro OEM)",
	25506: "H3C",
	37945: "Inspur",
	47196: "Hewlett Packard Enterprise",
	47488: "Nedam Engineering",
	49622: "ASRock Rack",
	58132: "xFusion Digital Technologies",
}

func ManufacturerNameFor(id uint32) string { return manufacturerNames[id] }

func (d *DeviceID) ManufacturerName() string { return ManufacturerNameFor(d.ManufacturerID) }

func FormatFirmwareRevision(major, minor byte) string {
	return fmt.Sprintf("%d.%02x", major&0x7f, minor)
}

var auxVersionVendors = map[uint32]bool{
	10876: true,
	21317: true,
}

func FormatFirmwareRevisionFull(manufacturerID uint32, major, minor byte, aux [4]byte) string {
	if !auxVersionVendors[manufacturerID] || aux[0] == 0 {
		return ""
	}
	return fmt.Sprintf("%02x.%02x.%02x", major&0x7f, minor, aux[0])
}

func (d *DeviceID) FirmwareRevisionFull() string {
	return FormatFirmwareRevisionFull(d.ManufacturerID, d.FirmwareMajor, d.FirmwareMinor, d.AuxFirmwareVersion)
}

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
