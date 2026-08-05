package ipmi

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

type DCMICapabilities struct {
	MajorVersion  byte
	MinorVersion  byte
	ParamRevision byte
	ParamData     []byte
}

func (d *DCMICapabilities) Version() string {
	return fmt.Sprintf("%d.%d", d.MajorVersion, d.MinorVersion)
}

func GetDCMICapabilities15(host string, port int, timeout time.Duration) (*DCMICapabilities, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	reply, err := c.Send(buildSessionlessMsg(NetFnGroup, CmdDCMIGetCapabilities,
		[]byte{DCMIGroupExtID, DCMIParamSupportedCaps}))
	if err != nil {
		return nil, err
	}
	return ParseDCMICapabilitiesReply(reply)
}

func ParseDCMICapabilitiesReply(reply []byte) (*DCMICapabilities, error) {
	start := -1
	for i := 0; i+7 < len(reply); i++ {
		if (reply[i] == 0x81 || reply[i] == 0x8c) && i+3 < len(reply) && reply[i+3] == 0x20 {
			start = i
			break
		}
	}
	if start < 0 || start+7 >= len(reply) {
		return nil, errors.New("dcmi: IPMB response header not found")
	}
	if cc := reply[start+6]; cc != 0x00 {
		return nil, fmt.Errorf("dcmi: completion code 0x%02x", cc)
	}
	d := reply[start+7:]
	if len(d) < 4 {
		return nil, errors.New("dcmi: short response")
	}
	if d[0] != DCMIGroupExtID {
		return nil, fmt.Errorf("dcmi: unexpected group id 0x%02x", d[0])
	}
	dc := &DCMICapabilities{
		MajorVersion:  d[1],
		MinorVersion:  d[2],
		ParamRevision: d[3],
	}
	if len(d) > 4 {
		dc.ParamData = append([]byte(nil), d[4:]...)
	}
	return dc, nil
}

func (d *DCMICapabilities) SupportedCapsHex() string {
	if len(d.ParamData) == 0 {
		return ""
	}
	return hex.EncodeToString(d.ParamData)
}
