package ipmi

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// DCMICapabilities holds the parsed reply to Get DCMI Capabilities Info (Group Extension
// NetFn 0x2C / Cmd 0x01, group ID 0xDC, parameter selector 0x01 = Supported DCMI
// capabilities). A valid reply confirms the DCMI group extension, and the version plus
// parameter revision are a sessionless fingerprint. The command is answered without a
// session on BMCs that gate group-extension discovery on the 0xDC group byte, so it belongs
// with the other unauthenticated reads.
type DCMICapabilities struct {
	MajorVersion  byte   // DCMI specification conformance, major (e.g. 1)
	MinorVersion  byte   // DCMI specification conformance, minor (e.g. 5 => DCMI 1.5)
	ParamRevision byte   // parameter data revision
	ParamData     []byte // raw parameter data for the Supported-capabilities selector
}

// Version renders the DCMI specification version as major.minor.
func (d *DCMICapabilities) Version() string {
	return fmt.Sprintf("%d.%d", d.MajorVersion, d.MinorVersion)
}

// GetDCMICapabilities15 sends an unauthenticated Get DCMI Capabilities Info
// (NetFn Group 0x2C / Cmd 0x01) over the sessionless IPMI 1.5 wrapper. The
// request carries the DCMI group ID (0xDC) followed by a parameter selector
// (0x01 = Supported DCMI capabilities). A non-DCMI BMC drops the request or
// returns a non-zero completion code; a DCMI BMC echoes the 0xDC group byte and
// its spec version.
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

// ParseDCMICapabilitiesReply parses a Get DCMI Capabilities Info reply. It anchors on the
// IPMB response header (rsAddr 0x81/0x8c followed by rqAddr 0x20), the same anchoring as
// ParseDeviceIDReply, then reads the completion code at start+6 and the data at start+7:
// group ID, major version, minor version, parameter revision, parameter data. The group ID
// has to be 0xDC, which is what separates a DCMI reply from a generic Group Extension
// error/echo; anything else is rejected rather than mis-reported as DCMI-capable.
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

// SupportedCapsHex returns the raw Supported-DCMI-capabilities parameter bytes
// as hex, or "" when absent. Reported as evidence for later analysis.
func (d *DCMICapabilities) SupportedCapsHex() string {
	if len(d.ParamData) == 0 {
		return ""
	}
	return hex.EncodeToString(d.ParamData)
}
