package ipmi

// Session-level ops for the SMC-0022 alert-delivery sinks: the OEM IPMI SMTP
// configuration setter/getter (NetFn 0x30, command 0x68, subfunction 0x06) and
// the PEF Alert Immediate trigger (NetFn 0x04, command 0x16).

import (
	"context"
	"fmt"
	"strings"
)

// SMCSMTPSet stores one SMTP configuration field. The completion code is
// returned so a caller can distinguish a stored value (0x00) from a build that
// validates or refuses it (X11 rejects shell metacharacters with 0xcc; X12,
// X13-DAI and H13 answer with a 0xcc stub). An error is returned only for a
// transport failure or a malformed request.
func (s *CmdSess) SMCSMTPSet(field byte, value string) (byte, error) {
	req, err := SMCSMTPRequest(SMCSMTPOpSet, field, value)
	if err != nil {
		return 0xff, err
	}
	cc, _, err := s.ExecRaw(NetFnSMCOEM, CmdSMCSMTPSetting, req)
	return cc, err
}

// SMCSMTPGet reads one SMTP configuration field back. The return is the raw
// stored bytes, which is the readback that proves a set was stored verbatim
// rather than rejected.
func (s *CmdSess) SMCSMTPGet(field byte) (string, byte, error) {
	req, err := SMCSMTPRequest(SMCSMTPOpGet, field, "")
	if err != nil {
		return "", 0xff, err
	}
	cc, data, err := s.ExecRaw(NetFnSMCOEM, CmdSMCSMTPSetting, req)
	if err != nil {
		return "", cc, err
	}
	return strings.TrimRight(string(data), "\x00"), cc, nil
}

// SMCAlertImmediate fires the PEF Alert Immediate command, which is the
// on-demand trigger for the alert-delivery sinks. channel and destination select
// the PEF destination; selector, when non-negative, is appended as the optional
// string-selector byte.
func (s *CmdSess) SMCAlertImmediate(channel, destination byte, selector int) (byte, error) {
	req := []byte{channel, destination}
	if selector >= 0 {
		req = append(req, byte(selector))
	}
	cc, _, err := s.ExecRaw(NetFnSensorEvent, CmdAlertImmediate, req)
	return cc, err
}

// SMCDeviceGeneration reads Get Device ID in-session and reports the recovered
// vendor firmware revision, for the report header.
func (s *CmdSess) SMCDeviceGeneration(ctx context.Context) (string, error) {
	info, err := s.MCInfo(ctx)
	if err != nil {
		return "", err
	}
	if info == nil {
		return "", fmt.Errorf("no device ID in reply")
	}
	if info.FirmwareRevisionFull != "" {
		return info.FirmwareRevisionFull, nil
	}
	return info.FirmwareRevision, nil
}
