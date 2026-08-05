package ipmi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

type NetFnSweepMode uint8

const (
	SweepPreSession NetFnSweepMode = iota

	SweepSessionZero
)

type NetFnSweepEntry struct {
	NetFn          byte
	Cmd            byte
	CompletionCode byte
	Accepted       bool
	AuthRequired   bool
	Unsupported    bool
	RawReply       []byte
	Err            string
}

type NetFnSweepResult struct {
	Host    string
	Mode    NetFnSweepMode
	Entries []NetFnSweepEntry

	Accepted []NetFnSweepEntry

	WriteReachable []NetFnSweepEntry
}

var OEMNetFnRange = [...]byte{
	0x2E, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E,
}

func SweepOEMNetFns(host string, port int, mode NetFnSweepMode, sweepAllCmds bool, timeout time.Duration) (*NetFnSweepResult, error) {
	if port == 0 {
		port = DefaultPort
	}
	if timeout == 0 {
		timeout = 500 * time.Millisecond
	}

	res := &NetFnSweepResult{Host: host, Mode: mode}

	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	for _, netfn := range OEMNetFnRange {
		for cmd := 0; cmd <= 0xFF; cmd++ {
			if !sweepAllCmds && cmd%2 != 0 {
				continue
			}
			e := sweepOne(c, host, port, netfn, byte(cmd), mode, timeout)
			res.Entries = append(res.Entries, e)
			if e.Accepted {
				res.Accepted = append(res.Accepted, e)

				if cmd%2 != 0 {
					res.WriteReachable = append(res.WriteReachable, e)
				}
			}
		}
	}
	return res, nil
}

func SweepOEMNetFnsSample(host string, port int, mode NetFnSweepMode, cmds []byte, timeout time.Duration, logf func(string)) (*NetFnSweepResult, error) {
	if port == 0 {
		port = DefaultPort
	}
	if timeout == 0 {
		timeout = 500 * time.Millisecond
	}
	res := &NetFnSweepResult{Host: host, Mode: mode}
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	total := len(OEMNetFnRange) * len(cmds)
	step := max(total/8, 1)
	idx := 0
	for _, netfn := range OEMNetFnRange {
		for _, cmd := range cmds {
			idx++
			if logf != nil && (idx == 1 || idx == total || idx%step == 0) {
				logf(fmt.Sprintf("ipmi.netfnOem: probe %d/%d netfn=0x%02x cmd=0x%02x", idx, total, netfn, cmd))
			}
			e := sweepOne(c, host, port, netfn, cmd, mode, timeout)
			res.Entries = append(res.Entries, e)
			if e.Accepted {
				res.Accepted = append(res.Accepted, e)
				if int(cmd)%2 != 0 {
					res.WriteReachable = append(res.WriteReachable, e)
				}
			}
		}
	}
	if logf != nil {
		logf(fmt.Sprintf("ipmi.netfnOem: sweep done (%d accepted)", len(res.Accepted)))
	}
	return res, nil
}

func sweepOne(c *Client, host string, port int, netfn, cmd byte, mode NetFnSweepMode, timeout time.Duration) NetFnSweepEntry {
	e := NetFnSweepEntry{NetFn: netfn, Cmd: cmd}

	var pkt []byte
	switch mode {
	case SweepPreSession:
		pkt = buildSessionlessMsg(netfn, cmd, nil)
	case SweepSessionZero:

		p, ferr := buildSessionZeroMsg(host, port, netfn, cmd, timeout)
		if ferr != nil {
			e.Err = ferr.Error()
			return e
		}
		pkt = p
	}

	reply, err := c.Send(pkt)
	if err != nil {
		e.Err = err.Error()
		return e
	}

	cc, ok := extractCompletionCode(reply)
	if !ok {
		e.Err = fmt.Sprintf("can't parse CC from %d-byte reply", len(reply))
		return e
	}
	e.CompletionCode = cc
	if len(reply) > 32 {
		e.RawReply = reply[:32]
	} else {
		e.RawReply = append([]byte(nil), reply...)
	}

	switch cc {
	case 0x00:
		e.Accepted = true
	case 0xD4, 0xD5, 0xD6:
		e.AuthRequired = true
	case 0xC1:
		e.Unsupported = true
	}
	return e
}

func buildSessionlessMsg(netfn, cmd byte, data []byte) []byte {

	body := make([]byte, 0, 7+len(data))
	body = append(body, 0x20)
	body = append(body, netfn<<2)
	body = append(body, 0x00)
	body[2] = IPMBChecksum(body[:2])
	body = append(body, 0x81)
	body = append(body, 0x00)
	body = append(body, cmd)
	body = append(body, data...)
	body = append(body, IPMBChecksum(body[3:]))

	var pkt bytes.Buffer
	pkt.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	pkt.WriteByte(IPMI15AuthNone)
	pkt.Write([]byte{0, 0, 0, 0})
	pkt.Write([]byte{0, 0, 0, 0})
	pkt.WriteByte(byte(len(body)))
	pkt.Write(body)
	return pkt.Bytes()
}

func buildSessionZeroMsg(host string, port int, netfn, cmd byte, timeout time.Duration) ([]byte, error) {

	res, err := DoRAKP12(host, port, "", RAKPNone, IntegrityNone, ConfNone, timeout)
	if err != nil {
		return nil, fmt.Errorf("session-zero open failed: %w", err)
	}

	body := make([]byte, 0, 8)
	body = append(body, 0x20)
	body = append(body, netfn<<2)
	body = append(body, 0x00)
	body[2] = IPMBChecksum(body[:2])
	body = append(body, 0x81)
	body = append(body, 0x00)
	body = append(body, cmd)
	body = append(body, IPMBChecksum(body[3:]))

	var pkt bytes.Buffer
	pkt.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	pkt.WriteByte(IPMI20Format)
	pkt.WriteByte(PayloadIPMI)

	sid := [4]byte{}
	sid[0] = byte(res.BMCSID)
	sid[1] = byte(res.BMCSID >> 8)
	sid[2] = byte(res.BMCSID >> 16)
	sid[3] = byte(res.BMCSID >> 24)
	pkt.Write(sid[:])
	pkt.Write([]byte{1, 0, 0, 0})
	pkt.Write([]byte{byte(len(body)), 0})
	pkt.Write(body)
	return pkt.Bytes(), nil
}

func extractCompletionCode(reply []byte) (byte, bool) {
	if len(reply) < 13 {
		return 0, false
	}
	var body []byte
	if reply[4] == IPMI20Format {
		if len(reply) < 16 {
			return 0, false
		}
		payloadLen := int(binary.LittleEndian.Uint16(reply[14:16]))
		if len(reply) < 16+payloadLen {
			return 0, false
		}
		body = reply[16 : 16+payloadLen]
	} else {

		body = reply[13:]
	}

	for i := 0; i+6 < len(body); i++ {
		if (body[i] == 0x81 || body[i] == 0x8c) && body[i+3] == 0x20 {
			return body[i+6], true
		}
	}
	return 0, false
}

func (r *NetFnSweepResult) SweepResultSummary() string {
	mode := "pre-session"
	if r.Mode == SweepSessionZero {
		mode = "session-zero"
	}
	return fmt.Sprintf(
		"host=%s mode=%s probes=%d accepted=%d writeReachable=%d",
		r.Host, mode, len(r.Entries), len(r.Accepted), len(r.WriteReachable),
	)
}
