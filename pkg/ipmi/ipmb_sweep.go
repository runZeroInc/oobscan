package ipmi

import (
	"bytes"
	"fmt"
	"time"
)

type IPMBSweepEntry struct {
	TargetAddr     byte
	CompletionCode byte
	Acked          bool
	InnerCC        byte
	HasInnerResp   bool
	RawReply       []byte
	Err            string
}

type IPMBSweepResult struct {
	Host    string
	Entries []IPMBSweepEntry

	Reachable []IPMBSweepEntry
}

func SweepIPMBBridge(host string, port int, timeout time.Duration, logf func(string)) (*IPMBSweepResult, error) {
	if port == 0 {
		port = DefaultPort
	}
	if timeout == 0 {
		timeout = 500 * time.Millisecond
	}

	res := &IPMBSweepResult{Host: host}

	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	total := ((0xFE - 0x20) / 2) + 1
	step := max(total/8, 1)
	idx := 0
	for addr := 0x20; addr <= 0xFE; addr += 2 {
		idx++
		if logf != nil && (idx == 1 || idx == total || idx%step == 0) {
			logf(fmt.Sprintf("ipmi.ipmb: probe %d/%d addr=0x%02x", idx, total, addr))
		}
		e := sweepIPMBAddr(c, byte(addr), timeout)
		res.Entries = append(res.Entries, e)
		if e.Acked && byte(addr) != 0x20 {
			res.Reachable = append(res.Reachable, e)
		}
	}
	if logf != nil {
		logf(fmt.Sprintf("ipmi.ipmb: sweep done (%d reachable)", len(res.Reachable)))
	}
	return res, nil
}

func sweepIPMBAddr(c *Client, targetAddr byte, timeout time.Duration) IPMBSweepEntry {
	e := IPMBSweepEntry{TargetAddr: targetAddr}

	pkt := buildSendMessagePkt(targetAddr)
	reply, err := c.Send(pkt)
	if err != nil {
		e.Err = err.Error()
		return e
	}
	if len(reply) > 32 {
		e.RawReply = reply[:32]
	} else {
		e.RawReply = append([]byte(nil), reply...)
	}

	outerCC, ok := extractCompletionCode(reply)
	if !ok {
		e.Err = fmt.Sprintf("can't parse outer CC from %d-byte reply", len(reply))
		return e
	}
	e.CompletionCode = outerCC
	if outerCC != 0x00 {
		return e
	}
	e.Acked = true

	e.InnerCC, e.HasInnerResp = extractInnerIPMBCC(reply)
	return e
}

func buildSendMessagePkt(targetAddr byte) []byte {

	inner := []byte{
		targetAddr,
		NetFnApp << 2,
		0x00,
		0x20,
		0x00,
		CmdGetDeviceID,
		0x00,
	}
	inner[2] = IPMBChecksum(inner[:2])
	inner[6] = IPMBChecksum(inner[3:6])

	var smData bytes.Buffer

	smData.WriteByte(0x40)
	smData.Write(inner)

	body := make([]byte, 0, 8+smData.Len())
	body = append(body, 0x20)
	body = append(body, NetFnBridge<<2)
	body = append(body, 0x00)
	body[2] = IPMBChecksum(body[:2])
	body = append(body, 0x81)
	body = append(body, 0x00)
	body = append(body, 0x34)
	body = append(body, smData.Bytes()...)
	body = append(body, IPMBChecksum(body[3:]))

	var pkt bytes.Buffer
	pkt.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	pkt.WriteByte(IPMI15AuthNone)
	pkt.Write(make([]byte, 8))
	pkt.WriteByte(byte(len(body)))
	pkt.Write(body)
	return pkt.Bytes()
}

func extractInnerIPMBCC(reply []byte) (byte, bool) {

	if len(reply) < 22 {
		return 0, false
	}

	inner := reply[22:]
	if len(inner) < 7 {
		return 0, false
	}

	return inner[6], true
}

func (r *IPMBSweepResult) IPMBSweepSummary() string {
	return fmt.Sprintf(
		"host=%s probed=%d reachable-satellites=%d",
		r.Host, len(r.Entries), len(r.Reachable),
	)
}
