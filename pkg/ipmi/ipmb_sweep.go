package ipmi

import (
	"bytes"
	"fmt"
	"time"
)

// IPMBSweepEntry records the BMC's reaction to a Send Message probe
// targeting a specific IPMB target address.
type IPMBSweepEntry struct {
	TargetAddr     byte   // IPMB slave address (7-bit, i.e. 0x00-0xFE even)
	CompletionCode byte   // outer CC from the BMC wrapper
	Acked          bool   // outer CC == 0x00
	InnerCC        byte   // inner CC from bridged response (if Acked)
	HasInnerResp   bool   // true if inner response body was decoded
	RawReply       []byte // first 32 bytes of raw reply
	Err            string
}

// IPMBSweepResult is the output of SweepIPMBBridge.
type IPMBSweepResult struct {
	Host    string
	Entries []IPMBSweepEntry
	// Reachable is the set of IPMB addresses where the outer CC was 0x00,
	// meaning the BMC attempted to forward to that satellite.
	Reachable []IPMBSweepEntry
}

// SweepIPMBBridge sends a sessionless IPMI 1.5 Send Message (NetFn=Bridge/0x02,
// Cmd=0x34) for each even IPMB slave address in 0x20-0xFE, wrapping a read-only
// Get Device ID (NetFn=App, Cmd=0x01) as the inner message, so nothing here can
// modify NVRAM or state. An outer completion code of 0x00 means the BMC forwarded
// to that satellite, and the inner response is decoded too; an ACK from any
// address but 0x20 (the BMC itself) is a satellite reachable from the network.
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

	// Sweep even addresses 0x20-0xFE. 0x20 is the BMC itself; skip it
	// to reduce noise, but still include it as a baseline.
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

// sweepIPMBAddr probes a single IPMB slave address via Send Message.
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

	// The outer response is an IPMI 1.5 message.
	// Layout: RMCP(4) | session-hdr(10) | body-len(1) | IPMI-body
	// IPMI-body: rsAddr | netfn/lun | csum | rqAddr | rqSeq | cmd | CC | [data] | csum2
	// We want the CC at body[6] from the start of the IPMI body.
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

	// Try to decode the inner IPMB response embedded in the Send Message
	// response data.  The inner frame starts after the outer CC byte.
	// Outer body: [rsAddr, netfn, csum, rqAddr, seq, cmd, CC, inner..., csum]
	// We scan for the inner frame start.
	e.InnerCC, e.HasInnerResp = extractInnerIPMBCC(reply)
	return e
}

// buildSendMessagePkt builds a sessionless IPMI 1.5 Send Message (0x34)
// on NetFn=Bridge (0x02) targeting the given IPMB slave address.
// The inner message is Get Device ID (NetFn=App/0x06, Cmd=0x01).
func buildSendMessagePkt(targetAddr byte) []byte {
	// Inner IPMB frame: rsAddr | netfn/lun | csum1 | rqAddr | rqSeq | cmd | csum2
	inner := []byte{
		targetAddr,     // rsAddr (satellite)
		NetFnApp << 2,  // netfn=App(0x06), lun=0
		0x00,           // csum1 placeholder
		0x20,           // rqAddr (BMC as bridge initiator)
		0x00,           // rqSeq/lun
		CmdGetDeviceID, // cmd = Get Device ID (0x01)
		0x00,           // csum2 placeholder
	}
	inner[2] = IPMBChecksum(inner[:2])
	inner[6] = IPMBChecksum(inner[3:6])

	// Send Message data: channel(1=IPMB, Tracking=11b) | inner IPMB frame
	var smData bytes.Buffer
	// channel byte: [7:6]=tracking(11=send+recv), [5:4]=reserved, [3:0]=channel
	// Use channel 0x00 (IPMB-0) with tracking bits 0x40 (send&track)
	smData.WriteByte(0x40)
	smData.Write(inner)

	// Outer IPMI body (sessionless): Bridge NetFn, Send Message cmd
	body := make([]byte, 0, 8+smData.Len())
	body = append(body, 0x20)           // rsAddr
	body = append(body, NetFnBridge<<2) // netfn=Bridge(0x02), lun=0
	body = append(body, 0x00)           // csum1 placeholder
	body[2] = IPMBChecksum(body[:2])
	body = append(body, 0x81) // rqAddr
	body = append(body, 0x00) // rqSeq/lun
	body = append(body, 0x34) // Send Message cmd
	body = append(body, smData.Bytes()...)
	body = append(body, IPMBChecksum(body[3:])) // csum2

	var pkt bytes.Buffer
	pkt.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	pkt.WriteByte(IPMI15AuthNone)
	pkt.Write(make([]byte, 8)) // session sequence and ID
	pkt.WriteByte(byte(len(body)))
	pkt.Write(body)
	return pkt.Bytes()
}

// extractInnerIPMBCC attempts to decode the bridged inner response embedded
// in a Send Message reply. Returns (inner CC, true) on success.
func extractInnerIPMBCC(reply []byte) (byte, bool) {
	// Outer IPMI body starts after RMCP(4) + session-hdr(10) + len(1) = 15.
	// Outer body: rsAddr(1) + netfn(1) + csum1(1) + rqAddr(1) + seq(1) + cmd(1) + CC(1) = 7 bytes
	// Then the Send Message response data begins (may include inner IPMB frame).
	if len(reply) < 22 {
		return 0, false
	}
	// Skip RMCP(4) + session-hdr(10) + body-len(1) + outer-header(7) = 22 bytes
	inner := reply[22:]
	if len(inner) < 7 {
		return 0, false
	}
	// Inner IPMB response: rsAddr | netfn/lun | csum1 | rqAddr | seq | cmd | CC | ...
	return inner[6], true
}

// IPMBSweepSummary returns a human-readable summary.
func (r *IPMBSweepResult) IPMBSweepSummary() string {
	return fmt.Sprintf(
		"host=%s probed=%d reachable-satellites=%d",
		r.Host, len(r.Entries), len(r.Reachable),
	)
}
