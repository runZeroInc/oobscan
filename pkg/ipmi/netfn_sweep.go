package ipmi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// NetFnSweepMode controls which session context is used when sweeping.
type NetFnSweepMode uint8

const (
	// SweepPreSession sends every probe as a sessionless (IPMI 1.5, SID=0)
	// message.  This is the highest-signal mode: any command accepted here
	// requires *zero* authentication.
	SweepPreSession NetFnSweepMode = iota

	// SweepSessionZero sends via an RMCP+ Open Session (no RAKP) so that the
	// BMC sees session-zero context.  Some OEM NetFns are accessible only at
	// this stage, before auth completes.
	SweepSessionZero
)

// NetFnSweepEntry records the BMC's reaction to a single (NetFn, Cmd) probe.
type NetFnSweepEntry struct {
	NetFn          byte
	Cmd            byte
	CompletionCode byte   // 0x00 = success, 0xC1 = unsupported, 0xD4 = no-auth, ...
	Accepted       bool   // true when CC == 0x00
	AuthRequired   bool   // true when CC == 0xD4 (insufficient privilege)
	Unsupported    bool   // true when CC == 0xC1 (invalid command)
	RawReply       []byte // first 32 bytes of the reply
	Err            string // non-empty if no reply at all
}

// NetFnSweepResult is the output of SweepOEMNetFns.
type NetFnSweepResult struct {
	Host    string
	Mode    NetFnSweepMode
	Entries []NetFnSweepEntry
	// Accepted collects every (NetFn, Cmd) pair where CC==0x00 (success).
	Accepted []NetFnSweepEntry
	// WriteReachable is the subset of Accepted that look like write commands
	// (odd Cmd byte is a rough heuristic; callers should refine).
	WriteReachable []NetFnSweepEntry
}

// OEMNetFnRange is the IPMI-spec OEM / group extension range.
// Tracks C sweeps 0x2E-0x3F (even = request; odd = response, not sent).
var OEMNetFnRange = [...]byte{
	0x2E, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E,
}

// SweepOEMNetFns iterates every (NetFn, Cmd) pair in the OEM range x [0x00, 0xFF]
// and records the BMC's completion code. It is read-biased by default: only even
// command bytes are probed, since writes are odd by loose convention in many
// vendor SDKs, which is why --mfg-mode has to set sweepAllCmds=true. That also
// stops the sweep avoiding commands likely to modify NVRAM, so it is for owned or
// lab hardware only.
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
				continue // skip odd cmds in safe mode
			}
			e := sweepOne(c, host, port, netfn, byte(cmd), mode, timeout)
			res.Entries = append(res.Entries, e)
			if e.Accepted {
				res.Accepted = append(res.Accepted, e)
				// Heuristic: odd cmd byte within even-numbered pair
				// suggests a mutating operation (get=even, set=odd).
				if cmd%2 != 0 {
					res.WriteReachable = append(res.WriteReachable, e)
				}
			}
		}
	}
	return res, nil
}

// SweepOEMNetFnsSample is a fast-path variant for audit mode. It probes only
// the provided command bytes across every OEM NetFn in OEMNetFnRange.
// Use SweepOEMNetFns for exhaustive research runs.
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

// sweepOne sends one pre-session or session-zero IPMI probe and classifies the
// reply.  It deliberately opens a fresh Client per call when in SessionZero
// mode so that each probe gets a fresh RMCP+ handshake.
func sweepOne(c *Client, host string, port int, netfn, cmd byte, mode NetFnSweepMode, timeout time.Duration) NetFnSweepEntry {
	e := NetFnSweepEntry{NetFn: netfn, Cmd: cmd}

	var pkt []byte
	switch mode {
	case SweepPreSession:
		pkt = buildSessionlessMsg(netfn, cmd, nil)
	case SweepSessionZero:
		// Session-zero: open a fresh RMCP+ session (no auth), then send
		// the IPMI message inside the session frame.  We reuse the helper
		// from rakp.go.  If it fails we fall back to pre-session.
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
	case 0xD4, 0xD5, 0xD6: // insufficient privilege / cannot execute, req in wrong state
		e.AuthRequired = true
	case 0xC1: // invalid/unsupported command
		e.Unsupported = true
	}
	return e
}

// buildSessionlessMsg constructs an IPMI 1.5 sessionless packet (SID=0,
// seq=0, auth=none) for the given NetFn and Cmd with optional payload.
//
// Wire format:
//
//	RMCP(4) | authType(1)=0 | seq(4)=0 | SID(4)=0 | msglen(1) |
//	rsAddr(1) | netfn/lun(1) | csum1(1) |
//	rqAddr(1) | rqSeq/lun(1) | cmd(1) | [data...] | csum2(1)
func buildSessionlessMsg(netfn, cmd byte, data []byte) []byte {
	// IPMI message body
	body := make([]byte, 0, 7+len(data))
	body = append(body, 0x20)     // rsAddr (BMC)
	body = append(body, netfn<<2) // netfn/lun (no lun)
	body = append(body, 0x00)     // csum1 placeholder
	body[2] = IPMBChecksum(body[:2])
	body = append(body, 0x81) // rqAddr (remote console)
	body = append(body, 0x00) // rqSeq/lun
	body = append(body, cmd)  // cmd
	body = append(body, data...)
	body = append(body, IPMBChecksum(body[3:])) // csum2

	var pkt bytes.Buffer
	pkt.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	pkt.WriteByte(IPMI15AuthNone)
	pkt.Write([]byte{0, 0, 0, 0}) // session seq
	pkt.Write([]byte{0, 0, 0, 0}) // session ID
	pkt.WriteByte(byte(len(body)))
	pkt.Write(body)
	return pkt.Bytes()
}

// buildSessionZeroMsg opens an RMCP+ session with no auth and wraps the IPMI
// command inside, returning the full framed packet ready to send. It opens a
// fresh connection each call. The BMC may or may not assign a valid session
// context before authentication completes; the resulting completion code says
// which side of that line a particular command sits on.
func buildSessionZeroMsg(host string, port int, netfn, cmd byte, timeout time.Duration) ([]byte, error) {
	// Open session with auth=None, integrity=None, conf=None.
	res, err := DoRAKP12(host, port, "", RAKPNone, IntegrityNone, ConfNone, timeout)
	if err != nil {
		return nil, fmt.Errorf("session-zero open failed: %w", err)
	}

	// Build IPMI message body.
	body := make([]byte, 0, 8)
	body = append(body, 0x20)
	body = append(body, netfn<<2)
	body = append(body, 0x00)
	body[2] = IPMBChecksum(body[:2])
	body = append(body, 0x81)
	body = append(body, 0x00)
	body = append(body, cmd)
	body = append(body, IPMBChecksum(body[3:]))

	// Wrap in RMCP+ IPMI payload with the BMC-assigned session ID.
	var pkt bytes.Buffer
	pkt.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	pkt.WriteByte(IPMI20Format)
	pkt.WriteByte(PayloadIPMI)
	// Session ID (BMC-assigned) and sequence number.
	sid := [4]byte{}
	sid[0] = byte(res.BMCSID)
	sid[1] = byte(res.BMCSID >> 8)
	sid[2] = byte(res.BMCSID >> 16)
	sid[3] = byte(res.BMCSID >> 24)
	pkt.Write(sid[:])
	pkt.Write([]byte{1, 0, 0, 0}) // seq=1
	pkt.Write([]byte{byte(len(body)), 0})
	pkt.Write(body)
	return pkt.Bytes(), nil
}

// extractCompletionCode returns the IPMI completion code from a raw reply.
// It supports both sessionless IPMI 1.5 wrappers and RMCP+ session-zero replies.
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
		// RMCP(4) + authType/session(9) for v1.5 wrappers.
		body = reply[13:]
	}

	// IPMI response body layout includes: rqAddr(0x81 or 0x8c on some bridged
	// channels), netfn|1, cksum, rsAddr(0x20), seq, cmd, completion_code.
	for i := 0; i+6 < len(body); i++ {
		if (body[i] == 0x81 || body[i] == 0x8c) && body[i+3] == 0x20 {
			return body[i+6], true
		}
	}
	return 0, false
}

// SweepResultSummary returns a human-readable summary for display.
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
