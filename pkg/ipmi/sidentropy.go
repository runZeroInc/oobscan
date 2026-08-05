package ipmi

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

type SIDClass struct {
	Pattern string
	Detail  string
	Delta   uint32
	Lo, Hi  uint32
}

func (c SIDClass) CheckID() string {
	if c.Pattern == "static" {
		return "ipmi.sidEntropy"
	}
	return "ipmi.sidPredictable"
}

func ClassifySessionIDs(sids []uint32) (SIDClass, bool) {
	if len(sids) < 3 {
		return SIDClass{}, false
	}
	lo, hi := sids[0], sids[0]
	static := true
	for _, v := range sids[1:] {
		if v != sids[0] {
			static = false
		}
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
	}
	if static {
		return SIDClass{Pattern: "static", Lo: lo, Hi: hi,
			Detail: fmt.Sprintf("session ID fixed at 0x%08x across %d samples", sids[0], len(sids))}, true
	}
	if step, ok := constantStep(sids); ok {
		return SIDClass{Pattern: "fixedStep", Delta: step, Lo: lo, Hi: hi,
			Detail: fmt.Sprintf("session ID advances by a constant 0x%x step across %d samples", step, len(sids))}, true
	}

	if hi-lo < 0x10000 {
		return SIDClass{Pattern: "smallSpace", Lo: lo, Hi: hi,
			Detail: fmt.Sprintf("%d session IDs confined to a 0x%x window [0x%08x..0x%08x]", len(sids), hi-lo, lo, hi)}, true
	}
	return SIDClass{}, false
}

func constantStep(sids []uint32) (uint32, bool) {
	step := sids[1] - sids[0]
	if step == 0 {
		return 0, false
	}
	for i := 2; i < len(sids); i++ {
		if sids[i]-sids[i-1] != step {
			return 0, false
		}
	}
	return step, true
}

func SampleSessionIDs(host string, port, n int, timeout time.Duration) []uint32 {
	out := make([]uint32, 0, n)
	fails := 0
	for range n {
		sid, ok := sampleOneSessionID(host, port, timeout)
		if !ok {
			fails++
			if fails >= 2 && len(out) == 0 {
				break
			}
			continue
		}
		out = append(out, sid)
	}
	return out
}

func sampleOneSessionID(host string, port int, timeout time.Duration) (uint32, bool) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return 0, false
	}
	defer c.Close()

	var cSID uint32
	if err := binary.Read(rand.Reader, binary.LittleEndian, &cSID); err != nil || cSID == 0 {
		cSID = 0xa0a2a3a4
	}

	body := buildOpenSessionMinimal(cSID, RAKPHMACSHA1, IntegrityNone, ConfNone)
	resp, err := c.Send(buildRMCPPlus(PayloadOpenSessionReq, 0, 0, body))
	if err != nil {
		return 0, false
	}
	bmcSID, err := parseOpenSessionResp(resp)
	if err != nil || bmcSID == 0 {
		return 0, false
	}
	abortSetupSession(c, bmcSID)
	return bmcSID, true
}

func abortSetupSession(c *Client, bmcSID uint32) {
	lan := buildSessionLANMsg(NetFnApp, CmdCloseSession, binary.LittleEndian.AppendUint32(nil, bmcSID), 1)
	_ = c.SendRaw(buildRMCPPlusSID(PayloadIPMI, bmcSID, 0, lan))
}
