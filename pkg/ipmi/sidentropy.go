package ipmi

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

// Sampler and classifier for the RMCP+ managed-session-ID weakness. The live
// check, the runZero projection and the report all score the exposure through
// ClassifySessionIDs so they agree on what counts as a weak SID.

// SIDClass is the verdict of classifying a set of BMC-assigned managed session
// IDs sampled across several RMCP+ Open Session exchanges.
type SIDClass struct {
	// Pattern is "static" (every sample identical), "fixedStep" (a constant
	// non-zero delta between consecutive samples), or "smallSpace" (samples
	// confined to a narrow window of the 32-bit space -- the Supermicro/ATEN
	// signature a fixed-step test misses because the low bits still jitter).
	Pattern string
	Detail  string // human-readable evidence
	Delta   uint32 // step size for fixedStep
	Lo, Hi  uint32 // observed range
}

// CheckID maps a verdict onto the oobscan finding id: a session ID that never
// changes is reported as ipmi.sidEntropy (zero entropy), and any other
// predictable assignment as ipmi.sidPredictable.
func (c SIDClass) CheckID() string {
	if c.Pattern == "static" {
		return "ipmi.sidEntropy"
	}
	return "ipmi.sidPredictable"
}

// ClassifySessionIDs decides whether a set of sampled managed session IDs
// reveals a predictable or low-entropy assignment. It needs at least three
// samples; ok=false means too few samples or a spread a well-seeded 32-bit SID
// would produce. Samples confined to a tight window mean the BMC randomizes
// only a handful of low bits, which lets an off-path attacker target an
// established session.
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
	// Three samples inside a 64k window is already decisive for a uniform 32-bit
	// SID, so treat it as a narrowed space rather than chance.
	if hi-lo < 0x10000 {
		return SIDClass{Pattern: "smallSpace", Lo: lo, Hi: hi,
			Detail: fmt.Sprintf("%d session IDs confined to a 0x%x window [0x%08x..0x%08x]", len(sids), hi-lo, lo, hi)}, true
	}
	return SIDClass{}, false
}

// constantStep reports whether the samples advance by a single non-zero delta.
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

// SampleSessionIDs collects up to n BMC-assigned managed session IDs, one per
// RMCP+ Open Session Request, each on its own short-lived socket with a fresh
// random client SID. Failed samples are skipped, and it stops early when the
// first two fail with nothing collected. Every sample attempts to abort the
// half-open session it created, but the abort is not guaranteed, so n bounds the
// setup sessions this can leave behind. See abortSetupSession.
func SampleSessionIDs(host string, port, n int, timeout time.Duration) []uint32 {
	out := make([]uint32, 0, n)
	fails := 0
	for range n {
		sid, ok := sampleOneSessionID(host, port, timeout)
		if !ok {
			fails++
			if fails >= 2 && len(out) == 0 {
				break // not answering RMCP+ setup; don't spend the whole budget here
			}
			continue
		}
		out = append(out, sid)
	}
	return out
}

// sampleOneSessionID opens a single RMCP+ setup session, reads the BMC-assigned
// managed session ID from the Open Session Response, and attempts to abort the
// half-open session before returning.
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
	// SHA1 auth maximizes Open Session acceptance across vendors (ATEN/Supermicro
	// reject auth-None outright); the managed SID comes back regardless of the
	// negotiated algorithm.
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

// abortSetupSession sends a best-effort Close Session for a half-open (pre-RAKP)
// session as a cleartext IPMI message under the managed SID, without waiting for a
// reply so an ignoring BMC cannot stall the sampler. It does not free the slot on
// ATEN, whose Close Session handler requires an active session and answers 0x87
// otherwise, leaving the entry to be reclaimed when the allocator reuses it. A
// failing RAKP3 does release the slot but charges the account's failure counter and
// can persist a lockout, so it is not a usable teardown.
func abortSetupSession(c *Client, bmcSID uint32) {
	lan := buildSessionLANMsg(NetFnApp, CmdCloseSession, binary.LittleEndian.AppendUint32(nil, bmcSID), 1)
	_ = c.SendRaw(buildRMCPPlusSID(PayloadIPMI, bmcSID, 0, lan))
}
