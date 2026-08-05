package ipmi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type PreAuthMapConfig struct {
	NetFns              []byte
	Cmds                []byte
	RunSessionZeroCheck bool
	RunIPMBSweep        bool
	RunRAKPChecks       bool
	RAKPUsers           []string
	Timeout             time.Duration
	LeakLenThreshold    int
	RepeatCount         int
	Concurrency         int
	Logf                func(string)
}

type PreAuthRequestResult struct {
	Mode           string `json:"mode"`
	NetFn          byte   `json:"netfn,omitempty"`
	Cmd            byte   `json:"cmd,omitempty"`
	IPMBAddr       byte   `json:"ipmbAddr,omitempty"`
	ResponseSeen   bool   `json:"responseSeen"`
	CompletionCode byte   `json:"completionCode,omitempty"`
	ParsedCC       bool   `json:"parsedCc"`
	ResponseLen    int    `json:"responseLen,omitempty"`
	ResponsePrefix string `json:"responsePrefix,omitempty"`
	Error          string `json:"error,omitempty"`

	PotentialMemoryLeak bool   `json:"potentialMemoryLeak"`
	LeakReason          string `json:"leakReason,omitempty"`

	PotentialAuthBypass bool   `json:"potentialAuthBypass"`
	BypassReason        string `json:"bypassReason,omitempty"`
}

type RAKPPreAuthResult struct {
	Username            string `json:"username"`
	ErrorCode           byte   `json:"errorCode"`
	HashLen             int    `json:"hashLen"`
	GUIDPrefix          string `json:"guidPrefix,omitempty"`
	PotentialHashLeak   bool   `json:"potentialHashLeak"`
	PotentialUserOracle bool   `json:"potentialUserOracle"`
	Error               string `json:"error,omitempty"`
}

type PreAuthMapResult struct {
	Host string `json:"host"`
	Port int    `json:"port"`

	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`

	Requests []PreAuthRequestResult `json:"requests"`
	RAKP     []RAKPPreAuthResult    `json:"rakp,omitempty"`

	ResponseCount        int `json:"responseCount"`
	AcceptedCount        int `json:"acceptedCount"`
	PotentialLeakCount   int `json:"potentialLeakCount"`
	PotentialBypassCount int `json:"potentialBypassCount"`
}

func DefaultBroadNetFns() []byte {
	return []byte{
		NetFnChassis, NetFnBridge, NetFnSensor, NetFnApp,
		NetFnFirmware, NetFnStorage, NetFnTransport,
		NetFnGroup,
		0x2E, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E,
	}
}

func DefaultBroadCmds() []byte {
	return []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C,
		0x40, 0x44, 0x48, 0x4C, 0x50, 0x54, 0x58, 0x5C,
		0x60, 0x64, 0x68, 0x6C, 0x70, 0x74, 0x78, 0x7C,
		0x80, 0x88, 0x90, 0x98, 0xA0, 0xB0, 0xC0, 0xD0,
		0xE0, 0xF0, 0xF8, 0xFC, 0xFD, 0xFE, 0xFF,
	}
}

func AllCmds() []byte {
	out := make([]byte, 256)
	for i := range 256 {
		out[i] = byte(i)
	}
	return out
}

func MapPreAuthSurface(host string, port int, cfg PreAuthMapConfig) (*PreAuthMapResult, error) {
	if port == 0 {
		port = DefaultPort
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 150 * time.Millisecond
	}
	if len(cfg.NetFns) == 0 {
		cfg.NetFns = DefaultBroadNetFns()
	}
	if len(cfg.Cmds) == 0 {
		cfg.Cmds = DefaultBroadCmds()
	}
	if cfg.LeakLenThreshold <= 0 {
		cfg.LeakLenThreshold = 96
	}
	if cfg.RepeatCount < 2 {
		cfg.RepeatCount = 2
	}
	if len(cfg.RAKPUsers) == 0 {

		cfg.RAKPUsers = []string{"admin", "root", "ADMIN", "USERID", "ipmiusr"}
	}
	if cfg.Logf != nil {
		cfg.Logf(fmt.Sprintf("ipmi.fullWalk: starting %d netfn x %d cmd pre-session sweep", len(cfg.NetFns), len(cfg.Cmds)))
	}

	res := &PreAuthMapResult{
		Host:      host,
		Port:      port,
		StartedAt: time.Now(),
	}

	c, err := NewClient(host, port, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	type sweepJob struct{ netfn, cmd byte }
	var jobs []sweepJob
	for _, netfn := range cfg.NetFns {
		for _, cmd := range cfg.Cmds {
			jobs = append(jobs, sweepJob{netfn, cmd})
		}
	}
	workers := cfg.Concurrency
	if workers <= 0 {
		workers = 16
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}
	if cfg.Logf != nil {
		cfg.Logf(fmt.Sprintf("ipmi.fullWalk: pre-session sweep %d probes", len(jobs)))
	}
	sweepResults := make([]PreAuthRequestResult, len(jobs))
	jobCh := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Go(func() {
			wc, cerr := NewClient(host, port, cfg.Timeout)
			if wc != nil {
				defer wc.Close()
			}
			for idx := range jobCh {
				if wc == nil {
					sweepResults[idx] = PreAuthRequestResult{
						Mode: "pre-session", NetFn: jobs[idx].netfn, Cmd: jobs[idx].cmd,
						Error: fmt.Sprintf("client: %v", cerr),
					}
					continue
				}
				sweepResults[idx] = probePreAuthRequest(wc, host, port, jobs[idx].netfn, jobs[idx].cmd, SweepPreSession, cfg)
			}
		})
	}
	for i := range jobs {
		jobCh <- i
	}
	close(jobCh)
	wg.Wait()
	res.Requests = append(res.Requests, sweepResults...)
	res.tally()
	if cfg.Logf != nil {
		cfg.Logf(fmt.Sprintf("ipmi.fullWalk: pre-session sweep done (%d responses, %d accepted)", res.ResponseCount, res.AcceptedCount))
	}

	if cfg.RunSessionZeroCheck {
		if cfg.Logf != nil {
			cfg.Logf("ipmi.fullWalk: session-zero follow-up")
		}
		seen := 0
		for _, prior := range res.Requests {
			if !prior.ResponseSeen {
				continue
			}
			seen++
			if cfg.Logf != nil && (seen == 1 || seen%32 == 0) {
				cfg.Logf(fmt.Sprintf("ipmi.fullWalk: session-zero probe %d", seen))
			}
			r := probePreAuthRequest(c, host, port, prior.NetFn, prior.Cmd, SweepSessionZero, cfg)
			res.Requests = append(res.Requests, r)
		}
	}

	if cfg.RunIPMBSweep {
		if cfg.Logf != nil {
			cfg.Logf("ipmi.fullWalk: IPMB bridge sweep")
		}
		ipmb, err := SweepIPMBBridge(host, port, cfg.Timeout, cfg.Logf)
		if err == nil {
			for _, e := range ipmb.Entries {
				r := PreAuthRequestResult{
					Mode:           "ipmb-bridge",
					IPMBAddr:       e.TargetAddr,
					ResponseSeen:   e.Err == "",
					CompletionCode: e.CompletionCode,
					ParsedCC:       e.Err == "",
					ResponseLen:    len(e.RawReply),
					ResponsePrefix: hexPrefix(e.RawReply),
					Error:          e.Err,
				}
				if e.Acked && e.TargetAddr != 0x20 {
					r.PotentialAuthBypass = true
					r.BypassReason = fmt.Sprintf("IPMB satellite reachable pre-auth at 0x%02x", e.TargetAddr)
				}
				res.Requests = append(res.Requests, r)
			}
		}
	}

	if cfg.RunRAKPChecks && len(cfg.RAKPUsers) > 0 {
		if cfg.Logf != nil {
			cfg.Logf(fmt.Sprintf("ipmi.fullWalk: RAKP pre-auth checks %d user(s)", len(cfg.RAKPUsers)))
		}

		invResp, invHash := false, false
		invCode := byte(0xFF)
		if inv, err := DoRAKP12(host, port, "oobscan-nouser-x9q7z", RAKPHMACSHA1, IntegrityNone, ConfNone, cfg.Timeout); err == nil && inv != nil {
			invResp, invCode, invHash = true, inv.ErrorCode, len(inv.RAKPHash) > 0
		}
		for i, user := range cfg.RAKPUsers {
			if cfg.Logf != nil {
				cfg.Logf(fmt.Sprintf("ipmi.fullWalk: RAKP user %d/%d %s", i+1, len(cfg.RAKPUsers), user))
			}
			rr := RAKPPreAuthResult{Username: user}
			r, err := DoRAKP12(host, port, user, RAKPHMACSHA1, IntegrityNone, ConfNone, cfg.Timeout)
			if err != nil {
				rr.Error = err.Error()
				res.RAKP = append(res.RAKP, rr)
				continue
			}
			rr.ErrorCode = r.ErrorCode
			rr.HashLen = len(r.RAKPHash)
			rr.GUIDPrefix = hexPrefix(r.BMCGUID)
			rr.PotentialHashLeak = len(r.RAKPHash) > 0

			rr.PotentialUserOracle = (rr.PotentialHashLeak && !invHash) ||
				(invResp && rr.ErrorCode != invCode)
			res.RAKP = append(res.RAKP, rr)
		}
	}

	res.tally()

	res.FinishedAt = time.Now()
	return res, nil
}

func (res *PreAuthMapResult) tally() {
	res.ResponseCount, res.AcceptedCount = 0, 0
	res.PotentialLeakCount, res.PotentialBypassCount = 0, 0
	for _, r := range res.Requests {
		if r.ResponseSeen {
			res.ResponseCount++
		}
		if r.ParsedCC && r.CompletionCode == 0x00 {
			res.AcceptedCount++
		}
		if r.PotentialMemoryLeak {
			res.PotentialLeakCount++
		}
		if r.PotentialAuthBypass {
			res.PotentialBypassCount++
		}
	}
	for _, r := range res.RAKP {
		if r.PotentialHashLeak || r.PotentialUserOracle {
			res.PotentialLeakCount++
		}
	}
}

func probePreAuthRequest(c *Client, host string, port int, netfn, cmd byte, mode NetFnSweepMode, cfg PreAuthMapConfig) PreAuthRequestResult {
	r := PreAuthRequestResult{NetFn: netfn, Cmd: cmd}
	if mode == SweepSessionZero {
		r.Mode = "session-zero"
	} else {
		r.Mode = "pre-session"
	}

	var pkt []byte
	var err error
	if mode == SweepSessionZero {
		pkt, err = buildSessionZeroMsg(host, port, netfn, cmd, cfg.Timeout)
		if err != nil {
			r.Error = err.Error()
			return r
		}
	} else {
		pkt = buildSessionlessMsg(netfn, cmd, nil)
	}

	resp, err := c.Send(pkt)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.ResponseSeen = true
	r.ResponseLen = len(resp)
	r.ResponsePrefix = hexPrefix(resp)
	if cc, ok := extractCompletionCode(resp); ok {
		r.ParsedCC = true
		r.CompletionCode = cc
	}

	classifyAuthBypass(&r)
	classifyPotentialLeak(c, pkt, resp, &r, cfg)
	return r
}

func classifyAuthBypass(r *PreAuthRequestResult) {
	if !r.ResponseSeen || !r.ParsedCC || r.CompletionCode != 0x00 {
		return
	}
	if isAllowlistedPreAuth(r.NetFn, r.Cmd) {
		return
	}
	if r.Cmd%2 == 1 {
		r.PotentialAuthBypass = true
		r.BypassReason = "write-like command accepted pre-auth"
		return
	}
	if r.NetFn == NetFnStorage || r.NetFn == NetFnTransport || r.NetFn == NetFnBridge {
		r.PotentialAuthBypass = true
		r.BypassReason = "sensitive netfn command accepted pre-auth"
	}
}

func classifyPotentialLeak(c *Client, pkt, firstResp []byte, r *PreAuthRequestResult, cfg PreAuthMapConfig) {
	if !r.ResponseSeen {
		return
	}
	if len(firstResp) >= cfg.LeakLenThreshold {
		r.PotentialMemoryLeak = true
		r.LeakReason = fmt.Sprintf("large pre-auth response (%d bytes)", len(firstResp))
	}
	if cfg.RepeatCount <= 1 {
		return
	}
	hashes := map[string]struct{}{}
	for i := 0; i < cfg.RepeatCount; i++ {
		rep, err := c.Send(pkt)
		if err != nil {
			continue
		}
		h := sha256.Sum256(rep)
		hashes[hex.EncodeToString(h[:])] = struct{}{}
	}
	if len(hashes) > 1 && !r.PotentialMemoryLeak {
		r.PotentialMemoryLeak = true
		r.LeakReason = "non-deterministic repeated pre-auth response bytes"
	}
}

func isAllowlistedPreAuth(netfn, cmd byte) bool {
	if netfn == NetFnApp {
		switch cmd {
		case CmdGetDeviceID, CmdGetChannelAuthCaps, CmdGetChannelCipherSuites, CmdGetDeviceGUID, CmdGetSystemGUID:
			return true
		}
	}
	if netfn == NetFnChassis && cmd == 0x00 {
		return true
	}
	if netfn == NetFnSensor && cmd == 0x2D {
		return true
	}
	return false
}

func hexPrefix(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) > 24 {
		b = b[:24]
	}
	return hex.EncodeToString(b)
}
