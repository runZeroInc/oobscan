package ipmi

// Pipelined physical memory read for the IPMI v1.5 session.
//
// The physical read handler returns 4 bytes per request, and the serial path
// pays a full round-trip per 4 bytes. This keeps a small window of read requests
// in flight - each tagged with a distinct requester sequence (rqSeq) so replies
// can be demuxed - to hide the round-trip latency, then re-batches anything that
// did not come back.
//
// SAFETY: the ATEN receive path tears a session down if a packet arrives more
// than 8 session-sequence numbers ahead of the one it expects. Each batch is
// therefore capped at pipelineMaxWindow (8) consecutive sequences and fully
// drained before the next batch is sent, so nothing is ever more than 7 ahead.
// Sequence numbers are monotonic and never reused, so a re-sent read is a fresh
// packet, never a replay the BMC would drop.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	pipelineDefaultWindow = 8
	pipelineMaxWindow     = 8 // ATEN tears the session down past +8 ahead
	pipelinePasses        = 4 // re-batch unanswered units this many times
)

// errPipelineUnsupported signals the caller to fall back to the serial path.
var errPipelineUnsupported = errors.New("pipelined read not supported for this session type")

// memReadReqData builds the request data for one physical read unit, matching
// memUnitRead's encoding (optional subfunction, width, then the 32-bit address in
// the profile's byte order).
func memReadReqData(p *MemProfile, addr uint64, width int) []byte {
	req := make([]byte, 0, 6)
	if p.HasReadSubFn {
		req = append(req, p.ReadSubFn)
	}
	req = append(req, byte(width))
	a := make([]byte, 4)
	if p.AddrBigEndian {
		binary.BigEndian.PutUint32(a, uint32(addr))
	} else {
		binary.LittleEndian.PutUint32(a, uint32(addr))
	}
	return append(req, a...)
}

// buildV15ReadReqLAN mirrors buildV15LANMsg but sets a caller-chosen rqSeq so a
// pipelined reply can be matched to its request.
func buildV15ReadReqLAN(netfn, cmd byte, data []byte, rqSeq byte) []byte {
	body := make([]byte, 0, 7+len(data))
	body = append(body, 0x20)     // rsAddr (BMC)
	body = append(body, netfn<<2) // netfn/lun
	body = append(body, 0x00)     // csum1 placeholder
	body[2] = IPMBChecksum(body[:2])
	body = append(body, 0x81)              // rqAddr (remote console)
	body = append(body, (rqSeq<<2)&0xfc)   // rqSeq (bits 7..2), lun 0
	body = append(body, cmd)               // cmd
	body = append(body, data...)
	body = append(body, IPMBChecksum(body[3:])) // csum2
	return body
}

// extractV15Seq is extractV15Payload plus the echoed requester sequence.
func extractV15Seq(reply []byte) (rqSeq, cc byte, data []byte, ok bool) {
	if len(reply) < 4 || reply[3] != RMCPClassIPMI {
		return 0, 0, nil, false
	}
	for i := 0; i+7 < len(reply); i++ {
		if (reply[i] == 0x81 || reply[i] == 0x8c) && reply[i+3] == 0x20 {
			rqSeq = reply[i+4] >> 2
			cc = reply[i+6]
			end := len(reply) - 1
			if end > i+7 {
				data = append([]byte(nil), reply[i+7:end]...)
			}
			return rqSeq, cc, data, true
		}
	}
	return 0, 0, nil, false
}

// MemReadPhysicalPipelined reads length bytes at unit granularity with `window`
// requests in flight over the v1.5 session. Only the v1.5 runner is supported;
// anything else returns errPipelineUnsupported so the caller falls back to serial.
func (s *CmdSess) MemReadPhysicalPipelined(ctx context.Context, p *MemProfile, addr uint64, length, window int, opts MemReadOptions) ([]byte, []MemHole, MemStats, error) {
	var stats MemStats
	if p == nil || !p.ReadSupported {
		return nil, nil, stats, fmt.Errorf("profile %q has no physical-memory read primitive", profileID(p))
	}
	r, ok := s.runner.(*v15Runner)
	if !ok || r.client == nil || r.sess == nil {
		return nil, nil, stats, errPipelineUnsupported
	}
	if addr > 0xffffffff || addr+uint64(length) > 0x100000000 {
		return nil, nil, stats, fmt.Errorf("0x%x+%d does not fit the 32-bit physical address field", addr, length)
	}
	unit := 4
	if p.MaxUnit < unit {
		unit = p.MaxUnit
	}
	if unit <= 0 {
		unit = 1
	}
	if window < 2 {
		window = pipelineDefaultWindow
	}
	if window > pipelineMaxWindow {
		window = pipelineMaxWindow
	}
	order := opts.ReplyOrder
	if order == "" {
		order = p.ReplyOrder
	}
	client, sess := r.client, r.sess
	timeout := client.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	// aligned unit addresses covering [addr, addr+length)
	start := addr &^ uint64(unit-1)
	end := addr + uint64(length)
	var pending []uint64
	for a := start; a < end; a += uint64(unit) {
		pending = append(pending, a)
	}
	got := make(map[uint64][]byte, len(pending))
	holeCC := map[uint64]byte{}
	// rolling requester sequence (1..63, never 0) so a late reply from a prior
	// batch cannot be misattributed to the same rqSeq in the current batch.
	var rqRoll byte

	for pass := 0; pass < pipelinePasses && len(pending) > 0; pass++ {
		var next []uint64
		for i := 0; i < len(pending); i += window {
			if err := ctx.Err(); err != nil {
				return assemblePipelineResult(addr, length, unit, got), nil, stats, err
			}
			batch := pending[i:min(i+window, len(pending))]
			seqToAddr := make(map[byte]uint64, len(batch))
			for _, a := range batch {
				rqRoll = rqRoll%63 + 1 // 1..63
				rq := rqRoll
				lan := buildV15ReadReqLAN(p.ReadNetFn, p.ReadCmd, memReadReqData(p, a, unit), rq)
				sseq := sess.InboundSeq
				if sseq == 0 {
					sseq = 1
				}
				pkt := buildV15Authenticated(sess.AuthType, sess.Password, sess.SessionID, sseq, lan)
				sess.InboundSeq = sseq + 1
				if sess.InboundSeq == 0 {
					sess.InboundSeq = 1
				}
				if err := client.SendRaw(pkt); err != nil {
					return assemblePipelineResult(addr, length, unit, got), nil, stats, err
				}
				stats.Requests++
				seqToAddr[rq] = a
			}
			// drain replies for this batch
			deadline := time.Now().Add(timeout)
			for len(seqToAddr) > 0 && time.Now().Before(deadline) {
				reply, err := client.Recv(time.Until(deadline))
				if err != nil {
					break // timeout or transport error: whatever is left retries
				}
				rq, cc, data, ok := extractV15Seq(reply)
				if !ok {
					continue
				}
				a, want := seqToAddr[rq]
				if !want {
					continue // stale/duplicate/foreign reply
				}
				delete(seqToAddr, rq)
				if cc != 0x00 || len(data) < unit {
					holeCC[a] = cc
					continue
				}
				v := data[:unit]
				if order == MemOrderMSBFirst && unit > 1 {
					v = reverseBytes(v)
				}
				got[a] = append([]byte(nil), v...)
			}
			for _, a := range seqToAddr { // unanswered -> retry next pass
				next = append(next, a)
				stats.Retries++
			}
			reportCommandProgress(ctx, "mem read: %d/%d units (pipeline x%d, %d retries)", len(got), len(got)+len(pending)+len(next), window, stats.Retries)
		}
		pending = next
	}

	data := assemblePipelineResult(addr, length, unit, got)
	var holes []MemHole
	for _, a := range pending { // never answered after all passes
		holes = append(holes, MemHole{Addr: a, Len: unit, Err: "no reply after pipelined retries"})
	}
	for a, cc := range holeCC {
		holes = append(holes, MemHole{Addr: a, Len: unit, CC: fmt.Sprintf("0x%02x", cc), Err: memCCMeaning(p, cc)})
	}
	if len(holes) > 0 && !opts.ContinueOnError {
		return data, holes, stats, fmt.Errorf("%d unit(s) unreadable (use continue to zero-fill)", len(holes))
	}
	return data, holes, stats, nil
}

// assemblePipelineResult stitches the per-unit results into the requested byte
// range; missing units are zero-filled (they are reported as holes separately).
func assemblePipelineResult(addr uint64, length, unit int, got map[uint64][]byte) []byte {
	start := addr &^ uint64(unit-1)
	end := addr + uint64(length)
	buf := make([]byte, 0, int(end-start))
	for a := start; a < end; a += uint64(unit) {
		if v, ok := got[a]; ok && len(v) == unit {
			buf = append(buf, v...)
		} else {
			buf = append(buf, make([]byte, unit)...)
		}
	}
	off := int(addr - start)
	if off+length <= len(buf) {
		return buf[off : off+length]
	}
	return buf
}
