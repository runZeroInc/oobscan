package asd

import (
	"errors"
	"fmt"
)

// JTAG scan-command opcode classes (single byte). Encoding recovered from
// process_jtag_message in the firmware: the low 6 bits carry a bit length where
// 0 means 64.
const (
	opSetTAP    = 0x20 // | (state & 0x0F)
	opWriteScan = 0x40 // | (bits & 0x3F)  TDI-only
	opReadScan  = 0x80 // | (bits & 0x3F)  TDO-only
	opRWScan    = 0xC0 // | (bits & 0x3F)  TDI+TDO
	opTAPReset  = 0x14
)

// TAP states (opcode 0x20 | state).
const (
	TAPTestLogicReset = 0x0
	TAPRunTestIdle    = 0x1
	TAPSelectDR       = 0x2
	TAPCaptureDR      = 0x3
	TAPShiftDR        = 0x4
	TAPExit1DR        = 0x5
	TAPPauseDR        = 0x6
	TAPExit2DR        = 0x7
	TAPUpdateDR       = 0x8
	TAPSelectIR       = 0x9
	TAPCaptureIR      = 0xA
	TAPShiftIR        = 0xB
	TAPExit1IR        = 0xC
	TAPPauseIR        = 0xD
	TAPExit2IR        = 0xE
	TAPUpdateIR       = 0xF
)

func setTAP(state byte) byte { return opSetTAP | (state & 0x0F) }

func nbytes(bits int) int { return (bits + 7) / 8 }

// scanLen encodes a bit count into the low 6 bits (0 == 64).
func scanLen(bits int) byte { return byte(bits & 0x3F) }

// BuildIRWrite composes an "enter Shift-IR, shift `bits` of `value` (LSB-first),
// leave to `end`" opcode buffer.
func BuildIRWrite(value uint64, bits int, end byte) ([]byte, error) {
	if bits < 1 || bits > 64 {
		return nil, errors.New("IR bits must be 1..64")
	}
	tdi := make([]byte, nbytes(bits))
	for i := range tdi {
		tdi[i] = byte(value >> (8 * i))
	}
	buf := []byte{setTAP(TAPShiftIR), opWriteScan | scanLen(bits)}
	buf = append(buf, tdi...)
	buf = append(buf, setTAP(end))
	return buf, nil
}

// BuildDRRead composes an "enter Shift-DR, read `bits` (chunked into <=64-bit
// scans that stay in the shift state between chunks), leave to `end`" buffer and
// returns the expected output length in bytes.
func BuildDRRead(bits int, end byte) ([]byte, int, error) {
	if bits < 1 {
		return nil, 0, errors.New("DR bits must be >= 1")
	}
	buf := []byte{setTAP(TAPShiftDR)}
	out := 0
	remaining := bits
	for remaining > 0 {
		chunk := min(remaining, 64)
		remaining -= chunk
		es := byte(TAPShiftDR)
		if remaining == 0 {
			es = end
		}
		buf = append(buf, opReadScan|scanLen(chunk), setTAP(es))
		out += nbytes(chunk)
	}
	return buf, out, nil
}

// BuildDRReadWrite composes an "enter Shift-DR, shift `bits` of `value` in while
// capturing TDO out, leave to `end`" buffer (single scan, <=64 bits).
func BuildDRReadWrite(value uint64, bits int, end byte) ([]byte, int, error) {
	if bits < 1 || bits > 64 {
		return nil, 0, errors.New("DR read-write bits must be 1..64")
	}
	tdi := make([]byte, nbytes(bits))
	for i := range tdi {
		tdi[i] = byte(value >> (8 * i))
	}
	buf := []byte{setTAP(TAPShiftDR), opRWScan | scanLen(bits)}
	buf = append(buf, tdi...)
	buf = append(buf, setTAP(end))
	return buf, nbytes(bits), nil
}

// BuildIDCODE composes a TAP reset + 32-bit DR read (the classic IDCODE read).
func BuildIDCODE() ([]byte, int) {
	dr, out, _ := BuildDRRead(32, TAPRunTestIdle)
	buf := []byte{opTAPReset, setTAP(TAPRunTestIdle)}
	return append(buf, dr...), out
}

// JTAGResult is a decoded JTAG scan response.
type JTAGResult struct {
	Status  byte
	TDO     []byte
	Blocked bool // reached the handler but no target on the chain (hardware-blocked)
}

func decodeJTAG(h Header, body []byte, expect int) JTAGResult {
	r := JTAGResult{Status: h.CmdStat, TDO: body}
	if h.CmdStat == StatusSuccess {
		if len(body) > 0 && allOnes(body) {
			r.Blocked = true // all-ones TDO == no target driving TDO
		}
		if expect > 0 && len(body) > expect {
			r.TDO = body[:expect]
		}
		return r
	}
	if HardwareBlocked(h.CmdStat) {
		r.Blocked = true
	}
	return r
}

func allOnes(b []byte) bool {
	for _, x := range b {
		if x != 0xFF {
			return false
		}
	}
	return len(b) > 0
}

// ShiftIR shifts an instruction-register value (ending in Run-Test-Idle).
func (c *Conn) ShiftIR(value uint64, bits int) (JTAGResult, error) {
	ops, err := BuildIRWrite(value, bits, TAPRunTestIdle)
	if err != nil {
		return JTAGResult{}, err
	}
	h, body, err := c.JTAG(ops)
	if err != nil {
		return JTAGResult{}, err
	}
	return decodeJTAG(h, body, 0), nil
}

// ReadDR reads `bits` from the data register (ending in Run-Test-Idle).
func (c *Conn) ReadDR(bits int) (JTAGResult, error) {
	ops, out, err := BuildDRRead(bits, TAPRunTestIdle)
	if err != nil {
		return JTAGResult{}, err
	}
	h, body, err := c.JTAG(ops)
	if err != nil {
		return JTAGResult{}, err
	}
	return decodeJTAG(h, body, out), nil
}

// ReadWriteDR shifts `value` into DR while capturing TDO (<=64 bits).
func (c *Conn) ReadWriteDR(value uint64, bits int) (JTAGResult, error) {
	ops, out, err := BuildDRReadWrite(value, bits, TAPRunTestIdle)
	if err != nil {
		return JTAGResult{}, err
	}
	h, body, err := c.JTAG(ops)
	if err != nil {
		return JTAGResult{}, err
	}
	return decodeJTAG(h, body, out), nil
}

// IDCODE reads the 32-bit device IDCODE after a TAP reset.
func (c *Conn) IDCODE() (uint32, JTAGResult, error) {
	ops, out := BuildIDCODE()
	h, body, err := c.JTAG(ops)
	if err != nil {
		return 0, JTAGResult{}, err
	}
	r := decodeJTAG(h, body, out)
	var id uint32
	for i := 0; i < len(r.TDO) && i < 4; i++ {
		id |= uint32(r.TDO[i]) << (8 * i)
	}
	return id, r, nil
}

// MemParams describes the target CPU's JTAG debug-register model used to compose
// memory accesses. ASD exposes only raw JTAG scans, so an address->bus->data
// sequence must be driven through the target's run-control TAP registers; those
// IR opcodes and widths are CPU-model specific and cannot be derived from the
// BMC firmware. The zero value uses documented placeholder defaults for an
// Intel-style run-control chain; override every field for a real target.
type MemParams struct {
	IRWidth    int    // instruction-register width in bits
	AddrIR     uint64 // IR selecting the address/command debug register
	DataIR     uint64 // IR selecting the data debug register
	TriggerIR  uint64 // IR that triggers the bus read/write (0 = none)
	WordBits   int    // data-register width per access (bits)
	AddrBits   int    // address-register width (bits)
	RWFlagBit  uint   // bit in the address word marking write vs read (0 = separate IR)
	Configured bool   // set true once a caller supplies a real model
}

// DefaultMemParams returns the placeholder Intel-style run-control model. These
// values are not verified against a specific SKU; supply --mem-* overrides for a
// real target.
func DefaultMemParams() MemParams {
	return MemParams{IRWidth: 8, AddrIR: 0x11, DataIR: 0x12, TriggerIR: 0x13, WordBits: 32, AddrBits: 40}
}

// MemAccessResult reports the outcome of a JTAG-composed memory operation.
type MemAccessResult struct {
	Data    []byte
	Blocked bool
	Note    string
}

// MemRead composes a JTAG debug-register sequence to read `length` bytes from
// physical `addr`, one WordBits word at a time. On any hardware-blocked scan it
// stops and returns Blocked=true with the partial data. This is a real JTAG scan
// sequence, but it only yields data on hardware whose debug-register model
// matches MemParams and that has a live host CPU on the chain.
func (c *Conn) MemRead(addr uint64, length int, p MemParams) (MemAccessResult, error) {
	if p.WordBits == 0 {
		p = DefaultMemParams()
	}
	wordBytes := nbytes(p.WordBits)
	res := MemAccessResult{}
	if !p.Configured {
		res.Note = "MemParams not configured for this target CPU; using placeholder run-control model"
	}
	for off := 0; off < length; off += wordBytes {
		if r, err := c.ShiftIR(p.AddrIR, p.IRWidth); err != nil {
			return res, err
		} else if r.Blocked {
			res.Blocked = true
			return res, nil
		}
		if r, err := c.ReadWriteDR(addr+uint64(off), p.AddrBits); err != nil {
			return res, err
		} else if r.Blocked {
			res.Blocked = true
			return res, nil
		}
		if p.TriggerIR != 0 {
			if _, err := c.ShiftIR(p.TriggerIR, p.IRWidth); err != nil {
				return res, err
			}
		}
		if r, err := c.ShiftIR(p.DataIR, p.IRWidth); err != nil {
			return res, err
		} else if r.Blocked {
			res.Blocked = true
			return res, nil
		}
		word, err := c.ReadDR(p.WordBits)
		if err != nil {
			return res, err
		}
		if word.Blocked {
			res.Blocked = true
			return res, nil
		}
		res.Data = append(res.Data, word.TDO...)
	}
	if length < len(res.Data) {
		res.Data = res.Data[:length]
	}
	return res, nil
}

// MemWrite composes a JTAG debug-register sequence to write `data` to physical
// `addr`, one WordBits word at a time. Same target-model caveats as MemRead.
func (c *Conn) MemWrite(addr uint64, data []byte, p MemParams) (MemAccessResult, error) {
	if p.WordBits == 0 {
		p = DefaultMemParams()
	}
	wordBytes := nbytes(p.WordBits)
	res := MemAccessResult{}
	if !p.Configured {
		res.Note = "MemParams not configured for this target CPU; using placeholder run-control model"
	}
	for off := 0; off < len(data); off += wordBytes {
		if r, err := c.ShiftIR(p.AddrIR, p.IRWidth); err != nil {
			return res, err
		} else if r.Blocked {
			res.Blocked = true
			return res, nil
		}
		if r, err := c.ReadWriteDR(addr+uint64(off), p.AddrBits); err != nil {
			return res, err
		} else if r.Blocked {
			res.Blocked = true
			return res, nil
		}
		if r, err := c.ShiftIR(p.DataIR, p.IRWidth); err != nil {
			return res, err
		} else if r.Blocked {
			res.Blocked = true
			return res, nil
		}
		var word uint64
		for i := 0; i < wordBytes && off+i < len(data); i++ {
			word |= uint64(data[off+i]) << (8 * i)
		}
		if r, err := c.ReadWriteDR(word, p.WordBits); err != nil {
			return res, err
		} else if r.Blocked {
			res.Blocked = true
			return res, nil
		}
		if p.TriggerIR != 0 {
			if _, err := c.ShiftIR(p.TriggerIR, p.IRWidth); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

// FormatStatus renders a status byte for display.
func FormatStatus(code byte) string { return fmt.Sprintf("%s (0x%02x)", StatusName(code), code) }
