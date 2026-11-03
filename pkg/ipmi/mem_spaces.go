package ipmi

// The non-physical address spaces behind the "ipmi mem" command: I2C/SMBus device
// offsets, SPD EEPROMs, FRU inventory areas, the SDR repository, MDIO/PHY
// registers, raw PECI and the vendor manufacturing-data store. Everything here is
// byte-addressed and chunked like the physical engine, so the CLI presents one
// read/write grammar across all of them. The spec commands are Master Write-Read
// (App/0x52), Read/Write FRU Data (Storage/0x11, 0x12) and Get SDR (Storage/0x23).

import (
	"context"
	"fmt"
	"time"
)

// Storage-netfn commands used by the FRU and SDR spaces.
const (
	CmdWriteFRUData     byte = 0x12
	CmdGetSDRRepoInfo   byte = 0x20
	CmdReserveSDRRepo   byte = 0x22
	CmdGetSDR           byte = 0x23
	CmdReserveFRUDevice byte = 0x00 // unused placeholder; FRU reads need no reservation
)

// MemBusOptions carries the bus-level parameters the non-physical spaces need.
// Fields that do not apply to a space are ignored.
type MemBusOptions struct {
	// Bus is the I2C/SMBus segment number.
	Bus byte
	// Slave is the 7-bit device address, shifted left by one on the wire as
	// the spec requires. Callers pass the 8-bit form (0xA0) or the 7-bit form
	// (0x50); NormalizeSlave settles it.
	Slave byte
	// AddrBytes is how many bytes of register offset the device wants (1 or
	// 2). SPD and most EEPROMs are 1; larger EEPROMs are 2.
	AddrBytes int
	// Chunk is the maximum payload per request. Zero means the space default.
	Chunk int
	// PageSize is the device's write-page size. A page write wraps inside the
	// page instead of carrying into the next one, so chunks are clipped to it.
	// Zero means 8, the smallest common EEPROM page.
	PageSize int
	// FRUID selects the FRU inventory device.
	FRUID byte
	// UseOEM asks for the vendor OEM transport instead of the spec command,
	// where the profile names one. On Supermicro this reaches bus 0 on
	// generations where App/0x52 refuses it.
	UseOEM bool
	// PECICmd, PECIReadLen are the raw PECI transaction parameters.
	PECICmd     byte
	PECIReadLen int

	Retries  int
	Delay    time.Duration
	Progress func(string)
}

// NormalizeSlave accepts either a 7-bit address (0x50) or the 8-bit write
// address (0xA0) and returns the byte the wire wants, which is the 8-bit form
// with bit 0 clear.
func NormalizeSlave(v byte) byte {
	if v < 0x80 {
		return v << 1
	}
	return v &^ 0x01
}

func chunkOr(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func retriesOr(v int) int {
	if v < 1 {
		return 3
	}
	return v
}

// offsetBytes renders a register offset in the device's addressing width,
// most-significant byte first, which is the convention every EEPROM in this
// corpus uses.
func offsetBytes(off uint64, width int) []byte {
	switch width {
	case 2:
		return []byte{byte(off >> 8), byte(off)}
	default:
		return []byte{byte(off)}
	}
}

// --- I2C / SMBus ------------------------------------------------------------

// i2cTransact runs one write-then-read against a device, choosing the spec
// command or the profile's OEM transport.
func (s *CmdSess) i2cTransact(p *MemProfile, o MemBusOptions, writeData []byte, readLen byte) ([]byte, byte, error) {
	slave := NormalizeSlave(o.Slave)

	// Supermicro OEM subfunction 0x7E: bus in data[1]>>1, slave data[2],
	// read count data[3], write payload from data[4]. It skips the bus-0
	// VBAT/KCS gate that App/0x52 applies on X11 and later.
	if o.UseOEM && p != nil && p.I2CUngatedSubFn != 0 {
		if len(writeData) >= oemI2CMaxLen || int(readLen) >= oemI2CMaxLen {
			return nil, 0, fmt.Errorf("oem i2c subfunction 0x%02x caps both directions at %d bytes", p.I2CUngatedSubFn, oemI2CMaxLen-1)
		}
		req := append([]byte{p.I2CUngatedSubFn, o.Bus << 1, slave, readLen}, writeData...)
		cc, d, err := s.ExecRaw(p.ReadNetFn, p.ReadCmd, req)
		if err != nil {
			return nil, 0, err
		}
		if cc != 0x00 {
			return nil, cc, fmt.Errorf("oem i2c cc=0x%02x (%s)", cc, memCCMeaning(p, cc))
		}
		return d, cc, nil
	}

	// X14's OpenBMC I2CMasterWriteRead lives on its own NetFn/Cmd and takes
	// the bus as a full byte, so it reaches buses above 15.
	if o.UseOEM && p != nil && p.I2CNetFn != 0 {
		req := append([]byte{o.Bus, slave, readLen}, writeData...)
		cc, d, err := s.ExecRaw(p.I2CNetFn, p.I2CCmd, req)
		if err != nil {
			return nil, 0, err
		}
		if cc != 0x00 {
			return nil, cc, fmt.Errorf("oem i2c cc=0x%02x (%s)", cc, memCCMeaning(p, cc))
		}
		return d, cc, nil
	}

	// Spec App/0x52. The channel byte carries the bus in bits 5:1 with the
	// private-bus flag in bit 0.
	ch := (o.Bus << 1) | 0x01
	cc, d, err := s.ExecRaw(NetFnApp, CmdMasterWriteRead, append([]byte{ch, slave, readLen}, writeData...))
	if err != nil {
		return nil, 0, err
	}
	if cc != 0x00 {
		return nil, cc, fmt.Errorf("master-write-read cc=0x%02x", cc)
	}
	return d, cc, nil
}

// oemI2CMaxLen is the ATEN OEM subfunction 0x7E bound: both the read count and
// the write length must be below 125.
const oemI2CMaxLen = 0x7d

// i2cLimits returns the per-request cap and validates the bus against the
// transport the caller actually selected.
func i2cLimits(p *MemProfile, o MemBusOptions) (maxLen int, err error) {
	maxLen = 32
	maxBus := byte(15)
	switch {
	case o.UseOEM && p != nil && p.I2CUngatedSubFn != 0:
		// The OEM subfunction is a different handler with a tighter bound
		// than App/0x52, and the profile's I2CMaxRead describes the latter.
		maxLen = oemI2CMaxLen - 1
		maxBus = 15
	case o.UseOEM && p != nil && p.I2CNetFn != 0:
		// The OpenBMC variant takes the bus as a whole byte.
		maxLen = 255
		maxBus = 255
	default:
		if p != nil && p.I2CMaxRead > 0 {
			maxLen = p.I2CMaxRead
		}
		if p != nil && p.I2CMaxBus > 0 {
			maxBus = p.I2CMaxBus
		}
	}
	if o.Bus > maxBus {
		return 0, fmt.Errorf("bus %d is out of range for this transport (max %d); the channel byte packs the bus into a narrow field, so a larger value aliases into a different bus", o.Bus, maxBus)
	}
	if p != nil && p.I2CBusZeroGated && o.Bus == 0 && !o.UseOEM {
		return 0, fmt.Errorf("bus 0 is gated off the LAN channel on %s (the handler answers CC 0xd6); retry with the bare token 'oem', which reaches it through subfunction 0x%02x", p.ID, p.I2CUngatedSubFn)
	}
	return maxLen, nil
}

// MemReadI2C reads length bytes starting at a register offset inside an I2C
// device, chunked to the transport's per-request cap.
func (s *CmdSess) MemReadI2C(ctx context.Context, p *MemProfile, off uint64, length int, o MemBusOptions) ([]byte, MemStats, error) {
	var stats MemStats
	if length <= 0 {
		return nil, stats, fmt.Errorf("length must be positive")
	}
	if o.AddrBytes == 0 {
		o.AddrBytes = 1
	}
	if o.AddrBytes != 1 && o.AddrBytes != 2 {
		return nil, stats, fmt.Errorf("addr-bytes must be 1 or 2 (got %d)", o.AddrBytes)
	}
	maxRead, lerr := i2cLimits(p, o)
	if lerr != nil {
		return nil, stats, lerr
	}
	chunk := chunkOr(o.Chunk, maxRead)
	if chunk > maxRead {
		chunk = maxRead
	}

	out := make([]byte, 0, length)
	retries := retriesOr(o.Retries)
	for len(out) < length {
		if err := ctx.Err(); err != nil {
			return out, stats, err
		}
		n := min(chunk, length-len(out))
		cur := off + uint64(len(out))
		var got []byte
		var lastErr error
		for attempt := range retries {
			stats.Requests++
			d, cc, err := s.i2cTransact(p, o, offsetBytes(cur, o.AddrBytes), byte(n))
			if err == nil {
				got = d
				break
			}
			lastErr = err
			// A real completion code is the target's answer; resending the
			// identical request just spends bus time to learn it again.
			if cc != 0x00 {
				break
			}
			stats.Retries++
			if o.Delay > 0 {
				time.Sleep(o.Delay * time.Duration(attempt+1))
			}
		}
		if got == nil {
			stats.Failures++
			return out, stats, fmt.Errorf("i2c read at offset 0x%x: %w", cur, lastErr)
		}
		if len(got) > n {
			got = got[:n]
		}
		if len(got) == 0 {
			return out, stats, fmt.Errorf("i2c read at offset 0x%x returned no data", cur)
		}
		out = append(out, got...)
		if o.Progress != nil {
			o.Progress(fmt.Sprintf("i2c bus %d slave 0x%02x: %d/%d bytes", o.Bus, NormalizeSlave(o.Slave), len(out), length))
		}
		if o.Delay > 0 {
			time.Sleep(o.Delay)
		}
	}
	return out[:length], stats, nil
}

// MemWriteI2C writes data at a register offset inside an I2C device. Each
// request carries the offset followed by its slice of the payload, which is
// the standard EEPROM page-write shape.
func (s *CmdSess) MemWriteI2C(ctx context.Context, p *MemProfile, off uint64, data []byte, o MemBusOptions) (MemStats, error) {
	var stats MemStats
	if len(data) == 0 {
		return stats, fmt.Errorf("no data to write")
	}
	if o.AddrBytes == 0 {
		o.AddrBytes = 1
	}
	maxLen, lerr := i2cLimits(p, o)
	if lerr != nil {
		return stats, lerr
	}
	// Most EEPROMs page-write in 8, 16 or 32 byte pages and wrap within the
	// page rather than carrying into the next one, so a chunk that straddles a
	// page boundary silently overwrites the bytes at the bottom of the same
	// page. Every chunk is therefore clipped to the page it starts in.
	page := chunkOr(o.PageSize, 8)
	chunk := chunkOr(o.Chunk, page)
	if chunk > maxLen {
		chunk = maxLen
	}
	retries := retriesOr(o.Retries)

	for written := 0; written < len(data); {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		n := min(chunk, len(data)-written)
		cur := off + uint64(written)
		if room := page - int(cur%uint64(page)); n > room {
			n = room
		}
		payload := append(offsetBytes(cur, o.AddrBytes), data[written:written+n]...)
		var lastErr error
		ok := false
		for attempt := range retries {
			stats.Requests++
			_, cc, err := s.i2cTransact(p, o, payload, 0)
			if err == nil {
				ok = true
				break
			}
			lastErr = err
			if cc != 0x00 {
				break
			}
			stats.Retries++
			if o.Delay > 0 {
				time.Sleep(o.Delay * time.Duration(attempt+1))
			}
		}
		if !ok {
			stats.Failures++
			return stats, fmt.Errorf("i2c write at offset 0x%x: %w", cur, lastErr)
		}
		written += n
		if o.Progress != nil {
			o.Progress(fmt.Sprintf("i2c bus %d slave 0x%02x: wrote %d/%d bytes", o.Bus, NormalizeSlave(o.Slave), written, len(data)))
		}
		if o.Delay > 0 {
			time.Sleep(o.Delay)
		}
	}
	return stats, nil
}

// MemReadSPD reads an SPD EEPROM. The first 256 bytes are a plain
// offset-addressed read; above that, DDR4 parts need a page select through the
// SPA0/SPA1 devices at 0x36/0x37, which is the JEDEC DDR4 convention rather than
// anything confirmed per board, so treat a read above 256 bytes as unverified.
// DDR5 SPD5118 parts page through the MR11 register instead of a separate SPA
// device, so this path does not reach a DDR5 SPD past its first 128-byte block;
// drive those directly with space=i2c.
func (s *CmdSess) MemReadSPD(ctx context.Context, p *MemProfile, off uint64, length int, o MemBusOptions) ([]byte, MemStats, error) {
	var stats MemStats
	if o.AddrBytes == 0 {
		o.AddrBytes = 1
	}
	if o.Slave == 0 {
		o.Slave = 0x50
	}
	if off+uint64(length) <= 256 {
		return s.MemReadI2C(ctx, p, off, length, o)
	}
	// The DDR4 SPA page-select scheme addresses exactly two 256-byte pages.
	// Beyond that the page number would wrap into a different SPA device and
	// return page-0 bytes labelled as the requested offset.
	if off+uint64(length) > 512 {
		return nil, stats, fmt.Errorf("the DDR4 SPD page-select scheme reaches 512 bytes; 0x%x+%d is past it, and DDR5 pages through SPD5118 MR11 instead - read the part directly with space=i2c", off, length)
	}

	out := make([]byte, 0, length)
	for len(out) < length {
		cur := off + uint64(len(out))
		page := byte(cur / 256)
		inPage := cur % 256
		if page > 1 {
			return out, stats, fmt.Errorf("spd page %d is outside the two-page SPA scheme", page)
		}
		n := min(length-len(out), int(256-inPage))
		// Page select: a zero-length write to 0x36+page selects the page on
		// DDR4 SPA devices.
		sel := MemBusOptions{Bus: o.Bus, Slave: 0x36 + page, AddrBytes: 1, UseOEM: o.UseOEM, Retries: o.Retries, Delay: o.Delay}
		stats.Requests++
		if _, _, err := s.i2cTransact(p, sel, []byte{0x00}, 0); err != nil {
			return out, stats, fmt.Errorf("spd page select %d: %w", page, err)
		}
		part, st, err := s.MemReadI2C(ctx, p, inPage, n, o)
		stats.Requests += st.Requests
		stats.Retries += st.Retries
		stats.Failures += st.Failures
		if err != nil {
			return out, stats, err
		}
		out = append(out, part...)
	}
	return out[:length], stats, nil
}

// --- FRU --------------------------------------------------------------------

// MemReadFRU reads raw bytes out of a FRU inventory device. Unlike "fru print"
// this does no field decoding: it is a byte-addressed window onto the EEPROM.
func (s *CmdSess) MemReadFRU(ctx context.Context, off uint64, length int, o MemBusOptions) ([]byte, MemStats, error) {
	var stats MemStats
	if length <= 0 {
		return nil, stats, fmt.Errorf("length must be positive")
	}
	chunk := chunkOr(o.Chunk, 16)
	if chunk > 32 {
		chunk = 32
	}
	retries := retriesOr(o.Retries)
	out := make([]byte, 0, length)
	for len(out) < length {
		if err := ctx.Err(); err != nil {
			return out, stats, err
		}
		cur := off + uint64(len(out))
		if cur > 0xffff {
			return out, stats, fmt.Errorf("FRU offsets are 16-bit; 0x%x is out of range", cur)
		}
		n := min(chunk, length-len(out))
		var got []byte
		var lastErr error
		// A device that cannot serve the requested count answers 0xc9/0xca.
		// Halving is a negotiation, not a retry, so it gets its own bounded
		// loop and does not eat the transport retry budget - otherwise a
		// device with an 8-byte window would exhaust the budget before the
		// chunk size ever got small enough to work.
		for range 6 {
			shrink := false
			req := []byte{o.FRUID, byte(cur), byte(cur >> 8), byte(n)}
			for attempt := range retries {
				stats.Requests++
				cc, d, err := s.ExecRaw(NetFnStorage, CmdReadFRUData, req)
				if err == nil && cc == 0x00 && len(d) >= 1 {
					// Byte 0 is the count actually returned.
					got = d[1:]
					if int(d[0]) < len(got) {
						got = got[:d[0]]
					}
					if len(got) == 0 {
						lastErr = fmt.Errorf("device returned a zero byte count at offset 0x%x", cur)
					}
					break
				}
				if err == nil {
					lastErr = fmt.Errorf("cc=0x%02x", cc)
					if (cc == 0xc9 || cc == 0xca) && n > 1 {
						n /= 2
						shrink = true
					}
					break
				}
				lastErr = err
				stats.Retries++
				if o.Delay > 0 {
					time.Sleep(o.Delay * time.Duration(attempt+1))
				}
			}
			if len(got) > 0 || !shrink {
				break
			}
		}
		// Keep the negotiated size for the rest of the transfer.
		if n < chunk {
			chunk = n
		}
		if len(got) == 0 {
			stats.Failures++
			return out, stats, fmt.Errorf("fru read at offset 0x%x: %w", cur, lastErr)
		}
		out = append(out, got...)
		if o.Progress != nil {
			o.Progress(fmt.Sprintf("fru %d: %d/%d bytes", o.FRUID, len(out), length))
		}
	}
	return out[:length], stats, nil
}

// MemWriteFRU writes raw bytes into a FRU inventory device.
func (s *CmdSess) MemWriteFRU(ctx context.Context, off uint64, data []byte, o MemBusOptions) (MemStats, error) {
	var stats MemStats
	if len(data) == 0 {
		return stats, fmt.Errorf("no data to write")
	}
	chunk := chunkOr(o.Chunk, 16)
	retries := retriesOr(o.Retries)
	for written := 0; written < len(data); {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		cur := off + uint64(written)
		if cur > 0xffff {
			return stats, fmt.Errorf("FRU offsets are 16-bit; 0x%x is out of range", cur)
		}
		n := min(chunk, len(data)-written)
		req := append([]byte{o.FRUID, byte(cur), byte(cur >> 8)}, data[written:written+n]...)
		var lastErr error
		ok := false
		for attempt := range retries {
			stats.Requests++
			cc, _, err := s.ExecRaw(NetFnStorage, CmdWriteFRUData, req)
			if err == nil && cc == 0x00 {
				ok = true
				break
			}
			if err == nil {
				lastErr = fmt.Errorf("cc=0x%02x", cc)
				break
			}
			lastErr = err
			stats.Retries++
			if o.Delay > 0 {
				time.Sleep(o.Delay * time.Duration(attempt+1))
			}
		}
		if !ok {
			stats.Failures++
			return stats, fmt.Errorf("fru write at offset 0x%x: %w", cur, lastErr)
		}
		written += n
		if o.Progress != nil {
			o.Progress(fmt.Sprintf("fru %d: wrote %d/%d bytes", o.FRUID, written, len(data)))
		}
	}
	return stats, nil
}

// --- SDR --------------------------------------------------------------------

// MemReadSDR reads raw bytes out of one SDR repository record. Addr is the
// record ID; off and length select a window inside it. A record ID of 0x0000
// starts at the first record, and the next record ID is returned so a caller
// can walk the repository.
func (s *CmdSess) MemReadSDR(ctx context.Context, recordID uint16, off uint64, length int, o MemBusOptions) ([]byte, uint16, MemStats, error) {
	var stats MemStats
	if length <= 0 {
		length = 0xff
	}
	// Reserve, so a partial read is coherent against a repository that is
	// being updated underneath us.
	var resv uint16
	stats.Requests++
	if cc, d, err := s.ExecRaw(NetFnStorage, CmdReserveSDRRepo, nil); err == nil && cc == 0x00 && len(d) >= 2 {
		resv = uint16(d[0]) | uint16(d[1])<<8
	}

	// The Get SDR offset field is one byte, so a record window past 255 is
	// not addressable. Say so rather than returning an empty success.
	if off > 0xff {
		return nil, 0, stats, fmt.Errorf("the SDR record offset field is 8-bit; 0x%x is out of range", off)
	}
	chunk := chunkOr(o.Chunk, 16)
	if chunk > 0xfe {
		chunk = 0xfe
	}
	out := make([]byte, 0, length)
	var next uint16
	for len(out) < length {
		if err := ctx.Err(); err != nil {
			return out, next, stats, err
		}
		cur := off + uint64(len(out))
		if cur > 0xff {
			break
		}
		n := min(chunk, length-len(out))
		req := []byte{byte(resv), byte(resv >> 8), byte(recordID), byte(recordID >> 8), byte(cur), byte(n)}
		stats.Requests++
		cc, d, err := s.ExecRaw(NetFnStorage, CmdGetSDR, req)
		if err != nil {
			return out, next, stats, err
		}
		if cc != 0x00 {
			// 0xc9/0xca/0xcb mean the requested window ran past the record,
			// which is a clean end. Anything else - a cancelled reservation,
			// a privilege refusal, a transport-level no - means the read did
			// not finish, and returning a truncated record with a nil error
			// would present it as complete.
			if len(out) > 0 && (cc == 0xc9 || cc == 0xca || cc == 0xcb) {
				break
			}
			return out, next, stats, fmt.Errorf("get sdr cc=0x%02x at offset 0x%x", cc, cur)
		}
		if len(d) < 2 {
			break
		}
		next = uint16(d[0]) | uint16(d[1])<<8
		body := d[2:]
		if len(body) == 0 {
			break
		}
		out = append(out, body...)
		if len(body) < n {
			break
		}
		if o.Progress != nil {
			o.Progress(fmt.Sprintf("sdr record 0x%04x: %d bytes", recordID, len(out)))
		}
	}
	if len(out) > length {
		out = out[:length]
	}
	return out, next, stats, nil
}

// --- MDIO / PHY -------------------------------------------------------------

// MemReadMII reads one 32-bit PHY register through the OEM MDIO command.
//
// The ATEN layout carries no PHY-address byte: the handler drives the BMC's
// own NIC through ioctl(sock, SIOCGMIIREG) with the interface fixed, so the
// request is just the subfunction and the register index.
func (s *CmdSess) MemReadMII(p *MemProfile, reg byte) (uint32, error) {
	if p == nil || !p.MIISupported || p.MIIReadSubFn == 0 {
		return 0, fmt.Errorf("profile %q has no MDIO/PHY read primitive", profileID(p))
	}
	cc, d, err := s.ExecRaw(p.ReadNetFn, p.ReadCmd, []byte{p.MIIReadSubFn, reg})
	if err != nil {
		return 0, err
	}
	if cc != 0x00 {
		return 0, fmt.Errorf("mii read cc=0x%02x (%s)", cc, memCCMeaning(p, cc))
	}
	if len(d) < 2 {
		return 0, fmt.Errorf("mii read short reply (%d bytes)", len(d))
	}
	var v uint32
	for _, b := range d[:min(4, len(d))] {
		v = v<<8 | uint32(b)
	}
	return v, nil
}

// MemWriteMII writes one 32-bit PHY register through the OEM MDIO command.
// The value goes on the wire big-endian, like every other ATEN OEM operand.
func (s *CmdSess) MemWriteMII(p *MemProfile, reg byte, val uint32) error {
	if p == nil || !p.MIISupported || p.MIIWriteSubFn == 0 {
		return fmt.Errorf("profile %q has no MDIO/PHY write primitive", profileID(p))
	}
	req := []byte{p.MIIWriteSubFn, reg, byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val)}
	cc, _, err := s.ExecRaw(p.ReadNetFn, p.ReadCmd, req)
	if err != nil {
		return err
	}
	if cc != 0x00 {
		return fmt.Errorf("mii write cc=0x%02x (%s)", cc, memCCMeaning(p, cc))
	}
	return nil
}

// --- PECI -------------------------------------------------------------------

// MemPECI runs one raw PECI transaction against the host CPU. Both directions
// are capped at the profile's PECIMaxLen (32 bytes on every ATEN build).
func (s *CmdSess) MemPECI(p *MemProfile, cmd byte, write []byte, readLen int) ([]byte, error) {
	if p == nil || !p.PECISupported {
		return nil, fmt.Errorf("profile %q has no PECI transport", profileID(p))
	}
	maxLen := p.PECIMaxLen
	if maxLen == 0 {
		maxLen = 32
	}
	if len(write) > maxLen || readLen > maxLen {
		return nil, fmt.Errorf("peci caps both directions at %d bytes", maxLen)
	}
	req := append([]byte{p.PECISubFn, cmd, byte(len(write)), byte(readLen)}, write...)
	cc, d, err := s.ExecRaw(p.ReadNetFn, p.ReadCmd, req)
	if err != nil {
		return nil, err
	}
	if cc != 0x00 {
		return nil, fmt.Errorf("peci cc=0x%02x (%s)", cc, memCCMeaning(p, cc))
	}
	return d, nil
}

// --- manufacturing NVRAM ----------------------------------------------------

// Supermicro manufacturing-data store: one byte per index, index < 0x40.
// kb/smc/notes/oem-netfn-hardware-access.md section 5.6a - the "raw NVRAM
// dump" reading of this command was refuted live, so it is exposed for what it
// actually is: a 64-byte indexed byte store.
const (
	netFnSMCManuf     byte = 0x3C
	cmdSMCWriteManuf  byte = 0x08
	cmdSMCReadManuf   byte = 0x09
	smcManufMaxIndex  byte = 0x3F
	smcManufIndexSpan int  = 0x40
)

// MemReadNVRAM reads the vendor manufacturing-data store one indexed byte at a
// time. Only Supermicro profiles implement it.
func (s *CmdSess) MemReadNVRAM(ctx context.Context, p *MemProfile, off uint64, length int, o MemBusOptions) ([]byte, MemStats, error) {
	var stats MemStats
	if p == nil || p.Vendor != "supermicro" {
		return nil, stats, fmt.Errorf("profile %q has no manufacturing-data store", profileID(p))
	}
	if off+uint64(length) > uint64(smcManufIndexSpan) {
		return nil, stats, fmt.Errorf("the manufacturing store is %d bytes; 0x%x+%d runs past index 0x%02x", smcManufIndexSpan, off, length, smcManufMaxIndex)
	}
	out := make([]byte, 0, length)
	for i := range length {
		if err := ctx.Err(); err != nil {
			return out, stats, err
		}
		idx := byte(off) + byte(i)
		stats.Requests++
		cc, d, err := s.ExecRaw(netFnSMCManuf, cmdSMCReadManuf, []byte{0x00, idx})
		if err != nil {
			stats.Failures++
			return out, stats, fmt.Errorf("nvram read index 0x%02x: %w", idx, err)
		}
		if cc != 0x00 || len(d) == 0 {
			stats.Failures++
			return out, stats, fmt.Errorf("nvram read index 0x%02x: cc=0x%02x", idx, cc)
		}
		out = append(out, d[0])
		if o.Progress != nil {
			o.Progress(fmt.Sprintf("nvram: %d/%d bytes", len(out), length))
		}
		if o.Delay > 0 {
			time.Sleep(o.Delay)
		}
	}
	return out, stats, nil
}

// MemWriteNVRAM writes the vendor manufacturing-data store one indexed byte at
// a time.
func (s *CmdSess) MemWriteNVRAM(ctx context.Context, p *MemProfile, off uint64, data []byte, o MemBusOptions) (MemStats, error) {
	var stats MemStats
	if p == nil || p.Vendor != "supermicro" {
		return stats, fmt.Errorf("profile %q has no manufacturing-data store", profileID(p))
	}
	if off+uint64(len(data)) > uint64(smcManufIndexSpan) {
		return stats, fmt.Errorf("the manufacturing store is %d bytes; 0x%x+%d runs past index 0x%02x", smcManufIndexSpan, off, len(data), smcManufMaxIndex)
	}
	for i, b := range data {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		idx := byte(off) + byte(i)
		stats.Requests++
		cc, _, err := s.ExecRaw(netFnSMCManuf, cmdSMCWriteManuf, []byte{0x00, idx, b})
		if err != nil {
			stats.Failures++
			return stats, fmt.Errorf("nvram write index 0x%02x: %w", idx, err)
		}
		if cc != 0x00 {
			stats.Failures++
			return stats, fmt.Errorf("nvram write index 0x%02x: cc=0x%02x", idx, cc)
		}
		if o.Progress != nil {
			o.Progress(fmt.Sprintf("nvram: wrote %d/%d bytes", i+1, len(data)))
		}
		if o.Delay > 0 {
			time.Sleep(o.Delay)
		}
	}
	return stats, nil
}
