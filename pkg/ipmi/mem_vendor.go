package ipmi

// Vendor-specific memory-adjacent primitives that do not fit the flat
// address-space model in mem.go: the AMD APML host-CPU register planes, the ATEN
// whole-flash streaming dump (WST NetFn 0x3E) and the X14 pin-level GPIO command.

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// --- AMD APML host-CPU register access (Supermicro 0x30/0x80) ---------------

// APMLPlane selects which of the three host-CPU register planes to talk to.
type APMLPlane string

const (
	// APMLMailbox is the SMU mailbox: a caller-chosen command number and a
	// 32-bit argument, executed by the CPU's system management unit.
	APMLMailbox APMLPlane = "mailbox"
	// APMLSBTSI is the sideband temperature sensor interface - the CPU-to-BMC
	// thermal path, 8-bit register indices.
	APMLSBTSI APMLPlane = "sbtsi"
	// APMLSBRMI is the sideband remote management interface, reaching the
	// whole 16-bit register space including the alert status/mask blocks.
	APMLSBRMI APMLPlane = "sbrmi"
)

// ParseAPMLPlane normalizes an apml=<plane> value.
func ParseAPMLPlane(s string) (APMLPlane, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "mailbox", "smu", "mbox":
		return APMLMailbox, nil
	case "sbtsi", "tsi", "thermal":
		return APMLSBTSI, nil
	case "sbrmi", "rmi":
		return APMLSBRMI, nil
	}
	return "", fmt.Errorf("unknown apml plane %q (use mailbox, sbtsi or sbrmi)", s)
}

const (
	netFnSMCOEM80 byte = 0x30
	cmdSMCOEM80   byte = 0x80

	apmlSubMailbox byte = 0x02
	apmlSubSBTSI   byte = 0x04
	apmlSubSBRMI   byte = 0x05
)

// APMLSupported reports whether a profile is expected to carry the APML
// command set. It is an AMD-socket surface: the code ships on the Intel
// generations too, but the socket-presence check refuses there.
func (p *MemProfile) APMLSupported() bool {
	return p != nil && p.Vendor == "supermicro" && p.APMLPlanes
}

// APMLResult is one host-CPU register transaction.
type APMLResult struct {
	Plane    APMLPlane `json:"plane"`
	Socket   byte      `json:"socket"`
	Register string    `json:"register"`
	Value    string    `json:"value,omitempty"`
	Status   string    `json:"status,omitempty"`
	Write    bool      `json:"write"`
}

// APMLRead reads one host-CPU register. For the mailbox plane reg is the SMU
// command number and arg is its 32-bit argument; the reply carries the SMU's
// own status byte plus the 32-bit result.
func (s *CmdSess) APMLRead(p *MemProfile, plane APMLPlane, socket byte, reg uint16, arg uint32) (*APMLResult, error) {
	if !p.APMLSupported() {
		return nil, fmt.Errorf("profile %q has no APML host-CPU register access", profileID(p))
	}
	if socket > 1 {
		return nil, fmt.Errorf("socket must be 0 or 1 (the handler validates socket < 2)")
	}
	res := &APMLResult{Plane: plane, Socket: socket, Register: fmt.Sprintf("0x%02x", reg)}
	var req []byte
	switch plane {
	case APMLMailbox:
		// 30 80 02 <socket> <mbox_cmd> [arg MSB-first]; the length check
		// accepts exactly 3 or 7 bytes counting the subfunction, and a
		// 3-byte request means a hard-zero argument.
		req = []byte{apmlSubMailbox, socket, byte(reg)}
		if arg != 0 {
			a := make([]byte, 4)
			binary.BigEndian.PutUint32(a, arg)
			req = append(req, a...)
		}
	case APMLSBTSI:
		req = []byte{apmlSubSBTSI, 0x00, socket, byte(reg)}
	case APMLSBRMI:
		req = []byte{apmlSubSBRMI, 0x00, socket}
		if reg > 0xff {
			req = append(req, byte(reg>>8), byte(reg))
		} else {
			req = append(req, byte(reg))
		}
	default:
		return nil, fmt.Errorf("unknown apml plane %q", plane)
	}

	cc, d, err := s.ExecRaw(netFnSMCOEM80, cmdSMCOEM80, req)
	if err != nil {
		return nil, err
	}
	if cc != 0x00 {
		return nil, fmt.Errorf("apml %s read cc=0x%02x (%s)", plane, cc, apmlCCMeaning(cc))
	}
	switch plane {
	case APMLMailbox:
		if len(d) < 5 {
			return nil, fmt.Errorf("apml mailbox short reply (%d bytes, expected 5)", len(d))
		}
		res.Status = fmt.Sprintf("0x%02x", d[0])
		res.Value = fmt.Sprintf("0x%08x", binary.BigEndian.Uint32(d[1:5]))
	default:
		if len(d) < 1 {
			return nil, fmt.Errorf("apml %s short reply", plane)
		}
		res.Value = fmt.Sprintf("0x%02x", d[0])
	}
	return res, nil
}

// APMLWrite writes one host-CPU register. The mailbox plane has no separate
// write form: a mailbox command with an argument is the write.
func (s *CmdSess) APMLWrite(p *MemProfile, plane APMLPlane, socket byte, reg uint16, val byte) (*APMLResult, error) {
	if !p.APMLSupported() {
		return nil, fmt.Errorf("profile %q has no APML host-CPU register access", profileID(p))
	}
	if socket > 1 {
		return nil, fmt.Errorf("socket must be 0 or 1 (the handler validates socket < 2)")
	}
	var req []byte
	switch plane {
	case APMLSBTSI:
		req = []byte{apmlSubSBTSI, 0x01, socket, byte(reg), val}
	case APMLSBRMI:
		req = []byte{apmlSubSBRMI, 0x01, socket}
		if reg > 0xff {
			req = append(req, byte(reg>>8), byte(reg))
		} else {
			req = append(req, byte(reg))
		}
		req = append(req, val)
	case APMLMailbox:
		return nil, fmt.Errorf("the mailbox plane has no write form: send a mailbox command with an argument via read instead")
	default:
		return nil, fmt.Errorf("unknown apml plane %q", plane)
	}
	cc, _, err := s.ExecRaw(netFnSMCOEM80, cmdSMCOEM80, req)
	if err != nil {
		return nil, err
	}
	if cc != 0x00 {
		return nil, fmt.Errorf("apml %s write cc=0x%02x (%s)", plane, cc, apmlCCMeaning(cc))
	}
	return &APMLResult{Plane: plane, Socket: socket, Register: fmt.Sprintf("0x%02x", reg), Value: fmt.Sprintf("0x%02x", val), Write: true}, nil
}

func apmlCCMeaning(cc byte) string {
	switch cc {
	case 0xcc:
		return "invalid data field - a length check failed, or the socket-presence bit is clear (the host is probably powered off)"
	case 0xd4:
		return "insufficient privilege - Administrator is required"
	case 0xc1:
		return "invalid command - this build has no APML command set"
	}
	return "unspecified"
}

// --- ATEN whole-flash streaming dump (WST NetFn 0x3E) -----------------------

const (
	netFnSMCWST          byte = 0x3E
	cmdWSTPrepareDump    byte = 0x1D
	cmdWSTCheckDumpDone  byte = 0x1E
	cmdWSTSendFlashChunk byte = 0x1F
	wstChunkBytes             = 0x38 // 56 bytes per request, fixed
)

// FlashDumpResult reports one streaming flash dump.
type FlashDumpResult struct {
	Size     uint32 `json:"size"`
	Read     int    `json:"read"`
	Requests int    `json:"requests"`
	Note     string `json:"note,omitempty"`
}

// FlashDumpSupported reports whether the profile is expected to carry the WST
// dump chain. Every ATEN build does; whether it yields flash is per-generation
// and has never been proven on a unit.
func (p *MemProfile) FlashDumpSupported() bool {
	return p != nil && p.WSTFlashDump
}

// FlashDumpStart asks the BMC to stage a whole-flash image on its own
// filesystem. It takes no arguments: the source partition is named by the
// firmware, not by the caller.
func (s *CmdSess) FlashDumpStart() error {
	cc, _, err := s.ExecRaw(netFnSMCWST, cmdWSTPrepareDump, nil)
	if err != nil {
		return err
	}
	if cc != 0x00 {
		return fmt.Errorf("PrepareDumpFlash cc=0x%02x", cc)
	}
	return nil
}

// FlashDumpStatus polls whether the staged image is ready and how large it is.
// The poll is destructive: the handler zeroes the completion flag the first time
// it reads as set, so a second call reports not-ready even though the image is
// staged. Call it once and carry the answer.
func (s *CmdSess) FlashDumpStatus() (ready bool, size uint32, err error) {
	cc, d, err := s.ExecRaw(netFnSMCWST, cmdWSTCheckDumpDone, nil)
	if err != nil {
		return false, 0, err
	}
	if cc != 0x00 {
		return false, 0, fmt.Errorf("CheckDumpFlashComplete cc=0x%02x", cc)
	}
	if len(d) < 1 {
		return false, 0, fmt.Errorf("CheckDumpFlashComplete short reply")
	}
	ready = d[0] != 0
	if ready && len(d) >= 5 {
		size = binary.BigEndian.Uint32(d[1:5])
	}
	return ready, size, nil
}

// FlashDumpRead streams the staged image out. The BMC drives the offset from its
// own counter, so this must be called sequentially from the start and cannot be
// seeked or resumed. size comes from the caller's own FlashDumpStatus call, which
// clears the completion flag as it reports it, so this must not poll again.
// maxBytes bounds the transfer; pass 0 for the whole reported size, but note that
// at 56 bytes per request a whole flash image is millions of requests.
func (s *CmdSess) FlashDumpRead(ctx context.Context, size uint32, maxBytes int, opts MemReadOptions) ([]byte, *FlashDumpResult, error) {
	res := &FlashDumpResult{Size: size}
	limit := maxBytes
	if limit <= 0 || (size > 0 && limit > int(size)) {
		limit = int(size)
	}
	if limit <= 0 {
		return nil, res, fmt.Errorf("the staged dump reports zero bytes")
	}

	out := make([]byte, 0, limit)
	for len(out) < limit {
		if err := ctx.Err(); err != nil {
			return out, res, err
		}
		res.Requests++
		cc, d, rerr := s.ExecRaw(netFnSMCWST, cmdWSTSendFlashChunk, nil)
		if rerr != nil {
			return out, res, rerr
		}
		if cc != 0x00 {
			return out, res, fmt.Errorf("SendFlashContent2Utility off=%d cc=0x%02x", len(out), cc)
		}
		if len(d) < 2 {
			return out, res, fmt.Errorf("SendFlashContent2Utility returned %d bytes at off=%d", len(d), len(out))
		}
		// data[0] is a status/length byte; the payload is the following 56.
		body := d[1:]
		if len(body) > wstChunkBytes {
			body = body[:wstChunkBytes]
		}
		// The BMC's counter advances a whole chunk whatever it sent, so a
		// short chunk anywhere but the end means the missing bytes are gone
		// and everything after them would sit at the wrong offset. Reporting
		// a contiguous image at that point would be a lie.
		if len(body) < wstChunkBytes && len(out)+len(body) < limit {
			res.Read = len(out)
			return out, res, fmt.Errorf("short chunk at offset %d (%d of %d bytes): the BMC counter has already advanced, so the rest of the stream would be misaligned",
				len(out), len(body), wstChunkBytes)
		}
		out = append(out, body...)
		if opts.Progress != nil && res.Requests%16 == 0 {
			opts.Progress(fmt.Sprintf("flash dump: %d/%d bytes in %d requests", len(out), limit, res.Requests))
		}
		if opts.Delay > 0 {
			time.Sleep(opts.Delay)
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	res.Read = len(out)
	res.Note = "the offset is a BMC-side counter, so this stream cannot be seeked or resumed"
	return out, res, nil
}

// --- X14 pin-level GPIO (0x30/0x70 subfn 0x4B) ------------------------------

// GPIOPinSupported reports whether the profile carries the pin-level GPIO
// command, as opposed to reaching GPIO through the memory window.
func (p *MemProfile) GPIOPinSupported() bool {
	return p != nil && p.GPIOPinSubFn != 0
}

// GPIOPinRead reads one GPIO pin by number.
func (s *CmdSess) GPIOPinRead(p *MemProfile, pin byte) (byte, error) {
	if !p.GPIOPinSupported() {
		return 0, fmt.Errorf("profile %q has no pin-level GPIO command; read the GPIO register window with space=gpio instead", profileID(p))
	}
	if pin > 0xdf {
		return 0, fmt.Errorf("pin %d is out of range (the handler throws out_of_range above 0xdf)", pin)
	}
	cc, d, err := s.ExecRaw(p.ReadNetFn, p.ReadCmd, []byte{p.GPIOPinSubFn, 0x00, pin})
	if err != nil {
		return 0, err
	}
	if cc != 0x00 {
		return 0, fmt.Errorf("gpio read cc=0x%02x (%s)", cc, memCCMeaning(p, cc))
	}
	if len(d) < 1 {
		return 0, fmt.Errorf("gpio read short reply")
	}
	return d[0], nil
}

// GPIOPinWrite drives one GPIO pin. On X14 the write path shells out to
// gpioset, so it changes real board state.
func (s *CmdSess) GPIOPinWrite(p *MemProfile, pin, value byte) error {
	if !p.GPIOPinSupported() {
		return fmt.Errorf("profile %q has no pin-level GPIO command", profileID(p))
	}
	if pin > 0xdf {
		return fmt.Errorf("pin %d is out of range (the handler throws out_of_range above 0xdf)", pin)
	}
	cc, _, err := s.ExecRaw(p.ReadNetFn, p.ReadCmd, []byte{p.GPIOPinSubFn, 0x01, pin, value})
	if err != nil {
		return err
	}
	if cc != 0x00 {
		return fmt.Errorf("gpio write cc=0x%02x (%s)", cc, memCCMeaning(p, cc))
	}
	return nil
}
