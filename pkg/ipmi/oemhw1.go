package ipmi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	NetFnSMCOEMHW1 byte = 0x30
	CmdSMCOEMHW1   byte = 0xae

	HW1SubMem  byte = 0x22
	HW1SubFile byte = 0x2e
	HW1SubSCSI byte = 0x35

	// An IPMI response data field is at most 255 bytes. Keeping file reads at
	// or below this bound avoids exercising the handler's unchecked reply size.
	HW1MaxFileRead = 0xff
	HW1MaxPathLen  = 0xfc

	smcHDDMapSub  byte = 0x4c
	smcHDDInfoSub byte = 0x4d
)

// HW1CompletionError preserves the target's completion code so callers can
// distinguish an absent sub-command, insufficient privilege, and a backend
// failure without parsing an error string.
type HW1CompletionError struct {
	Operation string
	Code      byte
}

func (e *HW1CompletionError) Error() string {
	return fmt.Sprintf("%s: OEMHW1 completion code 0x%02x (%s)", e.Operation, e.Code, HW1CompletionMeaning(e.Code))
}

// HW1CompletionCode extracts an OEMHW1 completion code from err.
func HW1CompletionCode(err error) (byte, bool) {
	var ccErr *HW1CompletionError
	if !errors.As(err, &ccErr) {
		return 0, false
	}
	return ccErr.Code, true
}

// HW1CompletionMeaning describes completion codes used by OEMHW1Command.
func HW1CompletionMeaning(cc byte) string {
	switch cc {
	case 0x00:
		return "success"
	case 0xc1:
		return "invalid command"
	case 0xc7:
		return "request data length invalid"
	case 0xc9:
		return "request length out of range"
	case 0xcc:
		return "sub-command absent, presence gate refused, or invalid data"
	case 0xce:
		return "backend operation failed"
	case 0xd4:
		return "insufficient privilege"
	default:
		return "target error"
	}
}

func (s *CmdSess) execHW1(operation string, req []byte) ([]byte, error) {
	cc, data, err := s.ExecRaw(NetFnSMCOEMHW1, CmdSMCOEMHW1, req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", operation, err)
	}
	if cc != 0x00 {
		return nil, &HW1CompletionError{Operation: operation, Code: cc}
	}
	return data, nil
}

// HW1FileMode selects fd_open's staging behavior.
type HW1FileMode byte

const (
	HW1FileTar  HW1FileMode = 0x00
	HW1FileCopy HW1FileMode = 0x01
)

func validateHW1Path(path string) error {
	if path == "" {
		return fmt.Errorf("remote path is empty")
	}
	if strings.IndexByte(path, 0) >= 0 {
		return fmt.Errorf("remote path contains a NUL byte")
	}
	if len(path) > HW1MaxPathLen {
		return fmt.Errorf("remote path is %d bytes; maximum is %d", len(path), HW1MaxPathLen)
	}
	return nil
}

// HW1FileOpen asks fd_open to stage path in /tmp/filedump. Copy mode stages
// one file; tar mode accepts the firmware's space-separated file list.
func (s *CmdSess) HW1FileOpen(path string, mode HW1FileMode) error {
	if err := validateHW1Path(path); err != nil {
		return err
	}
	if mode != HW1FileCopy && mode != HW1FileTar {
		return fmt.Errorf("invalid OEMHW1 file mode 0x%02x", byte(mode))
	}
	req := make([]byte, 3, 3+len(path))
	req[0], req[1], req[2] = HW1SubFile, 0x00, byte(mode)
	req = append(req, path...)
	_, err := s.execHW1("OEMHW1 fd_open", req)
	return err
}

// HW1FileRead reads one bounded chunk from /tmp/filedump.
func (s *CmdSess) HW1FileRead(offset uint32, length int) ([]byte, error) {
	if length < 1 || length > HW1MaxFileRead {
		return nil, fmt.Errorf("OEMHW1 fd_read length %d is outside 1..%d", length, HW1MaxFileRead)
	}
	if uint64(offset)+uint64(length) > uint64(1)<<32 {
		return nil, fmt.Errorf("OEMHW1 fd_read range 0x%08x+%d exceeds the 32-bit offset field", offset, length)
	}
	req := make([]byte, 10)
	req[0], req[1] = HW1SubFile, 0x03
	binary.LittleEndian.PutUint32(req[2:6], offset)
	binary.LittleEndian.PutUint32(req[6:10], uint32(length))
	data, err := s.execHW1("OEMHW1 fd_read", req)
	if err != nil {
		return nil, err
	}
	if len(data) > length {
		return nil, fmt.Errorf("OEMHW1 fd_read returned %d bytes for a %d-byte request", len(data), length)
	}
	return data, nil
}

// HW1FileStat runs fd_stat for path and returns the handler's raw stat data.
func (s *CmdSess) HW1FileStat(path string) ([]byte, error) {
	if err := validateHW1Path(path); err != nil {
		return nil, err
	}
	req := append([]byte{HW1SubFile, 0x02}, path...)
	return s.execHW1("OEMHW1 fd_stat", req)
}

// HW1SCSICommand issues one caller-supplied CDB through the Broadcom storage
// backend. Controller, target, direction, and CDB size are checked locally so
// malformed requests never reach the BMC.
func (s *CmdSess) HW1SCSICommand(controller, target, direction byte, timeout uint16, cdb []byte) ([]byte, error) {
	if controller > 3 {
		return nil, fmt.Errorf("SCSI controller %d is outside 0..3", controller)
	}
	if target >= 0x78 {
		return nil, fmt.Errorf("SCSI target 0x%02x is outside 0x00..0x77", target)
	}
	if direction > 3 {
		return nil, fmt.Errorf("SCSI direction %d is outside 0..3", direction)
	}
	switch len(cdb) {
	case 6, 10, 12, 16:
	default:
		return nil, fmt.Errorf("SCSI CDB is %d bytes; use 6, 10, 12, or 16", len(cdb))
	}
	req := make([]byte, 7, 7+len(cdb))
	req[0], req[1], req[2], req[3] = HW1SubSCSI, controller, target, direction
	binary.LittleEndian.PutUint16(req[4:6], timeout)
	req[6] = byte(len(cdb))
	req = append(req, cdb...)
	return s.execHW1("OEMHW1 SCSI CDB", req)
}

// SMCHDDTarget is one slot reported by GetHDDExistAndErrBitMap.
type SMCHDDTarget struct {
	Controller byte `json:"controller"`
	Target     byte `json:"target"`
	Error      bool `json:"error"`
}

// SMCHDDTargets returns every present target on one controller. The firmware
// packs five groups of 24 targets into little-endian 32-bit words; bits 24..31
// are unused and must not be interpreted as slots.
func (s *CmdSess) SMCHDDTargets(controller byte) ([]SMCHDDTarget, error) {
	if controller > 3 {
		return nil, fmt.Errorf("SCSI controller %d is outside 0..3", controller)
	}
	cc, data, err := s.ExecRaw(NetFnSMCOEMHW1, 0x70, []byte{smcHDDMapSub, controller})
	if err != nil {
		return nil, fmt.Errorf("SMC HDD presence map: %w", err)
	}
	if cc != 0x00 {
		return nil, &HW1CompletionError{Operation: "SMC HDD presence map", Code: cc}
	}
	if len(data) < 0x50 {
		return nil, fmt.Errorf("SMC HDD presence map returned %d bytes; need 80", len(data))
	}
	out := make([]SMCHDDTarget, 0)
	for group := 0; group < 5; group++ {
		present := binary.LittleEndian.Uint32(data[group*4:])
		errors := binary.LittleEndian.Uint32(data[0x28+group*4:])
		for bit := 0; bit < 24; bit++ {
			mask := uint32(1) << bit
			if present&mask == 0 {
				continue
			}
			out = append(out, SMCHDDTarget{
				Controller: controller,
				Target:     byte(group*24 + bit),
				Error:      errors&mask != 0,
			})
		}
	}
	return out, nil
}

// SMCHDDInfo is the stable identification subset of the cached HDDInfo_t record
// returned by sub-command 0x4d. Reply lengths vary by generation, but these
// fields all live in the first 116 bytes.
type SMCHDDInfo struct {
	Controller  byte   `json:"controller"`
	Target      byte   `json:"target"`
	Vendor      string `json:"vendor,omitempty"`
	Model       string `json:"model,omitempty"`
	Revision    string `json:"revision,omitempty"`
	Serial      string `json:"serial,omitempty"`
	Slot        byte   `json:"slot"`
	Enclosure   byte   `json:"enclosure"`
	Temperature *byte  `json:"temperature,omitempty"`
}

// SMCHDDInfoRecord returns the cached drive record for one in-range target.
// Call SMCHDDTargets first because absent slots may contain zero or stale data.
func (s *CmdSess) SMCHDDInfoRecord(controller, target byte) (SMCHDDInfo, error) {
	if controller > 3 {
		return SMCHDDInfo{}, fmt.Errorf("SCSI controller %d is outside 0..3", controller)
	}
	if target >= 0x78 {
		return SMCHDDInfo{}, fmt.Errorf("SCSI target 0x%02x is outside 0x00..0x77", target)
	}
	cc, data, err := s.ExecRaw(NetFnSMCOEMHW1, 0x70, []byte{smcHDDInfoSub, target, controller})
	if err != nil {
		return SMCHDDInfo{}, fmt.Errorf("SMC HDD info: %w", err)
	}
	if cc != 0x00 {
		return SMCHDDInfo{}, &HW1CompletionError{Operation: "SMC HDD info", Code: cc}
	}
	if len(data) < 0x74 {
		return SMCHDDInfo{}, fmt.Errorf("SMC HDD info returned %d bytes; need 116", len(data))
	}
	info := SMCHDDInfo{
		Controller: controller,
		Target:     target,
		Vendor:     trimSCSIFixedString(data[0x00:0x08]),
		Model:      trimSCSIFixedString(data[0x08:0x18]),
		Revision:   trimSCSIFixedString(data[0x18:0x1c]),
		Serial:     trimSCSIFixedString(data[0x54:0x74]),
		Slot:       data[0x38],
		Enclosure:  data[0x39],
	}
	if data[0x37] != 0xff {
		temperature := data[0x37]
		info.Temperature = &temperature
	}
	return info, nil
}

// HW1MemReadWrite performs the handler's mandatory 32-bit read-then-write
// (CVE-2026-65211). The returned word is the value observed before the write. Callers must use a
// write-immune register or write back a value they have already read unless an
// explicit mutation opt-in has been obtained.
func (s *CmdSess) HW1MemReadWrite(address, value uint32) (uint32, error) {
	req := make([]byte, 9)
	req[0] = HW1SubMem
	binary.BigEndian.PutUint32(req[1:5], address)
	binary.BigEndian.PutUint32(req[5:9], value)
	data, err := s.execHW1("OEMHW1 memory read/write", req)
	if err != nil {
		return 0, err
	}
	if len(data) < 4 {
		return 0, fmt.Errorf("OEMHW1 memory read/write returned %d bytes; need 4", len(data))
	}
	return binary.BigEndian.Uint32(data[:4]), nil
}

// SCSIInquiry identifies the standard fields returned by opcode 0x12.
type SCSIInquiry struct {
	Vendor   string `json:"vendor"`
	Product  string `json:"product"`
	Revision string `json:"revision"`
}

// DecodeSCSIInquiry decodes the fixed-width identification strings in a
// standard INQUIRY response.
func DecodeSCSIInquiry(data []byte) (SCSIInquiry, error) {
	if len(data) < 36 {
		return SCSIInquiry{}, fmt.Errorf("SCSI INQUIRY response is %d bytes; need at least 36", len(data))
	}
	return SCSIInquiry{
		Vendor:   trimSCSIFixedString(data[8:16]),
		Product:  trimSCSIFixedString(data[16:32]),
		Revision: trimSCSIFixedString(data[32:36]),
	}, nil
}

func trimSCSIFixedString(data []byte) string {
	return strings.Trim(string(data), " \x00")
}

// SCSICDBIsDestructive classifies common write, erase, format, sanitize, and
// media-control opcodes. Unknown opcodes are not classified as safe by callers;
// this helper only recognizes the destructive set the CLI must always gate.
func SCSICDBIsDestructive(cdb []byte) bool {
	if len(cdb) == 0 {
		return false
	}
	switch cdb[0] {
	case 0x04, // FORMAT UNIT
		0x0a, 0x2a, 0xaa, 0x8a, // WRITE(6/10/12/16)
		0x15, 0x55, // MODE SELECT(6/10)
		0x19,       // ERASE(6)
		0x1b,       // START STOP UNIT / load-eject
		0x1d,       // SEND DIAGNOSTIC (can alter device state)
		0x3b,       // WRITE BUFFER
		0x3f,       // WRITE LONG(10)
		0x41, 0x93, // WRITE SAME(10/16)
		0x42, // UNMAP
		0x48, // SANITIZE
		0x4c, // LOG SELECT
		0x5f, // PERSISTENT RESERVE OUT
		0x83, // EXTENDED COPY
		0x89, // COMPARE AND WRITE
		0x9f: // SERVICE ACTION OUT(16)
		return true
	default:
		return false
	}
}
