package ipmi

import (
	"bytes"
	"slices"
	"testing"
)

type recordingHW1Runner struct {
	netfn byte
	cmd   byte
	req   []byte
	cc    byte
	resp  []byte
	calls int
}

func (r *recordingHW1Runner) Close() {}

func (r *recordingHW1Runner) Exec(netfn, cmd byte, req []byte) (byte, []byte, error) {
	r.netfn, r.cmd, r.req, r.calls = netfn, cmd, append([]byte(nil), req...), r.calls+1
	return r.cc, append([]byte(nil), r.resp...), nil
}

func hw1TestSess(r *recordingHW1Runner) *CmdSess { return &CmdSess{runner: r} }

func TestHW1FileWireFormats(t *testing.T) {
	r := &recordingHW1Runner{}
	s := hw1TestSess(r)
	if err := s.HW1FileOpen("/etc/shadow", HW1FileCopy); err != nil {
		t.Fatalf("open: %v", err)
	}
	want := append([]byte{0x2e, 0x00, 0x01}, []byte("/etc/shadow")...)
	if r.netfn != 0x30 || r.cmd != 0xae || !bytes.Equal(r.req, want) {
		t.Fatalf("fd_open = %02x/%02x % x, want 30/ae % x", r.netfn, r.cmd, r.req, want)
	}

	r.resp = []byte{0xaa, 0xbb}
	got, err := s.HW1FileRead(0x11223344, 2)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	want = []byte{0x2e, 0x03, 0x44, 0x33, 0x22, 0x11, 0x02, 0x00, 0x00, 0x00}
	if !bytes.Equal(r.req, want) || !bytes.Equal(got, r.resp) {
		t.Fatalf("fd_read req=% x data=% x, want req=% x data=% x", r.req, got, want, r.resp)
	}
}

func TestHW1SCSIWireFormat(t *testing.T) {
	r := &recordingHW1Runner{resp: []byte{0x12, 0x34}}
	s := hw1TestSess(r)
	cdb := []byte{0x12, 0x00, 0x00, 0x00, 0x60, 0x00}
	got, err := s.HW1SCSICommand(2, 3, 1, 0x1234, cdb)
	if err != nil {
		t.Fatalf("SCSI: %v", err)
	}
	want := []byte{0x35, 0x02, 0x03, 0x01, 0x34, 0x12, 0x06, 0x12, 0x00, 0x00, 0x00, 0x60, 0x00}
	if !bytes.Equal(r.req, want) || !bytes.Equal(got, r.resp) {
		t.Fatalf("SCSI req=% x data=% x, want req=% x data=% x", r.req, got, want, r.resp)
	}
}

func TestSMCHDDTargetsUses24BitGroups(t *testing.T) {
	r := &recordingHW1Runner{resp: make([]byte, 0x50)}
	// Targets 0, 23, 24, and 119. Bit 31 is deliberately set and must be ignored.
	r.resp[0] = 0x01
	r.resp[2] = 0x80
	r.resp[3] = 0x80
	r.resp[4] = 0x01
	r.resp[18] = 0x80
	r.resp[19] = 0x80
	r.resp[0x28+4] = 0x01 // target 24 has an error bit
	targets, err := hw1TestSess(r).SMCHDDTargets(2)
	if err != nil {
		t.Fatal(err)
	}
	want := []SMCHDDTarget{
		{Controller: 2, Target: 0},
		{Controller: 2, Target: 23},
		{Controller: 2, Target: 24, Error: true},
		{Controller: 2, Target: 119},
	}
	if !slices.Equal(targets, want) {
		t.Fatalf("targets = %+v, want %+v", targets, want)
	}
	if r.netfn != 0x30 || r.cmd != 0x70 || !bytes.Equal(r.req, []byte{0x4c, 0x02}) {
		t.Fatalf("presence request = %02x/%02x % x", r.netfn, r.cmd, r.req)
	}
}

func TestSMCHDDInfoRecord(t *testing.T) {
	r := &recordingHW1Runner{resp: make([]byte, 0x74)}
	copy(r.resp[0x00:0x08], "ATA     ")
	copy(r.resp[0x08:0x18], "LAB DISK        ")
	copy(r.resp[0x18:0x1c], "1.0 ")
	copy(r.resp[0x54:0x74], "SERIAL-123")
	r.resp[0x37], r.resp[0x38], r.resp[0x39] = 31, 4, 1
	info, err := hw1TestSess(r).SMCHDDInfoRecord(3, 7)
	if err != nil {
		t.Fatal(err)
	}
	if info.Controller != 3 || info.Target != 7 || info.Vendor != "ATA" || info.Model != "LAB DISK" || info.Serial != "SERIAL-123" || info.Temperature == nil || *info.Temperature != 31 {
		t.Fatalf("info = %+v", info)
	}
	if !bytes.Equal(r.req, []byte{0x4d, 0x07, 0x03}) {
		t.Fatalf("info request = % x", r.req)
	}
}

func TestHW1MemWireFormat(t *testing.T) {
	r := &recordingHW1Runner{resp: []byte{0x05, 0x03, 0x03, 0x03}}
	got, err := hw1TestSess(r).HW1MemReadWrite(0x1e6e2004, 0)
	if err != nil {
		t.Fatalf("memory: %v", err)
	}
	want := []byte{0x22, 0x1e, 0x6e, 0x20, 0x04, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(r.req, want) || got != 0x05030303 {
		t.Fatalf("memory req=% x old=0x%08x, want req=% x old=0x05030303", r.req, got, want)
	}
}

func TestHW1ValidationSendsNoTraffic(t *testing.T) {
	r := &recordingHW1Runner{}
	s := hw1TestSess(r)
	if _, err := s.HW1FileRead(0, HW1MaxFileRead+1); err == nil {
		t.Fatal("oversized file read accepted")
	}
	if _, err := s.HW1FileRead(^uint32(0), 2); err == nil {
		t.Fatal("file read crossing the 32-bit offset boundary accepted")
	}
	if _, err := s.HW1SCSICommand(4, 0, 0, 0, make([]byte, 6)); err == nil {
		t.Fatal("invalid controller accepted")
	}
	if _, err := s.HW1SCSICommand(0, 0, 0, 0, make([]byte, 8)); err == nil {
		t.Fatal("invalid CDB length accepted")
	}
	if r.calls != 0 {
		t.Fatalf("validation spent %d requests; want 0", r.calls)
	}
}

func TestHW1CompletionError(t *testing.T) {
	r := &recordingHW1Runner{cc: 0xd4}
	_, err := hw1TestSess(r).HW1FileStat("/tmp/filedump")
	if cc, ok := HW1CompletionCode(err); !ok || cc != 0xd4 {
		t.Fatalf("completion error = %v, code 0x%02x ok=%v", err, cc, ok)
	}
	if got := HW1CompletionMeaning(0xc1); got != "invalid command" {
		t.Fatalf("completion 0xc1 = %q", got)
	}
	if got := HW1CompletionMeaning(0xc7); got != "request data length invalid" {
		t.Fatalf("completion 0xc7 = %q", got)
	}
}

func TestSCSIHelpers(t *testing.T) {
	data := make([]byte, 96)
	copy(data[8:16], "ATA     ")
	copy(data[16:32], "LAB DISK        ")
	copy(data[32:36], "1.0 ")
	inq, err := DecodeSCSIInquiry(data)
	if err != nil || inq.Vendor != "ATA" || inq.Product != "LAB DISK" || inq.Revision != "1.0" {
		t.Fatalf("inquiry = %+v, err=%v", inq, err)
	}
	if SCSICDBIsDestructive([]byte{0x12}) || !SCSICDBIsDestructive([]byte{0x2a}) || !SCSICDBIsDestructive([]byte{0x42}) {
		t.Fatal("destructive CDB classification mismatch")
	}
}
