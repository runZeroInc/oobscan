package ipmi

// End-to-end tests for the chunked read/write loops, driven through a fake
// cmdRunner rather than a socket. The loops are where the byte-order
// reversal, the alignment slicing, the hole accounting and the
// retry-vs-completion-code split all meet, and every one of those is a way to
// silently produce a wrong image.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// fakeMemBMC answers the Supermicro 0x30/0x70 memory subfunctions out of a
// byte-addressed backing store, in the reply order a chosen generation uses.
type fakeMemBMC struct {
	base    uint64
	mem     []byte
	order   MemByteOrder
	written map[uint64][]byte

	// refuse maps an address to a completion code the handler should answer
	// instead of data, so allowlist rejects and privilege failures can be
	// exercised mid-transfer.
	refuse map[uint64]byte
	// dropN makes the first N requests look like lost datagrams, to exercise
	// the transport retry path.
	dropN int

	requests int
}

func newFakeMemBMC(base uint64, size int, order MemByteOrder) *fakeMemBMC {
	m := make([]byte, size)
	for i := range m {
		m[i] = byte(i)
	}
	return &fakeMemBMC{base: base, mem: m, order: order, written: map[uint64][]byte{}, refuse: map[uint64]byte{}}
}

func (f *fakeMemBMC) Close() {}

func (f *fakeMemBMC) Exec(netfn, cmd byte, data []byte) (byte, []byte, error) {
	f.requests++
	if f.dropN > 0 {
		f.dropN--
		return 0xff, nil, errors.New("i/o timeout")
	}
	if netfn != 0x30 || cmd != 0x70 {
		return 0xc1, nil, nil
	}
	if len(data) < 6 {
		return 0xc7, nil, nil
	}
	sub, width := data[0], int(data[1])
	addr := uint64(data[2])<<24 | uint64(data[3])<<16 | uint64(data[4])<<8 | uint64(data[5])
	if cc, ok := f.refuse[addr]; ok {
		return cc, nil, nil
	}
	off := int(addr - f.base)
	if off < 0 || off+width > len(f.mem) {
		return 0xcc, nil, nil
	}

	switch sub {
	case 0xC0:
		if width == 0 {
			return 0x00, nil, nil // the side-effect-free allowlist oracle
		}
		out := make([]byte, width)
		copy(out, f.mem[off:off+width])
		if f.order == MemOrderMSBFirst && width > 1 {
			out = reverseBytes(out)
		}
		return 0x00, out, nil
	case 0xC1:
		if len(data) < 6+width {
			return 0xc7, nil, nil
		}
		val := make([]byte, width)
		copy(val, data[6:6+width])
		// The handler takes the value big-endian, so undo that to get
		// memory order before storing.
		if width > 1 {
			val = reverseBytes(val)
		}
		copy(f.mem[off:off+width], val)
		f.written[addr] = val
		return 0x00, nil, nil
	}
	return 0xcc, nil, nil
}

func fakeSess(f *fakeMemBMC) *CmdSess { return &CmdSess{runner: f, host: "192.0.2.10"} }

func TestMemReadPhysicalReassemblesImage(t *testing.T) {
	for _, order := range []MemByteOrder{MemOrderMSBFirst, MemOrderAscending} {
		t.Run(string(order), func(t *testing.T) {
			f := newFakeMemBMC(0x20000000, 256, order)
			s := fakeSess(f)
			p, _ := MemProfileByID("smc-x11")
			p.ReplyOrder = order

			got, holes, stats, err := s.MemReadPhysical(context.Background(), &p, 0x20000000, 64, MemReadOptions{})
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if len(holes) != 0 {
				t.Errorf("unexpected holes: %v", holes)
			}
			if !bytes.Equal(got, f.mem[:64]) {
				t.Errorf("image mismatch under %s reply order:\n got % x\nwant % x", order, got[:16], f.mem[:16])
			}
			if want := 16; stats.Requests != want {
				t.Errorf("requests = %d, want %d (64 bytes at 4 per request)", stats.Requests, want)
			}
		})
	}
}

// A read that does not start on a unit boundary must still return exactly the
// requested window: the loop aligns down, then slices.
func TestMemReadPhysicalUnaligned(t *testing.T) {
	f := newFakeMemBMC(0x20000000, 256, MemOrderMSBFirst)
	s := fakeSess(f)
	p, _ := MemProfileByID("smc-x11")

	got, _, stats, err := s.MemReadPhysical(context.Background(), &p, 0x20000002, 7, MemReadOptions{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, f.mem[2:9]) {
		t.Errorf("unaligned read = % x, want % x", got, f.mem[2:9])
	}
	// bytes 2..8 span the words at +0, +4 and +8, so three requests.
	if stats.Requests != 3 {
		t.Errorf("requests = %d, want 3", stats.Requests)
	}
}

func TestMemReadPhysicalUnitOne(t *testing.T) {
	// A one-byte unit has no byte order at all, which is the documented
	// escape hatch when the reply order for a build is unknown.
	f := newFakeMemBMC(0x20000000, 64, MemOrderMSBFirst)
	s := fakeSess(f)
	p, _ := MemProfileByID("smc-x11")

	got, _, stats, err := s.MemReadPhysical(context.Background(), &p, 0x20000000, 8, MemReadOptions{Unit: 1})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, f.mem[:8]) {
		t.Errorf("unit=1 read = % x, want % x", got, f.mem[:8])
	}
	if stats.Requests != 8 {
		t.Errorf("requests = %d, want 8", stats.Requests)
	}
}

// A real completion code is the target's answer, so it must abort by default
// and must never be retried.
func TestMemReadPhysicalCompletionCodeAborts(t *testing.T) {
	f := newFakeMemBMC(0x20000000, 256, MemOrderMSBFirst)
	f.refuse[0x20000008] = 0xcc
	s := fakeSess(f)
	p, _ := MemProfileByID("smc-x11")

	_, holes, stats, err := s.MemReadPhysical(context.Background(), &p, 0x20000000, 32, MemReadOptions{})
	if err == nil {
		t.Fatal("a refused unit must abort the read by default")
	}
	if len(holes) != 1 || holes[0].Addr != 0x20000008 || holes[0].CC != "0xcc" {
		t.Errorf("hole record = %+v", holes)
	}
	// Two good words plus the refused one, and no retry of the refusal.
	if stats.Requests != 3 {
		t.Errorf("requests = %d, want 3 (a completion code is never retried)", stats.Requests)
	}
	if stats.Retries != 0 {
		t.Errorf("retries = %d, want 0", stats.Retries)
	}
}

// With continue, the refused unit becomes a recorded hole and the transfer
// finishes, so a mostly-readable region still yields an image.
func TestMemReadPhysicalContinueOnError(t *testing.T) {
	f := newFakeMemBMC(0x20000000, 256, MemOrderMSBFirst)
	f.refuse[0x20000008] = 0xcc
	s := fakeSess(f)
	p, _ := MemProfileByID("smc-x11")

	got, holes, _, err := s.MemReadPhysical(context.Background(), &p, 0x20000000, 32, MemReadOptions{ContinueOnError: true})
	if err != nil {
		t.Fatalf("continue should not abort: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("got %d bytes, want 32", len(got))
	}
	if len(holes) != 1 {
		t.Errorf("holes = %v, want one", holes)
	}
	// The hole is zero-filled so offsets after it stay correct.
	if !bytes.Equal(got[8:12], []byte{0, 0, 0, 0}) {
		t.Errorf("hole should be zero-filled, got % x", got[8:12])
	}
	if !bytes.Equal(got[12:16], f.mem[12:16]) {
		t.Errorf("data after a hole is misaligned: % x", got[12:16])
	}
}

// A lost datagram is retried; the retry budget is spent on transport errors
// only.
func TestMemReadPhysicalRetriesTransportOnly(t *testing.T) {
	f := newFakeMemBMC(0x20000000, 64, MemOrderMSBFirst)
	f.dropN = 2
	s := fakeSess(f)
	p, _ := MemProfileByID("smc-x11")

	got, _, stats, err := s.MemReadPhysical(context.Background(), &p, 0x20000000, 4, MemReadOptions{Retries: 4})
	if err != nil {
		t.Fatalf("read should survive two lost datagrams: %v", err)
	}
	if !bytes.Equal(got, f.mem[:4]) {
		t.Errorf("got % x, want % x", got, f.mem[:4])
	}
	if stats.Retries != 2 {
		t.Errorf("retries = %d, want 2", stats.Retries)
	}
}

// The client-side allowlist check must stop a request the firmware would
// refuse, and force must send it anyway.
func TestMemReadPhysicalAllowlistGate(t *testing.T) {
	f := newFakeMemBMC(0x80000000, 64, MemOrderAscending)
	s := fakeSess(f)
	p, _ := MemProfileByID("smc-x13") // allowlisted; DRAM is refused

	_, _, stats, err := s.MemReadPhysical(context.Background(), &p, 0x80000000, 4, MemReadOptions{})
	if err == nil {
		t.Fatal("an address outside the allowlist must be refused client-side")
	}
	if stats.Requests != 0 {
		t.Errorf("a client-side refusal must not spend a request, spent %d", stats.Requests)
	}

	got, _, stats, err := s.MemReadPhysical(context.Background(), &p, 0x80000000, 4, MemReadOptions{SkipAllowlistCheck: true})
	if err != nil {
		t.Fatalf("force should send the request anyway: %v", err)
	}
	if stats.Requests != 1 || !bytes.Equal(got, f.mem[:4]) {
		t.Errorf("forced read: %d requests, data % x", stats.Requests, got)
	}
}

func TestMemWritePhysicalRoundTrip(t *testing.T) {
	f := newFakeMemBMC(0x80000000, 64, MemOrderAscending)
	s := fakeSess(f)
	p, _ := MemProfileByID("smc-x11")

	payload := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	res, err := s.MemWritePhysical(context.Background(), &p, 0x80000000, payload, MemWriteOptions{})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if res.Stats.Requests != 2 {
		t.Errorf("requests = %d, want 2", res.Stats.Requests)
	}
	if !bytes.Equal(f.mem[:8], payload) {
		t.Errorf("stored % x, want % x", f.mem[:8], payload)
	}
	if res.SubFn != "0xc1" {
		t.Errorf("subfn = %s, want 0xc1", res.SubFn)
	}
}

func TestMemWritePhysicalValidation(t *testing.T) {
	f := newFakeMemBMC(0x80000000, 64, MemOrderAscending)
	s := fakeSess(f)
	x11, _ := MemProfileByID("smc-x11")
	x13, _ := MemProfileByID("smc-x13")

	// No write primitive on an allowlisted read-only build.
	if _, err := s.MemWritePhysical(context.Background(), &x13, 0x80000000, []byte{1, 2, 3, 4}, MemWriteOptions{}); err == nil {
		t.Error("smc-x13 has no write primitive and must refuse")
	}
	// Misalignment: the handler splits the page at addr&0xfffff000 and stores
	// at addr&0xfff, so an unaligned 4-byte store is a caller error.
	if _, err := s.MemWritePhysical(context.Background(), &x11, 0x80000001, []byte{1, 2, 3, 4}, MemWriteOptions{}); err == nil {
		t.Error("an unaligned write must be refused")
	}
	// A partial unit would leave the last store undefined.
	if _, err := s.MemWritePhysical(context.Background(), &x11, 0x80000000, []byte{1, 2}, MemWriteOptions{}); err == nil {
		t.Error("a payload that is not a whole number of units must be refused")
	}
	if _, err := s.MemWritePhysical(context.Background(), &x11, 0x80000000, nil, MemWriteOptions{}); err == nil {
		t.Error("an empty write must be refused")
	}
}

// A pinned subfunction must actually reach the wire, since that is the only
// control an operator has on a generation whose numbering is unsettled.
func TestMemWritePhysicalSubFnOverride(t *testing.T) {
	f := newFakeMemBMC(0x80000000, 64, MemOrderAscending)
	s := fakeSess(f)
	p, _ := MemProfileByID("smc-x11")

	alt := byte(0xC2)
	res, err := s.MemWritePhysical(context.Background(), &p, 0x80000000, []byte{1, 2, 3, 4}, MemWriteOptions{SubFn: &alt})
	// The fake answers 0xcc for an unknown subfunction, which is what a real
	// board would do if 0xC2 is not the write - the point is that the
	// override reached the wire rather than being ignored.
	if err == nil {
		t.Fatal("the fake should refuse subfunction 0xC2")
	}
	if res.SubFn != "0xc2" {
		t.Errorf("subfn = %s, want 0xc2", res.SubFn)
	}
}

func TestMemWritePhysicalVerify(t *testing.T) {
	f := newFakeMemBMC(0x80000000, 64, MemOrderAscending)
	s := fakeSess(f)
	p, _ := MemProfileByID("smc-x11")
	p.ReplyOrder = MemOrderAscending

	res, err := s.MemWritePhysical(context.Background(), &p, 0x80000000, []byte{1, 2, 3, 4}, MemWriteOptions{Verify: true})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if !res.Verified {
		t.Error("Verified should be set")
	}
	if len(res.Mismatch) != 0 {
		t.Errorf("unexpected read-back mismatch: %v", res.Mismatch)
	}
	// One write plus one read-back.
	if res.Stats.Requests != 2 {
		t.Errorf("requests = %d, want 2", res.Stats.Requests)
	}
}

func TestMemProbePageOracle(t *testing.T) {
	f := newFakeMemBMC(0x1e780000, 0x1000, MemOrderAscending)
	f.refuse[0x1e6e2000] = 0xcc
	s := fakeSess(f)
	p, _ := MemProfileByID("smc-x14")

	ok, cc, err := s.MemProbePage(&p, 0x1e780000)
	if err != nil || !ok || cc != 0x00 {
		t.Errorf("GPIO page probe = %v cc=0x%02x err=%v, want accepted", ok, cc, err)
	}
	ok, cc, err = s.MemProbePage(&p, 0x1e6e2000)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if ok || cc != 0xcc {
		t.Errorf("SCU probe = %v cc=0x%02x, want rejected with 0xcc", ok, cc)
	}

	// A privilege failure is not an allowlist boundary and must surface as an
	// error rather than as "rejected".
	f.refuse[0x1e780000] = 0xd4
	if _, _, err := s.MemProbePage(&p, 0x1e780000); err == nil {
		t.Error("cc=0xd4 must be reported as an error, not folded into a page verdict")
	}
}

func TestMemReadPhysicalContextCancel(t *testing.T) {
	f := newFakeMemBMC(0x20000000, 4096, MemOrderAscending)
	s := fakeSess(f)
	p, _ := MemProfileByID("smc-x11")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := s.MemReadPhysical(ctx, &p, 0x20000000, 1024, MemReadOptions{}); err == nil {
		t.Error("a cancelled context must stop the read")
	}
}

func TestMemReadPhysicalProgress(t *testing.T) {
	f := newFakeMemBMC(0x20000000, 4096, MemOrderAscending)
	s := fakeSess(f)
	p, _ := MemProfileByID("smc-x11")
	var last string
	n := 0
	_, _, _, err := s.MemReadPhysical(context.Background(), &p, 0x20000000, 256, MemReadOptions{
		Progress: func(u string) { last = u; n++ },
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n == 0 {
		t.Fatal("progress was never reported")
	}
	if want := fmt.Sprintf("%d/%d units", 64, 64); !bytes.Contains([]byte(last), []byte(want)) {
		t.Errorf("final progress = %q, want it to contain %q", last, want)
	}
}

// --- bus spaces -------------------------------------------------------------

// fakeBusBMC answers App/0x52 Master Write-Read and the Storage FRU commands
// out of a byte-addressed device image, so the offset arithmetic and chunking
// of the bus spaces can be exercised without hardware.
type fakeBusBMC struct {
	dev       []byte
	fru       []byte
	maxRead   int
	lastChan  byte
	lastSlave byte
	requests  int
}

func newFakeBusBMC(size int) *fakeBusBMC {
	d := make([]byte, size)
	for i := range d {
		d[i] = byte(0xA0 + i)
	}
	f := make([]byte, size)
	for i := range f {
		f[i] = byte(i * 3)
	}
	return &fakeBusBMC{dev: d, fru: f, maxRead: 32}
}

func (f *fakeBusBMC) Close() {}

func (f *fakeBusBMC) Exec(netfn, cmd byte, data []byte) (byte, []byte, error) {
	f.requests++
	switch {
	case netfn == NetFnApp && cmd == CmdMasterWriteRead:
		if len(data) < 3 {
			return 0xc7, nil, nil
		}
		f.lastChan, f.lastSlave = data[0], data[1]
		n := int(data[2])
		if n == 0 {
			return 0x00, nil, nil // a pure write
		}
		if len(data) < 4 {
			return 0xcc, nil, nil
		}
		off := int(data[3])
		if off+n > len(f.dev) {
			n = len(f.dev) - off
		}
		if n <= 0 {
			return 0xcc, nil, nil
		}
		if n > f.maxRead {
			n = f.maxRead
		}
		return 0x00, append([]byte(nil), f.dev[off:off+n]...), nil
	case netfn == NetFnStorage && cmd == CmdReadFRUData:
		if len(data) < 4 {
			return 0xc7, nil, nil
		}
		off := int(data[1]) | int(data[2])<<8
		n := int(data[3])
		if off >= len(f.fru) {
			return 0xcc, nil, nil
		}
		if off+n > len(f.fru) {
			n = len(f.fru) - off
		}
		return 0x00, append([]byte{byte(n)}, f.fru[off:off+n]...), nil
	case netfn == NetFnStorage && cmd == CmdWriteFRUData:
		if len(data) < 4 {
			return 0xc7, nil, nil
		}
		off := int(data[1]) | int(data[2])<<8
		body := data[3:]
		if off+len(body) > len(f.fru) {
			return 0xcc, nil, nil
		}
		copy(f.fru[off:], body)
		return 0x00, []byte{byte(len(body))}, nil
	}
	return 0xc1, nil, nil
}

func TestMemReadI2CChunks(t *testing.T) {
	f := newFakeBusBMC(256)
	s := &CmdSess{runner: f, host: "192.0.2.10"}
	p, _ := MemProfileByID("generic")

	got, stats, err := s.MemReadI2C(context.Background(), &p, 0x10, 100, MemBusOptions{Bus: 3, Slave: 0x50, Chunk: 32})
	if err != nil {
		t.Fatalf("i2c read: %v", err)
	}
	if !bytes.Equal(got, f.dev[0x10:0x10+100]) {
		t.Errorf("i2c read mismatch:\n got % x\nwant % x", got[:8], f.dev[0x10:0x18])
	}
	if stats.Requests != 4 {
		t.Errorf("requests = %d, want 4 (100 bytes in 32-byte chunks)", stats.Requests)
	}
	// The spec channel byte carries the bus in bits 5:1 with the private-bus
	// flag in bit 0; the slave goes on the wire in its 8-bit form.
	if f.lastChan != (3<<1)|1 {
		t.Errorf("channel byte = 0x%02x, want 0x%02x", f.lastChan, (3<<1)|1)
	}
	if f.lastSlave != 0xa0 {
		t.Errorf("slave byte = 0x%02x, want 0xa0 (0x50 shifted left)", f.lastSlave)
	}
}

// Bus 0 is refused over LAN on the generations that gate it, and the error has
// to name the OEM escape hatch rather than just reporting a completion code.
func TestMemReadI2CBusZeroGate(t *testing.T) {
	f := newFakeBusBMC(64)
	s := &CmdSess{runner: f, host: "192.0.2.10"}
	p, _ := MemProfileByID("smc-x11")

	_, _, err := s.MemReadI2C(context.Background(), &p, 0, 8, MemBusOptions{Bus: 0, Slave: 0x50})
	if err == nil {
		t.Fatal("bus 0 must be refused on a gated generation")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("0x7e")) {
		t.Errorf("the error should point at the ungated OEM subfunction, got %q", err)
	}
	if f.requests != 0 {
		t.Errorf("a client-side refusal must not spend a request, spent %d", f.requests)
	}
	// X10 does not gate bus 0, so the same call goes through.
	x10, _ := MemProfileByID("smc-x10")
	if _, _, err := s.MemReadI2C(context.Background(), &x10, 0, 8, MemBusOptions{Bus: 0, Slave: 0x50}); err != nil {
		t.Errorf("X10 does not gate bus 0: %v", err)
	}
}

func TestMemReadWriteFRU(t *testing.T) {
	f := newFakeBusBMC(256)
	s := &CmdSess{runner: f, host: "192.0.2.10"}

	got, stats, err := s.MemReadFRU(context.Background(), 0, 64, MemBusOptions{Chunk: 16})
	if err != nil {
		t.Fatalf("fru read: %v", err)
	}
	if !bytes.Equal(got, f.fru[:64]) {
		t.Errorf("fru read mismatch: % x", got[:8])
	}
	if stats.Requests != 4 {
		t.Errorf("requests = %d, want 4", stats.Requests)
	}

	patch := []byte{0xde, 0xad, 0xbe, 0xef}
	if _, err := s.MemWriteFRU(context.Background(), 0x20, patch, MemBusOptions{}); err != nil {
		t.Fatalf("fru write: %v", err)
	}
	if !bytes.Equal(f.fru[0x20:0x24], patch) {
		t.Errorf("fru write stored % x, want % x", f.fru[0x20:0x24], patch)
	}
}

func TestMemReadFRUOffsetIsLittleEndian(t *testing.T) {
	// The FRU offset is 16-bit little-endian on the wire (LSB then MSB); a
	// swapped pair reads a completely different part of the EEPROM.
	f := newFakeBusBMC(0x400)
	s := &CmdSess{runner: f, host: "192.0.2.10"}
	got, _, err := s.MemReadFRU(context.Background(), 0x0102, 4, MemBusOptions{Chunk: 4})
	if err != nil {
		t.Fatalf("fru read: %v", err)
	}
	if !bytes.Equal(got, f.fru[0x102:0x106]) {
		t.Errorf("offset encoding wrong: got % x, want % x", got, f.fru[0x102:0x106])
	}
}

// TestMemReadKnownAnswerFromCapture replays request/response pairs taken off a
// real X11 (FW 01.74) capture of the 0x30/0x70 subfn 0xC0 read against the
// memory-mapped SPI window at 0x20000000. It pins three things at once: the
// request encoding, the MSB-first reply order on this generation, and the
// reassembly, because the recovered image has to be recognisable ARM.
//
// The wire bytes below are transcribed from the capture, not synthesised.
func TestMemReadKnownAnswerFromCapture(t *testing.T) {
	// addr -> the four data bytes the BMC actually put on the wire.
	capture := map[uint64][4]byte{
		0x20000000: {0xea, 0x00, 0x00, 0x13},
		0x20000004: {0xe5, 0x9f, 0xf0, 0x14},
		0x20000008: {0xe5, 0x9f, 0xf0, 0x14},
		0x2000000c: {0xe5, 0x9f, 0xf0, 0x14},
		0x20000010: {0xe5, 0x9f, 0xf0, 0x14},
		0x20000014: {0xe5, 0x9f, 0xf0, 0x14},
		0x20000018: {0xe5, 0x9f, 0xf0, 0x14},
		0x2000001c: {0xe5, 0x9f, 0xf0, 0x14},
		0x20000020: {0x00, 0x00, 0x01, 0x80},
		0x2000003c: {0x12, 0x34, 0x56, 0x78},
	}
	var sawRequest []byte
	s := &CmdSess{runner: runnerFunc(func(netfn, cmd byte, data []byte) (byte, []byte, error) {
		if netfn != 0x30 || cmd != 0x70 {
			return 0xc1, nil, nil
		}
		sawRequest = append([]byte(nil), data...)
		addr := uint64(data[2])<<24 | uint64(data[3])<<16 | uint64(data[4])<<8 | uint64(data[5])
		w, ok := capture[addr]
		if !ok {
			return 0xcc, nil, nil
		}
		return 0x00, w[:], nil
	})}
	p, _ := MemProfileByID("smc-x11")

	got, _, _, err := s.MemReadPhysical(context.Background(), &p, 0x20000000, 8, MemReadOptions{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// The reset vector is ARM `b +0x54` = 0xea000013, stored little-endian.
	want := []byte{0x13, 0x00, 0x00, 0xea, 0x14, 0xf0, 0x9f, 0xe5}
	if !bytes.Equal(got, want) {
		t.Errorf("reassembled image = % x, want % x (an ARM vector table)", got, want)
	}
	// The last request the loop sent must match the capture byte for byte.
	if !bytes.Equal(sawRequest, []byte{0xC0, 0x04, 0x20, 0x00, 0x00, 0x04}) {
		t.Errorf("request = % x, want c0 04 20 00 00 04", sawRequest)
	}

	// 0x2000003c holds the U-Boot magic 0x12345678, which is only recognisable
	// after the reversal - the strongest single check that the order is right.
	got, _, _, err = s.MemReadPhysical(context.Background(), &p, 0x2000003c, 4, MemReadOptions{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, []byte{0x78, 0x56, 0x34, 0x12}) {
		t.Errorf("magic word = % x, want 78 56 34 12", got)
	}
}

// runnerFunc adapts a function to the cmdRunner interface.
type runnerFunc func(netfn, cmd byte, data []byte) (byte, []byte, error)

func (f runnerFunc) Exec(netfn, cmd byte, data []byte) (byte, []byte, error) {
	return f(netfn, cmd, data)
}
func (f runnerFunc) Close() {}

// A device that refuses the default 16-byte FRU count must be negotiated down
// rather than exhausting the transport retry budget at the wrong size.
func TestMemReadFRUNegotiatesChunkSize(t *testing.T) {
	f := newFakeBusBMC(256)
	maxFRU := 4
	s := &CmdSess{runner: runnerFunc(func(netfn, cmd byte, data []byte) (byte, []byte, error) {
		if netfn != NetFnStorage || cmd != CmdReadFRUData {
			return 0xc1, nil, nil
		}
		if int(data[3]) > maxFRU {
			return 0xca, nil, nil // "cannot return number of requested bytes"
		}
		return f.Exec(netfn, cmd, data)
	})}

	got, _, err := s.MemReadFRU(context.Background(), 0, 32, MemBusOptions{})
	if err != nil {
		t.Fatalf("fru read should negotiate down to a workable count: %v", err)
	}
	if !bytes.Equal(got, f.fru[:32]) {
		t.Errorf("negotiated read mismatch: % x", got[:8])
	}
}

// A 33-bit address does not fit the wire field. Truncating it silently would
// read or write a completely different page and hand back plausible bytes.
func TestMemPhysicalAddressRangeIsChecked(t *testing.T) {
	f := newFakeMemBMC(0x80000000, 64, MemOrderAscending)
	s := fakeSess(f)
	p, _ := MemProfileByID("smc-x11")

	if _, _, _, err := s.MemReadPhysical(context.Background(), &p, 0x180000000, 4, MemReadOptions{}); err == nil {
		t.Error("a read above 4 GiB must be refused, not truncated")
	}
	if _, err := s.MemWritePhysical(context.Background(), &p, 0x180000000, []byte{1, 2, 3, 4}, MemWriteOptions{}); err == nil {
		t.Error("a write above 4 GiB must be refused, not truncated")
	}
	if _, _, err := s.MemProbePage(&p, 0x180000000); err == nil {
		t.Error("a probe above 4 GiB must be refused")
	}
	// A range that starts in bounds but runs off the end is the same defect.
	if _, _, _, err := s.MemReadPhysical(context.Background(), &p, 0xfffffff0, 64, MemReadOptions{}); err == nil {
		t.Error("a range that wraps past the 32-bit ceiling must be refused")
	}
	if f.requests != 0 {
		t.Errorf("a range check must not spend requests, spent %d", f.requests)
	}
}

// A handler that answers success with an empty payload must not spin the
// cursor-driven loops forever.
func TestMemLoopsRejectEmptyPayload(t *testing.T) {
	empty := runnerFunc(func(netfn, cmd byte, data []byte) (byte, []byte, error) {
		return 0x00, nil, nil
	})
	s := &CmdSess{runner: empty, host: "192.0.2.10"}

	done := make(chan error, 1)
	go func() {
		_, _, err := s.MemReadYAFU(context.Background(), 0x1000, 64, YAFUSum32, MemReadOptions{})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("an empty payload must be an error, not silent progress")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("MemReadYAFU spun on an empty payload")
	}

	if _, _, err := s.MemReadI2C(context.Background(), nil, 0, 64, MemBusOptions{Slave: 0x50}); err == nil {
		t.Error("MemReadI2C must reject an empty payload")
	}
}

// The Get SDR record offset is a single byte, so a window past 255 is not
// addressable and must not read as an empty success.
func TestMemReadSDROffsetRange(t *testing.T) {
	s := &CmdSess{runner: runnerFunc(func(netfn, cmd byte, data []byte) (byte, []byte, error) {
		return 0x00, []byte{0, 0}, nil
	})}
	if _, _, _, err := s.MemReadSDR(context.Background(), 0, 0x100, 16, MemBusOptions{}); err == nil {
		t.Error("an SDR offset above 0xff must be refused")
	}
}

// An EEPROM page write wraps inside its page, so a chunk that straddles a page
// boundary silently overwrites the bottom of the same page. Each request must
// therefore be clipped to the page it starts in.
func TestMemWriteI2CClipsToPageBoundary(t *testing.T) {
	var offsets []byte
	var lens []int
	s := &CmdSess{runner: runnerFunc(func(netfn, cmd byte, data []byte) (byte, []byte, error) {
		if netfn != NetFnApp || cmd != CmdMasterWriteRead {
			return 0xc1, nil, nil
		}
		offsets = append(offsets, data[3])
		lens = append(lens, len(data)-4)
		return 0x00, nil, nil
	})}
	p, _ := MemProfileByID("generic")

	// Start at offset 6 with an 8-byte page: the first request may carry only
	// the 2 bytes up to the page boundary at 8.
	if _, err := s.MemWriteI2C(context.Background(), &p, 6, make([]byte, 20), MemBusOptions{Slave: 0x50, PageSize: 8}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(offsets) == 0 {
		t.Fatal("no requests were sent")
	}
	if offsets[0] != 6 || lens[0] != 2 {
		t.Errorf("first chunk = offset %d len %d, want offset 6 len 2 (clipped to the page boundary)", offsets[0], lens[0])
	}
	for i, off := range offsets {
		if int(off)%8+lens[i] > 8 {
			t.Errorf("chunk %d at offset %d carries %d bytes and crosses a page boundary", i, off, lens[i])
		}
	}
}

// A definitive completion code must not be re-sent as if the datagram were
// lost: it triples bus traffic to learn the same answer.
func TestMemReadI2CDoesNotRetryCompletionCodes(t *testing.T) {
	n := 0
	s := &CmdSess{runner: runnerFunc(func(netfn, cmd byte, data []byte) (byte, []byte, error) {
		n++
		return 0x83, nil, nil // no device ACK
	})}
	p, _ := MemProfileByID("generic")
	if _, stats, err := s.MemReadI2C(context.Background(), &p, 0, 8, MemBusOptions{Slave: 0x50, Retries: 4}); err == nil {
		t.Error("a refusal must surface as an error")
	} else if stats.Requests != 1 {
		t.Errorf("spent %d requests on a definitive completion code, want 1", stats.Requests)
	}
}

// The bus field is narrow: an out-of-range bus aliases into a different bus
// rather than failing, so it has to be rejected before anything is sent.
func TestMemI2CBusRangeIsChecked(t *testing.T) {
	sent := 0
	s := &CmdSess{runner: runnerFunc(func(netfn, cmd byte, data []byte) (byte, []byte, error) {
		sent++
		return 0x00, make([]byte, 8), nil
	})}
	ami, _ := MemProfileByID("ami-megarac") // three-bit bus field, max 7
	if _, _, err := s.MemReadI2C(context.Background(), &ami, 0, 8, MemBusOptions{Bus: 9, Slave: 0x50}); err == nil {
		t.Error("bus 9 must be refused on a profile whose bus field is three bits")
	}
	if sent != 0 {
		t.Errorf("a range check must not spend a request, spent %d", sent)
	}
	if _, _, err := s.MemReadI2C(context.Background(), &ami, 0, 8, MemBusOptions{Bus: 7, Slave: 0x50}); err != nil {
		t.Errorf("bus 7 is in range: %v", err)
	}
}

// A mid-record completion code that does not mean end-of-data must surface as
// an error, not as a short record with a nil error.
func TestMemReadSDRPartialIsAnError(t *testing.T) {
	n := 0
	s := &CmdSess{runner: runnerFunc(func(netfn, cmd byte, data []byte) (byte, []byte, error) {
		if cmd == CmdReserveSDRRepo {
			return 0x00, []byte{1, 0}, nil
		}
		n++
		if n == 1 {
			return 0x00, append([]byte{0x02, 0x00}, make([]byte, 16)...), nil
		}
		return 0xc5, nil, nil // reservation cancelled - not end of record
	})}
	out, _, _, err := s.MemReadSDR(context.Background(), 1, 0, 64, MemBusOptions{Chunk: 16})
	if err == nil {
		t.Error("a cancelled reservation mid-record must be an error, not a clean truncation")
	}
	if len(out) != 16 {
		t.Errorf("the bytes already read should still come back, got %d", len(out))
	}
}

// A zero-length YAFU read replies with the bare header. Treating that as a
// short reply makes the checksum probe unable to ever resolve an algorithm.
func TestYAFUZeroLengthReplyIsValid(t *testing.T) {
	s := &CmdSess{runner: runnerFunc(func(netfn, cmd byte, data []byte) (byte, []byte, error) {
		return 0x00, make([]byte, 12), nil
	})}
	got, err := s.YAFUResolveChecksum(context.Background())
	if err != nil {
		t.Fatalf("a header-only reply is a success: %v", err)
	}
	if got != YAFUCRC32 {
		t.Errorf("resolved %q, want the first candidate", got)
	}
}

// The handler tests flash mode before the checksum, so probing while disarmed
// tells you nothing and must say so rather than picking a candidate.
func TestYAFUProbeRefusesWhenDisarmed(t *testing.T) {
	s := &CmdSess{runner: runnerFunc(func(netfn, cmd byte, data []byte) (byte, []byte, error) {
		resp := make([]byte, 14)
		resp[12] = 0x08 // not in flash mode
		return 0x13, resp, nil
	})}
	if _, err := s.YAFUResolveChecksum(context.Background()); err == nil {
		t.Error("probing while disarmed must be reported as inconclusive")
	} else if !bytes.Contains([]byte(err.Error()), []byte("flash mode")) {
		t.Errorf("the error should explain why, got %q", err)
	}
}

// The WST stream's offset is a BMC-side counter that advances a whole chunk
// however much the BMC actually sent, so a short chunk anywhere but the end
// means the rest of the image would be misaligned.
func TestFlashDumpRejectsShortChunk(t *testing.T) {
	n := 0
	s := &CmdSess{runner: runnerFunc(func(netfn, cmd byte, data []byte) (byte, []byte, error) {
		if netfn != 0x3E || cmd != 0x1F {
			return 0xc1, nil, nil
		}
		n++
		if n == 2 {
			return 0x00, append([]byte{0x00}, make([]byte, 10)...), nil // short
		}
		return 0x00, append([]byte{0x00}, make([]byte, 56)...), nil
	})}
	out, res, err := s.FlashDumpRead(context.Background(), 4096, 4096, MemReadOptions{})
	if err == nil {
		t.Fatal("a short chunk mid-stream must be an error, not a silent misalignment")
	}
	if len(out) != 56 {
		t.Errorf("the contiguous prefix should still come back, got %d bytes", len(out))
	}
	if res.Read != 56 {
		t.Errorf("res.Read = %d, want 56", res.Read)
	}
}

// FlashDumpStatus clears the completion flag as it reports it, so the read
// must take the size from the caller's own poll rather than asking again.
func TestFlashDumpReadDoesNotRepoll(t *testing.T) {
	polls := 0
	s := &CmdSess{runner: runnerFunc(func(netfn, cmd byte, data []byte) (byte, []byte, error) {
		switch cmd {
		case 0x1E:
			polls++
			return 0x00, []byte{0x00, 0, 0, 0, 0}, nil // flag already consumed
		case 0x1F:
			return 0x00, append([]byte{0x00}, make([]byte, 56)...), nil
		}
		return 0xc1, nil, nil
	})}
	out, _, err := s.FlashDumpRead(context.Background(), 56, 56, MemReadOptions{})
	if err != nil {
		t.Fatalf("read should not depend on a second status poll: %v", err)
	}
	if polls != 0 {
		t.Errorf("FlashDumpRead polled the destructive status command %d times", polls)
	}
	if len(out) != 56 {
		t.Errorf("got %d bytes, want 56", len(out))
	}
}

// verify reads each unit back. If the operator had to override the reply order
// for the read, the same override has to apply to the read-back or every unit
// is reported as a spurious mismatch.
func TestMemWriteVerifyHonoursOrderOverride(t *testing.T) {
	// A board whose reply is MSB-first while the profile says ascending.
	f := newFakeMemBMC(0x80000000, 64, MemOrderMSBFirst)
	s := fakeSess(f)
	p, _ := MemProfileByID("smc-x11")
	p.ReplyOrder = MemOrderAscending // deliberately wrong for this board

	res, err := s.MemWritePhysical(context.Background(), &p, 0x80000000, []byte{1, 2, 3, 4},
		MemWriteOptions{Verify: true, ReplyOrder: MemOrderMSBFirst})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(res.Mismatch) != 0 {
		t.Errorf("the override should make the read-back match, got mismatches at %v", res.Mismatch)
	}

	// Without the override the same write reports a spurious mismatch, which
	// is exactly the failure the field exists to prevent.
	f2 := newFakeMemBMC(0x80000000, 64, MemOrderMSBFirst)
	s2 := fakeSess(f2)
	res2, err := s2.MemWritePhysical(context.Background(), &p, 0x80000000, []byte{1, 2, 3, 4},
		MemWriteOptions{Verify: true})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(res2.Mismatch) == 0 {
		t.Error("without the override the read-back should disagree, proving the field affects the result")
	}
}

// The OEM 0x7E transport caps both directions at 124 bytes, which is a
// different bound from the App/0x52 limit the profile records. Chunking to the
// wrong one makes every OEM read fail on its first request.
func TestMemReadI2COEMChunkCap(t *testing.T) {
	var maxSeen int
	s := &CmdSess{runner: runnerFunc(func(netfn, cmd byte, data []byte) (byte, []byte, error) {
		if netfn != 0x30 || cmd != 0x70 || data[0] != 0x7E {
			return 0xc1, nil, nil
		}
		n := int(data[3])
		if n >= 0x7d {
			return 0xc9, nil, nil // the handler's own bound
		}
		maxSeen = max(maxSeen, n)
		return 0x00, make([]byte, n), nil
	})}
	p, _ := MemProfileByID("smc-x11") // I2CMaxRead 255, I2CUngatedSubFn 0x7E

	got, _, err := s.MemReadI2C(context.Background(), &p, 0, 256, MemBusOptions{Bus: 1, Slave: 0x50, UseOEM: true})
	if err != nil {
		t.Fatalf("an OEM read must chunk to the OEM bound, not the App/0x52 one: %v", err)
	}
	if len(got) != 256 {
		t.Errorf("got %d bytes, want 256", len(got))
	}
	if maxSeen > 124 {
		t.Errorf("largest chunk was %d, want at most 124", maxSeen)
	}
}
