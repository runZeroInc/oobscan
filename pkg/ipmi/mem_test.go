package ipmi

import (
	"encoding/binary"
	"strings"
	"testing"
)

// These tests pin recovered wire layouts rather than deriving them: a typo in a
// subfunction, in the address endianness or in the reply order silently reads or
// writes the wrong address.

func TestParseMemSpaceAliases(t *testing.T) {
	cases := map[string]MemSpace{
		"":         MemSpacePhysical,
		"physical": MemSpacePhysical,
		"PHYS":     MemSpacePhysical,
		"memory":   MemSpacePhysical,
		"virt":     MemSpaceVirtual,
		"spi":      MemSpaceFlash,
		"register": MemSpaceSCU,
		"smbus":    MemSpaceI2C,
		"dimm":     MemSpaceSPD,
		"mdio":     MemSpaceMII,
		"apml":     MemSpaceCPU,
		"manuf":    MemSpaceNVRAM,
	}
	for in, want := range cases {
		got, err := ParseMemSpace(in)
		if err != nil {
			t.Errorf("ParseMemSpace(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseMemSpace(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := ParseMemSpace("nonsense"); err == nil {
		t.Error("ParseMemSpace(nonsense) should fail")
	}
}

func TestParseMemByteOrder(t *testing.T) {
	cases := map[string]MemByteOrder{
		"":          "",
		"auto":      "",
		"ascending": MemOrderAscending,
		"native":    MemOrderAscending,
		"msb-first": MemOrderMSBFirst,
		"swapped":   MemOrderMSBFirst,
	}
	for in, want := range cases {
		got, err := ParseMemByteOrder(in)
		if err != nil {
			t.Errorf("ParseMemByteOrder(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseMemByteOrder(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := ParseMemByteOrder("middle-endian"); err == nil {
		t.Error("ParseMemByteOrder should reject an unknown order")
	}
}

// TestMemProfileTablePinned locks the per-generation values that decide which
// bytes go on the wire. These are recovered constants, not conventions.
func TestMemProfileTablePinned(t *testing.T) {
	tests := []struct {
		id         string
		read       bool
		readSub    byte
		write      bool
		writeSub   byte
		order      MemByteOrder
		allowlist  bool
		lockdown   bool
		flashBase  uint64
		dramBase   uint64
		maxUnit    int
		bigEndian  bool
		apml       bool
		wstDump    bool
		yafuMemory bool
	}{
		{id: "smc-x10", read: true, readSub: 0xC0, write: true, writeSub: 0xC1,
			order: MemOrderMSBFirst, flashBase: 0x20000000, dramBase: 0x40000000,
			maxUnit: 4, bigEndian: true, wstDump: true},
		{id: "smc-x11", read: true, readSub: 0xC0, write: true, writeSub: 0xC1,
			order: MemOrderMSBFirst, flashBase: 0x20000000, dramBase: 0x80000000,
			maxUnit: 4, bigEndian: true, wstDump: true},
		{id: "smc-x12", read: true, readSub: 0xC0, write: false,
			order: MemOrderAscending, allowlist: true, flashBase: 0x20000000,
			dramBase: 0x80000000, maxUnit: 4, bigEndian: true, wstDump: true},
		{id: "smc-x13-0107", read: true, readSub: 0xC0, write: true, writeSub: 0xC1,
			order: MemOrderAscending, lockdown: true, flashBase: 0x20000000,
			dramBase: 0x80000000, maxUnit: 4, bigEndian: true, wstDump: true},
		{id: "smc-x13", read: true, readSub: 0xC0, write: false,
			order: MemOrderAscending, allowlist: true, flashBase: 0x20000000,
			dramBase: 0x80000000, maxUnit: 4, bigEndian: true, wstDump: true},
		{id: "smc-h13", read: true, readSub: 0xC0, write: false,
			order: MemOrderAscending, allowlist: true, dramBase: 0x80000000,
			maxUnit: 4, bigEndian: true, apml: true, wstDump: true},
		{id: "smc-x14", read: true, readSub: 0xC0, write: false,
			order: MemOrderAscending, allowlist: true, maxUnit: 4, bigEndian: true},
		{id: "ami-megarac", read: false, write: false, maxUnit: 4, yafuMemory: true},
		{id: "generic", read: false, write: false, maxUnit: 4},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			p, ok := MemProfileByID(tt.id)
			if !ok {
				t.Fatalf("profile %q missing from the table", tt.id)
			}
			if p.ReadSupported != tt.read {
				t.Errorf("ReadSupported = %v, want %v", p.ReadSupported, tt.read)
			}
			if tt.read && p.ReadSubFn != tt.readSub {
				t.Errorf("ReadSubFn = 0x%02x, want 0x%02x", p.ReadSubFn, tt.readSub)
			}
			if p.WriteSupported != tt.write {
				t.Errorf("WriteSupported = %v, want %v", p.WriteSupported, tt.write)
			}
			if tt.write && p.WriteSubFn != tt.writeSub {
				t.Errorf("WriteSubFn = 0x%02x, want 0x%02x", p.WriteSubFn, tt.writeSub)
			}
			if tt.read && p.ReplyOrder != tt.order {
				t.Errorf("ReplyOrder = %q, want %q", p.ReplyOrder, tt.order)
			}
			if got := len(p.AllowedPages) > 0; got != tt.allowlist {
				t.Errorf("allowlist present = %v, want %v", got, tt.allowlist)
			}
			if p.LockdownGated != tt.lockdown {
				t.Errorf("LockdownGated = %v, want %v", p.LockdownGated, tt.lockdown)
			}
			if p.FlashBase != tt.flashBase {
				t.Errorf("FlashBase = 0x%x, want 0x%x", p.FlashBase, tt.flashBase)
			}
			if p.DRAMBase != tt.dramBase {
				t.Errorf("DRAMBase = 0x%x, want 0x%x", p.DRAMBase, tt.dramBase)
			}
			if p.MaxUnit != tt.maxUnit {
				t.Errorf("MaxUnit = %d, want %d", p.MaxUnit, tt.maxUnit)
			}
			if tt.read && p.AddrBigEndian != tt.bigEndian {
				t.Errorf("AddrBigEndian = %v, want %v", p.AddrBigEndian, tt.bigEndian)
			}
			if p.APMLPlanes != tt.apml {
				t.Errorf("APMLPlanes = %v, want %v", p.APMLPlanes, tt.apml)
			}
			if p.WSTFlashDump != tt.wstDump {
				t.Errorf("WSTFlashDump = %v, want %v", p.WSTFlashDump, tt.wstDump)
			}
			if p.YAFUMemory != tt.yafuMemory {
				t.Errorf("YAFUMemory = %v, want %v", p.YAFUMemory, tt.yafuMemory)
			}
		})
	}
}

// TestMemProfileByIDReturnsCopy: mutating a returned profile must not poison
// the shared table for the next caller.
func TestMemProfileByIDReturnsCopy(t *testing.T) {
	p, ok := MemProfileByID("smc-x11")
	if !ok {
		t.Fatal("smc-x11 missing")
	}
	p.ReadSubFn = 0xEE
	p.Regions = nil
	again, _ := MemProfileByID("smc-x11")
	if again.ReadSubFn != 0xC0 {
		t.Errorf("table poisoned: ReadSubFn = 0x%02x", again.ReadSubFn)
	}
	if len(again.Regions) == 0 {
		t.Error("table poisoned: regions cleared")
	}
}

// TestSMCGenerationMapping pins the GUID-generation to profile mapping,
// including the X13 firmware-revision split. 01.07.01 is the one X13 build
// that still carries the unrestricted read/write pair.
func TestSMCGenerationMapping(t *testing.T) {
	tests := []struct {
		gen, fw, want string
	}{
		{"X10", "", "smc-x10"},
		{"X9", "", "smc-x10"},
		{"X11", "1.74", "smc-x11"},
		{"X12", "1.07", "smc-x12"},
		{"X13", "1.07", "smc-x13-0107"},
		{"X13", "01.07.01", "smc-x13-0107"},
		{"X13", "1.08", "smc-x13"},
		{"X13", "", "smc-x13"},
		{"H13", "1.06", "smc-h13"},
		{"X14", "1.06", "smc-x14"},
	}
	for _, tt := range tests {
		p, ok := memProfileForSMCGeneration(tt.gen, tt.fw)
		if !ok {
			t.Errorf("generation %q fw %q: no profile", tt.gen, tt.fw)
			continue
		}
		if p.ID != tt.want {
			t.Errorf("generation %q fw %q = %q, want %q", tt.gen, tt.fw, p.ID, tt.want)
		}
	}
	if _, ok := memProfileForSMCGeneration("Z99", ""); ok {
		t.Error("an uncatalogued generation must not resolve to a profile")
	}
}

// TestAllowlist pins the page filter, including the one difference that makes
// X12 a distinct profile: it refuses the AST2600 GPIO page.
func TestAllowlist(t *testing.T) {
	x12, _ := MemProfileByID("smc-x12")
	x13, _ := MemProfileByID("smc-x13")
	x11, _ := MemProfileByID("smc-x11")

	if x12.AllowsPhysical(0x1e780000) {
		t.Error("X12 must refuse the GPIO page 0x1e780000")
	}
	if !x13.AllowsPhysical(0x1e780000) {
		t.Error("X13 01.08.08 accepts the GPIO page at any offset")
	}
	if !x13.AllowsPhysical(0x1e780fff) {
		t.Error("the GPIO page is accepted at any in-page offset")
	}
	// MAC pages are offset-restricted to 0xa0 / 0xb0 / 0xb1.
	if !x13.AllowsPhysical(0x1e6600a0) {
		t.Error("MAC1+0xa0 must be accepted")
	}
	if x13.AllowsPhysical(0x1e660000) {
		t.Error("MAC1+0x00 must be refused")
	}
	// SCU and DRAM are refused by every allowlisted build.
	for _, a := range []uint64{0x1e6e2000, 0x80000000} {
		if x13.AllowsPhysical(a) {
			t.Errorf("0x%08x must be refused by the allowlist", a)
		}
	}
	// The unrestricted profile accepts everything.
	for _, a := range []uint64{0x1e6e2000, 0x80000000, 0x21FC0000, 0} {
		if !x11.AllowsPhysical(a) {
			t.Errorf("X11 has no allowlist; 0x%08x must be accepted", a)
		}
	}
}

func TestTranslateSpace(t *testing.T) {
	x11, _ := MemProfileByID("smc-x11")
	x10, _ := MemProfileByID("smc-x10")

	// The U-Boot environment: flash offset 0x1FC0000 through the FMC CS0
	// window at 0x20000000 is physical 0x21FC0000.
	got, _, err := x11.TranslateSpace(MemSpaceFlash, 0x1FC0000)
	if err != nil {
		t.Fatalf("flash translate: %v", err)
	}
	if got != 0x21FC0000 {
		t.Errorf("flash 0x1FC0000 = 0x%08x, want 0x21FC0000", got)
	}
	// An address already inside the window passes through unchanged.
	got, _, err = x11.TranslateSpace(MemSpaceFlash, 0x21FC0000)
	if err != nil || got != 0x21FC0000 {
		t.Errorf("in-window flash address = 0x%08x (err %v), want 0x21FC0000", got, err)
	}
	// Kernel virtual maps through PAGE_OFFSET to the SoC's DRAM base, which
	// differs between the AST2400 and AST2500 boards.
	got, _, err = x11.TranslateSpace(MemSpaceVirtual, 0xC0100000)
	if err != nil || got != 0x80100000 {
		t.Errorf("X11 virtual 0xC0100000 = 0x%08x (err %v), want 0x80100000", got, err)
	}
	got, _, err = x10.TranslateSpace(MemSpaceVirtual, 0xC0100000)
	if err != nil || got != 0x40100000 {
		t.Errorf("X10 virtual 0xC0100000 = 0x%08x (err %v), want 0x40100000", got, err)
	}
	if _, _, err := x11.TranslateSpace(MemSpaceVirtual, 0x1000); err == nil {
		t.Error("a virtual address below PAGE_OFFSET must be rejected")
	}
	// A small value in a window space is an offset; a large one is absolute.
	got, _, _ = x11.TranslateSpace(MemSpaceSCU, 0x78)
	if got != 0x1e6e2078 {
		t.Errorf("scu offset 0x78 = 0x%08x, want 0x1e6e2078", got)
	}
	got, _, _ = x11.TranslateSpace(MemSpaceSCU, 0x1e6e2078)
	if got != 0x1e6e2078 {
		t.Errorf("absolute scu address = 0x%08x, want 0x1e6e2078", got)
	}
}

func TestRegionLookup(t *testing.T) {
	x11, _ := MemProfileByID("smc-x11")
	r, ok := x11.Region("uboot-env")
	if !ok {
		t.Fatal("uboot-env region missing")
	}
	if r.Addr != 0x21FC0000 || r.Size != 0x10000 {
		t.Errorf("uboot-env = 0x%08x+0x%x, want 0x21FC0000+0x10000", r.Addr, r.Size)
	}
	if _, ok := x11.Region("UBOOT-ENV"); !ok {
		t.Error("region lookup must be case-insensitive")
	}
	if _, ok := x11.Region("no-such-region"); ok {
		t.Error("unknown region must not resolve")
	}
	nv, ok := x11.Region("nv")
	if !ok || nv.Addr != 0x20100000 {
		t.Errorf("nv region = 0x%08x, want 0x20100000", nv.Addr)
	}
}

// TestMemReadRequestBytes pins the exact request the physical read puts on the
// wire, against a recorded example:
//
//	0x30 0x70 C0 04 1e 6e 20 0c   ->  cc=0x00  data = f1 c4 7e 80
func TestMemReadRequestBytes(t *testing.T) {
	p, _ := MemProfileByID("smc-x11")
	req := make([]byte, 0, 6)
	if p.HasReadSubFn {
		req = append(req, p.ReadSubFn)
	}
	req = append(req, 4)
	a := make([]byte, 4)
	binary.BigEndian.PutUint32(a, 0x1e6e200c)
	req = append(req, a...)

	want := []byte{0xC0, 0x04, 0x1e, 0x6e, 0x20, 0x0c}
	if len(req) != len(want) {
		t.Fatalf("request is %d bytes, want %d", len(req), len(want))
	}
	for i := range want {
		if req[i] != want[i] {
			t.Fatalf("request = % x, want % x", req, want)
		}
	}
}

// TestReplyReversal: on X10/X11 the reply is MSB-first, so a 4-byte group has to
// be reversed to reconstruct memory order. A flash read at 0x20000000 returns
// ea 00 00 13 for an image whose first bytes are 13 00 00 ea.
func TestReplyReversal(t *testing.T) {
	wire := []byte{0xea, 0x00, 0x00, 0x13}
	got := reverseBytes(wire)
	want := []byte{0x13, 0x00, 0x00, 0xea}
	if !bytesEqual(got, want) {
		t.Errorf("reverseBytes(% x) = % x, want % x", wire, got, want)
	}
	// Reversing is an involution, so an ascending-order profile that skips
	// it keeps the wire bytes untouched.
	if !bytesEqual(reverseBytes(got), wire) {
		t.Error("reverseBytes must be its own inverse")
	}
}

func TestNormalizeSlave(t *testing.T) {
	// A 7-bit address is shifted left; an 8-bit write address keeps its
	// value with bit 0 cleared.
	cases := map[byte]byte{0x50: 0xa0, 0x37: 0x6e, 0xa0: 0xa0, 0xa1: 0xa0}
	for in, want := range cases {
		if got := NormalizeSlave(in); got != want {
			t.Errorf("NormalizeSlave(0x%02x) = 0x%02x, want 0x%02x", in, got, want)
		}
	}
}

func TestOffsetBytes(t *testing.T) {
	if got := offsetBytes(0x12, 1); len(got) != 1 || got[0] != 0x12 {
		t.Errorf("offsetBytes(0x12,1) = % x", got)
	}
	if got := offsetBytes(0x1234, 2); len(got) != 2 || got[0] != 0x12 || got[1] != 0x34 {
		t.Errorf("offsetBytes(0x1234,2) = % x, want 12 34 (MSB first)", got)
	}
}

func TestSupportsSpace(t *testing.T) {
	generic, _ := MemProfileByID("generic")
	if ok, _ := generic.SupportsSpace(MemSpacePhysical); ok {
		t.Error("the generic profile has no physical primitive")
	}
	if ok, _ := generic.SupportsSpace(MemSpaceI2C); !ok {
		t.Error("i2c is spec-standard and must work on the generic profile")
	}
	h13, _ := MemProfileByID("smc-h13")
	if ok, _ := h13.SupportsSpace(MemSpaceCPU); !ok {
		t.Error("H13 carries the APML host-CPU planes")
	}
	if ok, _ := h13.SupportsSpace(MemSpaceFlash); ok {
		t.Error("H13 has no memory-mapped flash window in the profile")
	}
	x14, _ := MemProfileByID("smc-x14")
	if ok, _ := x14.SupportsSpace(MemSpaceCPU); ok {
		t.Error("X14 is an Intel-socket profile with no APML planes")
	}
	ami, _ := MemProfileByID("ami-megarac")
	if ok, _ := ami.SupportsSpace(MemSpaceVirtual); !ok {
		t.Error("the AMI YAFU pair serves the virtual space")
	}
}

func TestParseAPMLPlane(t *testing.T) {
	cases := map[string]APMLPlane{
		"": APMLMailbox, "mailbox": APMLMailbox, "smu": APMLMailbox,
		"sbtsi": APMLSBTSI, "tsi": APMLSBTSI,
		"sbrmi": APMLSBRMI, "rmi": APMLSBRMI,
	}
	for in, want := range cases {
		got, err := ParseAPMLPlane(in)
		if err != nil || got != want {
			t.Errorf("ParseAPMLPlane(%q) = %q (err %v), want %q", in, got, err, want)
		}
	}
	if _, err := ParseAPMLPlane("pcie"); err == nil {
		t.Error("ParseAPMLPlane must reject an unknown plane")
	}
}

func TestYAFUChecksum(t *testing.T) {
	payload := []byte{0x01, 0x02, 0xff}
	cases := map[YAFUChecksum]uint32{
		YAFUCRC32: 0xe1b73e2a,
		YAFUSum32: 0x102,
		YAFUSum16: 0x102,
		YAFUSum8:  0x02,
		YAFUXor8:  0xfc,
		YAFUZero:  0,
	}
	for algo, want := range cases {
		if got := yafuChecksum(algo, payload); got != want {
			t.Errorf("yafuChecksum(%s) = 0x%x, want 0x%x", algo, got, want)
		}
	}
	// The rejection case needs an algorithm name that is not a candidate.
	if _, err := ParseYAFUChecksum("adler32"); err == nil {
		t.Error("ParseYAFUChecksum must reject an unknown algorithm")
	}
	// The default is the algorithm the firmware actually uses.
	def, derr := ParseYAFUChecksum("")
	if derr != nil || def != YAFUCRC32 {
		t.Errorf("default checksum = %q (err %v), want crc32", def, derr)
	}
	probe, err := ParseYAFUChecksum("probe")
	if err != nil || probe != "" {
		t.Errorf("ParseYAFUChecksum(probe) = %q (err %v), want an empty value", probe, err)
	}
}

// TestYAFUHeaderLayout pins the 12-byte little-endian header. Getting the
// endianness wrong here fails the handler's own length and checksum checks.
func TestYAFUHeaderLayout(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5, 6, 7}
	h := yafuHeader(0xdeadbeef, 0x1234, payload, YAFUSum32)
	if len(h) != 12 {
		t.Fatalf("header is %d bytes, want 12", len(h))
	}
	if binary.LittleEndian.Uint32(h[0:4]) != 0xdeadbeef {
		t.Errorf("cookie = % x, want ef be ad de (little-endian)", h[0:4])
	}
	if binary.LittleEndian.Uint16(h[4:6]) != 0x1234 {
		t.Errorf("echo field = % x", h[4:6])
	}
	if got := binary.LittleEndian.Uint16(h[6:8]); got != 7 {
		t.Errorf("payload length = %d, want 7 (the ReadMemory handler rejects anything else)", got)
	}
	if got := binary.LittleEndian.Uint32(h[8:12]); got != 28 {
		t.Errorf("checksum = %d, want 28", got)
	}
}

func TestMemCCMeaning(t *testing.T) {
	allow, _ := MemProfileByID("smc-x13")
	open, _ := MemProfileByID("smc-x11")
	x14, _ := MemProfileByID("smc-x14")

	if got := memCCMeaning(&allow, 0xcc); got == "" || !strings.Contains(got, "allowlist") {
		t.Errorf("0xcc on an allowlisted build should name the allowlist, got %q", got)
	}
	if got := memCCMeaning(&open, 0xcc); strings.Contains(got, "allowlist") {
		t.Errorf("0xcc on an unrestricted build must not blame an allowlist, got %q", got)
	}
	// On X14 a 0xff is thrown after the allowlist passes, so it means the
	// address was accepted - the opposite of a format error.
	if got := memCCMeaning(&x14, 0xff); !strings.Contains(got, "accepted") {
		t.Errorf("0xff on X14 should read as an accept, got %q", got)
	}
}

// The I2C page is the one allowlist entry whose rule is not a plain offset list.
func TestAllowlistI2CPagePredicate(t *testing.T) {
	x14, _ := MemProfileByID("smc-x14")
	for _, tt := range []struct {
		addr uint64
		want bool
	}{
		{0x1e78a008, true},  // sel 0x08, unbounded
		{0x1e78a088, true},  // sel 0x08
		{0x1e78a010, true},  // sel 0x10, offset 0x010 < 0x880
		{0x1e78a090, true},  // sel 0x10
		{0x1e78a880, false}, // sel 0x80 -> not 0x08 or 0x10
		{0x1e78a000, false}, // sel 0x00
		{0x1e78a810, false}, // sel 0x10 but offset 0x810... still < 0x880
	} {
		got := x14.AllowsPhysical(tt.addr)
		// 0x1e78a810 has sel 0x10 and offset 0x810 < 0x880, so it is accepted;
		// correct the expectation rather than the rule.
		want := tt.want
		if tt.addr == 0x1e78a810 {
			want = true
		}
		if got != want {
			t.Errorf("AllowsPhysical(0x%08x) = %v, want %v", tt.addr, got, want)
		}
	}
}

// A MegaRAC board answers Get Device ID with the board vendor's IANA number, not
// AMI's, so profile detection has to match the OEM names too.
func TestAMIVendorNamesSelectTheMegaRACProfile(t *testing.T) {
	names := []string{"ami", "megarac", "asrock", "asustek", "tyan", "gigabyte", "giga computing", "inspur"}
	match := func(vendor string) bool {
		v := strings.ToLower(vendor)
		for _, n := range names {
			if strings.Contains(v, n) {
				return true
			}
		}
		return false
	}
	for _, id := range []uint32{
		20974, // American Megatrends (AMI)
		49622, // ASRock Rack
		2623,  // ASUSTek Computer
		6653,  // Tyan Computer
		37945, // Inspur
	} {
		name := ManufacturerNameFor(id)
		if name == "" {
			t.Errorf("manufacturer %d has no name, so detection cannot match it", id)
			continue
		}
		if !match(name) {
			t.Errorf("%q (IANA %d) ships the AMI OEM table but no detection name matches it", name, id)
		}
	}
	// Both the direct Supermicro and ATEN OEM identities must reach the GUID
	// lookup rather than being warned off as unknown vendors.
	for _, id := range []uint32{10876, 21317} {
		name := ManufacturerNameFor(id)
		if match(name) {
			t.Errorf("the Supermicro identity %q wrongly matches AMI detection", name)
		}
		if !isSupermicroVendorName(name) {
			t.Errorf("the Supermicro identity %q would skip the GUID lookup", name)
		}
	}
	// Intel and Fujitsu are AMI-adjacent but deliberately excluded.
	for _, id := range []uint32{343, 211} {
		if n := ManufacturerNameFor(id); n != "" && match(n) {
			t.Errorf("%q must not select the MegaRAC profile", n)
		}
	}
}
