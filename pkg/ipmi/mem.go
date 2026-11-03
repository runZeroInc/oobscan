package ipmi

// Remote memory and hardware-register access over IPMI, behind one profile table
// so a caller names an address space instead of a vendor OEM subfunction.
// Subfunction numbers, address endianness and reply byte order differ per vendor
// and generation, so ReplyOrder is per profile and overridable. OEMCommandSet_70
// does no length validation before its switch, so a malformed probe of an unknown
// subfunction can perform a write with unspecified operands; nothing here probes
// by malformation, and no write is sent without an explicit caller opt-in.

import (
	"context"
	"encoding/binary"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// MemSpace names an address space reachable over IPMI. The CLI exposes these
// verbatim as --space values.
type MemSpace string

const (
	// MemSpacePhysical is the BMC's own physical address space, as seen
	// through the vendor's /dev/mem primitive.
	MemSpacePhysical MemSpace = "physical"
	// MemSpaceVirtual is a kernel virtual address, translated to physical
	// with the profile's PAGE_OFFSET and DRAM base before the request.
	MemSpaceVirtual MemSpace = "virtual"
	// MemSpaceFlash is an offset into the BMC SPI flash, translated through
	// the memory-mapped flash window.
	MemSpaceFlash MemSpace = "flash"
	// MemSpaceSCU is an offset into the SoC system-control register block.
	MemSpaceSCU MemSpace = "scu"
	// MemSpaceGPIO is an offset into the SoC GPIO register block.
	MemSpaceGPIO MemSpace = "gpio"
	// MemSpaceI2C is a byte offset inside a device on an I2C/SMBus segment.
	MemSpaceI2C MemSpace = "i2c"
	// MemSpaceSPD is MemSpaceI2C with the SPD EEPROM conventions applied.
	MemSpaceSPD MemSpace = "spd"
	// MemSpaceFRU is a byte offset inside a FRU inventory device.
	MemSpaceFRU MemSpace = "fru"
	// MemSpaceSDR is a record offset inside the SDR repository.
	MemSpaceSDR MemSpace = "sdr"
	// MemSpaceMII is a PHY register index on the BMC NIC.
	MemSpaceMII MemSpace = "mii"
	// MemSpacePECI is a raw PECI transaction to the host CPU.
	MemSpacePECI MemSpace = "peci"
	// MemSpaceCPU is the host CPU's own out-of-band register planes, reached
	// through AMD APML on the Supermicro AMD boards.
	MemSpaceCPU MemSpace = "cpu"
	// MemSpaceNVRAM is the vendor manufacturing-data store.
	MemSpaceNVRAM MemSpace = "nvram"
	// MemSpaceOOB is the H13 allow-list bypass: NetFn 0x30/0xA0/0x0c UploadOOBData
	// dumps DRAM from the fixed window 0x9ff00000 (which the 0xC0 page allowlist
	// refuses) into a BMC file, then reads it back via the OEMHW1 file primitive.
	// The offset is measured from 0x9ff00000. Readback works only on storage-class
	// firmware; on compute F401MS the dump runs but the bytes are not IPMI-retrievable.
	MemSpaceOOB MemSpace = "oob"
	// MemSpaceHost is HOST DRAM (the server CPU's RAM), not BMC memory. It is reached
	// by driving the ASPEED XDMA engine over the smc-restore-shell root shell (via=shell
	// only). direction downstream = read host, upstream = write host. AST2500 XDMA is
	// 32-bit (host addresses <4GB); the host must have granted PCIe BusMaster and, if an
	// IOMMU is enforcing, it must be off or the BMC's requester co-grouped.
	MemSpaceHost MemSpace = "host"
	// MemSpaceSHM addresses a byte offset WITHIN the IPMI daemon's SysV shared-
	// memory segment (the daemon config store), resolved to scattered physical
	// DRAM frames by the shmem page-cache walk in mem_shm.go. The address is a
	// segment offset; key=<n> selects the segment (default: the profile's
	// GlobalVar key). Needs MemProfile.ShmWalk (currently smc-x11).
	MemSpaceSHM MemSpace = "shm"
)

// MemSpaces lists every space the CLI accepts, in help-text order.
var MemSpaces = []MemSpace{
	MemSpacePhysical,
	MemSpaceVirtual,
	MemSpaceFlash,
	MemSpaceSCU,
	MemSpaceGPIO,
	MemSpaceI2C,
	MemSpaceSPD,
	MemSpaceFRU,
	MemSpaceSDR,
	MemSpaceMII,
	MemSpacePECI,
	MemSpaceCPU,
	MemSpaceNVRAM,
	MemSpaceOOB,
	MemSpaceSHM,
}

// MemSpaceNames returns the space names as plain strings, for help text.
func MemSpaceNames() []string {
	out := make([]string, 0, len(MemSpaces))
	for _, m := range MemSpaces {
		out = append(out, string(m))
	}
	return out
}

// ParseMemSpace normalizes a --space value, accepting a few aliases.
func ParseMemSpace(s string) (MemSpace, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "phys", "physical", "mem", "memory":
		return MemSpacePhysical, nil
	case "host", "hostdram", "host-dram", "hostram":
		return MemSpaceHost, nil
	case "virt", "virtual", "kernel":
		return MemSpaceVirtual, nil
	case "flash", "spi", "mtd", "rom":
		return MemSpaceFlash, nil
	case "scu", "reg", "register", "registers", "soc":
		return MemSpaceSCU, nil
	case "gpio":
		return MemSpaceGPIO, nil
	case "i2c", "smbus":
		return MemSpaceI2C, nil
	case "spd", "dimm":
		return MemSpaceSPD, nil
	case "fru":
		return MemSpaceFRU, nil
	case "sdr":
		return MemSpaceSDR, nil
	case "mii", "phy", "mdio":
		return MemSpaceMII, nil
	case "peci":
		return MemSpacePECI, nil
	case "cpu", "apml", "host-cpu":
		return MemSpaceCPU, nil
	case "nvram", "manuf", "manufdata":
		return MemSpaceNVRAM, nil
	case "oob", "oob-window", "uploadoob":
		return MemSpaceOOB, nil
	case "shm", "sysv", "globalvar", "shmem":
		return MemSpaceSHM, nil
	}
	return "", fmt.Errorf("unknown address space %q (use one of: %s)", s, strings.Join(MemSpaceNames(), ", "))
}

// MemByteOrder is how a profile serialises a multi-byte value on the wire.
type MemByteOrder string

const (
	// MemOrderAscending puts the byte at the lowest address first, which is
	// what a caller reassembling an image wants.
	MemOrderAscending MemByteOrder = "ascending"
	// MemOrderMSBFirst puts the most significant byte of the loaded word
	// first, so each group has to be reversed on a little-endian target.
	MemOrderMSBFirst MemByteOrder = "msb-first"
)

// ParseMemByteOrder normalizes a --reply-order value.
func ParseMemByteOrder(s string) (MemByteOrder, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto", "profile":
		return "", nil
	case "asc", "ascending", "native", "memory", "le":
		return MemOrderAscending, nil
	case "msb", "msb-first", "msbfirst", "swapped", "reverse", "be":
		return MemOrderMSBFirst, nil
	}
	return "", fmt.Errorf("unknown byte order %q (use auto, ascending, or msb-first)", s)
}

// MemPageRule is one entry of a firmware-side page allowlist. Off lists the
// only in-page offsets a build accepts; an empty Off means the whole page.
type MemPageRule struct {
	Page uint32   `json:"page"`
	Off  []uint32 `json:"off,omitempty"`
	Note string   `json:"note,omitempty"`
	// pred, when set, replaces the Off list with the handler's real test.
	pred func(addr uint32) bool
}

func (r MemPageRule) allows(addr uint32) bool {
	if addr&0xfffff000 != r.Page {
		return false
	}
	if r.pred != nil {
		return r.pred(addr)
	}
	if len(r.Off) == 0 {
		return true
	}
	return slices.Contains(r.Off, addr&0xfff)
}

// MemRegion is a named, well-known window inside a profile's physical space.
// A caller can pass the name in place of a numeric address.
type MemRegion struct {
	Name string `json:"name"`
	Addr uint64 `json:"addr"`
	Size uint64 `json:"size"`
	Desc string `json:"desc"`
}

// MemProfile is one vendor/generation variant of the memory-access primitives
// plus enough of the SoC memory map to translate the derived address spaces.
type MemProfile struct {
	ID          string `json:"id"`
	Vendor      string `json:"vendor"`
	Generations string `json:"generations"`
	Summary     string `json:"summary"`
	// Confidence is how well the primitive is established for this profile:
	// "live" (exercised on hardware or a faithful emulation), "static" (read
	// out of a decompile only), or "spec" (a standard IPMI command).
	Confidence string `json:"confidence"`

	// OEMHW1 capabilities are build-specific subcommands behind NetFn 0x30,
	// Cmd 0xae. Keep them false unless the exact firmware command table is known.
	OEMHW1Mem   bool `json:"oemHw1Mem,omitempty"`
	OEMHW1Files bool `json:"oemHw1Files,omitempty"`
	OEMHW1SCSI  bool `json:"oemHw1Scsi,omitempty"`

	// --- physical read -----------------------------------------------------

	ReadSupported bool `json:"readSupported"`
	ReadNetFn     byte `json:"-"`
	ReadCmd       byte `json:"-"`
	ReadSubFn     byte `json:"-"`
	// HasReadSubFn distinguishes "subfunction byte 0x00" from "no leading
	// subfunction byte at all".
	HasReadSubFn bool `json:"-"`
	// MaxUnit is the largest access width the handler accepts, in bytes.
	MaxUnit int `json:"maxUnit"`
	// AddrBigEndian is true when the 32-bit address goes on the wire MSB-first.
	AddrBigEndian bool `json:"addrBigEndian"`
	// ReplyOrder is how the handler serialises the value it read.
	ReplyOrder MemByteOrder `json:"replyOrder"`
	// AllowedPages, when non-empty, is the firmware's page allowlist. Reads
	// outside it are refused by the BMC with CC 0xcc.
	AllowedPages []MemPageRule `json:"allowedPages,omitempty"`

	// --- physical write ----------------------------------------------------

	WriteSupported bool `json:"writeSupported"`
	WriteSubFn     byte `json:"-"`
	// WriteSubFnAmbiguous marks a generation where the kb carries two
	// competing readings of the write subfunction. The engine refuses to
	// guess; the caller has to pin it explicitly.
	WriteSubFnAmbiguous bool         `json:"writeSubFnAmbiguous,omitempty"`
	WriteSubFnAlt       byte         `json:"-"`
	WriteValueOrder     MemByteOrder `json:"writeValueOrder,omitempty"`
	// LockdownGated is true when the write additionally requires system
	// lockdown to be off.
	LockdownGated bool `json:"lockdownGated,omitempty"`

	// --- SoC map. Zero means "not known for this profile". -----------------

	FlashBase  uint64 `json:"flashBase,omitempty"`
	FlashSize  uint64 `json:"flashSize,omitempty"`
	DRAMBase   uint64 `json:"dramBase,omitempty"`
	PageOffset uint64 `json:"pageOffset,omitempty"`
	SCUBase    uint64 `json:"scuBase,omitempty"`
	GPIOBase   uint64 `json:"gpioBase,omitempty"`

	// --- I2C / SMBus -------------------------------------------------------

	// I2C is the arbitrary bus transaction primitive. Every profile falls back
	// to the spec App/0x52 Master Write-Read when no OEM variant is named.
	I2CNetFn   byte `json:"-"`
	I2CCmd     byte `json:"-"`
	I2CMaxBus  byte `json:"i2cMaxBus,omitempty"`
	I2CMaxRead int  `json:"i2cMaxRead,omitempty"`
	// I2CBusZeroGated records that bus 0 is refused over LAN on this
	// generation (CC 0xd6), so the caller is told why before spending a probe.
	I2CBusZeroGated bool `json:"i2cBusZeroGated,omitempty"`
	// I2CUngatedSubFn is an OEM subfunction under ReadCmd that reaches the
	// same transport without the bus-0 gate. Zero means none is known.
	I2CUngatedSubFn byte `json:"-"`

	// --- MDIO / PHY --------------------------------------------------------

	MIISupported  bool `json:"miiSupported,omitempty"`
	MIIReadSubFn  byte `json:"-"`
	MIIWriteSubFn byte `json:"-"`

	// --- raw PECI to the host CPU ------------------------------------------

	PECISupported bool `json:"peciSupported,omitempty"`
	PECISubFn     byte `json:"-"`
	PECIMaxLen    int  `json:"peciMaxLen,omitempty"`

	// --- host-CPU register planes (AMD APML, 0x30/0x80) --------------------

	// APMLPlanes is set on the AMD-socket generations that carry the SMU
	// mailbox plus raw SB-TSI and SB-RMI register access. The code ships on
	// the Intel builds too, but the socket-presence check refuses there.
	APMLPlanes bool `json:"apmlPlanes,omitempty"`

	// --- whole-flash streaming dump (WST NetFn 0x3E) -----------------------

	// WSTFlashDump marks the generations that carry PrepareDumpFlash /
	// CheckDumpFlashComplete / SendFlashContent2Utility. All three answer on
	// every ATEN build; that an image actually materialises has never been
	// proven on a unit.
	WSTFlashDump bool `json:"wstFlashDump,omitempty"`

	// --- AMI MegaRAC YAFU --------------------------------------------------

	// YAFUMemory marks the AMI MegaRAC stacks whose OEM table carries
	// AMIYAFUReadMemory / AMIYAFUWriteMemory. That pair is a virtual read and
	// write of the IPMI daemon's own address space, not a physical one, and
	// it is gated on a disruptive flash-mode transition.
	YAFUMemory bool `json:"yafuMemory,omitempty"`

	// --- manufacturing data store ------------------------------------------

	// ManufStore marks the ATEN generations that carry ReadManufData /
	// WriteManufData on NetFn 0x3C. The X14 OpenBMC stack does not have that
	// table at all.
	ManufStore bool `json:"manufStore,omitempty"`

	// --- pin-level GPIO ----------------------------------------------------

	// GPIOPinSubFn is the subfunction of a pin-addressed GPIO get/set, as
	// opposed to reaching GPIO through the register window. Zero means none.
	GPIOPinSubFn byte `json:"-"`

	Regions []MemRegion `json:"regions,omitempty"`

	// Hazards is surfaced by "mem info" and before any write.
	Hazards string `json:"hazards,omitempty"`
	// ReadHazard is surfaced on every read, for the builds where even a read
	// can take the management plane down.
	ReadHazard string `json:"readHazard,omitempty"`
	// FlashWindowDark marks a build whose memory-mapped flash window is not
	// in linear-read mode, so reads there return zeros rather than an error.
	FlashWindowDark bool `json:"flashWindowDark,omitempty"`

	// ShmWalk, when set, carries the pinned kernel/build constants that let the
	// physical read resolve the IPMI daemon's SysV shm config segment (and dump
	// the cleartext credential table). Kernel-version specific; nil unless
	// verified live for this build. See mem_shm.go.
	ShmWalk *ShmWalk `json:"-"`
}

// Region returns a named region, case-insensitively.
func (p *MemProfile) Region(name string) (MemRegion, bool) {
	for _, r := range p.Regions {
		if strings.EqualFold(r.Name, strings.TrimSpace(name)) {
			return r, true
		}
	}
	return MemRegion{}, false
}

// RegionNames lists the profile's named regions.
func (p *MemProfile) RegionNames() []string {
	out := make([]string, 0, len(p.Regions))
	for _, r := range p.Regions {
		out = append(out, r.Name)
	}
	sort.Strings(out)
	return out
}

// AllowsPhysical reports whether a firmware-side allowlist would accept addr.
// A profile with no allowlist accepts everything.
func (p *MemProfile) AllowsPhysical(addr uint64) bool {
	if len(p.AllowedPages) == 0 {
		return true
	}
	if addr > 0xffffffff {
		return false
	}
	for _, r := range p.AllowedPages {
		if r.allows(uint32(addr)) {
			return true
		}
	}
	return false
}

// AllowedSample is a concrete pair of addresses a profile's page allowlist
// accepts on one page: the lowest and highest in-page offsets that pass the
// filter. Whole is true when every 4-byte-aligned offset on the page is
// accepted, which is the only case where a read near the top of the page can
// spill past the single mapped page - the behaviour "mem survey" exercises.
type AllowedSample struct {
	Page  uint32 `json:"page"`
	Base  uint32 `json:"base"`
	High  uint32 `json:"high"`
	Whole bool   `json:"whole"`
	Note  string `json:"note,omitempty"`
}

// AllowedSamples resolves each allowlist rule to a concrete accepted base and
// top address by scanning the page. It handles the plain offset list, the
// whole-page rule and the predicate rules uniformly, so a caller does not have
// to know how a given build expresses its filter. It is empty for an
// unrestricted profile, where every address is accepted and there is nothing to
// enumerate.
func (p *MemProfile) AllowedSamples() []AllowedSample {
	out := make([]AllowedSample, 0, len(p.AllowedPages))
	for _, r := range p.AllowedPages {
		var base, high uint32
		found, whole := false, true
		for off := uint32(0); off <= 0xffc; off += 4 {
			if r.allows(r.Page | off) {
				if !found {
					base, found = r.Page|off, true
				}
				high = r.Page | off
			} else {
				whole = false
			}
		}
		if !found {
			continue
		}
		out = append(out, AllowedSample{Page: r.Page, Base: base, High: high, Whole: whole, Note: r.Note})
	}
	return out
}

// SurveyPage is one page (or one notable register) in the ASPEED SoC map that
// "mem survey" tests. Desc names the controller so a report reads without a
// datasheet open.
type SurveyPage struct {
	Addr uint64 `json:"addr"`
	Name string `json:"name"`
	Desc string `json:"desc,omitempty"`
}

// ASPEEDSurveyPages is a bounded superset of the AST2400/2500/2600 controller
// map plus the memory-mapped flash window, DRAM base and a handful of exact
// registers worth naming. It is deliberately comprehensive: the point of a
// survey is to show which controllers a build's allowlist does and does not
// reach, and the ones that matter for a controller-to-host pivot - the SCU, the
// SDRAM controller, eSPI and the XDMA engine - are all here. Pages absent on a
// given SoC generation simply probe as refused, which is itself informative.
func ASPEEDSurveyPages() []SurveyPage {
	return []SurveyPage{
		{0x1e600000, "fmc", "flash memory controller (FMC/SPI, CS0)"},
		{0x1e620000, "spi1", "SPI1 controller"},
		{0x1e630000, "spi2", "SPI2 controller (AST2600)"},
		{0x1e650000, "mdio", "MDIO controller (AST2600)"},
		{0x1e660000, "mac1", "MAC1 - address at +0xa0"},
		{0x1e670000, "mac2", "MAC2"},
		{0x1e680000, "mac3", "MAC3 (AST2600)"},
		{0x1e690000, "mac4", "MAC4 (AST2600)"},
		{0x1e6a0000, "usb", "USB2.0 controller"},
		{0x1e6c0000, "sgpio-m", "SGPIO master / secondary SCU (AST2600)"},
		{0x1e6e0000, "sdmc", "SDRAM memory controller (SDMC)"},
		{0x1e6e0008, "sdmc-mcr08", "SDRAM configuration register MCR08"},
		{0x1e6e2000, "scu", "system control unit - clocking, straps, device enables"},
		{0x1e6e2004, "scu04", "SCU04 reset-domain register (XDMA armed = 0xF40EA098)"},
		{0x1e6e2078, "scu-rng", "hardware RNG - entropy behind ast_rand session IDs"},
		{0x1e6e3000, "hace", "hash and crypto engine (AST2600)"},
		{0x1e6e6000, "gfx", "2D graphics / VGA engine"},
		{0x1e6e7000, "xdma", "XDMA PCIe DMA engine - host-memory DMA path"},
		{0x1e6e8000, "espi", "eSPI controller (AST2600)"},
		{0x1e6e9000, "espi-mmbi", "eSPI/MMBI window (some builds map this)"},
		{0x1e6ed000, "sli", "SLI / die-to-die (AST2600)"},
		{0x1e6ee000, "pcie", "PCIe/eSPI control (firmware-referenced)"},
		{0x1e6ef000, "vga-pci", "VGA PCI config (firmware-referenced)"},
		{0x1e6f2000, "sbc", "secure boot controller (AST2600)"},
		{0x1e720000, "sram", "on-chip SRAM"},
		{0x1e780000, "gpio", "GPIO register block"},
		{0x1e781000, "sgpio", "serial GPIO (firmware-referenced)"},
		{0x1e784000, "gpio-1c", "GPIO/strap region (0x49 poke target at +0x1c)"},
		{0x1e785000, "wdt", "watchdog timers (firmware-referenced)"},
		{0x1e789000, "lpc", "LPC controller"},
		{0x1e789094, "lpc-post", "host POST port-80 snoop byte"},
		{0x1e78a000, "i2c", "I2C/SMBus controller - registers at +0x08/+0x10 families"},
		{0x1e78d000, "wdt2", "watchdog / timer"},
		{0x20000000, "flash-window", "memory-mapped SPI window (FMC CS0)"},
		{0x80000000, "dram", "DRAM base"},
	}
}

// SupportsSpace reports whether the profile can service a space at all.
func (p *MemProfile) SupportsSpace(space MemSpace) (bool, string) {
	switch space {
	case MemSpacePhysical:
		if !p.ReadSupported {
			return false, "no physical-memory primitive is known for this profile"
		}
	case MemSpaceVirtual:
		if p.YAFUMemory {
			return true, ""
		}
		if !p.ReadSupported {
			return false, "no physical-memory primitive is known for this profile"
		}
		if p.PageOffset == 0 || p.DRAMBase == 0 {
			return false, "no kernel PAGE_OFFSET/DRAM base is known for this profile"
		}
	case MemSpaceFlash:
		if !p.ReadSupported {
			return false, "no physical-memory primitive is known for this profile"
		}
		if p.FlashBase == 0 {
			return false, "no memory-mapped flash window is known for this profile"
		}
	case MemSpaceSCU:
		if !p.ReadSupported || p.SCUBase == 0 {
			return false, "no SoC register window is known for this profile"
		}
	case MemSpaceGPIO:
		if !p.ReadSupported || p.GPIOBase == 0 {
			return false, "no GPIO register window is known for this profile"
		}
	case MemSpaceMII:
		if !p.MIISupported {
			return false, "no MDIO/PHY primitive is known for this profile"
		}
	case MemSpacePECI:
		if !p.PECISupported {
			return false, "no PECI transport is known for this profile"
		}
	case MemSpaceCPU:
		if !p.APMLPlanes {
			return false, "no host-CPU register plane is known for this profile (APML is an AMD-socket surface)"
		}
	case MemSpaceNVRAM:
		if !p.ManufStore {
			return false, "no manufacturing-data store is known for this profile"
		}
	case MemSpaceSHM:
		if !p.ReadSupported {
			return false, "no physical-memory primitive is known for this profile"
		}
		if p.ShmWalk == nil {
			return false, "no shm page-cache walk parameters for this profile (kernel/build specific; currently smc-x11)"
		}
	}
	return true, ""
}

// TranslateSpace maps an address in space to a BMC physical address. It also
// returns a human-readable note about what the translation did.
func (p *MemProfile) TranslateSpace(space MemSpace, addr uint64) (uint64, string, error) {
	if ok, why := p.SupportsSpace(space); !ok {
		return 0, "", fmt.Errorf("%s: %s", space, why)
	}
	switch space {
	case MemSpacePhysical:
		return addr, "", nil
	case MemSpaceVirtual:
		if addr < p.PageOffset {
			return 0, "", fmt.Errorf("virtual 0x%x is below PAGE_OFFSET 0x%x", addr, p.PageOffset)
		}
		phys := p.DRAMBase + (addr - p.PageOffset)
		return phys, fmt.Sprintf("kernel virtual 0x%x -> physical 0x%x (PAGE_OFFSET 0x%x, DRAM 0x%x); valid only for the 1:1 lowmem window",
			addr, phys, p.PageOffset, p.DRAMBase), nil
	case MemSpaceFlash:
		// Accept either a flash offset or an already-translated physical
		// address inside the window.
		if p.FlashSize > 0 && addr >= p.FlashBase && addr < p.FlashBase+p.FlashSize {
			return addr, fmt.Sprintf("0x%x is already inside the flash window", addr), nil
		}
		phys := p.FlashBase + addr
		return phys, fmt.Sprintf("flash offset 0x%x -> physical 0x%x (window base 0x%x)", addr, phys, p.FlashBase), nil
	case MemSpaceSCU:
		return windowAddr(addr, p.SCUBase), "", nil
	case MemSpaceGPIO:
		return windowAddr(addr, p.GPIOBase), "", nil
	}
	return addr, "", nil
}

// windowAddr treats a small value as an offset into base and a large one as an
// address that already carries the base.
func windowAddr(addr, base uint64) uint64 {
	if addr < 0x10000 {
		return base + addr
	}
	return addr
}

// --- built-in profiles ------------------------------------------------------

// The Plt_ReadMemoryCmd page allowlist shared by X13 01.08.08, H13 01.06.05 and
// the X14 OpenBMC re-registration. X12 01.07.20 is the same list minus the GPIO
// page.
var (
	astAllowGPIO = MemPageRule{Page: 0x1e780000, Note: "AST2600 GPIO (any offset)"}
	astAllowI2C  = MemPageRule{
		Page: 0x1e78a000,
		Note: "I2C controller: accepted when addr[7:0]&0x7f is 0x08, or is 0x10 with an in-page offset below 0x880",
		pred: func(addr uint32) bool {
			switch sel := addr & 0x7f; sel {
			case 0x08:
				return true
			case 0x10:
				return addr&0xfff < 0x880
			default:
				return false
			}
		},
	}
	astAllowMACs = []MemPageRule{
		{Page: 0x1e660000, Off: []uint32{0xa0, 0xb0, 0xb1}, Note: "MAC1"},
		{Page: 0x1e670000, Off: []uint32{0xa0, 0xb0, 0xb1}, Note: "MAC2"},
		{Page: 0x1e680000, Off: []uint32{0xa0, 0xb0, 0xb1}, Note: "MAC3"},
		{Page: 0x1e690000, Off: []uint32{0xa0, 0xb0, 0xb1}, Note: "MAC4"},
	}
)

func astAllowlist(withGPIO bool) []MemPageRule {
	out := make([]MemPageRule, 0, 6)
	if withGPIO {
		out = append(out, astAllowGPIO)
	}
	out = append(out, astAllowI2C)
	return append(out, astAllowMACs...)
}

// smcFlashRegions is the SPI partition map X10 and X11 share, expressed as
// physical addresses through the FMC CS0 window at 0x20000000.
// kb/smc/notes/aten-memory-read-targets.md section 1.
func smcFlashRegions(bootSize, nvSize, rootfsAddr, kernelAddr uint64) []MemRegion {
	return []MemRegion{
		{Name: "uboot-env", Addr: 0x21FC0000, Size: 0x10000,
			Desc: "U-Boot environment sector: word 0 is its CRC32, then NUL-separated name=value pairs ended by a double NUL"},
		{Name: "bootloader", Addr: 0x20000000, Size: bootSize, Desc: "U-Boot"},
		{Name: "nv", Addr: 0x20100000, Size: nvSize, Desc: "/nv JFFS2 - the stored credential tree"},
		{Name: "rootfs", Addr: rootfsAddr, Size: 0, Desc: "root filesystem (cramfs)"},
		{Name: "kernel", Addr: kernelAddr, Size: 0, Desc: "kernel uImage"},
		{Name: "flash", Addr: 0x20000000, Size: 0x2000000, Desc: "the whole memory-mapped SPI window (FMC CS0)"},
	}
}

func astRegisterRegions(gen2600 bool) []MemRegion {
	gpio := uint64(0x1e780000)
	regions := []MemRegion{
		{Name: "scu", Addr: 0x1e6e2000, Size: 0x1000, Desc: "ASPEED system control unit"},
		{Name: "scu-rng", Addr: 0x1e6e2078, Size: 4, Desc: "hardware RNG register - the entropy behind ast_rand session IDs"},
		{Name: "gpio", Addr: gpio, Size: 0x1000, Desc: "GPIO register block"},
		{Name: "fmc", Addr: 0x1e620000, Size: 0x1000, Desc: "FMC/SPI controller (CE0 control at +0x10, segment at +0x30)"},
		{Name: "mac1", Addr: 0x1e660000, Size: 0x1000, Desc: "MAC1"},
		{Name: "mac2", Addr: 0x1e670000, Size: 0x1000, Desc: "MAC2"},
	}
	if gen2600 {
		regions = append(regions,
			MemRegion{Name: "mac3", Addr: 0x1e680000, Size: 0x1000, Desc: "MAC3"},
			MemRegion{Name: "mac4", Addr: 0x1e690000, Size: 0x1000, Desc: "MAC4"},
			MemRegion{Name: "i2c", Addr: 0x1e78a000, Size: 0x1000, Desc: "I2C controller"},
		)
	}
	return regions
}

func withRegions(sets ...[]MemRegion) []MemRegion {
	out := []MemRegion{}
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

const (
	smcHazardUnrestricted = "unrestricted physical write: a 4-byte poke into kernel text, a daemon, or an SoC control register is BMC code execution and can wedge the board. " +
		"OEMCommandSet_70 performs no request-length validation, so a short or malformed request writes stale buffer bytes to an unspecified address."
	smcHazardReadOnly = "read-only on this generation: the write sibling is absent or lockdown-gated. Reads are non-mutating, but the primitive is 1-4 bytes per request, so large ranges are slow."
)

// memProfiles is the built-in table. IDs are stable and usable with --profile.
var memProfiles = []MemProfile{
	{
		ID:            "smc-x10",
		Vendor:        "supermicro",
		Generations:   "X9, X10 (ATEN, AST2400)",
		Summary:       "unrestricted physical read and write via /dev/mem - no allowlist, no lockdown gate (GetSetSysLockdownEnable does not exist on this build)",
		Confidence:    "live",
		ReadSupported: true, ReadNetFn: 0x30, ReadCmd: 0x70, ReadSubFn: 0xC0, HasReadSubFn: true,
		MaxUnit: 4, AddrBigEndian: true, ReplyOrder: MemOrderMSBFirst,
		WriteSupported: true, WriteSubFn: 0xC1, WriteValueOrder: MemOrderMSBFirst,
		FlashBase: 0x20000000, FlashSize: 0x2000000,
		DRAMBase: 0x40000000, PageOffset: 0xC0000000,
		SCUBase: 0x1e6e2000, GPIOBase: 0x1e780000,
		I2CMaxBus: 15, I2CMaxRead: 255,
		// 0x7E (PltI2C_NCMasterWriteRead) starts at X11; X10 has no ungated
		// I2C escape hatch, and it does not need one - it never gated bus 0.
		MIISupported: true, MIIReadSubFn: 0xC5, MIIWriteSubFn: 0xC6,
		// X10 reaches PECI through 0x30/0xB0 subfn 0x03 - a different device
		// node and ioctl from the 0x70/0x6A path every later generation uses -
		// and that layout is not written down, so it is not exposed here.
		ManufStore:   true,
		WSTFlashDump: true,
		Regions: withRegions(smcFlashRegions(0x80000, 0x500000, 0x20600000, 0x21580000), astRegisterRegions(false),
			[]MemRegion{{Name: "dram", Addr: 0x40000000, Size: 0, Desc: "AST2400 DRAM base"}}),
		FlashWindowDark: true,
		Hazards:         smcHazardUnrestricted + " On X10 the FMC CE0 window is in user command mode, so linear flash reads at 0x20000000 return zeros until that is changed - which needs a write.",
	},
	{
		ID:            "smc-x11",
		Vendor:        "supermicro",
		Generations:   "X11 (ATEN, AST2500)",
		Summary:       "unrestricted physical read and write via /dev/mem - no allowlist, no lockdown gate; the read is live-confirmed on FW 01.74",
		Confidence:    "live",
		ReadSupported: true, ReadNetFn: 0x30, ReadCmd: 0x70, ReadSubFn: 0xC0, HasReadSubFn: true,
		MaxUnit: 4, AddrBigEndian: true, ReplyOrder: MemOrderMSBFirst,
		WriteSupported: true, WriteSubFn: 0xC1, WriteValueOrder: MemOrderMSBFirst,
		FlashBase: 0x20000000, FlashSize: 0x2000000,
		DRAMBase: 0x80000000, PageOffset: 0xC0000000,
		SCUBase: 0x1e6e2000, GPIOBase: 0x1e780000,
		I2CMaxBus: 15, I2CMaxRead: 255, I2CBusZeroGated: true,
		I2CUngatedSubFn: 0x7E,
		MIISupported:    true, MIIReadSubFn: 0xC5, MIIWriteSubFn: 0xC6,
		PECISupported: true, PECISubFn: 0x6A, PECIMaxLen: 32,
		ManufStore:   true,
		WSTFlashDump: true,
		Regions: withRegions(smcFlashRegions(0x100000, 0x300000, 0x20400000, 0x21400000), astRegisterRegions(false),
			[]MemRegion{{Name: "dram", Addr: 0x80000000, Size: 0, Desc: "AST2500 DRAM base"}}),
		Hazards: smcHazardUnrestricted,
		// Live-verified on X11DPT-PS FW 01.74 (AST2500, Linux 3.18.0): the shmem
		// page-cache walk lands on the daemon's key-0x19 config segment and the
		// credential table decodes to cleartext usernames+passwords.
		ShmWalk: &ShmWalk{
			MemMapPtr: 0x804568F8, IdrTop: 0x8042460C, IdrLayers: 0x80424614,
			IdrAry: 0x08, KeyOff: 0x08, ShmFileOff: 0x28, FInodeOff: 0x10, IMappingOff: 0x20,
			PtHeightOff: 0x04, PtRnodeOff: 0x0C, RtSlotsOff: 0x18,
			StructPage: 0x20, ArchPfnOff: 0x80000, Lowmem: 0x40000000, RadixShift: 6,
			GVKey: 0x19, UserBase: 0x560B8, UserStride: 0x24,
			UserNameLen: 16, UserPwOff: 0x10, UserPwLen: 20, UserSlots: 10,
		},
	},
	{
		ID:            "smc-x12",
		Vendor:        "supermicro",
		Generations:   "X12 (ATEN, AST2600, FW 01.07.20)",
		Summary:       "page-allowlisted physical read only (MAC + I2C pages; the GPIO page is refused on this build); no write primitive",
		Confidence:    "static",
		ReadSupported: true, ReadNetFn: 0x30, ReadCmd: 0x70, ReadSubFn: 0xC0, HasReadSubFn: true,
		MaxUnit: 4, AddrBigEndian: true, ReplyOrder: MemOrderAscending,
		AllowedPages: astAllowlist(false),
		FlashBase:    0x20000000, FlashSize: 0x2000000,
		DRAMBase: 0x80000000, PageOffset: 0xC0000000,
		SCUBase: 0x1e6e2000, GPIOBase: 0x1e780000,
		I2CMaxBus: 15, I2CMaxRead: 255, I2CBusZeroGated: true,
		I2CUngatedSubFn: 0x7E,
		MIISupported:    true, MIIReadSubFn: 0xC5, MIIWriteSubFn: 0xC6,
		PECISupported: true, PECISubFn: 0x6A, PECIMaxLen: 32,
		ManufStore:   true,
		WSTFlashDump: true,
		Regions:      astRegisterRegions(true),
		Hazards:      smcHazardReadOnly + " The allowlist refuses SCU and DRAM outright with CC 0xcc.",
	},
	{
		ID:            "smc-x13-0107",
		Vendor:        "supermicro",
		Generations:   "X13 FW 01.07.01 only (ATEN, AST2600)",
		Summary:       "unrestricted physical read AND write, block already renumbered - read 0xC0, write 0xC1; the write needs system lockdown off",
		Confidence:    "static",
		OEMHW1Mem:     true,
		OEMHW1Files:   true,
		OEMHW1SCSI:    true,
		ReadSupported: true, ReadNetFn: 0x30, ReadCmd: 0x70, ReadSubFn: 0xC0, HasReadSubFn: true,
		MaxUnit: 4, AddrBigEndian: true, ReplyOrder: MemOrderAscending,
		WriteSupported: true, WriteSubFn: 0xC1, WriteValueOrder: MemOrderMSBFirst, LockdownGated: true,
		FlashBase: 0x20000000, FlashSize: 0x2000000,
		DRAMBase: 0x80000000, PageOffset: 0xC0000000,
		SCUBase: 0x1e6e2000, GPIOBase: 0x1e780000,
		I2CMaxBus: 15, I2CMaxRead: 255, I2CBusZeroGated: true,
		I2CUngatedSubFn: 0x7E,
		MIISupported:    true, MIIReadSubFn: 0xC5, MIIWriteSubFn: 0xC6,
		PECISupported: true, PECISubFn: 0x6A, PECIMaxLen: 32,
		ManufStore:   true,
		WSTFlashDump: true,
		Regions:      astRegisterRegions(true),
		Hazards:      smcHazardUnrestricted + " The write answers CC 0xd4 when system lockdown is on.",
	},
	{
		ID:            "smc-x13",
		Vendor:        "supermicro",
		Generations:   "X13 FW 01.08.08 and later (ATEN, AST2600)",
		Summary:       "page-allowlisted physical read only (GPIO + I2C + MAC pages); the write sibling is gone",
		Confidence:    "static",
		ReadSupported: true, ReadNetFn: 0x30, ReadCmd: 0x70, ReadSubFn: 0xC0, HasReadSubFn: true,
		MaxUnit: 4, AddrBigEndian: true, ReplyOrder: MemOrderAscending,
		AllowedPages: astAllowlist(true),
		FlashBase:    0x20000000, FlashSize: 0x2000000,
		DRAMBase: 0x80000000, PageOffset: 0xC0000000,
		SCUBase: 0x1e6e2000, GPIOBase: 0x1e780000,
		I2CMaxBus: 15, I2CMaxRead: 255, I2CBusZeroGated: true,
		I2CUngatedSubFn: 0x7E,
		MIISupported:    true, MIIReadSubFn: 0xC5, MIIWriteSubFn: 0xC6,
		PECISupported: true, PECISubFn: 0x6A, PECIMaxLen: 32,
		ManufStore:   true,
		WSTFlashDump: true,
		Regions:      astRegisterRegions(true),
		Hazards:      smcHazardReadOnly,
	},
	{
		ID:          "smc-h13",
		Vendor:      "supermicro",
		Generations: "H13 (ATEN, AST2600), modelled on FW 01.06.05",
		Summary: "page-allowlisted physical read only (GPIO + I2C + MAC pages); the write sibling is gone. " +
			"The GUID board code cannot separate H13 builds, and 01.09.16 is not the same: it keeps a WriteMemoryCmd behind an access(\"/tmp/dev_fw\") test, so a development-key image has the write and a production ROT image answers CC 0xcc. Pin a profile if the build matters.",
		Confidence:    "static",
		ReadSupported: true, ReadNetFn: 0x30, ReadCmd: 0x70, ReadSubFn: 0xC0, HasReadSubFn: true,
		MaxUnit: 4, AddrBigEndian: true, ReplyOrder: MemOrderAscending,
		AllowedPages: astAllowlist(true),
		DRAMBase:     0x80000000, PageOffset: 0xC0000000,
		SCUBase: 0x1e6e2000, GPIOBase: 0x1e780000,
		I2CMaxBus: 15, I2CMaxRead: 255, I2CBusZeroGated: true,
		I2CUngatedSubFn: 0x7E,
		MIISupported:    true, MIIReadSubFn: 0xC5, MIIWriteSubFn: 0xC6,
		PECISupported: true, PECISubFn: 0x6A, PECIMaxLen: 32,
		ManufStore:   true,
		WSTFlashDump: true,
		APMLPlanes:   true,
		Regions:      astRegisterRegions(true),
		Hazards:      smcHazardReadOnly + " H13 keeps /nv on eMMC, not in the SPI window, so the flash space does not reach the credential tree here.",
	},
	{
		// smc-h13-0103 is the F401MS COMPUTE build (FW 01.03 / 01.06.05). It is a
		// near-clone of smc-h13 with file/SCSI/mem-RW deliberately OFF, because on
		// this build NetFn 0x30 Cmd 0xAE is TatlowChassisCmd (a chassis/watchdog-flag
		// toggle that wants datalen==3, else CC 0xc7) - NOT an OEMHW1 file/SCSI/mem
		// dispatcher. fd_open/fd_read (0x2e), SCSI CDB passthrough (0x35) and the
		// HW1LcdFwUpdate arbitrary R/W (0x22) are ABSENT here; they exist only on the
		// storage SKU (H13SSF/E401MS 01.09.16) and X13 01.07.01. The 0xc7 an operator
		// sees from smc-read/smc-cdb on this board is TatlowChassisCmd's length gate,
		// not an OEMHW1 handler rejecting a format - pinning smc-h13ssf-0109 here is a
		// mistake. Reads use the same page-allowlisted 0x70/0xC0; storage enumeration
		// (smc-cdb enum) uses 0x70/0x4c+0x4d. No BMC physical write on this build.
		ID:          "smc-h13-0103",
		Vendor:      "supermicro",
		Generations: "H13 F401MS FW 01.03 / 01.06.05 (ATEN, AST2600, compute)",
		Summary: "page-allowlisted physical read (GPIO+I2C+MAC) via 0x70/0xC0; host-CPU APML R/W via space=cpu; " +
			"storage enumeration via 0x70/0x4c+0x4d. OEMHW1 (0xAE) is TatlowChassisCmd here, NOT a file/SCSI dispatcher: " +
			"fd_open/fd_read/SCSI-CDB and the 0x22 arbitrary R/W are absent and return CC 0xc7 (a length gate, not a format mismatch). " +
			"No BMC physical write; the OEM allow-list has no general IPMI bypass on this compute build (UploadOOBData 0x30/0xA0 dumps only the fixed 0x9ff00000 OOB window, and its file readback is unresolved).",
		Confidence:    "static",
		ReadSupported: true, ReadNetFn: 0x30, ReadCmd: 0x70, ReadSubFn: 0xC0, HasReadSubFn: true,
		MaxUnit: 4, AddrBigEndian: true, ReplyOrder: MemOrderAscending,
		AllowedPages: astAllowlist(true),
		DRAMBase:     0x80000000, PageOffset: 0xC0000000,
		SCUBase: 0x1e6e2000, GPIOBase: 0x1e780000,
		I2CMaxBus: 15, I2CMaxRead: 255, I2CBusZeroGated: true,
		I2CUngatedSubFn: 0x7E,
		MIISupported:    true, MIIReadSubFn: 0xC5, MIIWriteSubFn: 0xC6,
		PECISupported: true, PECISubFn: 0x6A, PECIMaxLen: 32,
		ManufStore:   true,
		WSTFlashDump: true,
		APMLPlanes:   true,
		Regions:      astRegisterRegions(true),
		Hazards:      smcHazardReadOnly + " Compute F401MS: OEMHW1 file/SCSI absent (0xAE is TatlowChassisCmd); no physical write.",
	},
	{
		ID:            "smc-h13ssf-0109",
		Vendor:        "supermicro",
		Generations:   "H13SSF FW 01.09.16 only (ATEN, AST2600)",
		Summary:       "page-allowlisted physical read plus the OEMHW1 file and SCSI subcommands; OEMHW1 0x22 memory access is not wired",
		Confidence:    "static",
		OEMHW1Files:   true,
		OEMHW1SCSI:    true,
		ReadSupported: true, ReadNetFn: 0x30, ReadCmd: 0x70, ReadSubFn: 0xC0, HasReadSubFn: true,
		MaxUnit: 4, AddrBigEndian: true, ReplyOrder: MemOrderAscending,
		AllowedPages: astAllowlist(true),
		DRAMBase:     0x80000000, PageOffset: 0xC0000000,
		SCUBase: 0x1e6e2000, GPIOBase: 0x1e780000,
		I2CMaxBus: 15, I2CMaxRead: 255, I2CBusZeroGated: true,
		I2CUngatedSubFn: 0x7E,
		MIISupported:    true, MIIReadSubFn: 0xC5, MIIWriteSubFn: 0xC6,
		PECISupported: true, PECISubFn: 0x6A, PECIMaxLen: 32,
		ManufStore:   true,
		WSTFlashDump: true,
		APMLPlanes:   true,
		Regions:      astRegisterRegions(true),
		Hazards:      smcHazardReadOnly + " OEMHW1 file access stages data in /tmp/filedump; SCSI passthrough can reach host storage and is read-only by default.",
	},
	{
		ID:            "smc-x14",
		Vendor:        "supermicro",
		Generations:   "X14 (SMCI OpenBMC, AST2600)",
		Summary:       "page-allowlisted physical read only, re-registered at Privilege::None but held at Administrator by an inner check; reply is already in ascending-address order",
		Confidence:    "live",
		ReadSupported: true, ReadNetFn: 0x30, ReadCmd: 0x70, ReadSubFn: 0xC0, HasReadSubFn: true,
		MaxUnit: 4, AddrBigEndian: true, ReplyOrder: MemOrderAscending,
		AllowedPages: astAllowlist(true),
		SCUBase:      0x1e6e2000, GPIOBase: 0x1e780000,
		I2CNetFn: 0x32, I2CCmd: 0x01, I2CMaxBus: 255, I2CMaxRead: 255,
		GPIOPinSubFn: 0x4B,
		Regions:      astRegisterRegions(true),
		Hazards:      smcHazardReadOnly + " Under emulation every allowlisted page except the I2C controller answers CC 0xff (an ipmid exception after the allowlist passed), so a CC 0xff here is an accept, not a format error.",
		ReadHazard: "on X14 a read at an accepted GPIO or MAC page crashed phosphor-ipmi-host under emulation and it took 13-16s to come back; several in quick succession may trip the systemd start limit and leave IPMI down for good. " +
			"Map the allowlist with \"mem probe\" (a zero-length read that runs the filter without touching the bus) before reading for data.",
	},
	{
		ID:          "ami-megarac",
		Vendor:      "ami",
		Generations: "AMI MegaRAC SP-X: ASRock Rack, Tyan, Gigabyte, ASUS, Inspur, Fujitsu iRMC",
		Summary:     "arbitrary VIRTUAL read and write of the IPMI daemon's address space via the OEM YAFU family (NetFn 0x32 cmd 0x30/0x31); no physical/SoC-register primitive",
		Confidence:  "static",
		MaxUnit:     4,
		YAFUMemory:  true,
		// The MegaRAC Master Write-Read byte packs the channel in bits 7:4
		// and a three-bit bus id in bits 3:1, so buses above 7 are not
		// addressable the way they are on the ATEN stacks.
		I2CMaxBus: 7, I2CMaxRead: 255,
		Hazards: "the YAFU pair is virtual, not physical: it reads and writes IPMIMain's own address space, so SoC register pages are unreachable and an unmapped address SIGSEGVs the IPMI daemon, taking the management plane down until it restarts. " +
			"It is also gated on AMIYAFUActivateFlashMode, which calls PrepareFlashArea and a constant system() - that puts the BMC into firmware-update mode and is disruptive. Nothing is armed implicitly.",
	},
	{
		ID:          "generic",
		Vendor:      "",
		Generations: "any",
		Summary:     "no vendor physical-memory primitive is known; the spec-standard I2C, FRU and SDR spaces still work",
		Confidence:  "spec",
		MaxUnit:     4,
		I2CMaxBus:   15, I2CMaxRead: 255,
	},
}

// MemProfiles returns a copy of the built-in profile table.
func MemProfiles() []MemProfile {
	out := make([]MemProfile, len(memProfiles))
	copy(out, memProfiles)
	return out
}

// MemProfileByID looks a profile up by its stable ID.
func MemProfileByID(id string) (MemProfile, bool) {
	for _, p := range memProfiles {
		if strings.EqualFold(p.ID, strings.TrimSpace(id)) {
			return p, true
		}
	}
	return MemProfile{}, false
}

// MemProfileIDs lists every built-in profile ID.
func MemProfileIDs() []string {
	out := make([]string, 0, len(memProfiles))
	for _, p := range memProfiles {
		out = append(out, p.ID)
	}
	return out
}

// memProfileForSMCGeneration maps a GUID-derived generation label, refined by
// the firmware revision where one build differs from the rest of its family.
func memProfileForSMCGeneration(gen, fwRev string) (MemProfile, bool) {
	id := ""
	switch strings.ToUpper(strings.TrimSpace(gen)) {
	case "X9", "X10":
		id = "smc-x10"
	case "X11":
		id = "smc-x11"
	case "X12":
		id = "smc-x12"
	case "X13":
		// 01.07.01 is the one X13 build carrying the unrestricted read/write
		// pair; 01.08.08 and later are allowlisted and read-only. Get Device ID
		// reports only two revision components, so any 01.07.x maps to the
		// unrestricted profile, whose reads are identical either way and whose
		// writes need an explicit token. Pin a profile when the build matters.
		if strings.HasPrefix(strings.TrimSpace(fwRev), "1.07") || strings.HasPrefix(strings.TrimSpace(fwRev), "01.07") {
			id = "smc-x13-0107"
		} else {
			id = "smc-x13"
		}
	case "H13", "H12":
		if strings.HasPrefix(strings.TrimSpace(fwRev), "1.09") || strings.HasPrefix(strings.TrimSpace(fwRev), "01.09") {
			id = "smc-h13ssf-0109"
		} else {
			id = "smc-h13"
		}
	case "X14":
		id = "smc-x14"
	}
	if id == "" {
		return MemProfile{}, false
	}
	return MemProfileByID(id)
}

// MemProfileDetection reports how a profile was chosen.
type MemProfileDetection struct {
	Profile    MemProfile `json:"profile"`
	Source     string     `json:"source"`
	Vendor     string     `json:"vendor,omitempty"`
	Generation string     `json:"generation,omitempty"`
	Firmware   string     `json:"firmware,omitempty"`
	Warning    string     `json:"warning,omitempty"`
}

// DetectMemProfile picks a memory profile for a live session. It reads Get
// Device ID for the manufacturer, and for Supermicro refines the generation
// from the sessionless System GUID board code the SMC backup path already uses.
func (s *CmdSess) DetectMemProfile(ctx context.Context) (*MemProfileDetection, error) {
	if s == nil || s.runner == nil {
		return nil, fmt.Errorf("session closed")
	}
	det := &MemProfileDetection{Source: "fallback"}
	generic, _ := MemProfileByID("generic")
	det.Profile = generic

	mc, err := s.MCInfo(ctx)
	if err == nil && mc != nil {
		det.Vendor = mc.ManufacturerName
		if det.Vendor == "" {
			det.Vendor = ManufacturerNameFor(mc.ManufacturerID)
		}
		det.Firmware = mc.FirmwareRevision
	}
	vendor := strings.ToLower(det.Vendor)
	// A MegaRAC board answers Get Device ID with the board vendor's IANA number,
	// not AMI's, so these are the vendors whose images carry the AMI OEM command
	// table on NetFn 0x32. Intel (AMI-based, but registers its own command set)
	// and Fujitsu iRMC are deliberately absent.
	for _, name := range []string{"ami", "megarac", "asrock", "asustek", "tyan", "gigabyte", "giga computing", "inspur"} {
		if strings.Contains(vendor, name) {
			if p, ok := MemProfileByID("ami-megarac"); ok {
				det.Profile = p
				det.Source = "manufacturer-id"
				return det, nil
			}
		}
	}
	if !isSupermicroVendorName(vendor) && vendor != "" {
		det.Warning = fmt.Sprintf("no built-in memory profile for %q; only the spec-standard spaces (i2c, spd, fru, sdr) are available", det.Vendor)
		return det, nil
	}

	g, gerr := s.SMCGeneration(ctx)
	if gerr != nil {
		det.Warning = fmt.Sprintf("could not read the System GUID to detect a generation (%v); pass --profile to pin one", gerr)
		return det, nil
	}
	det.Generation = g.Generation
	prof, ok := memProfileForSMCGeneration(g.Generation, det.Firmware)
	if !ok {
		det.Warning = fmt.Sprintf("no built-in memory profile for generation %q (model prefix %q); pass --profile to pin one", g.Generation, g.ModelPrefix)
		return det, nil
	}
	det.Profile = prof
	det.Source = "system-guid"
	return det, nil
}

func isSupermicroVendorName(vendor string) bool {
	vendor = strings.ToLower(vendor)
	return strings.Contains(vendor, "supermicro") || strings.Contains(vendor, "super micro") || strings.Contains(vendor, "aten")
}

// --- physical read/write engine --------------------------------------------

// MemReadOptions tunes a physical read loop.
type MemReadOptions struct {
	// Unit is the per-request access width in bytes (1, 2 or 4). Zero means
	// the profile's MaxUnit. A unit of 1 sidesteps every reply-byte-order
	// question at four times the request cost.
	Unit int
	// ReplyOrder overrides the profile's reply byte order.
	ReplyOrder MemByteOrder
	// Retries is the transport retry budget per unit. A real completion code
	// is never retried - it is the target's answer, not a lost datagram.
	Retries int
	// Delay is an optional inter-request pause.
	Delay time.Duration
	// Progress, when set, is called with a short position string.
	Progress func(string)
	// ContinueOnError fills unreadable units with zeros and records a hole
	// instead of aborting the whole read.
	ContinueOnError bool
	// SkipAllowlistCheck sends requests the client believes the firmware will
	// refuse. Useful when the built-in allowlist is wrong for a build.
	SkipAllowlistCheck bool
	// Pipeline, when >1, keeps that many read requests in flight to hide the
	// round-trip latency (v1.5 sessions only; capped for session safety). Zero or
	// 1 uses the serial path.
	Pipeline int
}

// MemHole records a unit-sized gap in a dump.
type MemHole struct {
	Addr uint64 `json:"addr"`
	Len  int    `json:"len"`
	CC   string `json:"cc,omitempty"`
	Err  string `json:"err,omitempty"`
}

// MemStats counts the request traffic a transfer spent.
type MemStats struct {
	Requests int `json:"requests"`
	Retries  int `json:"retries"`
	Failures int `json:"failures"`
}

// memUnitRead issues one width-sized read and returns the bytes in ascending
// address order. It returns the raw completion code so the caller can tell an
// allowlist refusal (0xcc) from a transport loss.
func (s *CmdSess) memUnitRead(p *MemProfile, addr uint64, width int, order MemByteOrder) (data []byte, cc byte, err error) {
	req := make([]byte, 0, 6)
	if p.HasReadSubFn {
		req = append(req, p.ReadSubFn)
	}
	req = append(req, byte(width))
	a := make([]byte, 4)
	if p.AddrBigEndian {
		binary.BigEndian.PutUint32(a, uint32(addr))
	} else {
		binary.LittleEndian.PutUint32(a, uint32(addr))
	}
	req = append(req, a...)

	cc, resp, err := s.ExecRaw(p.ReadNetFn, p.ReadCmd, req)
	if err != nil {
		return nil, 0, err
	}
	if cc != 0x00 {
		return nil, cc, fmt.Errorf("cc=0x%02x (%s)", cc, memCCMeaning(p, cc))
	}
	if len(resp) < width {
		return nil, cc, fmt.Errorf("short reply: %d bytes for a %d-byte read", len(resp), width)
	}
	out := resp[:width]
	if order == MemOrderMSBFirst && width > 1 {
		out = reverseBytes(out)
	}
	return out, cc, nil
}

// MemReadUnitAt issues exactly one width-sized read at the exact address given,
// with no client-side alignment and no allowlist filtering, and returns the raw
// completion code alongside any data. It is the precise-request primitive behind
// "mem survey": passing an offset near the top of a page (for example base+0xffe
// with a 4-byte width) is how the survey checks whether a build re-validates
// offset+width against the page size, or reads past the single mapped page.
// width is clamped to the profile's MaxUnit. On a completion code other than
// 0x00 it returns that code with a descriptive error and no data.
func (s *CmdSess) MemReadUnitAt(p *MemProfile, addr uint64, width int) (data []byte, cc byte, err error) {
	if p == nil || !p.ReadSupported {
		return nil, 0, fmt.Errorf("profile %q has no physical-memory read primitive", profileID(p))
	}
	if addr > 0xffffffff {
		return nil, 0, fmt.Errorf("0x%x does not fit the 32-bit physical address field", addr)
	}
	if width <= 0 {
		width = 1
	}
	if width > p.MaxUnit {
		width = p.MaxUnit
	}
	return s.memUnitRead(p, addr, width, p.ReplyOrder)
}

// memCCMeaning annotates the completion codes these handlers actually use.
func memCCMeaning(p *MemProfile, cc byte) string {
	switch cc {
	case 0x00:
		return "ok"
	case 0xcc:
		if len(p.AllowedPages) > 0 {
			return "cc 0xcc, data field rejected - on this build the page allowlist refused the address"
		}
		return "cc 0xcc, data field rejected - open(\"/dev/mem\") or mmap failed for this page"
	case 0xd4:
		if p.LockdownGated {
			return "insufficient privilege - Administrator is required, and the write also needs system lockdown off"
		}
		return "insufficient privilege - this primitive is Administrator-gated"
	case 0xd6:
		return "command disabled - bus 0 is gated off the LAN channel on this generation"
	case 0xc1:
		return "cc 0xc1, command not recognised - this subfunction does not exist on this build"
	case 0xc7:
		return "cc 0xc7, request data length rejected"
	case 0xc9:
		return "parameter out of range - the requested length exceeds the handler's cap"
	case 0xff:
		if p.ID == "smc-x14" {
			return "unspecified error thrown after the allowlist passed - on X14 this means the address was accepted"
		}
		return "unspecified error"
	}
	return "unspecified"
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// MemReadPhysical reads length bytes from a BMC physical address. Requests are
// unit-sized and aligned; the result is sliced back to the exact range asked
// for, so an unaligned start costs at most one extra request.
func (s *CmdSess) MemReadPhysical(ctx context.Context, p *MemProfile, addr uint64, length int, opts MemReadOptions) ([]byte, []MemHole, MemStats, error) {
	var stats MemStats
	if p == nil || !p.ReadSupported {
		return nil, nil, stats, fmt.Errorf("profile %q has no physical-memory read primitive", profileID(p))
	}
	if length <= 0 {
		return nil, nil, stats, fmt.Errorf("length must be positive")
	}
	// The wire address field is 32 bits. Truncating silently would read a
	// completely different page and hand back plausible-looking bytes.
	if addr > 0xffffffff || addr+uint64(length) > 0x100000000 {
		return nil, nil, stats, fmt.Errorf("0x%x+%d does not fit the 32-bit physical address field", addr, length)
	}
	// Pipelined path (v1.5 sessions): keep several reads in flight. Falls through
	// to the serial loop for any other session type.
	if opts.Pipeline > 1 {
		if data, holes, st, err := s.MemReadPhysicalPipelined(ctx, p, addr, length, opts.Pipeline, opts); err != errPipelineUnsupported {
			return data, holes, st, err
		}
	}
	unit := opts.Unit
	if unit == 0 {
		unit = p.MaxUnit
	}
	if unit != 1 && unit != 2 && unit != 4 {
		return nil, nil, stats, fmt.Errorf("unit must be 1, 2 or 4 bytes (got %d)", unit)
	}
	if unit > p.MaxUnit {
		return nil, nil, stats, fmt.Errorf("profile %s accepts at most %d bytes per request", p.ID, p.MaxUnit)
	}
	order := opts.ReplyOrder
	if order == "" {
		order = p.ReplyOrder
	}
	retries := opts.Retries
	if retries < 1 {
		retries = 3
	}

	start := addr &^ uint64(unit-1)
	end := addr + uint64(length)
	total := int((end-start+uint64(unit)-1)/uint64(unit)) * unit
	buf := make([]byte, 0, total)
	var holes []MemHole

	units := total / unit
	for i := range units {
		if err := ctx.Err(); err != nil {
			return nil, holes, stats, err
		}
		ua := start + uint64(i*unit)
		if !opts.SkipAllowlistCheck && !p.AllowsPhysical(ua) {
			holes = append(holes, MemHole{Addr: ua, Len: unit, Err: "outside this build's firmware page allowlist"})
			buf = append(buf, make([]byte, unit)...)
			if !opts.ContinueOnError {
				return nil, holes, stats, fmt.Errorf("0x%08x is outside the %s page allowlist; pass the bare token 'force' to send it anyway", ua, p.ID)
			}
			continue
		}
		var got []byte
		var lastCC byte
		var lastErr error
		for attempt := 0; attempt < retries; attempt++ {
			stats.Requests++
			d, cc, err := s.memUnitRead(p, ua, unit, order)
			if err == nil {
				got = d
				break
			}
			lastErr, lastCC = err, cc
			if cc != 0x00 {
				// A real completion code is the target's answer. Retrying
				// spends requests to learn the same thing.
				break
			}
			stats.Retries++
			if opts.Delay > 0 {
				time.Sleep(opts.Delay * time.Duration(attempt+1))
			}
		}
		if got == nil {
			stats.Failures++
			h := MemHole{Addr: ua, Len: unit}
			if lastCC != 0 {
				h.CC = fmt.Sprintf("0x%02x", lastCC)
			}
			if lastErr != nil {
				h.Err = lastErr.Error()
			}
			holes = append(holes, h)
			if !opts.ContinueOnError {
				return nil, holes, stats, fmt.Errorf("read at 0x%08x: %w", ua, lastErr)
			}
			got = make([]byte, unit)
		}
		buf = append(buf, got...)
		if opts.Progress != nil && (i%16 == 15 || i == units-1) {
			opts.Progress(fmt.Sprintf("reading 0x%08x  %d/%d units (%d B) retries=%d holes=%d",
				ua, i+1, units, len(buf), stats.Retries, len(holes)))
		}
		if opts.Delay > 0 {
			time.Sleep(opts.Delay)
		}
	}

	off := int(addr - start)
	if off+length > len(buf) {
		length = len(buf) - off
	}
	return buf[off : off+length], holes, stats, nil
}

// MemWriteOptions tunes a physical write loop.
type MemWriteOptions struct {
	Unit int
	// ReplyOrder overrides the profile's reply byte order for the Verify
	// read-back. Without it a caller who needed order= on the read would see
	// every verified unit reported as a mismatch.
	ReplyOrder MemByteOrder
	// SubFn overrides the profile's write subfunction. Required on a
	// generation where the kb has not settled which subfunction is the write.
	SubFn    *byte
	Retries  int
	Delay    time.Duration
	Progress func(string)
	// Verify re-reads each unit after writing it and reports mismatches.
	Verify bool
}

// MemWriteResult reports what a write actually did.
type MemWriteResult struct {
	Addr      uint64   `json:"addr"`
	Len       int      `json:"len"`
	Unit      int      `json:"unit"`
	SubFn     string   `json:"subfn"`
	Stats     MemStats `json:"stats"`
	Verified  bool     `json:"verified"`
	Mismatch  []uint64 `json:"mismatch,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
}

// MemWritePhysical writes data to a BMC physical address, unit at a time. The
// caller is responsible for having obtained consent: this function sends the
// requests unconditionally.
func (s *CmdSess) MemWritePhysical(ctx context.Context, p *MemProfile, addr uint64, data []byte, opts MemWriteOptions) (*MemWriteResult, error) {
	if p == nil || !p.WriteSupported {
		return nil, fmt.Errorf("profile %q has no physical-memory write primitive", profileID(p))
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("no data to write")
	}
	if addr > 0xffffffff || addr+uint64(len(data)) > 0x100000000 {
		return nil, fmt.Errorf("0x%x+%d does not fit the 32-bit physical address field", addr, len(data))
	}
	unit := opts.Unit
	if unit == 0 {
		unit = p.MaxUnit
	}
	if unit != 1 && unit != 2 && unit != 4 {
		return nil, fmt.Errorf("unit must be 1, 2 or 4 bytes (got %d)", unit)
	}
	if addr%uint64(unit) != 0 {
		return nil, fmt.Errorf("address 0x%x is not %d-byte aligned; the handler splits the page at addr&0xfffff000 and stores at addr&0xfff", addr, unit)
	}
	if len(data)%unit != 0 {
		return nil, fmt.Errorf("%d bytes is not a whole number of %d-byte units", len(data), unit)
	}

	// The write subfunction defaults to the best-evidenced value for the
	// profile; on a generation with two competing readings the alternative is
	// reported so a caller can pin it. A wrong value is a benign failure - the
	// request lands on the read handler with an odd width and stores nothing -
	// which is why this warns rather than refusing.
	subfn := p.WriteSubFn
	if opts.SubFn != nil {
		subfn = *opts.SubFn
	}

	retries := opts.Retries
	if retries < 1 {
		retries = 3
	}
	order := p.WriteValueOrder
	if order == "" {
		order = MemOrderMSBFirst
	}
	verifyOrder := opts.ReplyOrder
	if verifyOrder == "" {
		verifyOrder = p.ReplyOrder
	}

	res := &MemWriteResult{Addr: addr, Len: len(data), Unit: unit, SubFn: fmt.Sprintf("0x%02x", subfn)}
	units := len(data) / unit
	for i := range units {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		ua := addr + uint64(i*unit)
		val := data[i*unit : (i+1)*unit]
		wire := val
		if order == MemOrderMSBFirst && unit > 1 {
			wire = reverseBytes(val)
		}
		req := make([]byte, 0, 6+unit)
		req = append(req, subfn, byte(unit))
		a := make([]byte, 4)
		if p.AddrBigEndian {
			binary.BigEndian.PutUint32(a, uint32(ua))
		} else {
			binary.LittleEndian.PutUint32(a, uint32(ua))
		}
		req = append(req, a...)
		req = append(req, wire...)

		var lastErr error
		ok := false
		for attempt := 0; attempt < retries; attempt++ {
			res.Stats.Requests++
			cc, _, err := s.ExecRaw(p.ReadNetFn, p.ReadCmd, req)
			if err == nil && cc == 0x00 {
				ok = true
				break
			}
			if err == nil {
				lastErr = fmt.Errorf("cc=0x%02x (%s)", cc, memCCMeaning(p, cc))
				break
			}
			lastErr = err
			res.Stats.Retries++
			if opts.Delay > 0 {
				time.Sleep(opts.Delay * time.Duration(attempt+1))
			}
		}
		if !ok {
			res.Stats.Failures++
			return res, fmt.Errorf("write at 0x%08x: %w", ua, lastErr)
		}
		if opts.Verify {
			back, _, verr := s.memUnitRead(p, ua, unit, verifyOrder)
			res.Stats.Requests++
			if verr != nil || !bytesEqual(back, val) {
				res.Mismatch = append(res.Mismatch, ua)
			}
		}
		if opts.Progress != nil && (i%16 == 15 || i == units-1) {
			opts.Progress(fmt.Sprintf("writing 0x%08x  %d/%d units", ua, i+1, units))
		}
		if opts.Delay > 0 {
			time.Sleep(opts.Delay)
		}
	}
	res.Verified = opts.Verify
	return res, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func profileID(p *MemProfile) string {
	if p == nil {
		return "<nil>"
	}
	return p.ID
}

// MemProbePage issues a zero-length read at addr. On the allowlisted ATEN and
// OpenBMC builds a count of 0 runs the whole allowlist check and returns
// without touching the bus, which makes it a side-effect-free oracle for
// mapping what a build will accept. It is also the documented X12-vs-X13/H13
// build discriminator at the GPIO page.
func (s *CmdSess) MemProbePage(p *MemProfile, addr uint64) (accepted bool, cc byte, err error) {
	if p == nil || !p.ReadSupported {
		return false, 0, fmt.Errorf("profile %q has no physical-memory read primitive", profileID(p))
	}
	if addr > 0xffffffff {
		return false, 0, fmt.Errorf("0x%x does not fit the 32-bit physical address field", addr)
	}
	req := make([]byte, 0, 6)
	if p.HasReadSubFn {
		req = append(req, p.ReadSubFn)
	}
	req = append(req, 0x00)
	a := make([]byte, 4)
	if p.AddrBigEndian {
		binary.BigEndian.PutUint32(a, uint32(addr))
	} else {
		binary.LittleEndian.PutUint32(a, uint32(addr))
	}
	req = append(req, a...)
	cc, _, err = s.ExecRaw(p.ReadNetFn, p.ReadCmd, req)
	if err != nil {
		return false, 0, err
	}
	// 0xcc is the allowlist reject; 0x00 and 0xff both mean the address got
	// past the filter (see kb/smc/notes/x14-readmemory-analysis.md). 0xd4 and
	// 0xc1 are not allowlist answers at all - the session is under-privileged
	// or the subfunction is absent - so they are reported as errors rather
	// than being folded into "rejected", which would read as a page boundary.
	switch cc {
	case 0xd4:
		return false, cc, fmt.Errorf("cc=0xd4: %s", memCCMeaning(p, cc))
	case 0xc1:
		return false, cc, fmt.Errorf("cc=0xc1: %s", memCCMeaning(p, cc))
	}
	return cc != 0xcc, cc, nil
}
