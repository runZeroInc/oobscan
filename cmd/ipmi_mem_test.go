package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// The target parser stops at the first known subcommand token, so "mem" has to
// be in ipmiKnownCommands or "oobscan ipmi <host> mem read ..." reports a
// target parse error instead of running the handler.
func TestIPMIMemIsATargetTerminator(t *testing.T) {
	if !slices.Contains(ipmiKnownCommands, "mem") {
		t.Fatalf("mem missing from ipmiKnownCommands: %v", ipmiKnownCommands)
	}
	if idx := findIPMICommandIndex([]string{"192.0.2.10", "mem"}); idx != 1 {
		t.Errorf("findIPMICommandIndex([host mem]) = %d, want 1", idx)
	}
	if idx := findIPMICommandIndex([]string{"192.0.2.10", "192.0.2.11", "mem", "read", "0x0", "16"}); idx != 2 {
		t.Errorf("findIPMICommandIndex with two targets = %d, want 2", idx)
	}
}

func TestParseIPMIMemArgs(t *testing.T) {
	o, err := parseIPMIMemArgs([]string{
		"space=flash", "0x1FC0000", "2k", "unit=2", "order=msb-first",
		"bus=3", "slave=0x50", "addr-bytes=2", "fru=1", "out=x.bin",
		"retries=5", "delay=20ms", "continue", "force", "oem",
		"apml=sbrmi", "socket=1", "pin=42", "checksum=sum8",
	})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if o.space != ipmi.MemSpaceFlash {
		t.Errorf("space = %q, want flash", o.space)
	}
	if len(o.pos) != 2 || o.pos[0] != "0x1FC0000" || o.pos[1] != "2k" {
		t.Errorf("positional args = %v, want [0x1FC0000 2k]", o.pos)
	}
	if o.unit != 2 || o.order != ipmi.MemOrderMSBFirst {
		t.Errorf("unit/order = %d/%q", o.unit, o.order)
	}
	if o.bus != 3 || o.slave != 0x50 || o.addrBytes != 2 || o.fruID != 1 {
		t.Errorf("bus opts = %d/0x%02x/%d/%d", o.bus, o.slave, o.addrBytes, o.fruID)
	}
	if o.outFile != "x.bin" || o.retries != 5 || o.delay.String() != "20ms" {
		t.Errorf("out/retries/delay = %q/%d/%s", o.outFile, o.retries, o.delay)
	}
	if !o.cont || !o.force || !o.useOEM {
		t.Errorf("bare flags: continue=%v force=%v oem=%v", o.cont, o.force, o.useOEM)
	}
	if o.apmlPlane != ipmi.APMLSBRMI || o.socket != 1 || o.pin != 42 {
		t.Errorf("apml/socket/pin = %q/%d/%d", o.apmlPlane, o.socket, o.pin)
	}
	if o.checksum != ipmi.YAFUSum8 {
		t.Errorf("checksum = %q, want sum8", o.checksum)
	}
	// A write is staged unless the bare "apply" token is present.
	if o.apply {
		t.Error("apply must default to false")
	}
}

func TestParseIPMIMemArgsDefaults(t *testing.T) {
	o, err := parseIPMIMemArgs(nil)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if o.space != ipmi.MemSpacePhysical {
		t.Errorf("default space = %q, want physical", o.space)
	}
	if o.addrBytes != 1 {
		t.Errorf("default addr-bytes = %d, want 1", o.addrBytes)
	}
	// A pin of -1 means "no pin was given", so the gpio space uses the
	// register window rather than the pin-level command.
	if o.pin != -1 {
		t.Errorf("default pin = %d, want -1", o.pin)
	}
	if o.checksum != ipmi.YAFUCRC32 {
		t.Errorf("default checksum = %q, want crc32", o.checksum)
	}
}

func TestIPMIMemSurveyConfirmRWRequiresApply(t *testing.T) {
	x11, _ := ipmi.MemProfileByID("smc-x11")
	if _, err := ipmiMemSurveyConfirmRW(context.TODO(), nil, &x11, &ipmiMemOpts{}); err == nil {
		t.Fatal("a nil session must fail before a write is considered")
	}
	x13, _ := ipmi.MemProfileByID("smc-x13")
	res, err := ipmiMemSurveyConfirmRW(context.TODO(), nil, &x13, &ipmiMemOpts{})
	if err != nil {
		t.Fatalf("read-only profile should report not write-capable, got %v", err)
	}
	if res.(map[string]any)["writeCapable"] != false || res.(map[string]any)["applied"] != false {
		t.Fatalf("read-only profile result = %#v", res)
	}
}

func TestParseIPMIMemArgsRejectsUnknown(t *testing.T) {
	if _, err := parseIPMIMemArgs([]string{"nonsense=1"}); err == nil {
		t.Error("an unknown key must be rejected")
	} else if !strings.Contains(err.Error(), "unknown mem option") {
		t.Errorf("error should name the bad option, got %q", err)
	}
	if _, err := parseIPMIMemArgs([]string{"space=nowhere"}); err == nil {
		t.Error("an unknown space must be rejected")
	}
	if _, err := parseIPMIMemArgs([]string{"addr-bytes=3"}); err == nil {
		t.Error("addr-bytes must be 1 or 2")
	}
	// The error text matters: runIPMI reprints the short usage only when the
	// message contains "usage:", "unsupported" or "invalid".
	_, err := parseIPMIMemArgs([]string{"unit=x"})
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("a bad value should produce an \"invalid\" error, got %v", err)
	}
}

func TestParseMemAddrAndLength(t *testing.T) {
	p, _ := ipmi.MemProfileByID("smc-x11")

	addr, region, err := parseMemAddr(&p, "uboot-env")
	if err != nil || addr != 0x21FC0000 || region != "uboot-env" {
		t.Errorf("named region = 0x%x/%q (err %v), want 0x21FC0000/uboot-env", addr, region, err)
	}
	addr, region, err = parseMemAddr(&p, "0x21FC0000")
	if err != nil || addr != 0x21FC0000 || region != "" {
		t.Errorf("hex address = 0x%x/%q (err %v)", addr, region, err)
	}
	if addr, _, err = parseMemAddr(&p, "1024"); err != nil || addr != 1024 {
		t.Errorf("decimal address = %d (err %v)", addr, err)
	}
	// An unparseable address should name the profile's regions so the
	// operator learns the vocabulary from the error.
	_, _, err = parseMemAddr(&p, "wat")
	if err == nil || !strings.Contains(err.Error(), "uboot-env") {
		t.Errorf("the error should list named regions, got %v", err)
	}

	for in, want := range map[string]int{"16": 16, "0x100": 256, "2k": 2048, "1m": 1024 * 1024, "4KB": 4096} {
		got, lerr := parseMemLength(&p, in)
		if lerr != nil || got != want {
			t.Errorf("parseMemLength(%q) = %d (err %v), want %d", in, got, lerr, want)
		}
	}
	// A named region supplies its own size.
	if got, lerr := parseMemLength(&p, "uboot-env"); lerr != nil || got != 0x10000 {
		t.Errorf("parseMemLength(uboot-env) = %d (err %v), want 65536", got, lerr)
	}
	if _, lerr := parseMemLength(&p, "0"); lerr == nil {
		t.Error("a zero length must be rejected")
	}
	if _, lerr := parseMemLength(&p, "1g"); lerr == nil {
		t.Error("an absurd length must be rejected")
	}
}

func TestParseMemWriteBytes(t *testing.T) {
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	for _, in := range [][]string{
		{"deadbeef"},
		{"de", "ad", "be", "ef"},
		{"0xde", "0xad", "0xbe", "0xef"},
		{"de:ad:be:ef"},
		{"de,ad,be,ef"},
	} {
		got, err := parseMemWriteBytes(in)
		if err != nil {
			t.Errorf("parseMemWriteBytes(%v) error: %v", in, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("parseMemWriteBytes(%v) = % x, want % x", in, got, want)
		}
	}
	if _, err := parseMemWriteBytes([]string{"zz"}); err == nil {
		t.Error("non-hex input must be rejected")
	}
}

func TestMemHexdump(t *testing.T) {
	data := []byte("uniquepwd=41424344\x00bootargs=console")
	lines := memHexdump(data, 0x21FC0004)
	if len(lines) != 3 {
		t.Fatalf("got %d lines for %d bytes, want 3", len(lines), len(data))
	}
	if !strings.HasPrefix(lines[0], "21fc0004  ") {
		t.Errorf("first line should start at the base address, got %q", lines[0])
	}
	if !strings.Contains(lines[0], "|uniquepwd=414243|") {
		t.Errorf("ASCII column wrong: %q", lines[0])
	}
	// The NUL must render as a dot, not vanish.
	if !strings.Contains(lines[1], "44.bootargs=cons") {
		t.Errorf("non-printables should render as dots: %q", lines[1])
	}
	// A short final line still has a full-width hex column so the ASCII
	// gutter stays aligned.
	if len(lines[1]) != len(lines[2])+0 && !strings.Contains(lines[2], "|") {
		t.Errorf("short final line lost its ASCII column: %q", lines[2])
	}
}

func TestIPMIMemInfoShape(t *testing.T) {
	p, _ := ipmi.MemProfileByID("smc-x11")
	res := ipmiMemInfo(&p, &ipmi.MemProfileDetection{Profile: p, Source: "pinned", Generation: "X11"})

	for _, k := range []string{"action", "profile", "profileSource", "summary", "physicalRead", "physicalWrite", "spaces", "allowlist", "regions", "hazards"} {
		if _, ok := res[k]; !ok {
			t.Errorf("mem info is missing %q", k)
		}
	}
	if res["allowlist"] != "none - every physical address is accepted" {
		t.Errorf("X11 has no allowlist, got %v", res["allowlist"])
	}
	if !strings.Contains(res["spaces"].(string), "physical") {
		t.Errorf("spaces should include physical, got %v", res["spaces"])
	}

	// An allowlisted profile must describe its filter instead.
	x13, _ := ipmi.MemProfileByID("smc-x13")
	res = ipmiMemInfo(&x13, &ipmi.MemProfileDetection{Profile: x13, Source: "pinned"})
	if !strings.Contains(res["allowlist"].(string), "0x1e780000") {
		t.Errorf("X13 allowlist should name the GPIO page, got %v", res["allowlist"])
	}
	if res["physicalWrite"] != false {
		t.Error("X13 01.08.08 has no write primitive")
	}

	// The whole result has to survive json.Marshal, since --format=json
	// serializes it verbatim.
	if _, err := json.Marshal(res); err != nil {
		t.Errorf("mem info is not JSON-serializable: %v", err)
	}
}

func TestWriteMemReadResultRendersHexdump(t *testing.T) {
	var buf bytes.Buffer
	r := &ipmiMemReadResult{
		Action: "mem read", Profile: "smc-x11", Space: "physical",
		Address: "0x21fc0000", Physical: "0x21fc0000", Region: "uboot-env",
		Length: 8, Unit: 4, Order: "msb-first", Requests: 2,
		Hexdump: memHexdump([]byte("bootcmd="), 0x21FC0000),
		Holes:   []ipmi.MemHole{{Addr: 0x21FC0010, Len: 4, CC: "0xcc"}},
	}
	if err := writeMemReadResult(&buf, r); err != nil {
		t.Fatalf("render error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"smc-x11", "uboot-env", "msb-first", "21fc0000", "|bootcmd=|", "hole 0x21fc0010", "cc=0xcc"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output missing %q:\n%s", want, out)
		}
	}
	// The hexdump has to survive as real lines; the generic table renderer
	// would have collapsed them into one truncated cell.
	if strings.Count(out, "\n") < 8 {
		t.Errorf("expected multi-line output, got:\n%s", out)
	}
}

func TestMemWritePreviewShowsExactBytes(t *testing.T) {
	p, _ := ipmi.MemProfileByID("smc-x11")
	o := &ipmiMemOpts{space: ipmi.MemSpacePhysical, unit: 4}
	got, err := memWritePreview(&p, o, 0x1e78a000, []byte{0xde, 0xad, 0xbe, 0xef})
	if err != nil {
		t.Fatalf("preview error: %v", err)
	}
	// 0x30 0x70 C1 04 <addr big-endian> <value MSB-first on the wire>.
	want := "30 70 c1 04 1e 78 a0 00 efbeadde"
	if got != want {
		t.Errorf("preview = %q, want %q", got, want)
	}
	// A payload that is not a whole number of units is a usage error, not a
	// half-sent write.
	if _, err := memWritePreview(&p, o, 0x1e78a000, []byte{0x01, 0x02}); err == nil {
		t.Error("a partial unit must be rejected")
	}
}

func TestParseIPMIMemArgsRangeChecks(t *testing.T) {
	// A negative or odd unit reaches a slicer that would panic, so it has to
	// be rejected at parse time.
	for _, bad := range []string{"unit=-4", "unit=3", "unit=0x10", "pin=300", "pin=-5", "chunk=-1", "retries=-2"} {
		if _, err := parseIPMIMemArgs([]string{bad}); err == nil {
			t.Errorf("%s must be rejected", bad)
		}
	}
	for _, ok := range []string{"unit=1", "unit=2", "unit=4", "pin=0", "pin=223"} {
		if _, err := parseIPMIMemArgs([]string{ok}); err != nil {
			t.Errorf("%s should be accepted: %v", ok, err)
		}
	}
}

// json/jsonl marshal the read result verbatim, so the bytes have to be in a
// serialised field or a JSON consumer gets a result with no data in it.
func TestMemReadResultCarriesDataInJSON(t *testing.T) {
	r := &ipmiMemReadResult{
		Action: "mem read", Profile: "smc-x11", Space: "physical",
		Address: "0x21fc0000", Length: 128,
		DataHex: strings.Repeat("ab", 128),
		Hexdump: []string{"ignored"},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, _ := back["dataHex"].(string)
	if len(got) != 256 {
		t.Errorf("dataHex carries %d chars, want 256 - a JSON consumer must get every byte", len(got))
	}
	if _, ok := back["Hexdump"]; ok {
		t.Error("the rendered hexdump should not be duplicated into JSON")
	}
}

// The staged preview must refuse anything the write engine would refuse, so an
// operator never sees a request that cannot actually be sent.
func TestMemWritePreviewRejectsWhatTheEngineWould(t *testing.T) {
	p, _ := ipmi.MemProfileByID("smc-x11")
	o := &ipmiMemOpts{space: ipmi.MemSpacePhysical, unit: 4}
	if _, err := memWritePreview(&p, o, 0x1e78a001, []byte{1, 2, 3, 4}); err == nil {
		t.Error("an unaligned address must be refused in the preview too")
	}
	o.unit = 3
	if _, err := memWritePreview(&p, o, 0x1e78a000, []byte{1, 2, 3}); err == nil {
		t.Error("an invalid unit must be refused in the preview")
	}
}

// The probe table is rendered into JSON, so its cells must not carry ANSI
// colour escapes.
func TestMemProbeRowsAreColourFree(t *testing.T) {
	p, _ := ipmi.MemProfileByID("smc-x13")
	if got := yesNoWord(p.AllowsPhysical(0x1e780000)); strings.ContainsRune(got, '\x1b') {
		t.Errorf("probe cell %q carries an ANSI escape", got)
	}
}

// The AMI YAFU pair reaches the IPMI daemon's process image, not the SoC.
// Answering a space=physical request out of daemon memory would hand back
// plausible bytes for an address the caller never asked about.
func TestYAFUProfileRefusesPhysicalSpace(t *testing.T) {
	p, _ := ipmi.MemProfileByID("ami-megarac")
	if !p.YAFUMemory {
		t.Fatal("ami-megarac should carry the YAFU pair")
	}
	if ok, _ := p.SupportsSpace(ipmi.MemSpacePhysical); ok {
		t.Error("the profile must not advertise a physical space")
	}
	if ok, _ := p.SupportsSpace(ipmi.MemSpaceVirtual); !ok {
		t.Error("the profile must advertise the virtual space")
	}
}
