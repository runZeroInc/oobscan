package ipmi

// Tests for the "mem survey" primitives: the concrete-address unit read that
// backs the page-boundary spill probe, the allowlist-sample resolver, and the
// SoC survey map.

import (
	"bytes"
	"testing"
)

func surveyReadProfile() *MemProfile {
	return &MemProfile{
		ReadSupported: true, ReadNetFn: 0x30, ReadCmd: 0x70, ReadSubFn: 0xC0,
		HasReadSubFn: true, MaxUnit: 4, AddrBigEndian: true, ReplyOrder: MemOrderMSBFirst,
	}
}

// MemReadUnitAt must send the exact address with no alignment, so a read that
// starts near the top of a page runs off the end of it - the copy-loop spill
// the allowlist audit found. Backing store spans the page and the next one so
// the over-read still lands in the fake's memory and can be checked.
func TestMemReadUnitAtSendsExactAddress(t *testing.T) {
	base := uint64(0x1e780000)
	f := newFakeMemBMC(base, 0x2000, MemOrderMSBFirst)
	s := fakeSess(f)
	p := surveyReadProfile()

	data, cc, err := s.MemReadUnitAt(p, base+0xffe, 4)
	if err != nil || cc != 0x00 {
		t.Fatalf("boundary read err=%v cc=0x%02x", err, cc)
	}
	// Ascending mem bytes at offsets 0xffe,0xfff,0x1000,0x1001. If the address
	// had been aligned down to 0xffc, the first byte would be 0xfc not 0xfe.
	want := []byte{f.mem[0xffe], f.mem[0xfff], f.mem[0x1000], f.mem[0x1001]}
	if !bytes.Equal(data, want) {
		t.Errorf("data=% x want=% x (address was aligned down?)", data, want)
	}
	if f.mem[0xffe] != 0xfe {
		t.Fatalf("fake backing assumption broke: mem[0xffe]=0x%02x", f.mem[0xffe])
	}
}

// A completion code other than 0x00 comes back as (nil, cc, err), so a survey
// can print the refusal without mistaking it for data.
func TestMemReadUnitAtSurfacesCompletionCode(t *testing.T) {
	f := newFakeMemBMC(0x1e6e2000, 0x1000, MemOrderMSBFirst)
	f.refuse[0x1e6e2000] = 0xcc
	s := fakeSess(f)

	data, cc, err := s.MemReadUnitAt(surveyReadProfile(), 0x1e6e2000, 4)
	if err == nil || cc != 0xcc || data != nil {
		t.Errorf("refused read = data % x cc 0x%02x err %v; want nil / 0xcc / error", data, cc, err)
	}
}

// AllowedSamples resolves each allowlist rule to a concrete base and top, and
// flags whether the whole page is accepted (the only case where a near-top read
// can spill). An unrestricted profile enumerates nothing.
func TestAllowedSamples(t *testing.T) {
	p := &MemProfile{AllowedPages: astAllowlist(true)}
	byPage := map[uint32]AllowedSample{}
	for _, s := range p.AllowedSamples() {
		byPage[s.Page] = s
	}

	if g := byPage[0x1e780000]; !g.Whole || g.Base != 0x1e780000 || g.High != 0x1e780ffc {
		t.Errorf("gpio sample = %+v; want whole page, base 0x1e780000, high 0x1e780ffc", g)
	}
	if i := byPage[0x1e78a000]; i.Whole || i.Base != 0x1e78a008 {
		t.Errorf("i2c sample = %+v; want base 0x1e78a008, not whole", i)
	}
	if m := byPage[0x1e660000]; m.Whole || m.Base != 0x1e6600a0 {
		t.Errorf("mac1 sample = %+v; want base 0x1e6600a0, not whole", m)
	}
	if s := (&MemProfile{}).AllowedSamples(); len(s) != 0 {
		t.Errorf("unrestricted AllowedSamples = %d entries; want 0", len(s))
	}
}

// The survey map must reach the controllers that matter for a controller-to-host
// pivot, or the survey would quietly skip them.
func TestASPEEDSurveyPagesCoverKeyControllers(t *testing.T) {
	names := map[string]bool{}
	for _, pg := range ASPEEDSurveyPages() {
		names[pg.Name] = true
	}
	for _, want := range []string{"scu", "scu04", "xdma", "sdmc", "gpio", "i2c", "espi", "flash-window", "dram"} {
		if !names[want] {
			t.Errorf("survey map missing %q", want)
		}
	}
}
