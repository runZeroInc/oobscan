package check

import (
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// TestDefaultUserKeyCriticalFindingCVE locks the CVE-2026-16141 disclosure CVE onto
// the confirmed-bypass finding (see disclosure/CVE-mapping.md).
func TestDefaultUserKeyCriticalFindingCVE(t *testing.T) {
	f := defaultUserKeyCriticalFinding(&DefaultUserKeyBypassProbe{
		Suite: 17, AuthBypassed: true, UsernameUsed: "root",
		RAKP1Status: 0x0a, RAKP3Status: 0x00,
	})
	if f.Check != "ipmi.openbmc.defaultUserKeyAuthBypass" || f.Risk != "critical" {
		t.Fatalf("finding = %+v", f)
	}
	if len(f.CVE) != 1 || f.CVE[0] != "CVE-2026-16141" {
		t.Errorf("CVE = %v, want [CVE-2026-16141]", f.CVE)
	}
}

// TestExplainDefaultUserKeyRender checks the explain output renders clean
// markdown: the backtick sentinel is fully substituted, code spans are present,
// and the supplied evidence fields (canonicalized keys) land in the table.
func TestExplainDefaultUserKeyRender(t *testing.T) {
	confirmed := engine.Finding{Fields: engine.F(
		"authBypassed", "true",
		"bmcSid", "0x2c86b0a6",
		"suite", "17",
		"rakp1Status", "0x0a",
		"rakp1StatusName", "unauthorized role or privilege",
		"usernameUsed", "root",
		"bmc-random", "00000000b06187000000000065000000",
		"bmc-randomHeapPtr", "0x008761b0",
		"rakp3Status", "0x00",
		"rakp3StatusName", "no errors",
	)}
	s := explainOpenBMCDefaultUserKeyBypass("192.0.2.10", confirmed)
	if strings.Contains(s, explainDefaultUserKeyBacktick) {
		t.Errorf("confirmed render still contains the backtick sentinel %q", explainDefaultUserKeyBacktick)
	}
	for _, want := range []string{"`userKey`", "`0penBmc`", "`RAKP34()`",
		"00000000b06187000000000065000000", "heap pointer 0x008761b0",
		"0x0a (unauthorized role or privilege)", "CWE-798"} {
		if !strings.Contains(s, want) {
			t.Errorf("confirmed render missing %q", want)
		}
	}

	pre := engine.Finding{Fields: engine.F(
		"authBypassed", "false",
		"rakp1Status", "0x0a",
		"rakp1StatusName", "unauthorized role or privilege",
		"attempts", "68",
	)}
	ps := explainOpenBMCDefaultUserKeyBypass("192.0.2.10", pre)
	if strings.Contains(ps, explainDefaultUserKeyBacktick) {
		t.Errorf("precondition render still contains the backtick sentinel")
	}
	for _, want := range []string{"precondition only", "across 68 attempts", "`--ipmi-openbmc-userkey-bmcrand`"} {
		if !strings.Contains(ps, want) {
			t.Errorf("precondition render missing %q", want)
		}
	}

	patchLead := engine.Finding{Fields: engine.F(
		"authBypassed", "false",
		"patchStatus", "likely-unpatched",
		"rakp1Status", "0x0a",
		"rakp1StatusName", "unauthorized role or privilege",
		"rakp3Status", "0x0f",
		"rakp3StatusName", "invalid integrity check",
		"fullTestOption", "--ipmi-openbmc-default-userkey",
	)}
	ls := explainOpenBMCDefaultUserKeyBypass("192.0.2.10", patchLead)
	for _, want := range []string{"likely unpatched", "0x0f (invalid integrity check)", "`--ipmi-openbmc-default-userkey`"} {
		if !strings.Contains(ls, want) {
			t.Errorf("patch-lead render missing %q", want)
		}
	}
}

func TestParseUserSuppliedBMCRand(t *testing.T) {
	cases := []struct {
		in   string
		want string // hex of 16-byte result, "" = error
	}{
		{"0000000020e066000000000065000000", "0000000020e066000000000065000000"}, // full 16B verbatim
		{"0x0066e020", "0000000020e066000000000065000000"},                       // 4B heap ptr -> residue
		{"0066e020", "0000000020e066000000000065000000"},                         // no 0x
		{"00 66 e0 20", "0000000020e066000000000065000000"},                      // spaces ok
		{"0x00:66:e0:20", "0000000020e066000000000065000000"},                    // colons ok
		{"", ""},       // empty -> error
		{"zz", ""},     // bad hex -> error
		{"001122", ""}, // 3 bytes -> error
	}
	for _, c := range cases {
		got, err := parseUserSuppliedBMCRand(c.in)
		if c.want == "" {
			if err == nil {
				t.Errorf("parseUserSuppliedBMCRand(%q): expected error, got % x", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseUserSuppliedBMCRand(%q): unexpected error %v", c.in, err)
			continue
		}
		if h := hexOf(got); h != c.want {
			t.Errorf("parseUserSuppliedBMCRand(%q) = %s, want %s", c.in, h, c.want)
		}
	}
}

func TestDefaultUserKeySuppliedValueSkipsSweep(t *testing.T) {
	if !skipDefaultUserKeySweep([]byte{1}) {
		t.Fatal("supplied bmc-random should skip the heap sweep")
	}
	if skipDefaultUserKeySweep(nil) {
		t.Fatal("missing bmc-random should allow the configured heap sweep")
	}
}

func TestParseHeapAddr(t *testing.T) {
	if v, err := parseHeapAddr("", 0x1234); err != nil || v != 0x1234 {
		t.Errorf("empty should return default: got 0x%x err %v", v, err)
	}
	if v, err := parseHeapAddr("0x00623000", 0); err != nil || v != 0x00623000 {
		t.Errorf("0x00623000: got 0x%x err %v", v, err)
	}
	if v, err := parseHeapAddr("686000", 0); err != nil || v != 0x686000 {
		t.Errorf("686000: got 0x%x err %v", v, err)
	}
	if _, err := parseHeapAddr("nothex", 7); err == nil {
		t.Errorf("bad hex should error")
	}
}

func TestParsePageOffsets(t *testing.T) {
	cases := []struct {
		in   string
		want []uint32
	}{
		{"", nil},
		{"0xae8", []uint32{0xae8}},
		{"ae8", []uint32{0xae8}},
		{"0xae8,0xae0,0x650", []uint32{0xae8, 0xae0, 0x650}},
		{" 0xae8 , ae0 ", []uint32{0xae8, 0xae0}},
		{"0x1ae8", []uint32{0xae8}},      // masked to low 12 bits
		{"0xae8,0xae8", []uint32{0xae8}}, // deduped
		{"zz,0x650", []uint32{0x650}},    // bad entry skipped
	}
	for _, c := range cases {
		got := parsePageOffsets(c.in)
		if len(got) != len(c.want) {
			t.Errorf("parsePageOffsets(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parsePageOffsets(%q) = %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}

// TestForEachSweepAddr verifies the page-offset fast path emits exactly the
// requested in-page offset(s) one page at a time, and that the empty-offset path
// steps through every 4-byte-aligned offset (the full space).
func TestForEachSweepAddr(t *testing.T) {
	start, end := uint32(0x01d03000), uint32(0x01d13000) // 16 pages

	// Page-strided: single in-page offset 0xae8 -> one address per page.
	var stride []uint32
	forEachSweepAddr(start, end, []uint32{0xae8}, func(addr uint32) bool {
		stride = append(stride, addr)
		return true
	})
	for _, a := range stride {
		if a&0xfff != 0xae8 {
			t.Errorf("page-stride emitted 0x%08x with in-page offset 0x%03x, want 0xae8", a, a&0xfff)
		}
		if a < start || a > end {
			t.Errorf("page-stride emitted 0x%08x outside [0x%08x,0x%08x]", a, start, end)
		}
	}
	if len(stride) < 15 || len(stride) > 17 { // ~16 pages
		t.Errorf("page-stride over 16 pages emitted %d addresses, want ~16", len(stride))
	}

	// Multiple offsets: emits each in-range offset per page. Over [start,start+0x2000]
	// the first two pages contribute both offsets (4); the final page (== end) has
	// both offsets above end, so 4 total.
	var multi []uint32
	forEachSweepAddr(start, start+0x2000, []uint32{0xae8, 0x650}, func(addr uint32) bool {
		multi = append(multi, addr)
		return true
	})
	if len(multi) != 4 {
		t.Errorf("2-offset stride emitted %d addresses, want 4", len(multi))
	}
	for _, a := range multi {
		if o := a & 0xfff; o != 0xae8 && o != 0x650 {
			t.Errorf("2-offset stride emitted 0x%08x with unexpected offset 0x%03x", a, o)
		}
	}

	// Full space (no offsets): consecutive sweepOffsetStride steps (malloc
	// alignment on 32-bit ARM glibc); verify early-stop works.
	var full []uint32
	forEachSweepAddr(start, start+0x40, nil, func(addr uint32) bool {
		full = append(full, addr)
		return len(full) < 4 // stop after 4
	})
	if len(full) != 4 {
		t.Fatalf("full sweep early-stop: got %d addresses, want 4", len(full))
	}
	for i, a := range full {
		if want := start + uint32(i*sweepOffsetStride); a != want {
			t.Errorf("full sweep addr[%d]=0x%08x, want 0x%08x", i, a, want)
		}
	}
}

// TestForEachSweepAddrPageMajor pins the ordering property the whole fix turns
// on: a page is fully exhausted (known offsets first) before the next page
// begins, so a build whose in-page offset is not in the known list is still
// reached a few pages into an operator-narrowed range.
func TestForEachSweepAddrPageMajor(t *testing.T) {
	const base = uint32(0x0179d000)
	known := []uint32{0x740, 0x1b0}

	var got []uint32
	forEachSweepAddrPageMajor(base, base+0x1fff, known, func(addr uint32) bool {
		got = append(got, addr)
		return true
	})

	perPage := 0x1000 / sweepOffsetStride
	if want := 2 * perPage; len(got) != want {
		t.Fatalf("emitted %d addresses over 2 pages, want %d", len(got), want)
	}
	// Known offsets lead each page, in the order given.
	if got[0] != base|0x740 || got[1] != base|0x1b0 {
		t.Errorf("page 0 did not lead with the known offsets: got 0x%08x,0x%08x", got[0], got[1])
	}
	if got[perPage] != (base+0x1000)|0x740 || got[perPage+1] != (base+0x1000)|0x1b0 {
		t.Errorf("page 1 did not lead with the known offsets: got 0x%08x,0x%08x", got[perPage], got[perPage+1])
	}
	// Page 0 is fully exhausted before page 1 starts.
	for i, a := range got[:perPage] {
		if a&^uint32(0xfff) != base {
			t.Fatalf("addr[%d]=0x%08x left page 0 before it was exhausted", i, a)
		}
	}
	// No duplicates, and every 8-aligned offset in page 0 is covered exactly once.
	seen := map[uint32]bool{}
	for _, a := range got[:perPage] {
		if seen[a] {
			t.Errorf("duplicate candidate 0x%08x", a)
		}
		seen[a] = true
	}
	for off := uint32(0); off < 0x1000; off += sweepOffsetStride {
		if !seen[base|off] {
			t.Errorf("page 0 missed offset 0x%03x", off)
		}
	}
}

// TestSweepPassesNarrowRangeIsExhaustive is the regression guard for the
// reported bug: with an operator-narrowed range the plan must be able to reach
// an in-page offset that is not in defaultUserKeyPageOffsets. The old
// offset-major plan put every such candidate behind a full known-offset pass
// over the entire range, so on a wide or mistyped range it was never reached.
func TestSweepPassesNarrowRangeIsExhaustive(t *testing.T) {
	// The heap from the bug report: 0179d000-017df000 (66 pages).
	passes := sweepPasses(0x0179d000, 0x017df000, nil)
	if len(passes) != 1 {
		t.Fatalf("narrow range produced %d passes, want a single exhaustive pass", len(passes))
	}
	// An offset deliberately absent from the known list.
	const target = uint32(0x017a3338)
	for _, off := range defaultUserKeyPageOffsets {
		if off == target&0xfff {
			t.Fatalf("test offset 0x%03x is in the known list; pick another", off)
		}
	}
	found, n := false, 0
	passes[0].each(func(addr uint32) bool {
		n++
		if addr == target {
			found = true
			return false
		}
		return true
	})
	if !found {
		t.Fatalf("exhaustive pass never emitted 0x%08x", target)
	}
	// It must arrive early -- within the first handful of pages, not after a
	// full-range pass. 0x017a3338 is 6 pages in, so ~7 pages of candidates.
	if maxWant := 8 * (0x1000 / sweepOffsetStride); n > maxWant {
		t.Errorf("reached 0x%08x only after %d candidates, want <=%d (page-major ordering)", target, n, maxWant)
	}
}

// TestSweepPassesWideRangeKeepsCheapTierFirst confirms the wide/blind default
// still tries the cheap known-offset tier across the whole space before paying
// for the exhaustive tier -- with an unknown heap base, the offset is the better
// thing to hold fixed.
func TestSweepPassesWideRangeKeepsCheapTierFirst(t *testing.T) {
	passes := sweepPasses(defaultUserKeySweepStart, defaultUserKeySweepEnd, nil)
	if len(passes) != 2 {
		t.Fatalf("wide range produced %d passes, want 2 tiers", len(passes))
	}
	if passes[0].candidates >= passes[1].candidates {
		t.Errorf("tier 0 (%d candidates) should be far cheaper than tier 1 (%d)",
			passes[0].candidates, passes[1].candidates)
	}
}

// TestSweepPassesHonorsOperatorOffset keeps the operator's explicit
// --ipmi-openbmc-userkey-page-offset literal: it means "only this offset".
func TestSweepPassesHonorsOperatorOffset(t *testing.T) {
	passes := sweepPasses(0x0179d000, 0x017df000, []uint32{0xae8})
	if len(passes) != 1 {
		t.Fatalf("operator offset produced %d passes, want 1", len(passes))
	}
	passes[0].each(func(addr uint32) bool {
		if addr&0xfff != 0xae8 {
			t.Fatalf("operator-pinned sweep emitted 0x%08x (offset 0x%03x)", addr, addr&0xfff)
		}
		return true
	})
}

func hexOf(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexd[c>>4]
		out[i*2+1] = hexd[c&0xf]
	}
	return string(out)
}

// TestSweepPacerAdaptsToObservedLatency covers the pacing the sweep relies on:
// cold-start at the ceiling, tighten once real latencies arrive, never drop
// below the floor, and never exceed the ceiling.
func TestSweepPacerAdaptsToObservedLatency(t *testing.T) {
	p := newSweepPacer(maxSweepAttemptTimeout)
	if got := p.timeout(); got != maxSweepAttemptTimeout {
		t.Errorf("cold start timeout=%s, want the %s ceiling", got, maxSweepAttemptTimeout)
	}

	// A 10ms-RTT management LAN: replies land in tens of ms.
	for range 50 {
		p.observe(12 * time.Millisecond)
	}
	got := p.timeout()
	if got >= maxSweepAttemptTimeout {
		t.Errorf("after 50 fast samples timeout=%s, want well under the %s ceiling", got, maxSweepAttemptTimeout)
	}
	if got < minSweepAttemptTimeout {
		t.Errorf("timeout=%s dropped below the %s floor", got, minSweepAttemptTimeout)
	}
	// srtt+4*rttvar on a steady 12ms reply converges near the floor -- an order
	// of magnitude cheaper per drop than the old fixed 750ms.
	if got > 100*time.Millisecond {
		t.Errorf("timeout=%s, want the pacer to converge near the observed 12ms", got)
	}

	// A very slow target must never be paced below its own latency, or every
	// candidate would be misread as a drop.
	slow := newSweepPacer(maxSweepAttemptTimeout)
	for range 10 {
		slow.observe(400 * time.Millisecond)
	}
	if got := slow.timeout(); got < 400*time.Millisecond {
		t.Errorf("slow target timeout=%s, want at least the observed 400ms latency", got)
	}

	// Jitter widens the wait: the same mean with spread must pace slower than
	// the steady case, or half the replies would be misread as drops.
	jittery := newSweepPacer(maxSweepAttemptTimeout)
	for i := range 50 {
		if i%2 == 0 {
			jittery.observe(4 * time.Millisecond)
		} else {
			jittery.observe(20 * time.Millisecond)
		}
	}
	if jittery.timeout() <= got {
		t.Errorf("jittery target paced at %s, want more than the steady target's %s", jittery.timeout(), got)
	}
}

// TestSweepPacerBacksOffAndRecovers covers the drop path: consecutive unanswered
// requests widen the wait, and the next answered reply clears it.
func TestSweepPacerBacksOffAndRecovers(t *testing.T) {
	// Pick a latency above the floor so backoff is observable; on a fast LAN the
	// floor legitimately absorbs the first doublings (a 10ms target is already
	// given 40ms), which is the clamp doing its job, not backoff failing.
	p := newSweepPacer(maxSweepAttemptTimeout)
	for range 30 {
		p.observe(60 * time.Millisecond)
	}
	steady := p.timeout()
	if steady <= minSweepAttemptTimeout {
		t.Fatalf("steady timeout %s is at the floor; the backoff assertions below would be vacuous", steady)
	}

	p.backoff()
	once := p.timeout()
	if once <= steady {
		t.Errorf("after one backoff timeout=%s, want more than the steady %s", once, steady)
	}
	p.backoff()
	if twice := p.timeout(); twice <= once {
		t.Errorf("after two backoffs timeout=%s, want more than %s", twice, once)
	}

	// Backoff is bounded by the ceiling, not unbounded doubling.
	for range 20 {
		p.backoff()
	}
	if got := p.timeout(); got > maxSweepAttemptTimeout {
		t.Errorf("backoff ran past the %s ceiling: %s", maxSweepAttemptTimeout, got)
	}

	// An answered reply clears the backoff.
	p.observe(60 * time.Millisecond)
	if got := p.timeout(); got > steady {
		t.Errorf("after recovery timeout=%s, want back to about the steady %s", got, steady)
	}

	// On a fast target the floor absorbs early backoffs -- 10ms already gets the
	// 40ms floor, which is 4x the observed latency.
	fast := newSweepPacer(maxSweepAttemptTimeout)
	for range 30 {
		fast.observe(10 * time.Millisecond)
	}
	if got := fast.timeout(); got != minSweepAttemptTimeout {
		t.Errorf("fast target steady timeout=%s, want the %s floor", got, minSweepAttemptTimeout)
	}
	fast.backoff()
	if got := fast.timeout(); got != minSweepAttemptTimeout {
		t.Errorf("fast target after one backoff=%s, want the floor to still absorb it", got)
	}
}

// TestSweepPacerHonorsLowerProbeTimeout keeps --timeout authoritative when the
// operator sets it below the ceiling.
func TestSweepPacerHonorsLowerProbeTimeout(t *testing.T) {
	p := newSweepPacer(200 * time.Millisecond)
	if got := p.timeout(); got != 200*time.Millisecond {
		t.Errorf("cold start timeout=%s, want the supplied 200ms ceiling", got)
	}
	for range 20 {
		p.observe(150 * time.Millisecond)
	}
	if got := p.timeout(); got > 200*time.Millisecond {
		t.Errorf("timeout=%s exceeded the supplied 200ms ceiling", got)
	}
}

// TestHeapGroomResidueTiers pins the hot/cold split. The hot tier is the values
// confirmed to activate a session and is re-rolled every round; the cold tier is
// the exhaustive sliding-window coverage, sampled periodically.
func TestHeapGroomResidueTiers(t *testing.T) {
	hot := heapGroomHotResidues()
	cold := heapGroomColdResidues()

	// Every confirmed live hit must be in the hot tier.
	for _, want := range []string{"e IPMI LAN sessi", "/xyz/openbmc_pro", "/ipmi/session/et"} {
		found := false
		for _, h := range hot {
			if string(h) == want {
				found = true
			}
		}
		if !found {
			t.Errorf("confirmed residue %q missing from the hot tier", want)
		}
	}

	// Every residue is exactly 16 bytes, and the tiers are disjoint.
	hotSet := map[string]bool{}
	for _, h := range hot {
		if len(h) != 16 {
			t.Errorf("hot residue %q is %d bytes, want 16", h, len(h))
		}
		hotSet[string(h)] = true
	}
	for _, c := range cold {
		if len(c) != 16 {
			t.Errorf("cold residue %q is %d bytes, want 16", c, len(c))
		}
		if hotSet[string(c)] {
			t.Errorf("residue %q appears in both tiers", c)
		}
	}

	// The cold tier must actually cover the rest of the phosphor-logging
	// template -- the gap that heapGroomLogStringWindows was supposed to fill.
	// The one observed window sits at template offset 12, so check a couple of
	// other 4-byte-aligned windows are present.
	tmpl := heapGroomLogStringTemplate
	coldSet := map[string]bool{}
	for _, c := range cold {
		coldSet[string(c)] = true
	}
	for _, off := range []int{0, 4, 8, 16, 24} {
		if off+16 > len(tmpl) {
			continue
		}
		if w := tmpl[off : off+16]; !coldSet[w] && !hotSet[w] {
			t.Errorf("template window at offset %d (%q) is covered by neither tier", off, w)
		}
	}
	if len(cold) < 20 {
		t.Errorf("cold tier has only %d windows; expected the full sliding-window set", len(cold))
	}

	// The flat list is the union, hot first, with no duplicates.
	all := heapGroomStringResidueCandidates()
	if len(all) != len(hot)+len(cold) {
		t.Errorf("flat list has %d entries, want %d hot + %d cold", len(all), len(hot), len(cold))
	}
	for i, h := range hot {
		if string(all[i]) != string(h) {
			t.Errorf("flat list entry %d = %q, want the hot value %q", i, all[i], h)
		}
	}
}

// TestPrintableResidue keeps the log annotation honest: text residues render,
// binary ones (heap pointers) do not.
func TestPrintableResidue(t *testing.T) {
	if got := printableResidue([]byte("/xyz/openbmc_pro")); got != "/xyz/openbmc_pro" {
		t.Errorf("printableResidue(text) = %q", got)
	}
	if got := printableResidue(makeHeapResidue(0x0209a6b0)); got != "" {
		t.Errorf("printableResidue(heap ptr) = %q, want empty", got)
	}
}

// TestGroomParametersAreBounded guards the deliberate-leak side of grooming.
// The abandoned sessions are the same setup slots the probe itself needs, so an
// unbounded or too-aggressive groom would starve the search it is meant to help.
func TestGroomParametersAreBounded(t *testing.T) {
	if defaultUserKeyGroomMax <= 0 {
		t.Fatal("groom must be capped: abandoned sessions consume setup slots on the target")
	}
	if defaultUserKeyGroomEvery <= 0 {
		t.Fatal("groom interval must be positive")
	}
	// Over a full run the groom must stay a small fraction of total attempts.
	groomRounds := defaultUserKeyFastRounds / defaultUserKeyGroomEvery
	if maxGroom := groomRounds * defaultUserKeyGroomBatch; maxGroom < defaultUserKeyGroomMax {
		t.Errorf("cap %d is unreachable (schedule tops out at %d); the cap should bind, not the schedule",
			defaultUserKeyGroomMax, maxGroom)
	}
	if defaultUserKeyGroomMax > 64 {
		t.Errorf("groom cap %d is high enough to fill the setup-session table", defaultUserKeyGroomMax)
	}
}

// TestGroomAbandonSessionUnreachableHost pins the error path: a groom failure is
// one fewer stale entry, never a scan failure.
func TestGroomAbandonSessionUnreachableHost(t *testing.T) {
	suite := defaultProbeCipherSuites()[0]
	if groomAbandonSession("192.0.2.1", 623, suite, 50*time.Millisecond, 0x60000000) {
		t.Error("groom reported success against an unroutable host")
	}
}
