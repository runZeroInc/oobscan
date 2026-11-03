package report

import (
	"fmt"
	"strings"
	"testing"
)

func TestPasswordShape(t *testing.T) {
	cases := []struct{ pw, mask string }{
		{"29935983", "NNNNNNNN"},
		{"CBP3GN23", "AAANAANN"}, // N is the letter N, not a digit
		{"admin", "aaaaa"},
		{"Passw0rd!", "AaaaaNaax"},
		{"", ""},
	}
	for _, c := range cases {
		mask, _, ok := passwordShape(c.pw)
		if c.pw == "" {
			if ok {
				t.Errorf("passwordShape(%q) ok=true, want false", c.pw)
			}
			continue
		}
		if !ok || mask != c.mask {
			t.Errorf("passwordShape(%q) = %q, want %q", c.pw, mask, c.mask)
		}
	}
}

// An all-digit family that used every digit reads as \d{n}; a family whose
// observed alphabet has gaps must show the gaps, because the excluded
// characters are the finding.
func TestPatternRegexReflectsObservedAlphabet(t *testing.T) {
	digits := map[rune]int{}
	for _, r := range "0123456789" {
		digits[r] = 1
	}
	got := patternRegex(digits, map[charClass]bool{classDigit: true}, 8)
	if want := `\d{8}`; got != want {
		t.Errorf("all-digit regex = %q, want %q", got, want)
	}

	// Uppercase + digits, but never 0 or 1 -- the HPE iLO alphanumeric shape.
	alnum := map[rune]int{}
	for _, r := range "23456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		alnum[r] = 1
	}
	got = patternRegex(alnum, map[charClass]bool{classDigit: true, classUpper: true}, 8)
	if want := "[2-9A-Z]{8}"; got != want {
		t.Errorf("alnum regex = %q, want %q", got, want)
	}
}

func TestCompressRanges(t *testing.T) {
	cases := []struct{ in, want string }{
		{"23456789", "2-9"},
		{"ACE", "ACE"},   // no run of 3+
		{"ABCZ", "A-CZ"}, // run then a single
		{"", ""},
	}
	for _, c := range cases {
		if got := compressRanges([]rune(c.in)); got != c.want {
			t.Errorf("compressRanges(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The per-unit rule is the whole basis of the analysis: a plaintext shared by
// many hosts is a vendor default and must not join a generated family, because
// doing so widens the family's observed alphabet and destroys the
// missing-character signal.
func TestSharedCredentialExcludedFromPatterns(t *testing.T) {
	a := newPatternAccum()
	// A generated family, large enough to be characterized, never using 0 or 1.
	const digits, letters = "23456789", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for i := range 26 {
		b := []byte{digits[i%len(digits)]}
		for j := range 7 {
			b = append(b, letters[(i*5+j*3)%len(letters)])
		}
		a.add(string(b), fmt.Sprintf("198.51.100.%d", i+1), "hpe", "hpe iLO4")
	}
	// A shared default of the same shape, carrying a 0, on many hosts.
	for i := range 40 {
		a.add("0ASSWORD", fmt.Sprintf("203.0.113.%d", i+1), "hpe", "hpe iLO4")
	}

	rows := a.patternRows()
	if len(rows) != 1 {
		t.Fatalf("patternRows() = %d rows, want 1: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.Distinct != 26 {
		t.Errorf("Distinct = %d, want 26 (the shared default must be excluded)", r.Distinct)
	}
	if strings.ContainsRune(r.Alphabet, '0') {
		t.Errorf("Alphabet = %q, must not contain '0' from the shared default", r.Alphabet)
	}
	if !strings.ContainsRune(r.Missing, '0') || !strings.ContainsRune(r.Missing, '1') {
		t.Errorf("Missing = %q, want it to report both 0 and 1 as unused", r.Missing)
	}
}

// A family too small to say anything about its own alphabet is not a described
// pattern, so it is not reported at all. Without this, five 8-character
// lowercase passwords (40 characters over a 26-letter alphabet) would surface
// as a "pattern" whose dozen unused letters are pure sampling noise.
func TestUndersampledFamilyNotReported(t *testing.T) {
	a := newPatternAccum()
	for i, pw := range []string{"password", "mustangs", "baseball", "computer", "trombone"} {
		a.add(pw, fmt.Sprintf("192.0.2.%d", i+1), "dell", "")
	}
	if rows := a.patternRows(); len(rows) != 0 {
		t.Errorf("want no rows for an uncharacterized family, got %+v", rows)
	}
}

// A factory password is printed on a label and often barcoded, so generators do
// not emit symbols; a symbol-bearing family is operator-chosen.
func TestSymbolFamilyNotReported(t *testing.T) {
	a := newPatternAccum()
	pws := []string{"Aa1!bcde", "Bb2@cdef", "Cc3#defg", "Dd4$efgh", "Ee5%fghi",
		"Ff6^ghij", "Gg7&hijk", "Hh8*ijkl", "Ii9(jklm", "Jj0)klmn",
		"Kk1!lmno", "Ll2@mnop", "Mm3#nopq", "Nn4$opqr", "Oo5%pqrs"}
	for i, pw := range pws {
		a.add(pw, fmt.Sprintf("192.0.2.%d", i+1), "dell", "")
	}
	if rows := a.patternRows(); len(rows) != 0 {
		t.Errorf("want no rows for a symbol-bearing family, got %+v", rows)
	}
}

// With enough observed characters the absence becomes reportable. Every value
// here is one digit followed by seven uppercase letters, so they form a single
// family, and none of them uses 0 or 1 -- the HPE iLO exclusion.
func TestMissingCharsReportedWhenWellSampled(t *testing.T) {
	const digits, letters = "23456789", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	a := newPatternAccum()
	for i := range 26 {
		b := []byte{digits[i%len(digits)]}
		for j := range 7 {
			b = append(b, letters[(i*5+j*3)%len(letters)])
		}
		a.add(string(b), fmt.Sprintf("192.0.2.%d", i+1), "hpe", "hpe iLO4")
	}
	rows := a.patternRows()
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d: %+v", len(rows), rows)
	}
	r := rows[0]
	if !strings.ContainsRune(r.Missing, '0') || !strings.ContainsRune(r.Missing, '1') {
		t.Errorf("Missing = %q, want it to include 0 and 1", r.Missing)
	}
	if strings.ContainsRune(r.Alphabet, '0') || strings.ContainsRune(r.Alphabet, '1') {
		t.Errorf("Alphabet = %q, must not contain 0 or 1", r.Alphabet)
	}
}

// A generator over [A-Z0-9] emits an all-letters value now and then, and those
// draws land in their own class-keyed family even though nothing distinguishes
// them. The narrower family must collapse into the more-seen one, and say so.
func TestOverlappingFamiliesCollapse(t *testing.T) {
	const digits, letters = "23456789", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	a := newPatternAccum()
	host := 0
	add := func(pw string) {
		host++
		a.add(pw, fmt.Sprintf("192.0.2.%d", host), "HPE", "HPE iLO5")
	}
	// The main family: one digit + seven uppercase letters.
	for i := range 26 {
		b := []byte{digits[i%len(digits)]}
		for j := range 7 {
			b = append(b, letters[(i*5+j*3)%len(letters)])
		}
		add(string(b))
	}
	// The digit-free tail of the same generator: eight uppercase letters.
	for i := range 8 {
		b := []byte{}
		for j := range 8 {
			b = append(b, letters[(i*7+j*5)%len(letters)])
		}
		add(string(b))
	}

	rows := a.patternRows()
	if len(rows) != 1 {
		t.Fatalf("overlapping families must collapse to 1 row, got %d: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.Distinct != 34 {
		t.Errorf("Distinct = %d, want 34 (26 + the 8 absorbed)", r.Distinct)
	}
	if len(r.Absorbed) != 1 {
		t.Errorf("Absorbed = %+v, want the folded uppercase-only family named", r.Absorbed)
	}
	// The surviving row keeps the wider class set, so digits stay in its alphabet.
	if !strings.ContainsRune(r.Alphabet, '2') {
		t.Errorf("Alphabet = %q, want the digit class retained", r.Alphabet)
	}
}

// Direction is the safety property: only the less-seen family is absorbed, so a
// large all-digit generator is never swallowed by a small alphanumeric one that
// merely has a superset of its character classes.
func TestCollapseNeverSwallowsTheLargerFamily(t *testing.T) {
	const digits, letters = "23456789", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	a := newPatternAccum()
	host := 0
	// A big all-digit generator.
	for i := range 60 {
		a.add(fmt.Sprintf("%08d", 10000000+i*137), fmt.Sprintf("192.0.2.%d", host), "HPE", "")
		host++
	}
	// A small alphanumeric family whose classes are a superset of digits-only.
	for i := range 26 {
		b := []byte{digits[i%len(digits)]}
		for j := range 7 {
			b = append(b, letters[(i*5+j*3)%len(letters)])
		}
		a.add(string(b), fmt.Sprintf("198.51.100.%d", i+1), "HPE", "")
	}

	rows := a.patternRows()
	if len(rows) != 2 {
		t.Fatalf("want both families kept, got %d: %+v", len(rows), rows)
	}
	if rows[0].Distinct != 60 || rows[0].Regex != `\d{8}` {
		t.Errorf("rows[0] = %s/%d, want \\d{8}/60", rows[0].Regex, rows[0].Distinct)
	}
	if len(rows[0].Absorbed) != 0 {
		t.Errorf("the digit family must absorb nothing, got %+v", rows[0].Absorbed)
	}
	if rows[1].Distinct != 26 {
		t.Errorf("rows[1].Distinct = %d, want 26", rows[1].Distinct)
	}
}

// Overlap is only collapsed within one vendor: two vendors' generators that
// happen to share a shape are different generators.
func TestCollapseIsPerVendor(t *testing.T) {
	const digits, letters = "23456789", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	a := newPatternAccum()
	for i := range 26 {
		b := []byte{digits[i%len(digits)]}
		for j := range 7 {
			b = append(b, letters[(i*5+j*3)%len(letters)])
		}
		a.add(string(b), fmt.Sprintf("192.0.2.%d", i+1), "HPE", "")
	}
	// A different vendor's all-uppercase family, big enough to stand alone.
	for i := range 20 {
		b := []byte{}
		for j := range 8 {
			b = append(b, letters[(i*3+j*7)%len(letters)])
		}
		a.add(string(b), fmt.Sprintf("198.51.100.%d", i+1), "Dell", "")
	}
	rows := a.patternRows()
	if len(rows) != 2 {
		t.Fatalf("want 2 rows (one per vendor), got %d: %+v", len(rows), rows)
	}
	for _, r := range rows {
		if len(r.Absorbed) != 0 {
			t.Errorf("%s (%s) absorbed %+v across vendors", r.Regex, r.Vendor, r.Absorbed)
		}
	}
}

func TestPatternRowFacets(t *testing.T) {
	a := newPatternAccum()
	// Six per-unit values, four of them concentrated in one /24.
	hosts := []string{
		"192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13",
		"198.51.100.7", "203.0.113.9", "203.0.113.10",
	}
	pws := []string{"29935983", "16419642", "49372661", "88485558", "93051170", "61016132", "77218394"}
	for i, pw := range pws {
		a.add(pw, hosts[i], "hpe", "hpe ProLiant DL380p Gen8")
	}
	rows := a.patternRows()
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	r := rows[0]
	if r.Regex != `\d{8}` {
		t.Errorf("Regex = %q, want \\d{8}", r.Regex)
	}
	if r.Mask != "NNNNNNNN" {
		t.Errorf("Mask = %q, want NNNNNNNN", r.Mask)
	}
	if r.Hosts != 7 || r.Distinct != 7 {
		t.Errorf("Hosts/Distinct = %d/%d, want 7/7", r.Hosts, r.Distinct)
	}
	if len(r.Vendors) != 1 || r.Vendors[0].Value != "hpe" {
		t.Errorf("Vendors = %+v, want hpe", r.Vendors)
	}
	if len(r.Products) != 1 || r.Products[0].Value != "hpe ProLiant DL380p Gen8" {
		t.Errorf("Products = %+v", r.Products)
	}
}

// Too few distinct values is not evidence of a generator, even when they are
// all from one vendor.
func TestPatternMinDistinct(t *testing.T) {
	a := newPatternAccum()
	for i, pw := range []string{"29935983", "16419642", "49372661", "88485558"} {
		a.add(pw, fmt.Sprintf("192.0.2.%d", i+1), "hpe", "")
	}
	if rows := a.patternRows(); len(rows) != 0 {
		t.Errorf("want no rows below minPatternDistinct, got %+v", rows)
	}
}

// A shape shared by operators across many vendors is not a generator. This is
// the filter that keeps a real corpus from surfacing a dozen meaningless
// families of human-chosen passwords that merely share a length and class.
func TestPatternRequiresVendorConcentration(t *testing.T) {
	pws := []string{"29935983", "16419642", "49372661", "88485558", "93051170", "61016132", "77218394"}
	vendors := []string{"Supermicro", "Dell", "AMI", "Huawei", "Intel", "Cisco", "Lenovo"}

	spread := newPatternAccum()
	for i, pw := range pws {
		spread.add(pw, fmt.Sprintf("192.0.2.%d", i+1), vendors[i], "")
	}
	if rows := spread.patternRows(); len(rows) != 0 {
		t.Errorf("a shape spread across %d vendors must not be reported, got %+v", len(vendors), rows)
	}

	// The same shape concentrated in one vendor is reported, and names it.
	one := newPatternAccum()
	for i, pw := range pws {
		one.add(pw, fmt.Sprintf("192.0.2.%d", i+1), "Supermicro", "")
	}
	rows := one.patternRows()
	if len(rows) != 1 {
		t.Fatalf("want 1 row for a vendor-concentrated family, got %d", len(rows))
	}
	if rows[0].Vendor != "Supermicro" || rows[0].Concentration != 1 {
		t.Errorf("Vendor/Concentration = %q/%v, want Supermicro/1", rows[0].Vendor, rows[0].Concentration)
	}
}

// "Unknown" is not a manufacturer, so a family concentrating there is not
// attributable and must not be reported as a vendor's generator.
func TestPatternUnknownVendorNotConcentration(t *testing.T) {
	a := newPatternAccum()
	for i, pw := range []string{"29935983", "16419642", "49372661", "88485558", "93051170", "61016132", "77218394"} {
		a.add(pw, fmt.Sprintf("192.0.2.%d", i+1), "Unknown", "")
	}
	if rows := a.patternRows(); len(rows) != 0 {
		t.Errorf("want no rows for an unattributed family, got %+v", rows)
	}
}

// A host with several RAKP rows carrying the same password counts once, so a
// multi-hash host cannot fake per-unit breadth.
func TestPatternHostDedup(t *testing.T) {
	a := newPatternAccum()
	for range 5 {
		a.add("29935983", "192.0.2.1", "hpe", "") // one host, five RAKP rows
	}
	for i, pw := range []string{"16419642", "49372661", "88485558", "93051170", "61016132", "77218394"} {
		a.add(pw, fmt.Sprintf("192.0.2.%d", i+2), "hpe", "")
	}
	rows := a.patternRows()
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].Hosts != 7 {
		t.Errorf("Hosts = %d, want 7 (repeat rows on one host collapse)", rows[0].Hosts)
	}
}

// Merging sources must dedup by host, so a host present in two corpora is not
// counted twice in the combined view.
func TestPatternMergeDedupsHosts(t *testing.T) {
	a, b := newPatternAccum(), newPatternAccum()
	a.add("29935983", "192.0.2.1", "hpe", "")
	b.add("29935983", "192.0.2.1", "hpe", "") // same host, second source
	for i, pw := range []string{"16419642", "49372661", "88485558", "93051170", "61016132", "77218394"} {
		b.add(pw, fmt.Sprintf("192.0.2.%d", i+2), "hpe", "")
	}
	a.merge(b)
	rows := a.patternRows()
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].Hosts != 7 {
		t.Errorf("Hosts = %d, want 7", rows[0].Hosts)
	}
}

func TestPasswordsViewCombines(t *testing.T) {
	a, b := newPatternAccum(), newPatternAccum()
	for i, pw := range []string{"29935983", "16419642", "49372661", "88485558", "93051170", "61016132", "77218394"} {
		a.add(pw, fmt.Sprintf("192.0.2.%d", i+1), "hpe", "")
	}
	for i := range 30 {
		b.add("admin", fmt.Sprintf("198.51.100.%d", i+1), "supermicro", "")
	}
	v := passwordsView([]string{"Internal", "External"}, []*patternAccum{a, b})
	if v == nil {
		t.Fatal("passwordsView() = nil")
	}
	if v.PerUnit != 7 {
		t.Errorf("PerUnit = %d, want 7", v.PerUnit)
	}
	if v.Shared != 1 {
		t.Errorf("Shared = %d, want 1", v.Shared)
	}
	if len(v.SharedTop) != 1 || v.SharedTop[0].Value != "admin" || v.SharedTop[0].Count != 30 {
		t.Errorf("SharedTop = %+v", v.SharedTop)
	}
	if v.Hosts != 37 {
		t.Errorf("Hosts = %d, want 37", v.Hosts)
	}
	// Three samples cannot exhibit all ten digits, so the regex is over the
	// observed alphabet, not \d -- that narrowing is the intended behaviour.
	if len(v.Patterns) != 1 || v.Patterns[0].Mask != "NNNNNNNN" {
		t.Errorf("Patterns = %+v", v.Patterns)
	}
	// Per-source host counts moved to the overview slide, which reads them from
	// the source views rather than from the pooled password analysis.
	if v.Hosts != 37 {
		t.Errorf("Hosts = %d, want the pooled host count across both sources", v.Hosts)
	}
}

func TestPasswordsViewEmpty(t *testing.T) {
	if v := passwordsView([]string{"A"}, []*patternAccum{newPatternAccum()}); v != nil {
		t.Errorf("passwordsView() with no cracks = %+v, want nil", v)
	}
}
