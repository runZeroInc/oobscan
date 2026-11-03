package report

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode"
)

// Password-pattern analysis: which recovered plaintexts look like they came out of
// a factory password *generator* rather than a shipped default, and what shape that
// generator produces. The distinction is per-unit-ness, so a plaintext seen on more
// than sharedHostCeiling hosts is treated as a shared credential and excluded from
// every family, keeping a dictionary hit from widening a generated alphabet.
//
// Caveat when reading a family: it describes the passwords that were cracked, not a
// uniform sample of what exists. Only a mask run to exhaustion yields a trustworthy
// family; one recovered by dictionary or a truncated mask has per-position structure
// that is an artifact of the attack, not a property of the generator.

const (
	// sharedHostCeiling is the most hosts a plaintext may appear on and still
	// count as a per-unit secret. Above it the value is a shared default and is
	// excluded from every family. Two allows for a re-scanned or dual-homed host
	// without admitting a real shared credential.
	sharedHostCeiling = 2

	// minPatternDistinct is the fewest distinct plaintexts a family needs before
	// it is reported. Below this there is no evidence of a generator, just a
	// handful of unrelated passwords that happen to share a length.
	minPatternDistinct = 5

	// minVendorConcentration is the share of a family's sightings that must fall
	// on a single named vendor before it is reported as a pattern. A factory
	// generator belongs to one vendor's manufacturing line, so its family is
	// almost purely that vendor, while human-chosen passwords of a given shape
	// are spread across every vendor in the corpus. Without this filter, a real
	// corpus surfaces many meaningless mixed-vendor families and buries the one
	// that is an actual generator.
	minVendorConcentration = 0.6

	// minExpectedPerChar is how many times a character must be *expected* to occur
	// under a uniform draw from the family's natural alphabet before the family
	// counts as characterized and is reported at all. It doubles as the noise filter
	// that vendor concentration cannot provide on a single-vendor corpus: without it,
	// unrelated passwords that merely share a length would report their unused
	// letters as a finding when that is only sampling noise.
	minExpectedPerChar = 5

	maxPatternRows  = 12
	maxPatternFacet = 6
)

// charClass is the character class of a single rune, in the order used to build
// both the mask and the regex.
type charClass int

const (
	classDigit charClass = iota
	classUpper
	classLower
	classOther
)

func classOf(r rune) charClass {
	switch {
	case r >= '0' && r <= '9':
		return classDigit
	case unicode.IsUpper(r) && r < 128:
		return classUpper
	case unicode.IsLower(r) && r < 128:
		return classLower
	}
	return classOther
}

// maskRune is the single letter a class contributes to a shape mask: N for a
// digit, A for uppercase, a for lowercase, x for anything else.
func (c charClass) maskRune() rune {
	switch c {
	case classDigit:
		return 'N'
	case classUpper:
		return 'A'
	case classLower:
		return 'a'
	}
	return 'x'
}

// passwordShape returns the per-position class mask ("NNNNNNNN", "AANNAAAA")
// and the set of classes present. ok is false for an empty password.
func passwordShape(pw string) (mask string, classes map[charClass]bool, ok bool) {
	if pw == "" {
		return "", nil, false
	}
	classes = map[charClass]bool{}
	var b strings.Builder
	for _, r := range pw {
		c := classOf(r)
		classes[c] = true
		b.WriteRune(c.maskRune())
	}
	return b.String(), classes, true
}

// familyKey groups passwords that plausibly come from one generator: the same
// character-class composition at the same length. It deliberately does not key
// on the per-position mask, because one generator drawing uniformly from
// [A-Z0-9] emits a different mask nearly every time.
func familyKey(classes map[charClass]bool, length int) string {
	order := []charClass{classDigit, classUpper, classLower, classOther}
	var b strings.Builder
	for _, c := range order {
		if classes[c] {
			b.WriteRune(c.maskRune())
		}
	}
	return fmt.Sprintf("%s:%d", b.String(), length)
}

// naturalAlphabet is the full character set a family's classes could have
// drawn from. Comparing it against what was actually observed is what surfaces
// a generator that excludes look-alike characters. Families containing symbols
// have no well-defined superset, so they report none.
func naturalAlphabet(classes map[charClass]bool) string {
	if classes[classOther] {
		return ""
	}
	var b strings.Builder
	if classes[classDigit] {
		b.WriteString("0123456789")
	}
	if classes[classUpper] {
		b.WriteString("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	}
	if classes[classLower] {
		b.WriteString("abcdefghijklmnopqrstuvwxyz")
	}
	return b.String()
}

// compressRanges renders a sorted rune set as a regex character-class body,
// collapsing runs of three or more consecutive runes into "a-z" form.
func compressRanges(runes []rune) string {
	if len(runes) == 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(runes); {
		j := i
		for j+1 < len(runes) && runes[j+1] == runes[j]+1 {
			j++
		}
		switch n := j - i + 1; {
		case n >= 3:
			b.WriteRune(runes[i])
			b.WriteRune('-')
			b.WriteRune(runes[j])
		default:
			for k := i; k <= j; k++ {
				b.WriteRune(runes[k])
			}
		}
		i = j + 1
	}
	return b.String()
}

// patternRegex renders the family as a regex over the alphabet actually
// observed, so an excluded character shows up in the pattern itself. An
// all-digit family collapses to the familiar \d{n} when every digit occurs.
func patternRegex(observed map[rune]int, classes map[charClass]bool, length int) string {
	runes := sortedRunes(observed)
	if len(runes) == 0 {
		return ""
	}
	if len(classes) == 1 && classes[classDigit] && len(runes) == 10 {
		return fmt.Sprintf(`\d{%d}`, length)
	}
	// Order the class body digits -> upper -> lower so it reads like a charset.
	var byClass [4][]rune
	for _, r := range runes {
		byClass[classOf(r)] = append(byClass[classOf(r)], r)
	}
	var b strings.Builder
	b.WriteByte('[')
	for _, c := range []charClass{classDigit, classUpper, classLower, classOther} {
		b.WriteString(compressRanges(byClass[c]))
	}
	b.WriteByte(']')
	return fmt.Sprintf("%s{%d}", b.String(), length)
}

func sortedRunes(m map[rune]int) []rune {
	out := make([]rune, 0, len(m))
	for r := range m {
		out = append(out, r)
	}
	slices.Sort(out)
	return out
}

// PatternRow is one detected password pattern: a family of recovered plaintexts
// sharing a character-class composition and length, with the vendors, products
// and networks it was seen in.
type PatternRow struct {
	Regex  string `json:"regex"`  // over the OBSERVED alphabet, e.g. "[2-9A-Z]{8}"
	Mask   string `json:"mask"`   // dominant per-position shape, e.g. "NNNNNNNN"
	Vendor string `json:"vendor"` // the vendor this family concentrates in
	// Concentration is that vendor's share of the family's sightings (0..1). A
	// value near 1 is what makes the family credible as one vendor's generator.
	Concentration float64 `json:"concentration"`
	Length        int     `json:"length"`
	Hosts         int     `json:"hosts"`    // hosts carrying a password of this shape
	Distinct      int     `json:"distinct"` // distinct plaintexts in the family
	Alphabet      string  `json:"alphabet"` // characters actually observed
	// Missing lists characters the family's classes allow but that never occur.
	// Every reported family is large enough for this to be meaningful, so an
	// empty value means the family uses its whole alphabet.
	Missing string `json:"missing"`
	// Absorbed names the narrower same-generator families folded into this row
	// (see mergeOverlapping), so a collapse is visible rather than silent.
	Absorbed []string `json:"absorbed,omitempty"`
	Shapes   []Pair   `json:"shapes,omitempty"`   // per-position masks, most common first
	Vendors  []Pair   `json:"vendors,omitempty"`  // vendor -> hosts
	Products []Pair   `json:"products,omitempty"` // vendor/product -> hosts
}

// dominantVendor returns the vendor holding the largest share of a family's
// sightings, and that share. An unattributed top vendor yields "" because
// "Unknown" concentrating a family says nothing about a manufacturer.
func dominantVendor(c *counter) (string, float64) {
	if c == nil || c.total == 0 {
		return "", 0
	}
	top := c.top(1)
	if len(top) == 0 || strings.EqualFold(top[0].Value, "unknown") {
		return "", 0
	}
	return top[0].Value, float64(top[0].Count) / float64(c.total)
}

// patternObs accumulates every sighting of one distinct plaintext.
type patternObs struct {
	hosts    map[string]bool
	vendors  *counter
	products *counter
}

// patternAccum collects recovered plaintexts for pattern analysis. It is keyed
// by plaintext so the per-unit test (how many hosts carry this exact value?)
// can be applied before anything is grouped into a family.
type patternAccum struct {
	byPassword map[string]*patternObs
}

func newPatternAccum() *patternAccum {
	return &patternAccum{byPassword: map[string]*patternObs{}}
}

// add records one recovered plaintext for a host. Repeat calls for the same
// (password, host) collapse, so a host with several RAKP rows carrying the same
// password counts once.
func (a *patternAccum) add(pw, host, vendor, product string) {
	pw = strings.TrimSpace(pw)
	if a == nil || pw == "" {
		return
	}
	obs := a.byPassword[pw]
	if obs == nil {
		obs = &patternObs{
			hosts: map[string]bool{}, vendors: newCounter(),
			products: newCounter(),
		}
		a.byPassword[pw] = obs
	}
	if host != "" {
		if obs.hosts[host] {
			return // already counted this host for this password
		}
		obs.hosts[host] = true
	}
	if vendor != "" {
		obs.vendors.add(vendor)
	}
	if product != "" {
		obs.products.add(product)
	}
}

// merge folds another accumulator in, preserving host-level dedup so a host
// present in two sources is not double-counted in the combined view.
func (a *patternAccum) merge(o *patternAccum) {
	if a == nil || o == nil {
		return
	}
	for pw, src := range o.byPassword {
		dst := a.byPassword[pw]
		if dst == nil {
			dst = &patternObs{
				hosts: map[string]bool{}, vendors: newCounter(),
				products: newCounter(),
			}
			a.byPassword[pw] = dst
		}
		for h := range src.hosts {
			if dst.hosts[h] {
				continue
			}
			dst.hosts[h] = true
		}
		dst.vendors.mergeFrom(src.vendors)
		dst.products.mergeFrom(src.products)
	}
}

// patternRows groups the accumulated plaintexts into families and returns the
// reportable ones, most hosts first.
// patternFamily is one candidate generator: every per-unit plaintext sharing a
// character-class composition and length, with the facets needed to describe it.
type patternFamily struct {
	classes  map[charClass]bool
	length   int
	hosts    int
	distinct int
	observed map[rune]int
	shapes   *counter
	vendors  *counter
	products *counter
	absorbed []string // regexes of narrower families folded in
}

// absorb folds a narrower family of the same generator into f, taking its
// values, facets and observed characters. regex names the folded family so the
// merge is visible in the output rather than silent.
func (f *patternFamily) absorb(o *patternFamily, regex string) {
	f.hosts += o.hosts
	f.distinct += o.distinct
	for r, n := range o.observed {
		f.observed[r] += n
	}
	f.shapes.mergeFrom(o.shapes)
	f.vendors.mergeFrom(o.vendors)
	f.products.mergeFrom(o.products)
	f.absorbed = append(f.absorbed, regex)
	f.absorbed = append(f.absorbed, o.absorbed...)
}

// classSubset reports whether every class in a is also in b.
func classSubset(a, b map[charClass]bool) bool {
	for c := range a {
		if !b[c] {
			return false
		}
	}
	return true
}

// mergeOverlapping collapses families that are one generator seen through
// different draws: a generator over [A-Z0-9] sometimes emits an all-letters
// password, which lands in its own class-keyed family and would otherwise report as
// a second, narrower pattern for the same vendor.
//
// A family is folded into the most-seen family of the same vendor and length whose
// character classes are a superset of its own. Direction is what keeps this safe:
// only the less-seen family is ever absorbed, so a large all-digit generator cannot
// be swallowed by a small alphanumeric one. Absorbed regexes ride along on the
// surviving row.
func mergeOverlapping(fams []*patternFamily, regexOf func(*patternFamily) string) []*patternFamily {
	order := make([]*patternFamily, len(fams))
	copy(order, fams)
	sort.Slice(order, func(i, j int) bool {
		if order[i].hosts != order[j].hosts {
			return order[i].hosts > order[j].hosts
		}
		if order[i].distinct != order[j].distinct {
			return order[i].distinct > order[j].distinct
		}
		return order[i].length < order[j].length
	})
	gone := make([]bool, len(order))
	for i, target := range order {
		if gone[i] {
			continue
		}
		tv, _ := dominantVendor(target.vendors)
		if tv == "" {
			continue
		}
		for j := i + 1; j < len(order); j++ {
			cand := order[j]
			if gone[j] || cand.length != target.length {
				continue
			}
			if !classSubset(cand.classes, target.classes) {
				continue
			}
			if cv, _ := dominantVendor(cand.vendors); !strings.EqualFold(cv, tv) {
				continue
			}
			target.absorb(cand, regexOf(cand))
			gone[j] = true
		}
	}
	out := make([]*patternFamily, 0, len(order))
	for i, f := range order {
		if !gone[i] {
			out = append(out, f)
		}
	}
	return out
}

func (a *patternAccum) patternRows() []PatternRow {
	if a == nil || len(a.byPassword) == 0 {
		return nil
	}
	fams := map[string]*patternFamily{}
	for pw, obs := range a.byPassword {
		hostCount := len(obs.hosts)
		// A value on many hosts is a shared default, not a per-unit secret.
		if hostCount > sharedHostCeiling {
			continue
		}
		mask, classes, ok := passwordShape(pw)
		if !ok {
			continue
		}
		// A factory password is printed on a pull-tab or carton label and is often
		// barcoded (Code 39 carries A-Z 0-9 only), so generators do not emit
		// symbols. Drop symbol-bearing values before anything is grouped, so they
		// cannot be merged into a real family and widen its alphabet.
		if classes[classOther] {
			continue
		}
		key := familyKey(classes, len([]rune(pw)))
		f := fams[key]
		if f == nil {
			f = &patternFamily{
				classes: classes, length: len([]rune(pw)), observed: map[rune]int{},
				shapes: newCounter(), vendors: newCounter(),
				products: newCounter(),
			}
			fams[key] = f
		}
		f.distinct++
		// A password with no host attribution still evidences the shape.
		if hostCount == 0 {
			hostCount = 1
		}
		f.hosts += hostCount
		f.shapes.add(mask)
		for _, r := range pw {
			f.observed[r]++
		}
		f.vendors.mergeFrom(obs.vendors)
		f.products.mergeFrom(obs.products)
	}

	list := make([]*patternFamily, 0, len(fams))
	for _, f := range fams {
		list = append(list, f)
	}
	// Collapse before filtering: a narrow family may be too small to report on
	// its own yet still belong to a generator that is comfortably reportable.
	regexOf := func(f *patternFamily) string {
		return patternRegex(f.observed, f.classes, f.length)
	}
	list = mergeOverlapping(list, regexOf)

	out := make([]PatternRow, 0, len(list))
	for _, f := range list {
		if f.distinct < minPatternDistinct {
			continue
		}
		// A generator belongs to one vendor's line; a spread across vendors means
		// these are operator-chosen passwords that merely share a shape.
		vendor, share := dominantVendor(f.vendors)
		if vendor == "" || share < minVendorConcentration {
			continue
		}
		observedRunes := sortedRunes(f.observed)
		natural := naturalAlphabet(f.classes)
		// Report a family only once each character has had a real chance to
		// appear -- otherwise nothing can be said about its alphabet, which is
		// the whole point of describing it.
		if natural == "" || f.distinct*f.length < minExpectedPerChar*len(natural) {
			continue
		}
		row := PatternRow{
			Regex:         patternRegex(f.observed, f.classes, f.length),
			Vendor:        vendor,
			Concentration: share,
			Length:        f.length,
			Hosts:         f.hosts,
			Distinct:      f.distinct,
			Alphabet:      string(observedRunes),
			Missing:       missingChars(natural, f.observed),
			Absorbed:      f.absorbed,
			Vendors:       f.vendors.top(maxPatternFacet),
			Products:      f.products.top(maxPatternFacet),
			Shapes:        f.shapes.top(maxPatternFacet),
		}
		if s := f.shapes.top(1); len(s) > 0 {
			row.Mask = s[0].Value
		}
		out = append(out, row)
	}
	// Rank by evidence strength: how many distinct per-unit values back the
	// family, not how many hosts happened to be scanned.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Distinct != out[j].Distinct {
			return out[i].Distinct > out[j].Distinct
		}
		if out[i].Hosts != out[j].Hosts {
			return out[i].Hosts > out[j].Hosts
		}
		return out[i].Regex < out[j].Regex
	})
	if len(out) > maxPatternRows {
		out = out[:maxPatternRows]
	}
	return out
}

// missingChars returns the characters a family's classes allow but that never
// appeared -- the part of the keyspace the generator seems not to use.
func missingChars(natural string, observed map[rune]int) string {
	if natural == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range natural {
		if observed[r] == 0 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// PasswordsView is the combined cross-source password analysis rendered as its
// own slide: every source's recovered credentials pooled, deduplicated by host.
type PasswordsView struct {
	Sources   []string     `json:"sources"`
	Hosts     int          `json:"hosts"`     // hosts with any recovered credential
	Distinct  int          `json:"distinct"`  // distinct recovered plaintexts
	PerUnit   int          `json:"perUnit"`   // distinct plaintexts seen on <= sharedHostCeiling hosts
	Shared    int          `json:"shared"`    // distinct plaintexts above that ceiling
	SharedTop []Pair       `json:"sharedTop"` // the shared-credential head, hosts desc
	Patterns  []PatternRow `json:"patterns"`  // generated-looking families
	Vendors   []Pair       `json:"vendors"`   // hosts with a recovered credential, by vendor
}

// passwordsView builds the combined view from the per-source accumulators. The
// sources are pooled rather than reported separately: per-source population
// belongs to the overview slide, and a generator family is only credible with
// every sighting behind it.
func passwordsView(names []string, accums []*patternAccum) *PasswordsView {
	combined := newPatternAccum()
	for _, a := range accums {
		if a == nil {
			continue
		}
		combined.merge(a)
	}
	if len(combined.byPassword) == 0 {
		return nil
	}
	hosts := map[string]bool{}
	vendors := newCounter()
	perUnit, shared := 0, 0
	var sharedTop []Pair
	for pw, obs := range combined.byPassword {
		for h := range obs.hosts {
			hosts[h] = true
		}
		vendors.mergeFrom(obs.vendors)
		if len(obs.hosts) > sharedHostCeiling {
			shared++
			sharedTop = append(sharedTop, Pair{Value: pw, Count: len(obs.hosts)})
		} else {
			perUnit++
		}
	}
	sort.Slice(sharedTop, func(i, j int) bool {
		if sharedTop[i].Count != sharedTop[j].Count {
			return sharedTop[i].Count > sharedTop[j].Count
		}
		return sharedTop[i].Value < sharedTop[j].Value
	})
	if len(sharedTop) > 12 {
		sharedTop = sharedTop[:12]
	}
	// Redact before the value reaches the payload, not at render time: a masked
	// value the page never receives cannot be recovered from the bundle.
	sharedTop = redactSecretPairs(sharedTop)
	return &PasswordsView{
		Sources:   names,
		Hosts:     len(hosts),
		Distinct:  len(combined.byPassword),
		PerUnit:   perUnit,
		Shared:    shared,
		SharedTop: sharedTop,
		Patterns:  combined.patternRows(),
		Vendors:   vendors.top(10),
	}
}
