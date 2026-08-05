package report

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode"
)

const (
	sharedHostCeiling = 2

	minPatternDistinct = 5

	minVendorConcentration = 0.6

	minExpectedPerChar = 5

	maxPatternRows  = 12
	maxPatternFacet = 6
)

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

func patternRegex(observed map[rune]int, classes map[charClass]bool, length int) string {
	runes := sortedRunes(observed)
	if len(runes) == 0 {
		return ""
	}
	if len(classes) == 1 && classes[classDigit] && len(runes) == 10 {
		return fmt.Sprintf(`\d{%d}`, length)
	}

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

type PatternRow struct {
	Regex  string `json:"regex"`
	Mask   string `json:"mask"`
	Vendor string `json:"vendor"`

	Concentration float64 `json:"concentration"`
	Length        int     `json:"length"`
	Hosts         int     `json:"hosts"`
	Distinct      int     `json:"distinct"`
	Alphabet      string  `json:"alphabet"`

	Missing string `json:"missing"`

	Absorbed []string `json:"absorbed,omitempty"`
	Shapes   []Pair   `json:"shapes,omitempty"`
	Vendors  []Pair   `json:"vendors,omitempty"`
	Products []Pair   `json:"products,omitempty"`
}

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

type patternObs struct {
	hosts    map[string]bool
	vendors  *counter
	products *counter
}

type patternAccum struct {
	byPassword map[string]*patternObs
}

func newPatternAccum() *patternAccum {
	return &patternAccum{byPassword: map[string]*patternObs{}}
}

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
			return
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

type patternFamily struct {
	classes  map[charClass]bool
	length   int
	hosts    int
	distinct int
	observed map[rune]int
	shapes   *counter
	vendors  *counter
	products *counter
	absorbed []string
}

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

func classSubset(a, b map[charClass]bool) bool {
	for c := range a {
		if !b[c] {
			return false
		}
	}
	return true
}

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

		if hostCount > sharedHostCeiling {
			continue
		}
		mask, classes, ok := passwordShape(pw)
		if !ok {
			continue
		}

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

	regexOf := func(f *patternFamily) string {
		return patternRegex(f.observed, f.classes, f.length)
	}
	list = mergeOverlapping(list, regexOf)

	out := make([]PatternRow, 0, len(list))
	for _, f := range list {
		if f.distinct < minPatternDistinct {
			continue
		}

		vendor, share := dominantVendor(f.vendors)
		if vendor == "" || share < minVendorConcentration {
			continue
		}
		observedRunes := sortedRunes(f.observed)
		natural := naturalAlphabet(f.classes)

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

type PasswordsView struct {
	Sources   []string     `json:"sources"`
	Hosts     int          `json:"hosts"`
	Distinct  int          `json:"distinct"`
	PerUnit   int          `json:"perUnit"`
	Shared    int          `json:"shared"`
	SharedTop []Pair       `json:"sharedTop"`
	Patterns  []PatternRow `json:"patterns"`
	Vendors   []Pair       `json:"vendors"`
}

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
