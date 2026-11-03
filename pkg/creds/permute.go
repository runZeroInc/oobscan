package creds

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// CommonPasswordSeeds are base words used to generate password variants when the
// static default/vendor lists miss. Ported from the runZero platform IPMI probe.
var CommonPasswordSeeds = []string{
	"", "admin", "administrator", "root", "calvin", "changeme", "letmein",
	"welcome", "default", "password", "badpassword", "superuser", "system",
	"newsys", "awesome", "abcd",
}

var (
	permOnce   sync.Once
	permAffixe []string
)

// passwordAffixes returns year / digit-sequence / symbol tokens that get combined
// (as prefix or suffix) with base variants during a deep permutation pass.
func passwordAffixes() []string {
	permOnce.Do(func() {
		set := map[string]struct{}{}
		for i := 1950; i <= 2100; i++ {
			set[strconv.Itoa(i)] = struct{}{}
		}
		for _, v := range []string{
			"1", "2", "3", "12", "123", "1234", "12345", "123456", "1234567", "12345678",
			"0", "00", "000", "69", "007", "321", "111", "1111", "01", "99",
		} {
			set[v] = struct{}{}
		}
		for _, v := range []string{"!", "@", "#", "$", "%", "^", "&", "*", "-", "_", "+", "=", ".", "!!", "@#", "123!", "!@#"} {
			set[v] = struct{}{}
		}
		permAffixe = slices.Collect(maps.Keys(set))
	})
	return permAffixe
}

// Permute generates case, leetspeak, and word-doubling variants of base and tests
// each with test(). When deep is true it also combines each variant with common
// year/sequence/symbol affixes as a prefix and suffix. It returns the first
// candidate for which test() reports a match. Ported/adapted from the runZero
// platform PermutePassword (rules-driven RAKP candidate engine).
func Permute(base string, deep bool, test func(string) bool) (string, bool) {
	variants := map[string]struct{}{
		base:                  {},
		strings.ToLower(base): {},
		strings.ToUpper(base): {},
	}
	if base != "" {
		lb := strings.ToLower(base)
		variants[strings.ToUpper(lb[:1])+lb[1:]] = struct{}{} // Title case
	}

	// Leetspeak substitutions on each case variant.
	reps := []struct{ a, b string }{
		{"s", "5"}, {"S", "5"}, {"s", "$"}, {"S", "$"},
		{"a", "@"}, {"a", "4"}, {"A", "@"}, {"A", "4"},
		{"o", "0"}, {"O", "0"}, {"e", "3"}, {"E", "3"},
		{"i", "!"}, {"I", "!"}, {"i", "1"}, {"I", "1"},
	}
	leet := map[string]struct{}{}
	for k := range variants {
		for _, r := range reps {
			leet[strings.ReplaceAll(k, r.a, r.b)] = struct{}{}
		}
	}
	maps.Copy(variants, leet)

	// Word doubling (e.g. adminadmin).
	for w := range maps.Clone(variants) {
		variants[w+w] = struct{}{}
	}

	bases := slices.Collect(maps.Keys(variants))
	for _, b := range bases {
		if test(b) {
			return b, true
		}
	}
	if !deep {
		return "", false
	}
	for _, b := range bases {
		for _, af := range passwordAffixes() {
			if test(b + af) {
				return b + af, true
			}
			if test(af + b) {
				return af + b, true
			}
		}
	}
	return "", false
}
