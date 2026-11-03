package creds

import (
	"sort"
	"strings"
	"sync"
)

// VendorPair is a high-signal vendor default (user, pass). It is a compatibility
// view derived from Table for callers that only need the vendor pairs. Edit
// Table, not this.
type VendorPair struct {
	Vendor   string
	User     string
	Password string
	Notes    string
}

// VendorPairs is derived from Table at init: every row that names a vendor.
var VendorPairs []VendorPair

var (
	poolOnce  sync.Once
	usernames []string
	passwords []string
)

func init() {
	for _, c := range Table {
		if c.Vendor == "" {
			continue
		}
		VendorPairs = append(VendorPairs, VendorPair{
			Vendor: c.Vendor, User: c.Username, Password: c.Password, Notes: c.Notes,
		})
	}
}

// buildPools merges the flat username/password wordlists with every credential
// in Table, de-duplicated, preserving first-seen (hit-rate) order.
func buildPools() {
	poolOnce.Do(func() {
		us := dedupeKeepOrder(CommonUsernames)
		ps := dedupeKeepOrder(append(append([]string{}, DefaultPasswords...), CommonPasswords...))
		seenU := toSet(us)
		seenP := toSet(ps)
		for _, c := range Table {
			if _, ok := seenU[c.Username]; !ok {
				seenU[c.Username] = struct{}{}
				us = append(us, c.Username)
			}
			if _, ok := seenP[c.Password]; !ok {
				seenP[c.Password] = struct{}{}
				ps = append(ps, c.Password)
			}
		}
		usernames, passwords = us, ps
	})
}

// Usernames returns the de-duplicated username pool (flat lists + Table),
// ordered highest-hit-rate first.
func Usernames() []string { buildPools(); return usernames }

// UsernamesFor returns the username pool with the given vendor's known default
// usernames moved to the front, so the highest-signal account is probed first.
// This matters against rate-limiting BMCs (OpenBMC, iDRAC): the correct username
// is hit on the first RAKP packet, before drops force the enumeration to bail.
// With an empty/unknown vendor it is identical to Usernames().
func UsernamesFor(vendor string) []string {
	buildPools()
	if vendor == "" {
		return usernames
	}
	var front []string
	seen := map[string]struct{}{}
	for _, c := range CredsFor(vendor, ClassIPMI) {
		if c.Vendor == "" { // stop at the generic/spray rows; only vendor-specific
			break
		}
		if c.Username == "" {
			continue
		}
		if _, ok := seen[c.Username]; ok {
			continue
		}
		seen[c.Username] = struct{}{}
		front = append(front, c.Username)
	}
	if len(front) == 0 {
		return usernames
	}
	out := append([]string{}, front...)
	for _, u := range usernames {
		if _, ok := seen[u]; !ok {
			out = append(out, u)
		}
	}
	return out
}

// Passwords returns the de-duplicated password pool (defaults + common + Table),
// ordered highest-hit-rate first.
func Passwords() []string { buildPools(); return passwords }

// CredsFor returns credentials to try against a target, best-first:
//  1. exact {vendor, class} rows,
//  2. {vendor, ClassAny} rows,
//  3. generic (Vendor=="") rows for that class or ClassAny,
//  4. the vendor-agnostic cartesian spray (AllCommon).
//
// The result is de-duplicated by (Username, Password), preserving order, so the
// highest-signal vendor pairs are always attempted before the broad spray.
func CredsFor(vendor string, class DeviceClass) []Credential {
	vendor = strings.ToLower(vendor)
	var out []Credential
	seen := map[[2]string]struct{}{}
	add := func(c Credential) {
		k := [2]string{c.Username, c.Password}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, c)
	}
	matchClass := func(c DeviceClass) bool { return c == ClassAny || class == ClassAny || c == class }

	if vendor != "" {
		for _, c := range Table { // 1: exact vendor+class
			if c.Vendor == vendor && c.Class == class {
				add(c)
			}
		}
		for _, c := range Table { // 2: vendor, any class
			if c.Vendor == vendor && matchClass(c.Class) {
				add(c)
			}
		}
	}
	for _, c := range Table { // 3: generic rows
		if c.Vendor == "" && matchClass(c.Class) {
			add(c)
		}
	}
	for _, c := range AllCommon() { // 4: broad spray
		add(c)
	}
	return out
}

// VendorCredsFor returns just the vendor-specific default credentials for the given
// vendor+class, best-first: exact {vendor, class} rows then {vendor, ClassAny} rows,
// de-duplicated by (Username, Password). Unlike CredsFor it never falls back to the
// generic rows or the cartesian spray, and it returns nil for an unknown vendor.
//
// This is the targeted set for state-changing logins: a handful of documented
// defaults stays well below a BMC's account lockout threshold, where the full
// CredsFor spray would risk locking the account out.
func VendorCredsFor(vendor string, class DeviceClass) []Credential {
	vendor = strings.ToLower(vendor)
	if vendor == "" {
		return nil
	}
	var out []Credential
	seen := map[[2]string]struct{}{}
	add := func(c Credential) {
		k := [2]string{c.Username, c.Password}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, c)
	}
	matchClass := func(c DeviceClass) bool { return c == ClassAny || class == ClassAny || c == class }
	for _, c := range Table { // exact vendor+class first
		if c.Vendor == vendor && c.Class == class {
			add(c)
		}
	}
	for _, c := range Table { // then vendor, any class
		if c.Vendor == vendor && matchClass(c.Class) {
			add(c)
		}
	}
	return out
}

// DocumentedDefaults returns every documented default credential for the given
// class, vendor-specific and generic rows alike, de-duplicated by (Username,
// Password). It excludes the vendor-agnostic cartesian spray (AllCommon).
//
// The highest-hit-rate cross-vendor pairs (canonicalDefaultOrder) come first so a
// caller that caps its attempts still exercises the most common credentials; the
// rest follow in Table order.
//
// This is the fallback for a confirmed-present service whose vendor could not be
// identified: it exercises the well-known cross-vendor defaults without escalating
// to a spray that would risk account lockout. Callers should still cap their
// attempt count.
func DocumentedDefaults(class DeviceClass) []Credential {
	matchClass := func(c DeviceClass) bool { return c == ClassAny || class == ClassAny || c == class }
	// Index the class-matching rows by (user, pass), keeping the first (highest
	// priority) Table row for each pair.
	byPair := map[[2]string]Credential{}
	var order [][2]string
	for _, c := range Table {
		if !matchClass(c.Class) {
			continue
		}
		k := [2]string{c.Username, c.Password}
		if _, ok := byPair[k]; ok {
			continue
		}
		byPair[k] = c
		order = append(order, k)
	}

	var out []Credential
	emitted := map[[2]string]struct{}{}
	emit := func(k [2]string) {
		if _, done := emitted[k]; done {
			return
		}
		if c, ok := byPair[k]; ok {
			emitted[k] = struct{}{}
			out = append(out, c)
		}
	}
	for _, k := range canonicalDefaultOrder { // high-signal cross-vendor first
		emit(k)
	}
	for _, k := range order { // then the rest in Table order
		emit(k)
	}
	return out
}

// canonicalDefaultOrder lists the highest-hit-rate cross-vendor BMC defaults, in
// priority order, used to front-load DocumentedDefaults so a capped consumer
// still tries the most common credentials first. Pairs not present in Table for
// the requested class are simply skipped.
var canonicalDefaultOrder = [][2]string{
	{"root", "calvin"},                 // Dell iDRAC
	{"root", "0penBmc"},                // OpenBMC / NVIDIA BlueField
	{"USERID", "PASSW0RD"},             // IBM/Lenovo IMM/XCC
	{"ADMIN", "ADMIN"},                 // Supermicro / AMI MegaRAC
	{"Administrator", "Administrator"}, // ancient iLO2 only (modern iLO = per-unit random pw, no universal default)
	{"admin", "admin"},                 // HPE / Fujitsu / generic
	{"sysadmin", "superuser"},          // Fujitsu / AMI MegaRAC
	{"root", "root"},                   // generic
}

// AllCommon returns the vendor-agnostic cartesian spray (Usernames x Passwords)
// as generic credentials, used when the vendor is unknown or after vendor
// pairs miss.
func AllCommon() []Credential {
	us, ps := Usernames(), Passwords()
	out := make([]Credential, 0, len(us)*len(ps))
	for _, u := range us {
		for _, p := range ps {
			out = append(out, Credential{Username: u, Password: p, Source: "spray"})
		}
	}
	return out
}

func dedupeKeepOrder(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func toSet(in []string) map[string]struct{} {
	s := make(map[string]struct{}, len(in))
	for _, v := range in {
		s[v] = struct{}{}
	}
	return s
}

// Vendors returns the sorted set of distinct vendor slugs present in Table.
func Vendors() []string {
	set := map[string]struct{}{}
	for _, c := range Table {
		if c.Vendor != "" {
			set[c.Vendor] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
