package creds

import (
	"sort"
	"strings"
	"sync"
)

type VendorPair struct {
	Vendor   string
	User     string
	Password string
	Notes    string
}

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

func Usernames() []string { buildPools(); return usernames }

func UsernamesFor(vendor string) []string {
	buildPools()
	if vendor == "" {
		return usernames
	}
	var front []string
	seen := map[string]struct{}{}
	for _, c := range CredsFor(vendor, ClassIPMI) {
		if c.Vendor == "" {
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

func Passwords() []string { buildPools(); return passwords }

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
		for _, c := range Table {
			if c.Vendor == vendor && c.Class == class {
				add(c)
			}
		}
		for _, c := range Table {
			if c.Vendor == vendor && matchClass(c.Class) {
				add(c)
			}
		}
	}
	for _, c := range Table {
		if c.Vendor == "" && matchClass(c.Class) {
			add(c)
		}
	}
	for _, c := range AllCommon() {
		add(c)
	}
	return out
}

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
	for _, c := range Table {
		if c.Vendor == vendor && c.Class == class {
			add(c)
		}
	}
	for _, c := range Table {
		if c.Vendor == vendor && matchClass(c.Class) {
			add(c)
		}
	}
	return out
}

func DocumentedDefaults(class DeviceClass) []Credential {
	matchClass := func(c DeviceClass) bool { return c == ClassAny || class == ClassAny || c == class }

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
	for _, k := range canonicalDefaultOrder {
		emit(k)
	}
	for _, k := range order {
		emit(k)
	}
	return out
}

var canonicalDefaultOrder = [][2]string{
	{"root", "calvin"},
	{"root", "0penBmc"},
	{"USERID", "PASSW0RD"},
	{"ADMIN", "ADMIN"},
	{"Administrator", "Administrator"},
	{"admin", "admin"},
	{"sysadmin", "superuser"},
	{"root", "root"},
}

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
