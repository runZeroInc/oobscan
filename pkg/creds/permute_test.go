package creds

import "testing"

func TestPermute(t *testing.T) {
	hit := func(target string) func(string) bool {
		return func(c string) bool { return c == target }
	}
	// Case variant (upper).
	if _, ok := Permute("admin", false, hit("ADMIN")); !ok {
		t.Errorf("expected ADMIN via upper-case variant")
	}
	// Leetspeak single substitution (o -> 0).
	if _, ok := Permute("password", false, hit("passw0rd")); !ok {
		t.Errorf("expected passw0rd via leetspeak")
	}
	// Word doubling.
	if _, ok := Permute("admin", false, hit("adminadmin")); !ok {
		t.Errorf("expected adminadmin via doubling")
	}
	// Deep affix (year/sequence suffix).
	if got, ok := Permute("Admin", true, hit("Admin123")); !ok || got != "Admin123" {
		t.Errorf("expected Admin123 via deep affix, got %q ok=%v", got, ok)
	}
	// Shallow pass must not reach affix combos.
	if _, ok := Permute("Admin", false, hit("Admin123")); ok {
		t.Errorf("shallow permute should not produce Admin123")
	}
	// No false positive.
	if _, ok := Permute("admin", true, hit("nomatch~unrelated")); ok {
		t.Errorf("unexpected false-positive match")
	}
}
