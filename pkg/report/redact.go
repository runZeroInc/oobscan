package report

import "strings"

// Recovered plaintexts are the one class of value in this bundle that can name a
// victim. "admin" and "calvin" are vendor defaults and say nothing about who runs
// the host; a password built from a company name says exactly who runs it, and a
// report meant to be shared cannot carry it.
//
// The gate is an allowlist, not a denylist. There is no enumerable set of
// org-specific passwords to exclude, so anything not recognised as a vendor
// default or a universally-common weak password is masked to its shape. That
// keeps the analysis -- which shared credentials dominate, and what the
// operator-chosen tail looks like -- while refusing to print the secret.

// publishableSecrets is every plaintext that may be rendered verbatim: vendor-
// shipped defaults, and weak passwords so common they carry no attribution.
// Adding to this list publishes the value, so an entry needs to be defensible as
// "this appears in a vendor manual or a top-1000 list", not merely "this looks
// generic to me".
var publishableSecrets = map[string]bool{
	// Vendor-shipped defaults.
	"admin": true, "ADMIN": true, "Admin": true, "administrator": true,
	"Administrator": true, "root": true, "calvin": true, "superuser": true,
	"sysadmin": true, "user": true, "guest": true, "operator": true,
	"changeme": true, "CHANGEME": true, "public": true, "private": true,
	"support": true, "0penBmc": true, "openbmc": true, "hpinvent": true,
	"advantech": true, "ipmi": true, "IPMI": true, "unknown": true,
	"Supermicro": true, "supermicro": true, "PASSWORD": true,
	// Universally-common weak passwords: present in every public leak corpus, so
	// printing one identifies nobody.
	"password": true, "Password": true, "password1": true, "Password1": true,
	"passw0rd": true, "Passw0rd": true, "P@ssw0rd": true, "p@ssw0rd": true,
	"PASSW0RD": true, "admin123": true, "Admin123": true, "admin1234": true,
	"123456": true, "1234567": true, "12345678": true, "123456789": true,
	"1234567890": true, "12345": true, "111111": true, "000000": true,
	"qwerty": true, "letmein": true, "welcome": true, "Welcome1": true,
	"abc123": true, "test": true, "test123": true, "toor": true,
	"adminadmin": true, "rootroot": true, "ADMINADMIN": true,
}

// placeholderSecrets maps a pipeline token that is not a password at all onto the
// bracketed form that marks it as a placeholder. Without this the crack-method
// name reads as a recovered credential.
var placeholderSecrets = map[string]string{
	"common": "<common>",
	"":       "<empty>",
}

// redactSecret returns the value to display for a recovered plaintext. A
// publishable value passes through, a pipeline token becomes its bracketed
// placeholder, and anything else is reduced to its per-position shape so the
// family is still legible without the secret.
func redactSecret(pw string) string {
	if p, ok := placeholderSecrets[pw]; ok {
		return p
	}
	if pw == smcrakpFixedKeyMarker {
		return pw // already a bracketed marker
	}
	if publishableSecrets[pw] {
		return pw
	}
	mask, _, ok := passwordShape(pw)
	if !ok {
		return "<redacted>"
	}
	return "<redacted:" + mask + ">"
}

// redactSecretPairs applies redactSecret across a value/count histogram, merging
// counts that collapse onto the same masked shape so the total is preserved
// rather than duplicated across identical-looking rows.
func redactSecretPairs(in []Pair) []Pair {
	if len(in) == 0 {
		return nil
	}
	out := make([]Pair, 0, len(in))
	at := map[string]int{}
	for _, p := range in {
		v := redactSecret(p.Value)
		if i, seen := at[v]; seen {
			out[i].Count += p.Count
			continue
		}
		at[v] = len(out)
		out = append(out, Pair{Value: v, Count: p.Count})
	}
	return out
}

// isOrgAttributable reports whether a plaintext would be masked. It exists for
// the tests, which assert the gate on values that must never be published.
func isOrgAttributable(pw string) bool {
	return strings.HasPrefix(redactSecret(pw), "<redacted")
}
