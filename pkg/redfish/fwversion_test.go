package redfish

import "testing"

// Regression guard for extractDellFwVersion: the closing tag must be found
// relative to the opening tag so a stray leading close tag is ignored.
func TestExtractDellFwVersion(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"normal", "<fwVersion>2.65.65.65</fwVersion>", "2.65.65.65", true},
		{"surrounded", `{"a":1}<fwVersion>7.20.10.50</fwVersion>trailing`, "7.20.10.50", true},
		{"stray_leading_close", "</fwVersion> junk <fwVersion>CORRECT</fwVersion>", "CORRECT", true},
		{"no_open", "no version here", "", false},
		{"open_no_close", "<fwVersion>unterminated", "", false},
		{"empty_value", "<fwVersion></fwVersion>", "", true},
	}
	for _, c := range cases {
		got, ok := extractDellFwVersion(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: extractDellFwVersion(%q) = (%q,%v), want (%q,%v)", c.name, c.in, got, ok, c.want, c.ok)
		}
	}
}
