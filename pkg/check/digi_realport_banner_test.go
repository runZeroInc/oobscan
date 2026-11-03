package check

import (
	"strings"
	"testing"
)

func TestIsMeaningfulSerialBanner(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "empty", raw: "", want: false},
		{name: "short token", raw: "P0", want: false},
		{name: "repeated byte noise", raw: strings.Repeat("w\xf7", 64), want: false},
		{name: "binary heavy framing", raw: "09A\x00\xb3\x06\x0309A\x10l)\t09B\x01\xb5\x06\x03", want: false},
		{name: "login prompt", raw: "PortServer login: ", want: true},
		{name: "equipment banner", raw: "Cisco IOS Software, Version 15.2\r\n", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isMeaningfulSerialBanner(test.raw, sanitizeBanner(test.raw)); got != test.want {
				t.Fatalf("isMeaningfulSerialBanner() = %v, want %v", got, test.want)
			}
		})
	}
}
