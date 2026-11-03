package digi

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// TestRealportCollectFraming verifies that the banner reader follows the
// reference RealPort framing: sequence-number frames are skipped, keep-alives
// are ignored, and length-prefixed data frames are read exactly so that a data
// byte equal to a marker value is not misinterpreted as a new frame header and
// frames spanning read boundaries are not dropped.
func TestRealportCollectFraming(t *testing.T) {
	server, client := net.Pipe()

	// portIndex 0 => sequence marker 0xa0, data marker 0x80.
	stream := []byte{
		0xa0, 0x00, 0x01, // sequence number frame (discarded)
		0x80, 0x05, 'h', 'e', 'l', 'l', 'o', // data frame "hello"
		0xf0,                  // keep-alive (ignored)
		0x80, 0x02, 0x80, '!', // data frame whose payload contains the 0x80 marker byte
		0x80, 0x03, 'a', 'b', 'c', // data frame "abc" must still be parsed in alignment
	}

	go func() {
		_, _ = server.Write(stream)
		_ = server.Close()
	}()

	got := realportCollect(client, 0, 500*time.Millisecond, 4096)
	_ = client.Close()

	want := "hello" + string([]byte{0x80, '!'}) + "abc"
	if got != want {
		t.Fatalf("realportCollect() = %q, want %q", got, want)
	}
}

func TestSplitRealPortInfo(t *testing.T) {
	meta := make([]byte, 6)
	binary.BigEndian.PutUint16(meta[0:2], 0x0001)
	binary.BigEndian.PutUint16(meta[2:4], 24)
	binary.BigEndian.PutUint16(meta[4:6], 0x0000)
	in := append([]byte("PortServer TS 8\xfc\x02"), meta...)

	name, fields := splitRealPortInfo(in)
	if name != "PortServer TS 8" {
		t.Fatalf("name=%q", name)
	}
	if len(fields) < 2 || fields[1] != 24 {
		t.Fatalf("fields=%v", fields)
	}
}

func TestSplitRealPortInfoWithoutMarker(t *testing.T) {
	name, fields := splitRealPortInfo([]byte("Digi RealPort"))
	if name != "Digi RealPort" {
		t.Fatalf("name=%q", name)
	}
	if fields != nil {
		t.Fatalf("fields should be nil, got %v", fields)
	}
}

func TestLooksReadableBanner(t *testing.T) {
	tests := []struct {
		name   string
		banner string
		want   bool
	}{
		// Real serial-console output: diverse printable chars, should accept.
		{"industrial-protocol", "01A01ABb*/4Bb?0& 01A01ABb*/5Bb?0&", true},
		{"login-prompt", "login: ", true},
		{"short-valid", "P0", true},

		// Baud-rate mismatch: monotone 0x77 stream, should reject.
		{"monotone-w", strings.Repeat("w", 200), false},
		// Baud-rate mismatch: 0x77+0xf7 mix. 0x77 ('w') accounts for 82.8% of
		// bytes (>75%), so the monotone check rejects it. Note: a rune-based
		// unicode.IsPrint check would incorrectly pass this because Go converts
		// 0xf7 to U+FFFD (replacement char) which IsPrint returns true for.
		{"w-with-f7-framing", buildMixedBanner(53, 11), false},
		// Exact-80% boundary: 48 x 0x77, 12 x 0xf7 = 60 bytes, 0x77 at exactly
		// 80.0%. With threshold >= 0.75 this is correctly rejected.
		{"w-exact-80pct", buildMixedBanner(48, 12), false},
		// Binary-protocol device: mostly non-ASCII framing bytes but contains
		// alnum chars ('P','0') and no single byte exceeds 80%. Represents the
		// real case of a device speaking a binary protocol over the serial port.
		{"binary-protocol-with-alnum", "\xb4\x50\x11\x30\xb9\xfa\xf9\xfb\xfa\xfb\xfb\xfa", true},
		// Pure binary garbage: no alphanumeric bytes.
		{"all-non-printable", "\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6", false},
		// Empty.
		{"empty", "", false},
		// Only whitespace.
		{"whitespace", "   \t\n  ", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksReadableBanner(tc.banner); got != tc.want {
				t.Fatalf("looksReadableBanner(%q) = %v, want %v", tc.banner[:min(len(tc.banner), 30)], got, tc.want)
			}
		})
	}
}

// buildMixedBanner returns a string of nPrint 0x77 ('w') bytes interspersed
// with nNoise 0xf7 bytes, matching the baud-mismatch pattern seen on live hosts.
func buildMixedBanner(nPrint, nNoise int) string {
	b := make([]byte, 0, nPrint+nNoise)
	for i := 0; i < nPrint+nNoise; i++ {
		if i%(nPrint/nNoise+1) == 0 && nNoise > 0 {
			b = append(b, 0xf7)
			nNoise--
		} else {
			b = append(b, 0x77)
		}
	}
	return string(b)
}
