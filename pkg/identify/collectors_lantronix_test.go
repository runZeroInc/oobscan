package identify

import "testing"

// TestLooksLantronixTelnetBanner covers the defensive banner gate that stops
// collectLantronixTelnet from stamping `lantronix.setup_telnet` evidence onto
// hosts whose TCP/9999 listener is actually an HTTP server (Moxa NPort HTTP
// on 9999, Citrix Gateway honeypots) or a binary noise service.
func TestLooksLantronixTelnetBanner(t *testing.T) {
	cases := []struct {
		name   string
		banner string
		want   bool
	}{
		{
			name:   "real xDirect setup mode banner",
			banner: "*** Lantronix xDirect232 Device Server ***\r\nSerial Number   MAC address 0080A38BCF88",
			want:   true,
		},
		{
			name:   "password prompt after IAC",
			banner: "MAC address 00204ACF25D1\n\rSoftware version V6.7.0.1\r\nPassword :",
			want:   true,
		},
		{
			name:   "HTTP 400 from a Moxa embedded server on 9999/tcp",
			banner: "HTTP/1.1 400 Bad Request\r\nDate: Mon, 27 Mar 2006 08:00:00 GMT\r\nServer: MoxaHttp/",
			want:   false,
		},
		{
			name:   "HTTP 200 Citrix Gateway honeypot",
			banner: "HTTP/1.1 200 OK\r\nDate: Mon, 06 Jul 2026 09:46:47 GMT\r\nContent-Type: text/html",
			want:   false,
		},
		{
			name:   "opening HTML from a webserver front",
			banner: "<html><head><title>Login</title></head>",
			want:   false,
		},
		{
			name:   "binary noise from an unrelated Moxa 9999/tcp responder",
			banner: "\x00\x01\x02\x03",
			want:   false,
		},
		{
			// A dropbear sshd relocated to 9999/tcp was captured and
			// escalated as a Lantronix setup banner. An SSH-<ver>-<soft> banner
			// is never a Lantronix setup service.
			name:   "dropbear SSH banner on 9999/tcp",
			banner: "SSH-2.0-dropbear_2016.74\r\n",
			want:   false,
		},
		{
			name:   "OpenSSH banner on 9999/tcp",
			banner: "SSH-2.0-OpenSSH_8.6\r\n",
			want:   false,
		},
		{
			name:   "empty",
			banner: "",
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLantronixTelnetBanner(tc.banner); got != tc.want {
				t.Fatalf("looksLantronixTelnetBanner(%q) = %v, want %v", tc.banner, got, tc.want)
			}
		})
	}
}

func TestSanitizeIdentityText(t *testing.T) {
	t.Run("drops NUL and trims", func(t *testing.T) {
		in := "\x00\nMAC address 0080A3BC0000\n\r\x00Software version V6.10.0.1\r\x00\nPassword :"
		got := sanitizeIdentityText(in)
		if got == "" {
			t.Fatal("sanitizeIdentityText returned empty for valid banner")
		}
		if containsAny(got, "\x00") {
			t.Fatalf("sanitizeIdentityText left NUL byte: %q", got)
		}
	})

	t.Run("invalid UTF-8 falls back to printable ASCII", func(t *testing.T) {
		in := string([]byte{0xff, 0xfe, 'A', '\n', 0x00, 'B'})
		got := sanitizeIdentityText(in)
		if got != "A\nB" {
			t.Fatalf("sanitizeIdentityText invalid utf8 = %q, want %q", got, "A\\nB")
		}
	})
}

func containsAny(s string, chars string) bool {
	for _, c := range chars {
		for _, sc := range s {
			if sc == c {
				return true
			}
		}
	}
	return false
}
