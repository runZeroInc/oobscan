package amt

import (
	"testing"
	"time"
)

// TestProbeIPv6NoPanic guards the regression where an unbracketed IPv6 host made
// a malformed URL ("http://2001:db8::1:16992/") -> http.NewRequest returned a nil
// request whose error was ignored -> client.Do(nil) panicked with a nil-pointer
// dereference (observed on IPv6 targets). Probe/VerifyEmptyDigest must
// bracket the host and never panic. The 2001:db8::/32 documentation prefix is
// unroutable, so the calls simply fail fast with Present=false.
func TestProbeIPv6NoPanic(t *testing.T) {
	r, err := Probe("2001:db8::dead:beef", 150*time.Millisecond)
	if err != nil {
		t.Fatalf("Probe(IPv6) returned err: %v", err)
	}
	if r == nil {
		t.Fatal("Probe(IPv6) returned nil result")
	}
	if r.Present {
		t.Errorf("unexpected Present=true on an unroutable IPv6 target")
	}
	// The active bypass path must also be IPv6-safe (it built its own URLs).
	r.Cleartext, r.TLS = true, true
	VerifyEmptyDigest(r, 150*time.Millisecond) // must not panic
}

func TestExtractVersionFromServer(t *testing.T) {
	cases := []struct {
		server string
		want   string
	}{
		{"Intel(R) Active Management Technology 11.8.50", "11.8.50"},
		{"Intel(R) Active Management Technology 11.6.27", "11.6.27"},
		{"Intel(R) Standard Manageability 8.1.31", "8.1.31"},
		{"Intel(R) Standard Manageability 14.1.67.2046", "14.1.67.2046"},
		{"Intel(R) AMT 9.0.30", "9.0.30"},
		{"AMT 6.0.0", "6.0.0"},
		// No version present -> empty.
		{"Intel(R) Active Management Technology", ""},
		{"Intel(R) Standard Manageability", ""},
		{"Intel(R) AMT", ""},
		{"lighttpd/1.4.35", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := extractVersionFromServer(c.server); got != c.want {
			t.Errorf("extractVersionFromServer(%q) = %q, want %q", c.server, got, c.want)
		}
	}
}

func TestExtractVersionLoose(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"<title>Intel(R) Active Management Technology 11.8.50</title>", "11.8.50"},
		{"Intel(R) Standard Manageability 8.1.31", "8.1.31"},
		{"Intel(R) AMT 9.1.41", "9.1.41"},
		{"hello world", ""},
	}
	for _, c := range cases {
		if got := extractVersionLoose(c.in); got != c.want {
			t.Errorf("extractVersionLoose(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsAMT(t *testing.T) {
	cases := []struct {
		server string
		body   string
		want   bool
	}{
		// Real pre-auth case: version only in header, body is a frameset.
		{"Intel(R) Active Management Technology 11.8.50", "<title>Intel&reg; Active Management Technology</title>", true},
		// Body marker only.
		{"", "Intel(R) Active Management foo", true},
		// Standard Manageability body marker.
		{"", "<title>Intel(R) Standard Manageability</title>", true},
		// Neither.
		{"nginx/1.20", "<html>hello</html>", false},
		// A generic Intel product header is not AMT proof.
		{"Intel(R) HTTP Server", "<html>hello</html>", false},
	}
	for _, c := range cases {
		if got := isAMT(c.server, c.body); got != c.want {
			t.Errorf("isAMT(%q, %q) = %v, want %v", c.server, c.body, got, c.want)
		}
	}
}

func TestAMTFingerprint(t *testing.T) {
	source, fingerprint, ok := amtFingerprint("Intel(R) Active Management Technology", "")
	if !ok || source != "http_server" || fingerprint != "Intel(R) Active Management Technology" {
		t.Fatalf("server fingerprint = %q/%q/%v", source, fingerprint, ok)
	}
	source, fingerprint, ok = amtFingerprint("nginx", "<title>Intel(R) Standard Manageability</title>")
	if !ok || source != "http_body" || fingerprint != "Intel(R) Standard Manageability" {
		t.Fatalf("body fingerprint = %q/%q/%v", source, fingerprint, ok)
	}
}

// verdict mirrors the CVE-2017-5689 flagging decision in Probe() so the gate
// can be unit-tested without opening a socket. cve fires on any confirmed AMT
// box; inRange annotates whether the parsed version is in the affected band.
func verdict(serverHdr, body string) (version string, cve, inRange bool) {
	if !isAMT(serverHdr, body) {
		return "", false, false
	}
	if v := extractVersionFromServer(serverHdr); v != "" {
		version = v
	} else if v := extractVersion(body); v != "" {
		version = v
	}
	cve = true
	inRange = version != "" && vulnerable20175689(version)
	return version, cve, inRange
}

// TestCVEFiresOnRealPreauthResponse verifies AMT detection when the version is
// present only in the Server header.
func TestCVEFiresOnRealPreauthResponse(t *testing.T) {
	server := "Intel(R) Active Management Technology 11.8.50"
	body := "<html><head><title>Intel&reg; Active Management Technology</title></head>" +
		"<frameset rows=\"*\"><frame src=\"logon.htm\"></frameset></html>"

	ver, cve, _ := verdict(server, body)
	if ver != "11.8.50" {
		t.Fatalf("expected version 11.8.50 from Server header, got %q", ver)
	}
	if !cve {
		t.Fatalf("CVE-2017-5689 must fire on a real pre-auth AMT response (server=%q)", server)
	}
}

func TestCVEFlaggingGate(t *testing.T) {
	cases := []struct {
		name        string
		server      string
		body        string
		wantVer     string
		wantCVE     bool
		wantInRange bool
	}{
		{
			name:        "vulnerable version in header",
			server:      "Intel(R) Active Management Technology 9.1.40",
			body:        "<title>Intel&reg; Active Management Technology</title>",
			wantVer:     "9.1.40",
			wantCVE:     true,
			wantInRange: true,
		},
		{
			name:        "AMT confirmed but version unknown still fires",
			server:      "Intel(R) Active Management Technology",
			body:        "<title>Intel&reg; Active Management Technology</title>",
			wantVer:     "",
			wantCVE:     true,
			wantInRange: false,
		},
		{
			name:        "AMT confirmed with out-of-band version still fires, not in-range",
			server:      "Intel(R) Active Management Technology 12.0.0",
			body:        "<title>Intel&reg; Active Management Technology</title>",
			wantVer:     "12.0.0",
			wantCVE:     true,
			wantInRange: false,
		},
		{
			name:        "standard manageability version in header",
			server:      "Intel(R) Standard Manageability 8.1.31",
			body:        "<title>Intel(R) Standard Manageability</title>",
			wantVer:     "8.1.31",
			wantCVE:     true,
			wantInRange: true,
		},
		{
			name:        "non-AMT server never fires",
			server:      "Apache/2.4.6",
			body:        "<html>not amt</html>",
			wantVer:     "",
			wantCVE:     false,
			wantInRange: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ver, cve, inRange := verdict(c.server, c.body)
			if ver != c.wantVer {
				t.Errorf("version = %q, want %q", ver, c.wantVer)
			}
			if cve != c.wantCVE {
				t.Errorf("cve = %v, want %v", cve, c.wantCVE)
			}
			if inRange != c.wantInRange {
				t.Errorf("inRange = %v, want %v", inRange, c.wantInRange)
			}
		})
	}
}
