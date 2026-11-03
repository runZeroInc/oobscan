package netaddr

import (
	"net/url"
	"testing"
)

func TestDialHostPort(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{"10.0.0.1", 623, "10.0.0.1:623"},
		{"bmc.example", 443, "bmc.example:443"},
		{"fe80::1", 443, "[fe80::1]:443"},
		// The zone must survive verbatim: the resolver needs it to pick the
		// interface for a link-local address.
		{"fe80::1%en0", 623, "[fe80::1%en0]:623"},
		{"[fe80::1%en0]", 623, "[fe80::1%en0]:623"},
	}
	for _, c := range cases {
		if got := DialHostPort(c.host, c.port); got != c.want {
			t.Errorf("DialHostPort(%q, %d) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}

func TestURLHostPortEscapesZone(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{"10.0.0.1", 8443, "10.0.0.1:8443"},
		{"fe80::1", 8443, "[fe80::1]:8443"},
		{"fe80::1%en0", 8443, "[fe80::1%25en0]:8443"},
		// Idempotent: an already-escaped zone is not double-escaped.
		{"fe80::1%25en0", 8443, "[fe80::1%25en0]:8443"},
	}
	for _, c := range cases {
		if got := URLHostPort(c.host, c.port); got != c.want {
			t.Errorf("URLHostPort(%q, %d) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}

func TestURL(t *testing.T) {
	cases := []struct {
		scheme string
		host   string
		port   int
		path   string
		want   string
	}{
		{"https", "10.0.0.1", 443, "/redfish/v1/", "https://10.0.0.1/redfish/v1/"},
		{"https", "10.0.0.1", 8443, "/redfish/v1/", "https://10.0.0.1:8443/redfish/v1/"},
		{"http", "10.0.0.1", 80, "/", "http://10.0.0.1/"},
		{"http", "10.0.0.1", 8080, "/", "http://10.0.0.1:8080/"},
		// An unset port is left out rather than rendered as ":0"/":-1".
		{"https", "10.0.0.1", 0, "/", "https://10.0.0.1/"},
		{"https", "10.0.0.1", -1, "/", "https://10.0.0.1/"},
		{"https", "fe80::1%en0", 443, "/", "https://[fe80::1%25en0]/"},
		{"https", "fe80::1%en0", 8443, "/xmldata?item=all", "https://[fe80::1%25en0]:8443/xmldata?item=all"},
	}
	for _, c := range cases {
		if got := URL(c.scheme, c.host, c.port, c.path); got != c.want {
			t.Errorf("URL(%q, %q, %d, %q) = %q, want %q", c.scheme, c.host, c.port, c.path, got, c.want)
		}
	}
}

// TestURLParsesBackToDialableHost is the property that matters for link-local
// scanning: net/url must decode the escaped zone, since net/http hands
// url.Hostname() to the dialer. An unescaped '%' is an invalid URL escape and
// would fail before a packet ever left.
func TestURLParsesBackToDialableHost(t *testing.T) {
	u, err := url.Parse(URL("https", "fe80::1%en0", 8443, "/redfish/v1/"))
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if got := u.Hostname(); got != "fe80::1%en0" {
		t.Errorf("Hostname() = %q, want %q", got, "fe80::1%en0")
	}
	if got := u.Port(); got != "8443" {
		t.Errorf("Port() = %q, want 8443", got)
	}
	// The negative half of the property: built with a raw '%', the same URL does
	// not parse at all. Assembled from parts so it is not a constant staticcheck
	// can flag as a knowingly-invalid literal.
	zones := []string{"en0"}
	raw := "https://[fe80::1%" + zones[0] + "]:8443/"
	if _, err := url.Parse(raw); err == nil {
		t.Errorf("url.Parse(%q) succeeded; the %%25 escaping is not needed anymore", raw)
	}
}

func TestURLAuthority(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.0.0.1", "10.0.0.1"},
		{"10.0.0.1:8443", "10.0.0.1:8443"},
		{"fe80::1%en0", "[fe80::1%25en0]"},
		{"[fe80::1%en0]:443", "[fe80::1%25en0]:443"},
		{"[fe80::1]", "[fe80::1]"},
	}
	for _, c := range cases {
		if got := URLAuthority(c.in); got != c.want {
			t.Errorf("URLAuthority(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestZoneAndStripZone(t *testing.T) {
	cases := []struct {
		in       string
		zone     string
		stripped string
		isIPv6   bool
	}{
		{"fe80::1%en0", "en0", "fe80::1", true},
		{"[fe80::1%25en0]", "en0", "fe80::1", true},
		{"fe80::1", "", "fe80::1", true},
		{"10.0.0.1", "", "10.0.0.1", false},
		// A hostname with a '%' has no IPv6 zone to strip.
		{"host%weird", "", "host%weird", false},
	}
	for _, c := range cases {
		if got := Zone(c.in); got != c.zone {
			t.Errorf("Zone(%q) = %q, want %q", c.in, got, c.zone)
		}
		if got := StripZone(c.in); got != c.stripped {
			t.Errorf("StripZone(%q) = %q, want %q", c.in, got, c.stripped)
		}
		if got := IsIPv6(c.in); got != c.isIPv6 {
			t.Errorf("IsIPv6(%q) = %v, want %v", c.in, got, c.isIPv6)
		}
	}
}
