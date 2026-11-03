// Package netaddr centralizes host:port formatting so IPv6 targets survive the
// trip from a target spec to a dialed socket or an HTTP URL.
//
// Two things go wrong with hand-rolled fmt.Sprintf("%s:%d", host, port):
// an IPv6 literal needs brackets, and a link-local literal carries a zone
// (fe80::1%en0) whose '%' is an invalid escape inside a URL. Link-local
// discovery (see pkg/discover) produces exactly those zoned literals, so every
// dial and URL built from a target host goes through the helpers here:
// DialHostPort for sockets, URLHostPort/URL for anything parsed as a URL.
package netaddr

import (
	"net"
	"strconv"
	"strings"
)

// Host normalizes a host for dialing: it trims surrounding brackets from an
// IPv6 literal so the result can be handed to net.JoinHostPort (which adds them
// back) without doubling them up.
func Host(host string) string {
	h := strings.TrimSpace(host)
	if len(h) > 1 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	return h
}

// DialHostPort formats host and port for net.Dial: IPv6 literals are bracketed
// and any zone is left intact, since the resolver needs the raw '%zone' form.
func DialHostPort(host string, port int) string {
	return net.JoinHostPort(Host(host), strconv.Itoa(port))
}

// URLHost formats a bare host for use in a URL authority: IPv6 in brackets with
// the zone percent-escaped ("fe80::1%en0" -> "[fe80::1%25en0]"). Go's net/url
// decodes %25 back to '%' when parsing, and net/http then dials the zoned
// address, so a URL built this way reaches a link-local target.
func URLHost(host string) string {
	h := escapeZone(Host(host))
	if strings.Contains(h, ":") {
		return "[" + h + "]"
	}
	return h
}

// URLHostPort formats host:port for a URL authority, bracketing and
// zone-escaping IPv6 like URLHost.
func URLHostPort(host string, port int) string {
	return net.JoinHostPort(escapeZone(Host(host)), strconv.Itoa(port))
}

// URL builds "scheme://host[:port]path". A port that is unset (<= 0) or the
// scheme's default is omitted. path is appended verbatim, so callers keep
// control of query strings and pre-escaped path segments.
func URL(scheme, host string, port int, path string) string {
	authority := URLHost(host)
	if port > 0 && !defaultPort(scheme, port) {
		authority = URLHostPort(host, port)
	}
	return scheme + "://" + authority + path
}

// URLAuthority formats a host that may or may not already carry a port
// ("10.0.0.1", "10.0.0.1:8443", "fe80::1%en0", "[fe80::1%en0]:443") for use in a
// URL. It exists for the probe helpers that take a single host-or-host:port
// string and paste it straight after "https://".
func URLAuthority(hostPort string) string {
	if h, p, err := net.SplitHostPort(hostPort); err == nil {
		if n, cerr := strconv.Atoi(p); cerr == nil {
			return URLHostPort(h, n)
		}
	}
	return URLHost(hostPort)
}

// IsIPv6 reports whether host is an IPv6 literal (bracketed or not, zoned or
// not) rather than an IPv4 literal or a hostname.
func IsIPv6(host string) bool {
	h := Host(host)
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i]
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.To4() == nil
}

// Zone returns the zone (scope) of a zoned IPv6 literal, or "" when there is
// none. The zone is what binds a link-local address to an interface.
func Zone(host string) string {
	h := Host(host)
	i := strings.IndexByte(h, '%')
	if i < 0 || !strings.Contains(h[:i], ":") {
		return ""
	}
	return strings.TrimPrefix(h[i+1:], "25")
}

// StripZone removes the '%zone' suffix from an IPv6 literal. Use it where a
// zone is meaningless or invalid -- TLS SNI, certificate name matching, and
// anything compared against an address recorded by the device itself.
func StripZone(host string) string {
	h := Host(host)
	i := strings.IndexByte(h, '%')
	if i < 0 || !strings.Contains(h[:i], ":") {
		return h
	}
	return h[:i]
}

// escapeZone percent-escapes the '%' introducing an IPv6 zone so the literal is
// valid inside a URL. It is idempotent: an already-escaped %25 is left alone.
func escapeZone(host string) string {
	i := strings.IndexByte(host, '%')
	if i < 0 || !strings.Contains(host[:i], ":") {
		return host
	}
	if strings.HasPrefix(host[i:], "%25") {
		return host
	}
	return host[:i] + "%25" + host[i+1:]
}

// plaintextWebPorts are the ports assumed to serve cleartext HTTP when no live probe
// has determined a scheme; everything else defaults to https. One list, one answer:
// this previously lived in four copies that had drifted on 8081.
//
// The per-vendor probe allowlists in check/fujitsu_check.go and check/web_check.go are
// deliberately not folded in: they enumerate which ports to try for a device family, a
// different question from what scheme an unprobed port defaults to.
var plaintextWebPorts = map[int]bool{
	80: true, 8000: true, 8080: true, 8081: true, 8888: true,
}

// DefaultScheme guesses a URL scheme for a web port when no live probe determined
// one. Callers that have observed a scheme must prefer the observation: this is a
// fallback, not an override.
func DefaultScheme(port int) string {
	if plaintextWebPorts[port] {
		return "http"
	}
	return "https"
}

// IsPlaintextWebPort reports whether port is a well-known cleartext HTTP port.
func IsPlaintextWebPort(port int) bool { return plaintextWebPorts[port] }

// defaultPort reports whether port is the default for scheme and can be left
// out of a URL authority.
func defaultPort(scheme string, port int) bool {
	switch strings.ToLower(scheme) {
	case "http":
		return port == 80
	case "https":
		return port == 443
	}
	return false
}
