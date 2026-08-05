package netaddr

import (
	"net"
	"strconv"
	"strings"
)

func Host(host string) string {
	h := strings.TrimSpace(host)
	if len(h) > 1 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	return h
}

func DialHostPort(host string, port int) string {
	return net.JoinHostPort(Host(host), strconv.Itoa(port))
}

func URLHost(host string) string {
	h := escapeZone(Host(host))
	if strings.Contains(h, ":") {
		return "[" + h + "]"
	}
	return h
}

func URLHostPort(host string, port int) string {
	return net.JoinHostPort(escapeZone(Host(host)), strconv.Itoa(port))
}

func URL(scheme, host string, port int, path string) string {
	authority := URLHost(host)
	if port > 0 && !defaultPort(scheme, port) {
		authority = URLHostPort(host, port)
	}
	return scheme + "://" + authority + path
}

func URLAuthority(hostPort string) string {
	if h, p, err := net.SplitHostPort(hostPort); err == nil {
		if n, cerr := strconv.Atoi(p); cerr == nil {
			return URLHostPort(h, n)
		}
	}
	return URLHost(hostPort)
}

func IsIPv6(host string) bool {
	h := Host(host)
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i]
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.To4() == nil
}

func Zone(host string) string {
	h := Host(host)
	i := strings.IndexByte(h, '%')
	if i < 0 || !strings.Contains(h[:i], ":") {
		return ""
	}
	return strings.TrimPrefix(h[i+1:], "25")
}

func StripZone(host string) string {
	h := Host(host)
	i := strings.IndexByte(h, '%')
	if i < 0 || !strings.Contains(h[:i], ":") {
		return h
	}
	return h[:i]
}

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

var plaintextWebPorts = map[int]bool{
	80: true, 8000: true, 8080: true, 8081: true, 8888: true,
}

func DefaultScheme(port int) string {
	if plaintextWebPorts[port] {
		return "http"
	}
	return "https"
}

func IsPlaintextWebPort(port int) bool { return plaintextWebPorts[port] }

func defaultPort(scheme string, port int) bool {
	switch strings.ToLower(scheme) {
	case "http":
		return port == 80
	case "https":
		return port == 443
	}
	return false
}
