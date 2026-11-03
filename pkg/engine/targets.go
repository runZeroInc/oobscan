package engine

import (
	"bufio"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const maxExpandedTargets = 1 << 20

// ExpandTargets parses target specifiers into a shuffled list of hosts. A
// specifier may be an IP or hostname, an IPv4 CIDR, an IPv4 hyphen range, or a
// host:port pair. Expansion is text-only: IPv6 literals (including zoned
// link-local) and IPv6 multicast sweep specs pass through verbatim for
// pkg/discover to resolve. A host:port is kept verbatim and the named port becomes
// a web-port hint (see SplitHostPortHint). Order is randomized so a scan spreads
// load across a network instead of hammering one subnet first.
func ExpandTargets(specs []string) ([]string, error) {
	var out []string
	for _, raw := range specs {
		for _, tok := range strings.Fields(strings.ReplaceAll(raw, ",", " ")) {
			tok = strings.TrimSpace(tok)
			if tok == "" || strings.HasPrefix(tok, "#") {
				continue
			}
			hosts, err := expandOne(tok)
			if err != nil {
				return nil, err
			}
			out = append(out, hosts...)
		}
	}
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out, nil
}

func expandOne(tok string) ([]string, error) {
	switch {
	case strings.Contains(tok, "/"):
		return expandCIDR(tok)
	case isHyphenRange(tok):
		return expandHyphenRange(tok)
	default:
		// A single host or a host:port pair. Keep the token verbatim (including any
		// :port and bracketed IPv6 literal); consumers split the port off with
		// SplitHostPortHint - scan turns it into a web-port hint, the IPMI path
		// discards it.
		return []string{tok}, nil
	}
}

// SplitHostPortHint splits a "host:port" target spec into a bare host and a
// numeric port hint. A spec without a valid trailing port (a bare IP or
// hostname, or an unbracketed IPv6 literal) is returned unchanged with port 0.
// It centralizes the host:port parsing so the scan engine (web-port hint) and
// the IPMI path (which discards the port) agree on what counts as a port.
func SplitHostPortHint(spec string) (host string, port int) {
	h, p, err := net.SplitHostPort(spec)
	if err != nil {
		return spec, 0
	}
	if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
		return h, n
	}
	return h, 0
}

func expandCIDR(tok string) ([]string, error) {
	prefix, err := netip.ParsePrefix(tok)
	if err != nil {
		return nil, fmt.Errorf("bad CIDR %q: %w", tok, err)
	}
	base := prefix.Masked().Addr()
	if !base.Is4() {
		return nil, fmt.Errorf("IPv6 CIDR not supported: %q", tok)
	}
	count := uint64(1) << (32 - prefix.Bits())
	if count > maxExpandedTargets {
		return nil, fmt.Errorf("CIDR expands to %d targets, limit is %d: %q", count, maxExpandedTargets, tok)
	}
	out := make([]string, 0, count)
	for i := uint64(0); i < count; i++ {
		out = append(out, base.String())
		base = base.Next()
	}
	return out, nil
}

// isHyphenRange reports whether tok looks like an IPv4 hyphen range and not a
// hostname that merely contains a dash.
func isHyphenRange(tok string) bool {
	lo, _, ok := strings.Cut(tok, "-")
	if !ok {
		return false
	}
	return net.ParseIP(lo).To4() != nil
}

// expandHyphenRange expands "10.0.0.1-10.0.0.20" and the shorthand
// "10.0.0.1-20" (last octet only).
func expandHyphenRange(tok string) ([]string, error) {
	loStr, hiStr, _ := strings.Cut(tok, "-")
	lo := net.ParseIP(strings.TrimSpace(loStr)).To4()
	if lo == nil {
		return nil, fmt.Errorf("bad range start %q", loStr)
	}
	hiStr = strings.TrimSpace(hiStr)
	var hi net.IP
	if strings.Contains(hiStr, ".") {
		hi = net.ParseIP(hiStr).To4()
	} else { // last-octet shorthand
		n, err := strconv.Atoi(hiStr)
		if err != nil || n < 0 || n > 255 {
			return nil, fmt.Errorf("bad range end %q", hiStr)
		}
		hi = net.IPv4(lo[0], lo[1], lo[2], byte(n)).To4()
	}
	if hi == nil {
		return nil, fmt.Errorf("bad range end %q", hiStr)
	}
	start := ipToU32(lo)
	end := ipToU32(hi)
	if start > end {
		return nil, fmt.Errorf("range start > end: %q", tok)
	}
	count := uint64(end) - uint64(start) + 1
	if count > maxExpandedTargets {
		return nil, fmt.Errorf("range expands to %d targets, limit is %d: %q", count, maxExpandedTargets, tok)
	}
	out := make([]string, 0, count)
	for offset := uint64(0); offset < count; offset++ {
		out = append(out, u32ToIP(start+uint32(offset)).String())
	}
	return out, nil
}

func ipToU32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func u32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// ParsePorts turns a comma-delimited "port[/proto]" spec into Ports. A bare
// port defaults to TCP; ranges (n-m) are supported for TCP. Example:
// "623/udp,443/tcp,80,16992/tcp".
func ParsePorts(spec string) ([]Port, error) {
	var out []Port
	seen := map[Port]bool{}
	add := func(p Port) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		portPart, protoPart, _ := strings.Cut(tok, "/")
		var proto Proto
		switch strings.ToLower(protoPart) {
		case "", "tcp":
			proto = ProtoTCP
		case "udp":
			proto = ProtoUDP
		default:
			return nil, fmt.Errorf("bad proto in %q", tok)
		}
		if lo, hi, ok := strings.Cut(portPart, "-"); ok {
			ln, err1 := strconv.Atoi(lo)
			hn, err2 := strconv.Atoi(hi)
			if err1 != nil || err2 != nil || !validPort(ln) || !validPort(hn) || ln > hn {
				return nil, fmt.Errorf("bad port range %q", tok)
			}
			for n := ln; n <= hn; n++ {
				add(Port{Num: n, Proto: proto})
			}
			continue
		}
		n, err := strconv.Atoi(portPart)
		if err != nil || !validPort(n) {
			return nil, fmt.Errorf("bad port %q", tok)
		}
		add(Port{Num: n, Proto: proto})
	}
	return out, nil
}

func validPort(n int) bool { return n > 0 && n <= 65535 }

// ReadTargetLines reads newline-delimited targets from r (a file or stdin),
// skipping blank lines and # comments. Each line is expanded like a CLI arg.
func ReadTargetLines(r io.Reader) ([]string, error) {
	var specs []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		specs = append(specs, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return ExpandTargets(specs)
}
