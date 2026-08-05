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

		return []string{tok}, nil
	}
}

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

func isHyphenRange(tok string) bool {
	lo, _, ok := strings.Cut(tok, "-")
	if !ok {
		return false
	}
	return net.ParseIP(lo).To4() != nil
}

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
	} else {
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
