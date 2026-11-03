// Package wire holds small, dependency-free helpers shared by the
// proprietary UDP/TCP protocol probes (Advantech ADAM, Red Lion UDR, Moxa
// DSCI, Avocent adsap, ServerTech JAWS, Vertiv Velocity).
//
// The generic extractors (Printable/IPv4s/MACs) let a probe report every
// human-meaningful token in a device response even when the exact byte
// offsets of a proprietary reply were not reverse-engineered. A probe should
// always also carry the raw hex so nothing in the response is lost.
package wire

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// UDPQuery sends one datagram to host:port and returns the first datagram
// read back. A connected UDP socket surfaces an ICMP port-unreachable as a
// read error, which lets a caller distinguish closed from open|filtered.
func UDPQuery(host string, port int, payload []byte, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	c, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if len(payload) > 0 {
		if _, err := c.Write(payload); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

// TCPQuery connects to host:port. It reports whether the connection opened.
// If payload is non-nil it is written; then one read is attempted. A silent
// server (open, no banner) returns open=true with a nil response.
func TCPQuery(host string, port int, payload []byte, timeout time.Duration) (open bool, resp []byte, err error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false, nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if len(payload) > 0 {
		if _, werr := c.Write(payload); werr != nil {
			return true, nil, werr
		}
	}
	buf := make([]byte, 8192)
	n, _ := c.Read(buf)
	if n > 0 {
		return true, append([]byte(nil), buf[:n]...), nil
	}
	return true, nil, nil
}

var (
	rePrintable = regexp.MustCompile(`[\x20-\x7e]{3,}`)
	reIPv4      = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reMAC       = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
)

// Printable returns the unique printable-ASCII runs (length >= 3) found in
// raw, in first-seen order.
func Printable(raw []byte) []string {
	return uniq(rePrintable.FindAllString(string(raw), -1))
}

// IPv4s returns the unique dotted-quad tokens found in raw.
func IPv4s(raw []byte) []string { return uniq(reIPv4.FindAllString(string(raw), -1)) }

// MACs returns the unique ASCII-form MAC tokens found in raw.
func MACs(raw []byte) []string {
	out := reMAC.FindAllString(string(raw), -1)
	for i := range out {
		out[i] = strings.ToLower(strings.ReplaceAll(out[i], "-", ":"))
	}
	return uniq(out)
}

// MACFromBytes formats 6 raw bytes as a colon MAC, or "" if the slice is the
// all-zero or all-0xFF placeholder (not a real address).
func MACFromBytes(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	b = b[:6]
	zero, ff := true, true
	for _, x := range b {
		if x != 0x00 {
			zero = false
		}
		if x != 0xff {
			ff = false
		}
	}
	if zero || ff {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// Join renders a token list as a comma-separated field value.
func Join(xs []string) string { return strings.Join(xs, ",") }

func uniq(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

// SortedUniq is uniq with a stable sort, for fingerprint-style fields.
func SortedUniq(xs []string) []string {
	out := uniq(xs)
	sort.Strings(out)
	return out
}
