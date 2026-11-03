package check

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// A DNS daemon conventionally answers a CHAOS-class TXT query for
// `version.bind` with its own version string: one read-only UDP datagram,
// equivalent to `dig +short @host chaos txt version.bind`. dnsmasq gets an
// affected-range note because several devices bundle a stale copy
// (kb/vertiv/, kb/_cross-vendor/); it records what the daemon reports, not
// patch status -- a backport can fix a bug without changing the banner -- so
// it never asserts a host is vulnerable.
func init() {
	Register(Check{
		Name:        "udp.dns.versionBind",
		Description: "DNS daemon version disclosed via CHAOS TXT version.bind (bundled-component age signal; affected-range note for dnsmasq)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runDNSVersionBind,
	})
	RegisterExplain("udp.dns.versionBind", explainDNSVersionBind)
}

const dnsPort = 53

func runDNSVersionBind(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	// UDP port state is rarely known up front (no negative result exists for an
	// unanswered datagram), so this probes unconditionally the way the other UDP
	// discovery checks do. One 4-byte-question datagram with a short timeout is
	// cheap enough not to need a gate, and a non-DNS host simply never replies.
	timeout := min(t.Timeout, 4*time.Second)

	ver, qname := "", ""
	for _, q := range []string{"version.bind", "version.server"} {
		got, err := dnsChaosTXT(t.Host, dnsPort, q, timeout)
		if err != nil || got == "" {
			continue
		}
		ver, qname = got, q
		break
	}
	if ver == "" {
		return nil
	}
	t.MarkOpen(dnsPort, "udp", "dns")

	num := dnsVersionNumber(ver)
	impl := dnsImplementation(ver)

	// The version disclosure itself is informational for every implementation.
	// Only dnsmasq gets an affected-range comparison, because it is the one whose
	// bundled-copy staleness we have characterised from firmware; asserting a range
	// for an implementation we have not looked at would be guesswork.
	risk := "info"
	note := "DNS daemon version disclosed pre-auth; recorded for the component inventory. No affected-range comparison is attempted for this implementation."
	if impl == "dnsmasq" {
		switch {
		case num == "":
			note = "dnsmasq version disclosed but not parseable; no affected-range comparison attempted."
		case cmpDottedVersion(num, "2.78") < 0:
			// CVE-2017-14491 was fixed in 2.78. Everything below it is in range.
			risk = "medium"
			note = "version predates dnsmasq 2.78 -- inside the CVE-2017-14491 affected range (heap overflow in DNS response parsing). PATCH STATUS NOT ESTABLISHED: a vendor backport would not change this banner. Confirm by inspecting the shipped binary."
		default:
			note = "dnsmasq 2.78 or later -- outside the CVE-2017-14491 affected range."
		}
	}

	return []engine.Finding{{
		Check: "udp.dns.versionBind", Category: "exposure", Risk: risk,
		Port: dnsPort, Transport: "udp", Protocol: "dns",
		Fields: engine.F(
			"query", qname,
			"version", cleanSnippet(ver),
			"implementation", impl,
			"versionNumber", num,
			"note", note,
			"proof", proofKV("query", qname, "class", "CHAOS", "type", "TXT", "answer", ver),
		),
	}}
}

// dnsChaosTXT sends one CHAOS-class TXT question and returns the first TXT string
// in the answer section. Read-only: a single well-formed question, no retries
// beyond the caller's loop, and nothing malformed on the wire.
func dnsChaosTXT(host string, port int, qname string, timeout time.Duration) (string, error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return "", err
	}
	id := binary.BigEndian.Uint16(idb[:])

	q, err := buildDNSQuestion(id, qname)
	if err != nil {
		return "", err
	}

	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	if _, err := conn.Write(q); err != nil {
		return "", err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return parseDNSTXTAnswer(buf[:n], id)
}

// buildDNSQuestion encodes a single question: QTYPE=TXT(16), QCLASS=CHAOS(3),
// RD set. CHAOS class is what both dnsmasq and BIND answer version queries in.
func buildDNSQuestion(id uint16, qname string) ([]byte, error) {
	var b []byte
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:], id)
	binary.BigEndian.PutUint16(hdr[2:], 0x0100) // standard query, recursion desired
	binary.BigEndian.PutUint16(hdr[4:], 1)      // QDCOUNT
	b = append(b, hdr...)

	for label := range strings.SplitSeq(qname, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("dns label too long")
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0x00) // root

	qt := make([]byte, 4)
	binary.BigEndian.PutUint16(qt[0:], 16) // TXT
	binary.BigEndian.PutUint16(qt[2:], 3)  // CHAOS
	return append(b, qt...), nil
}

// parseDNSTXTAnswer walks the response far enough to return the first TXT
// character-string. Every offset is bounds-checked against the datagram, and
// compression pointers in the answer NAME are skipped rather than followed, so a
// hostile or malformed reply cannot walk off the buffer or loop.
func parseDNSTXTAnswer(pkt []byte, wantID uint16) (string, error) {
	if len(pkt) < 12 {
		return "", fmt.Errorf("short dns response")
	}
	if binary.BigEndian.Uint16(pkt[0:]) != wantID {
		return "", fmt.Errorf("dns id mismatch")
	}
	qd := int(binary.BigEndian.Uint16(pkt[4:]))
	an := int(binary.BigEndian.Uint16(pkt[6:]))
	if an == 0 {
		return "", fmt.Errorf("no answer records")
	}

	off := 12
	// Skip the echoed question section.
	for range qd {
		n, err := skipDNSName(pkt, off)
		if err != nil {
			return "", err
		}
		off = n + 4 // QTYPE + QCLASS
		if off > len(pkt) {
			return "", fmt.Errorf("truncated question")
		}
	}

	for range an {
		n, err := skipDNSName(pkt, off)
		if err != nil {
			return "", err
		}
		off = n
		if off+10 > len(pkt) {
			return "", fmt.Errorf("truncated rr header")
		}
		rrType := binary.BigEndian.Uint16(pkt[off:])
		rdLen := int(binary.BigEndian.Uint16(pkt[off+8:]))
		off += 10
		if rdLen < 0 || off+rdLen > len(pkt) {
			return "", fmt.Errorf("truncated rdata")
		}
		if rrType == 16 && rdLen >= 1 {
			// TXT rdata is one or more <length><bytes> character-strings.
			slen := int(pkt[off])
			if slen > 0 && off+1+slen <= len(pkt) {
				return string(pkt[off+1 : off+1+slen]), nil
			}
		}
		off += rdLen
	}
	return "", fmt.Errorf("no TXT answer")
}

// skipDNSName returns the offset just past a wire-format name at off. A
// compression pointer terminates the name, so it is consumed (2 bytes) and not
// followed - this parser never needs the expanded name, and refusing to follow
// pointers makes pointer loops unreachable.
func skipDNSName(pkt []byte, off int) (int, error) {
	for {
		if off >= len(pkt) {
			return 0, fmt.Errorf("name runs past end")
		}
		l := int(pkt[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			if off+2 > len(pkt) {
				return 0, fmt.Errorf("truncated compression pointer")
			}
			return off + 2, nil
		case l&0xc0 != 0:
			return 0, fmt.Errorf("reserved label type")
		default:
			off += 1 + l
		}
	}
}

// dnsImplementation names the daemon when the banner identifies itself, and
// returns "" otherwise. Only a self-identifying banner is trusted: guessing the
// implementation would put a wrong component in the inventory, and the whole point
// of reading version.bind is to record what the daemon says rather than infer it.
func dnsImplementation(s string) string {
	low := strings.ToLower(s)
	for _, impl := range []string{"dnsmasq", "powerdns", "unbound", "knot", "bind"} {
		if strings.Contains(low, impl) {
			return impl
		}
	}
	return ""
}

// dnsVersionNumber pulls the dotted version out of a version.bind banner such as
// "dnsmasq-2.75", "dnsmasq 2.90" or "9.11.4-P2-RedHat".
func dnsVersionNumber(s string) string {
	i := strings.IndexAny(s, "0123456789")
	if i < 0 {
		return ""
	}
	end := i
	for end < len(s) && (s[end] == '.' || (s[end] >= '0' && s[end] <= '9')) {
		end++
	}
	v := strings.Trim(s[i:end], ".")
	if !strings.Contains(v, ".") {
		return ""
	}
	return v
}

// cmpDottedVersion compares two dotted numeric versions, returning -1, 0 or 1.
// Non-numeric components compare as 0, which keeps a malformed banner from
// producing a confident verdict.
func cmpDottedVersion(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(as), len(bs)); i++ {
		var ai, bi int
		if i < len(as) {
			ai, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bi, _ = strconv.Atoi(bs[i])
		}
		if ai != bi {
			if ai < bi {
				return -1
			}
			return 1
		}
	}
	return 0
}

func explainDNSVersionBind(host string, f engine.Finding) string {
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	ver := explainField(f, "version")
	impl := explainField(f, "implementation")
	b.WriteString("\nThe device's DNS service answers a CHAOS-class TXT query for `version.bind`\n")
	b.WriteString("with its own version string, disclosing the bundled DNS daemon version with no\n")
	b.WriteString("authentication. Embedded management cards frequently ship a DNS daemon that is\n")
	b.WriteString("years behind upstream, so this is a useful component-age signal.\n")
	if ver != "" {
		b.WriteString(fmt.Sprintf("\n**Reported version:** `%s`\n", ver))
	}
	if impl != "" {
		b.WriteString(fmt.Sprintf("\n**Implementation:** `%s` (self-identified in the banner)\n", impl))
	}
	if note := explainField(f, "note"); note != "" {
		b.WriteString(fmt.Sprintf("\n**Assessment:** %s\n", note))
	}
	b.WriteString("\n**Reproduce (read-only, one packet):**\n")
	b.WriteString(explainSh(fmt.Sprintf("dig +short @%s chaos txt version.bind", host)))
	b.WriteString("\n\n**Caveat:** a version banner is not a patch status. Distributors routinely\n")
	b.WriteString("backport security fixes without changing the reported version, so treat any\n")
	b.WriteString("affected-range note above as a candidate to confirm against the shipped binary,\n")
	b.WriteString("not as proof of exploitability.\n")
	b.WriteString("\n**Mitigation:** Disable the DNS service if unused, restrict UDP/53 to trusted\n")
	b.WriteString("clients, or apply vendor firmware that refreshes the bundled daemon. The version\n")
	b.WriteString("disclosure itself can be suppressed on most implementations.\n")
	return b.String()
}
