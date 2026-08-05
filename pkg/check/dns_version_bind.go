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

	risk := "info"
	note := "DNS daemon version disclosed pre-auth; recorded for the component inventory. No affected-range comparison is attempted for this implementation."
	if impl == "dnsmasq" {
		switch {
		case num == "":
			note = "dnsmasq version disclosed but not parseable; no affected-range comparison attempted."
		case cmpDottedVersion(num, "2.78") < 0:

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

func buildDNSQuestion(id uint16, qname string) ([]byte, error) {
	var b []byte
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:], id)
	binary.BigEndian.PutUint16(hdr[2:], 0x0100)
	binary.BigEndian.PutUint16(hdr[4:], 1)
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
	b = append(b, 0x00)

	qt := make([]byte, 4)
	binary.BigEndian.PutUint16(qt[0:], 16)
	binary.BigEndian.PutUint16(qt[2:], 3)
	return append(b, qt...), nil
}

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

	for range qd {
		n, err := skipDNSName(pkt, off)
		if err != nil {
			return "", err
		}
		off = n + 4
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

			slen := int(pkt[off])
			if slen > 0 && off+1+slen <= len(pkt) {
				return string(pkt[off+1 : off+1+slen]), nil
			}
		}
		off += rdLen
	}
	return "", fmt.Errorf("no TXT answer")
}

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

func dnsImplementation(s string) string {
	low := strings.ToLower(s)
	for _, impl := range []string{"dnsmasq", "powerdns", "unbound", "knot", "bind"} {
		if strings.Contains(low, impl) {
			return impl
		}
	}
	return ""
}

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
