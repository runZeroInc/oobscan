package check

import (
	"encoding/binary"
	"testing"
)

// txtResponse builds a minimal DNS response carrying one CHAOS TXT answer, using
// a compression pointer for the answer NAME the way a real resolver does.
func txtResponse(id uint16, qname, txt string) []byte {
	q, err := buildDNSQuestion(id, qname)
	if err != nil {
		panic(err)
	}
	pkt := append([]byte{}, q...)
	binary.BigEndian.PutUint16(pkt[2:], 0x8180) // response, RD+RA
	binary.BigEndian.PutUint16(pkt[6:], 1)      // ANCOUNT

	pkt = append(pkt, 0xc0, 0x0c) // NAME -> compression pointer to the question
	rr := make([]byte, 8)
	binary.BigEndian.PutUint16(rr[0:], 16) // TYPE TXT
	binary.BigEndian.PutUint16(rr[2:], 3)  // CLASS CHAOS
	pkt = append(pkt, rr...)
	rdlen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdlen, uint16(len(txt)+1))
	pkt = append(pkt, rdlen...)
	pkt = append(pkt, byte(len(txt)))
	return append(pkt, txt...)
}

func TestParseDNSTXTAnswer(t *testing.T) {
	const id = 0x1234
	got, err := parseDNSTXTAnswer(txtResponse(id, "version.bind", "dnsmasq-2.75"), id)
	if err != nil {
		t.Fatalf("parseDNSTXTAnswer: %v", err)
	}
	if got != "dnsmasq-2.75" {
		t.Fatalf("got %q, want %q", got, "dnsmasq-2.75")
	}
}

func TestParseDNSTXTAnswerRejects(t *testing.T) {
	const id = 0x1234
	full := txtResponse(id, "version.bind", "dnsmasq-2.75")

	t.Run("id mismatch", func(t *testing.T) {
		if _, err := parseDNSTXTAnswer(full, id+1); err == nil {
			t.Fatal("expected an error on transaction-id mismatch")
		}
	})
	t.Run("short header", func(t *testing.T) {
		if _, err := parseDNSTXTAnswer(full[:8], id); err == nil {
			t.Fatal("expected an error on a short header")
		}
	})
	t.Run("no answers", func(t *testing.T) {
		p := append([]byte{}, full...)
		binary.BigEndian.PutUint16(p[6:], 0)
		if _, err := parseDNSTXTAnswer(p, id); err == nil {
			t.Fatal("expected an error when ANCOUNT is zero")
		}
	})
	// Truncation at every length must fail cleanly rather than panic: the parser
	// runs on attacker-supplied datagrams, so a bounds bug here is remotely
	// reachable.
	t.Run("every truncation", func(t *testing.T) {
		for n := range len(full) {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panic on %d-byte truncation: %v", n, r)
					}
				}()
				_, _ = parseDNSTXTAnswer(full[:n], id)
			}()
		}
	})
	t.Run("rdlength past end", func(t *testing.T) {
		p := append([]byte{}, full...)
		// The RDLENGTH field sits 2 bytes before the rdata, at the tail.
		binary.BigEndian.PutUint16(p[len(p)-len("dnsmasq-2.75")-3:], 0xffff)
		if _, err := parseDNSTXTAnswer(p, id); err == nil {
			t.Fatal("expected an error when RDLENGTH runs past the datagram")
		}
	})
}

func TestSkipDNSNamePointerNotFollowed(t *testing.T) {
	// A pointer to itself would loop forever if the parser followed pointers.
	pkt := []byte{0xc0, 0x00}
	off, err := skipDNSName(pkt, 0)
	if err != nil {
		t.Fatalf("skipDNSName: %v", err)
	}
	if off != 2 {
		t.Fatalf("got offset %d, want 2 (pointer consumed, not followed)", off)
	}
}

func TestDNSVersionNumber(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"dnsmasq-2.75", "2.75"},
		{"dnsmasq 2.90", "2.90"},
		{"dnsmasq-2.80rc1", "2.80"},
		{"dnsmasq", ""},
		{"9.11.4-P2-RedHat", "9.11.4"},
		{"version 3", ""}, // no dot -> not a usable dotted version
	} {
		if got := dnsVersionNumber(tc.in); got != tc.want {
			t.Errorf("dnsVersionNumber(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDNSImplementation(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"dnsmasq-2.75", "dnsmasq"},
		{"9.11.4-P2-RedHat", ""}, // BIND does not name itself in this banner
		{"BIND 9.16.1", "bind"},  // but does when it is present
		{"PowerDNS Recursor 4.4.2", "powerdns"},
		{"unbound 1.13.1", "unbound"},
		{"", ""},
		{"some-appliance-dns 1.0", ""}, // unrecognised: report nothing rather than guess
	} {
		if got := dnsImplementation(tc.in); got != tc.want {
			t.Errorf("dnsImplementation(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCmpDottedVersion(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"2.75", "2.78", -1},
		{"2.78", "2.78", 0},
		{"2.90", "2.78", 1},
		{"2.8", "2.78", -1}, // component-wise, not lexical
		{"2.78.1", "2.78", 1},
		{"2", "2.78", -1},
	} {
		if got := cmpDottedVersion(tc.a, tc.b); got != tc.want {
			t.Errorf("cmpDottedVersion(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
