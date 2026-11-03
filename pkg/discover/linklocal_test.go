package discover

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestIsSpec(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"ff02::1%en0", true},
		{"ff02::1", true},
		{"[ff02::1%en0]", true},
		{"ff02::2%eth0", true}, // all-routers is a multicast group too
		{"ff05::1:3", true},    // any IPv6 multicast group, not just link-scope
		// Real targets, not sweeps.
		{"fe80::1%en0", false},
		{"fe80::1", false},
		{"10.0.0.1", false},
		{"224.0.0.1", false}, // IPv4 multicast: no link-local IPv6 sweep applies
		{"bmc.example", false},
		{"10.0.0.0/24", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsSpec(c.in); got != c.want {
			t.Errorf("IsSpec(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseSpecSplitsZone(t *testing.T) {
	group, zone, ok := parseSpec("ff02::1%en0")
	if !ok {
		t.Fatal("parseSpec failed")
	}
	if group.String() != "ff02::1" {
		t.Errorf("group = %q, want ff02::1", group.String())
	}
	if zone != "en0" {
		t.Errorf("zone = %q, want en0", zone)
	}
}

// TestResolveSpecsPassesThroughOrdinaryTargets pins the no-I/O path: a target
// list without a multicast spec must come back untouched, so an ordinary scan
// never waits on discovery.
func TestResolveSpecsPassesThroughOrdinaryTargets(t *testing.T) {
	in := []string{"10.0.0.1", "fe80::1%en0", "bmc.example:8443", "10.0.0.1"}
	got, err := ResolveSpecs(context.Background(), in, Options{})
	if err != nil {
		t.Fatalf("ResolveSpecs: %v", err)
	}
	want := []string{"10.0.0.1", "fe80::1%en0", "bmc.example:8443"} // duplicate collapsed
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestLinkLocalRejectsNonMulticast(t *testing.T) {
	if _, err := LinkLocal(context.Background(), "fe80::1%en0", Options{}); err == nil {
		t.Error("LinkLocal accepted a unicast spec")
	}
	if _, err := LinkLocal(context.Background(), "not-an-address", Options{}); err == nil {
		t.Error("LinkLocal accepted a non-address")
	}
}

func TestLinkLocalUnknownZone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := LinkLocal(ctx, "ff02::1%nosuchif0", Options{Wait: 200 * time.Millisecond})
	if err == nil {
		// This must not silently fall back to the default interface: net maps an
		// unknown zone to interface index 0, so the probes would leave by the
		// default route and an operator's typo would read as an empty segment.
		t.Fatal("LinkLocal succeeded on a nonexistent interface")
	}
	if !strings.Contains(err.Error(), `unknown interface "nosuchif0"`) {
		t.Errorf("error does not name the bad zone: %v", err)
	}
}

func TestHitSetRecorder(t *testing.T) {
	var h hitSet
	icmp := h.recorder("en0", "icmp6")
	rmcp := h.recorder("en0", "rmcp")

	icmp(netip.MustParseAddr("fe80::dead:beef"))
	rmcp(netip.MustParseAddr("fe80::dead:beef")) // same host, second vector
	rmcp(netip.MustParseAddr("2001:db8::5"))     // routable source: kept, unzoned
	// Dropped: not scannable.
	icmp(netip.MustParseAddr("ff02::1"))
	icmp(netip.MustParseAddr("::"))
	icmp(netip.MustParseAddr("10.0.0.1"))
	icmp(netip.MustParseAddr("::ffff:10.0.0.1"))
	icmp(netip.Addr{})

	got := h.responders()
	if len(got) != 2 {
		t.Fatalf("got %d responders (%v), want 2", len(got), got)
	}
	// Sorted output: the routable address sorts before the link-local one.
	if got[0].Host() != "2001:db8::5" {
		t.Errorf("responder[0] = %q, want 2001:db8::5", got[0].Host())
	}
	if got[1].Host() != "fe80::dead:beef%en0" {
		t.Errorf("responder[1] = %q, want the zoned link-local address", got[1].Host())
	}
	if strings.Join(got[1].Via, "+") != "icmp6+rmcp" {
		t.Errorf("responder[1].Via = %v, want [icmp6 rmcp]", got[1].Via)
	}
}
