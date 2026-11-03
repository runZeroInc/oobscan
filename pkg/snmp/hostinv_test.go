package snmp

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestNormalizeMAC(t *testing.T) {
	for _, tc := range []struct {
		name string
		val  any
		want string
	}{
		{"six raw octets", []byte{0x3c, 0xfd, 0xfe, 0x00, 0x00, 0x90}, "3c:fd:fe:00:00:90"},
		{"colon text", "3C:FD:FE:00:00:90", "3c:fd:fe:00:00:90"},
		{"dash text", "3C-FD-FE-00-00-90", "3c:fd:fe:00:00:90"},
		{"dotted text", "3cfd.fe00.0090", "3c:fd:fe:00:00:90"},
		{"bare hex", "3cfdfe000090", "3c:fd:fe:00:00:90"},
		{"short", "3c:fd:fe", ""},
		{"not a mac", "PowerEdge R640", ""},
		{"empty", "", ""},
		// Every OID this is called on is a PhysAddress, so a six-octet
		// OctetString is the address itself even when the bytes are printable.
		{"six octets are always an address", []byte("abcdef"), "61:62:63:64:65:66"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeMAC(gosnmp.SnmpPDU{Value: tc.val})
			if got != tc.want {
				t.Fatalf("normalizeMAC(%v) = %q, want %q", tc.val, got, tc.want)
			}
		})
	}
}

func TestSplitARPIndex(t *testing.T) {
	base := oidIPNetToMediaPhys
	for _, tc := range []struct {
		name    string
		in      string
		wantIdx string
		wantIP  string
	}{
		{"normal", base + ".3.192.0.2.36", "3", "192.0.2.36"},
		{"index above 255", base + ".1001.192.0.2.7", "1001", "192.0.2.7"},
		{"wrong arity", base + ".3.192.0.2", "", ""},
		{"not under base", "1.3.6.1.2.1.4.20.1.1.192.0.2.1", "", ""},
		{"bad octet", base + ".3.192.0.2.999", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idx, ip := splitARPIndex(tc.in, base)
			if idx != tc.wantIdx || ip != tc.wantIP {
				t.Fatalf("splitARPIndex(%q) = (%q,%q), want (%q,%q)",
					tc.in, idx, ip, tc.wantIdx, tc.wantIP)
			}
		})
	}
}

// The join is the whole point of the walk: a managed-machine NIC MAC seen in the
// neighbour cache names the address of the machine the controller manages.
func TestResolveJoinsNICListAgainstARP(t *testing.T) {
	inv := &HostInventory{
		Host:       "192.0.2.39",
		OwnMACs:    []string{"3c:fd:fe:00:00:9f"},
		ServerNICs: []string{"3c:fd:fe:00:00:90", "3c:fd:fe:00:00:92"},
		ARP: []ARPEntry{
			{IP: "192.0.2.33", MAC: "88:18:f1:00:00:12"},
			{IP: "192.0.2.36", MAC: "3c:fd:fe:00:00:90"},
		},
	}
	inv.Resolve()
	if len(inv.ManagedIPs) != 1 || inv.ManagedIPs[0] != "192.0.2.36" {
		t.Fatalf("ManagedIPs = %v, want [192.0.2.36]", inv.ManagedIPs)
	}
}

// A MAC is globally unique, so a neighbour cache entry resolves the pair even
// when the managed machine sits in a different segment from the controller.
func TestResolveCrossesSubnets(t *testing.T) {
	inv := &HostInventory{
		Host:       "192.0.2.39",
		ServerNICs: []string{"3c:fd:fe:00:00:90"},
		ARP:        []ARPEntry{{IP: "198.51.100.20", MAC: "3c:fd:fe:00:00:90"}},
	}
	inv.Resolve()
	if len(inv.ManagedIPs) != 1 || inv.ManagedIPs[0] != "198.51.100.20" {
		t.Fatalf("ManagedIPs = %v, want [198.51.100.20]", inv.ManagedIPs)
	}
}

// The controller's own interfaces appear in both tables on some agents. Its own
// address is not the managed machine.
func TestResolveExcludesTheAgentItself(t *testing.T) {
	inv := &HostInventory{
		Host:       "192.0.2.39",
		OwnMACs:    []string{"3c:fd:fe:00:00:9f"},
		ServerNICs: []string{"3c:fd:fe:00:00:9f", "3c:fd:fe:00:00:90"},
		ARP: []ARPEntry{
			{IP: "192.0.2.39", MAC: "3c:fd:fe:00:00:9f"},
			{IP: "192.0.2.36", MAC: "3c:fd:fe:00:00:90"},
		},
	}
	inv.Resolve()
	for _, ip := range inv.ManagedIPs {
		if ip == "192.0.2.39" {
			t.Fatalf("ManagedIPs must not contain the agent address: %v", inv.ManagedIPs)
		}
	}
	if len(inv.ManagedIPs) != 1 || inv.ManagedIPs[0] != "192.0.2.36" {
		t.Fatalf("ManagedIPs = %v, want [192.0.2.36]", inv.ManagedIPs)
	}
}

func TestResolveNeedsBothSides(t *testing.T) {
	only := &HostInventory{ServerNICs: []string{"3c:fd:fe:00:00:90"}}
	only.Resolve()
	if len(only.ManagedIPs) != 0 {
		t.Fatalf("no ARP cache must yield no pair, got %v", only.ManagedIPs)
	}
	arp := &HostInventory{ARP: []ARPEntry{{IP: "192.0.2.36", MAC: "3c:fd:fe:00:00:90"}}}
	arp.Resolve()
	if len(arp.ManagedIPs) != 0 {
		t.Fatalf("no NIC list must yield no pair, got %v", arp.ManagedIPs)
	}
}

func TestEmpty(t *testing.T) {
	if !(&HostInventory{}).Empty() {
		t.Fatal("zero inventory should be empty")
	}
	if (&HostInventory{ARP: []ARPEntry{{IP: "192.0.2.1", MAC: "aa:bb:cc:dd:ee:ff"}}}).Empty() {
		t.Fatal("an inventory with a neighbour cache is not empty")
	}
	var nilInv *HostInventory
	if !nilInv.Empty() {
		t.Fatal("nil inventory should be empty")
	}
}
