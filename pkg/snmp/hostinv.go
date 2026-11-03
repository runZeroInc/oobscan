package snmp

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Host-inventory OIDs. The first two are standard MIB-II; the rest are vendor
// subtrees describing the machine the controller is attached to.
const (
	oidIPNetToMediaPhys = "1.3.6.1.2.1.4.22.1.2"                  // ARP cache, address to MAC
	oidIfPhysAddress    = "1.3.6.1.2.1.2.2.1.6"                   // the agent's own interface MACs
	oidDellNICMAC       = "1.3.6.1.4.1.674.10892.5.4.1100.90.1.6" // managed server NIC MACs
	oidDellServiceTag   = "1.3.6.1.4.1.674.10892.5.1.3.2.0"
	oidDellModel        = "1.3.6.1.4.1.674.10892.5.1.3.12.0"
	oidDellHostOS       = "1.3.6.1.4.1.674.10892.5.1.3.6.0"
	oidHPEHostSerial    = "1.3.6.1.4.1.232.2.2.2.1.0" // Insight agent, host side
)

// Exported for findings that need to cite which object was read.
const (
	OIDIPNetToMediaPhys = oidIPNetToMediaPhys
	OIDDellNICMAC       = oidDellNICMAC
)

// Walk bounds. A neighbour cache on a management segment is small; these caps
// exist so a misbehaving or hostile agent cannot hold the walk open.
const (
	maxARPEntries = 1024
	maxNICEntries = 64
	walkMaxReps   = 16
)

// ARPEntry is one ipNetToMediaTable row.
type ARPEntry struct {
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	IfIndex string `json:"ifIndex,omitempty"`
}

// HostInventory is what an agent discloses about the machine it is attached to
// and about its own segment. Every field is optional: agents vary widely in
// which subtrees they serve.
type HostInventory struct {
	Host      string `json:"host"`
	Community string `json:"community"`
	Version   int    `json:"version"`

	SysName string `json:"sysName,omitempty"`

	// OwnMACs are the agent's own interfaces (ifPhysAddress). ServerNICs are
	// the interfaces of the managed machine, which is a different set.
	OwnMACs    []string `json:"ownMACs,omitempty"`
	ServerNICs []string `json:"serverNICs,omitempty"`

	// ARP is the neighbour cache, which covers the segment rather than just
	// the managed machine.
	ARP []ARPEntry `json:"arp,omitempty"`

	ServiceTag string `json:"serviceTag,omitempty"`
	Model      string `json:"model,omitempty"`
	HostOS     string `json:"hostOS,omitempty"`
	HostSerial string `json:"hostSerial,omitempty"`

	// ManagedIPs are neighbour-cache addresses whose MAC belongs to the
	// managed machine, so they resolve the controller-to-host pair directly.
	ManagedIPs []string `json:"managedIPs,omitempty"`
}

// Empty reports whether the walk produced nothing worth recording.
func (h *HostInventory) Empty() bool {
	if h == nil {
		return true
	}
	return len(h.OwnMACs) == 0 && len(h.ServerNICs) == 0 && len(h.ARP) == 0 &&
		h.ServiceTag == "" && h.Model == "" && h.HostOS == "" && h.HostSerial == ""
}

// CollectHostInventory reads the neighbour cache, the interface tables and the
// vendor inventory scalars with an already-working community. It is read-only:
// GET and GETNEXT/GETBULK only, no SET.
//
// Resolve is called at the end, so ManagedIPs is populated when the agent
// served both a managed-machine NIC list and a neighbour cache.
func CollectHostInventory(host string, port int, community string, version int, timeout time.Duration) (*HostInventory, error) {
	if port == 0 {
		port = 161
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid SNMP port %d", port)
	}
	if community == "" {
		community = "public"
	}
	ver := gosnmp.Version2c
	if version == 0 {
		ver = gosnmp.Version1
	}
	g := &gosnmp.GoSNMP{
		Target:         host,
		Port:           uint16(port),
		Community:      community,
		Version:        ver,
		Timeout:        timeout,
		Retries:        0,
		MaxOids:        4,
		MaxRepetitions: walkMaxReps,
	}
	if err := g.Connect(); err != nil {
		return nil, err
	}
	defer g.Conn.Close()

	inv := &HostInventory{Host: host, Community: community, Version: version}

	// Scalars first: one GET covers the vendor inventory, and a failure here
	// must not prevent the table walks.
	if resp, err := g.Get([]string{oidSysName, oidDellServiceTag, oidDellModel, oidDellHostOS}); err == nil {
		for _, v := range resp.Variables {
			switch strings.TrimPrefix(v.Name, ".") {
			case oidSysName:
				inv.SysName = cleanText(pduString(v))
			case oidDellServiceTag:
				inv.ServiceTag = cleanText(pduString(v))
			case oidDellModel:
				inv.Model = cleanText(pduString(v))
			case oidDellHostOS:
				inv.HostOS = cleanText(pduString(v))
			}
		}
	}
	if resp, err := g.Get([]string{oidHPEHostSerial}); err == nil {
		for _, v := range resp.Variables {
			if strings.TrimPrefix(v.Name, ".") == oidHPEHostSerial {
				inv.HostSerial = cleanText(pduString(v))
			}
		}
	}

	inv.OwnMACs = walkMACs(g, oidIfPhysAddress, maxNICEntries)
	inv.ServerNICs = walkMACs(g, oidDellNICMAC, maxNICEntries)
	inv.ARP = walkARP(g, oidIPNetToMediaPhys, maxARPEntries)

	inv.Resolve()
	return inv, nil
}

// Resolve joins the managed-machine NIC list against the neighbour cache. A MAC
// is globally unique, so the join needs no subnet scoping and will place the
// managed machine in a different segment from the controller when that is where
// it is.
func (h *HostInventory) Resolve() {
	if h == nil || len(h.ServerNICs) == 0 || len(h.ARP) == 0 {
		return
	}
	own := make(map[string]bool, len(h.OwnMACs))
	for _, m := range h.OwnMACs {
		own[m] = true
	}
	want := make(map[string]bool, len(h.ServerNICs))
	for _, m := range h.ServerNICs {
		if !own[m] {
			want[m] = true
		}
	}
	seen := make(map[string]bool)
	var out []string
	for _, e := range h.ARP {
		if !want[e.MAC] || seen[e.IP] || e.IP == h.Host {
			continue
		}
		seen[e.IP] = true
		out = append(out, e.IP)
	}
	sort.Strings(out)
	h.ManagedIPs = out
}

// walkMACs collects the MAC-valued leaves under an OID, de-duplicated and in a
// stable order. An all-zero address is dropped: agents pad unconfigured rows
// with it and it is not an identifier.
func walkMACs(g *gosnmp.GoSNMP, oid string, limit int) []string {
	pdus, err := walk(g, oid)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, p := range pdus {
		mac := normalizeMAC(p)
		if mac == "" || mac == "00:00:00:00:00:00" || seen[mac] {
			continue
		}
		seen[mac] = true
		out = append(out, mac)
		if len(out) >= limit {
			break
		}
	}
	sort.Strings(out)
	return out
}

// walkARP collects ipNetToMediaTable rows. The address is carried in the OID
// suffix as <ifIndex>.<a>.<b>.<c>.<d>, so it is parsed from the name rather
// than the value.
func walkARP(g *gosnmp.GoSNMP, oid string, limit int) []ARPEntry {
	pdus, err := walk(g, oid)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []ARPEntry
	for _, p := range pdus {
		mac := normalizeMAC(p)
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}
		idx, ip := splitARPIndex(strings.TrimPrefix(p.Name, "."), oid)
		if ip == "" {
			continue
		}
		key := ip + "/" + mac
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ARPEntry{IP: ip, MAC: mac, IfIndex: idx})
		if len(out) >= limit {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// walk uses GETBULK on v2c and GETNEXT on v1, which does not support it.
func walk(g *gosnmp.GoSNMP, oid string) ([]gosnmp.SnmpPDU, error) {
	if g.Version == gosnmp.Version1 {
		return g.WalkAll(oid)
	}
	return g.BulkWalkAll(oid)
}

// splitARPIndex pulls the ifIndex and the dotted-quad out of an
// ipNetToMediaPhysAddress instance name.
func splitARPIndex(name, base string) (string, string) {
	rest := strings.TrimPrefix(name, strings.TrimPrefix(base, ".")+".")
	if rest == name {
		return "", ""
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 5 {
		return "", ""
	}
	ip := strings.Join(parts[1:], ".")
	if net.ParseIP(ip) == nil {
		return "", ""
	}
	return parts[0], ip
}

// normalizeMAC renders a PDU as aa:bb:cc:dd:ee:ff. Agents return either six raw
// octets or a printable form using any of the usual separators. Every OID this
// is called on is a PhysAddress, so a six-octet value is the address itself and
// is never re-interpreted as text.
func normalizeMAC(p gosnmp.SnmpPDU) string {
	if b, ok := p.Value.([]byte); ok && len(b) == 6 {
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
	}
	s := strings.TrimSpace(pduString(p))
	if s == "" {
		return ""
	}
	var hex strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			hex.WriteRune(r)
		case r == ':', r == '-', r == '.', r == ' ':
		default:
			return ""
		}
	}
	h := hex.String()
	if len(h) != 12 {
		return ""
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s", h[0:2], h[2:4], h[4:6], h[6:8], h[8:10], h[10:12])
}

// cleanText trims a scalar and drops control characters, which some agents pad
// fixed-width fields with.
func cleanText(s string) string {
	s = strings.TrimSpace(s)
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
