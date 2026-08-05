package snmp

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

const (
	oidIPNetToMediaPhys = "1.3.6.1.2.1.4.22.1.2"
	oidIfPhysAddress    = "1.3.6.1.2.1.2.2.1.6"
	oidDellNICMAC       = "1.3.6.1.4.1.674.10892.5.4.1100.90.1.6"
	oidDellServiceTag   = "1.3.6.1.4.1.674.10892.5.1.3.2.0"
	oidDellModel        = "1.3.6.1.4.1.674.10892.5.1.3.12.0"
	oidDellHostOS       = "1.3.6.1.4.1.674.10892.5.1.3.6.0"
	oidHPEHostSerial    = "1.3.6.1.4.1.232.2.2.2.1.0"
)

const (
	OIDIPNetToMediaPhys = oidIPNetToMediaPhys
	OIDDellNICMAC       = oidDellNICMAC
)

const (
	maxARPEntries = 1024
	maxNICEntries = 64
	walkMaxReps   = 16
)

type ARPEntry struct {
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	IfIndex string `json:"ifIndex,omitempty"`
}

type HostInventory struct {
	Host      string `json:"host"`
	Community string `json:"community"`
	Version   int    `json:"version"`

	SysName string `json:"sysName,omitempty"`

	OwnMACs    []string `json:"ownMACs,omitempty"`
	ServerNICs []string `json:"serverNICs,omitempty"`

	ARP []ARPEntry `json:"arp,omitempty"`

	ServiceTag string `json:"serviceTag,omitempty"`
	Model      string `json:"model,omitempty"`
	HostOS     string `json:"hostOS,omitempty"`
	HostSerial string `json:"hostSerial,omitempty"`

	ManagedIPs []string `json:"managedIPs,omitempty"`
}

func (h *HostInventory) Empty() bool {
	if h == nil {
		return true
	}
	return len(h.OwnMACs) == 0 && len(h.ServerNICs) == 0 && len(h.ARP) == 0 &&
		h.ServiceTag == "" && h.Model == "" && h.HostOS == "" && h.HostSerial == ""
}

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

func walk(g *gosnmp.GoSNMP, oid string) ([]gosnmp.SnmpPDU, error) {
	if g.Version == gosnmp.Version1 {
		return g.WalkAll(oid)
	}
	return g.BulkWalkAll(oid)
}

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

func cleanText(s string) string {
	s = strings.TrimSpace(s)
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
