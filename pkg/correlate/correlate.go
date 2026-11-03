// Package correlate answers, for each scanned out-of-band device, the question the
// scan itself does not: which machine does this BMC manage, and where is it?
//
// Two stages, deliberately separated because they have very different error modes.
//
// Extract reads one record and returns what the BMC said about its own server. This
// is identity: a name, a serial, a UUID, a set of NIC MAC addresses, sometimes an IP.
// It is cheap, it needs no other host, and on the vendors that disclose it at all it
// is close to free -- an HPE iLO hands over its server's NIC list and configured
// addresses to an unauthenticated GET.
//
// Resolve then tries to turn identity into an address, which is the part that is
// actually hard. A MAC is only an address once something maps it to one, and the only
// mapping oracles available from a scan are the neighbour tables other BMCs give up
// and the names DNS will resolve. Measured against internet data, a leaked MAC
// converts to a confirmed managed-host address about 2.5% of the time; a leaked
// hostname converts far more often, because DNS is universal. Both stages therefore
// record provenance and a confidence, and callers are expected to treat
// Identity-only results as inventory, not as a located host.
package correlate

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ilo"
	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

// Confidence grades a managed-host claim by what had to be true for it to hold.
type Confidence string

const (
	// Stated: the BMC named the server's address itself. No inference.
	Stated Confidence = "stated"
	// Resolved: an identifier the BMC published was matched to an address by an
	// independent observation (a neighbour table, or another scanned host).
	Resolved Confidence = "resolved"
	// Identity: the BMC described its server but nothing located it.
	Identity Confidence = "identity"
)

// Source records which pre-auth channel produced a value, so a downstream consumer
// can weigh a hostname the BMC asserts about itself differently from one it asserts
// about the machine it manages.
type Source struct {
	// Producer is the oobscan check id that yielded the value, or a `correlate.*`
	// pseudo-id when the correlation pass derived it rather than a check observing
	// it. It is deliberately not called Check: not every value comes from one, and a
	// field literally named Check makes this struct look like a finding emit site to
	// the registry parity test that scans pkg/ for them.
	Producer string `json:"producer"`
	Field    string `json:"field,omitempty"` // field within that producer
	Auth     string `json:"auth"`            // preauth | defaultcred | postauth
}

// Value is one observation with its provenance.
type Value struct {
	Value  string   `json:"value"`
	Source []Source `json:"source"`
}

// ManagedHost is the BMC's account of the server it manages. Every field is
// optional: most BMCs disclose some of it and none disclose all of it.
type ManagedHost struct {
	// BMC is the address the disclosure came from. It is omitted by Embedded, which is
	// the form written back onto that device's own scan record: there it would just
	// restate the record's own host.
	BMC        string      `json:"bmc,omitempty"`
	BMCVendor  string      `json:"bmcVendor,omitempty"`
	BMCClass   string      `json:"bmcClass,omitempty"`
	Names      []Value     `json:"names,omitempty"`      // the server's hostname, as the BMC knows it
	Addresses  []Value     `json:"addresses,omitempty"`  // the server's IPs, stated or resolved
	MACs       []Value     `json:"macs,omitempty"`       // the server's NIC MACs
	Serial     []Value     `json:"serial,omitempty"`     // chassis serial / service tag
	UUID       []Value     `json:"uuid,omitempty"`       // SMBIOS / system UUID
	Model      []Value     `json:"model,omitempty"`      // server model, not the BMC's
	OS         []Value     `json:"os,omitempty"`         // host operating system, where the BMC reports it
	BMCMACs    []string    `json:"bmcMacs,omitempty"`    // the BMC's own MACs, kept for adjacency work
	Neighbours []Neighbour `json:"neighbours,omitempty"` // IP->MAC the BMC has cached for its segment
	Confidence Confidence  `json:"confidence"`
	Note       string      `json:"note,omitempty"`
}

// Neighbour is one entry of a BMC's ARP/neighbour cache: an address on the BMC's own
// L2 segment and the MAC behind it. Pooled across every BMC in a scan this is the
// only address oracle a scan produces on its own.
type Neighbour struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

// Embedded returns the form that is written back onto the device's own scan record,
// or nil when there is nothing to write. Everything the record already states about
// itself is dropped: the BMC's address, vendor and class are the record's own
// identity, its MACs come from the checks that saw them, and the neighbour cache is a
// verbatim reparse of the snmp.host.arpCache finding sitting on the same line. What
// remains is the account of the managed server, which is the part a scan record has
// nowhere else to put.
func (m *ManagedHost) Embedded() *ManagedHost {
	if m == nil || m.Empty() {
		return nil
	}
	c := *m
	c.BMC, c.BMCVendor, c.BMCClass = "", "", ""
	c.BMCMACs, c.Neighbours = nil, nil
	return &c
}

// Empty reports whether the BMC disclosed nothing about a managed server.
func (m *ManagedHost) Empty() bool {
	return len(m.Names) == 0 && len(m.Addresses) == 0 && len(m.MACs) == 0 &&
		len(m.Serial) == 0 && len(m.UUID) == 0 && len(m.Model) == 0 && len(m.OS) == 0
}

var (
	macRE = regexp.MustCompile(`(?i)\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b`)
	// Placeholder identifiers that ship on many units. A value that many devices
	// share is a product marker, never a machine identity.
	junkID = regexp.MustCompile(`(?i)^(0+|1+|x+|n/?a|none|unknown|default|tobefilledbyoem|` +
		`serial|svctag|servicetag|chassis|system serial number|empty|null|localhost|` +
		`localhost\.localdomain|0123456789|1234567890?)$`)
	junkName = map[string]bool{
		"localhost": true, "unknown": true, "default": true, "system": true, "none": true,
		"ipmi": true, "idrac": true, "ilo": true, "bmc": true, "xcc": true, "imm": true,
		"minwinpc": true, "": true,
	}
)

func normMAC(s string) string {
	m := macRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return ""
	}
	mac := strings.ToLower(m[1])
	// A group/multicast address is never a NIC's own address, and an all-zero one is
	// an unset field that several vendors emit rather than omitting the key.
	first, err := strconv.ParseUint(mac[:2], 16, 8)
	if err != nil || first&1 == 1 || strings.HasPrefix(mac, "00:00:00:00") {
		return ""
	}
	return mac
}

func usableName(s string) string {
	s = strings.TrimSpace(strings.Trim(s, `".`))
	if s == "" || strings.ContainsAny(s, " \t") || len(s) < 3 {
		return ""
	}
	low := strings.ToLower(s)
	if junkName[low] || junkName[strings.Split(low, ".")[0]] {
		return ""
	}
	// Windows and hoster autogenerated names identify an install, not a machine an
	// operator named, and they collide across unrelated hosts.
	for _, p := range []string{"win-", "desktop-", "static.", "ip-"} {
		if strings.HasPrefix(low, p) {
			return ""
		}
	}
	return s
}

func usableID(s string) string {
	s = strings.TrimSpace(strings.Trim(s, `"`))
	if s == "" || junkID.MatchString(s) {
		return ""
	}
	core := strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return r
		}
		return -1
	}, s)
	// Fewer than three distinct characters is a fill pattern, not an identifier.
	seen := map[rune]bool{}
	for _, r := range strings.ToLower(core) {
		seen[r] = true
	}
	if len(core) < 5 || len(seen) < 3 {
		return ""
	}
	return s
}

func (m *ManagedHost) add(dst *[]Value, v string, src Source) {
	if v == "" {
		return
	}
	for i := range *dst {
		if strings.EqualFold((*dst)[i].Value, v) {
			if !slices.Contains((*dst)[i].Source, src) {
				(*dst)[i].Source = append((*dst)[i].Source, src)
			}
			return
		}
	}
	*dst = append(*dst, Value{Value: v, Source: []Source{src}})
}

const (
	preauth  = "preauth"
	defcred  = "defaultcred"
	postauth = "postauth"
)

// Extract reads one scan record and returns what the BMC disclosed about the server
// it manages. It returns nil when the record is not an out-of-band device or the
// device disclosed nothing.
func Extract(rec *scanfile.Record) *ManagedHost {
	if rec == nil || rec.Host == "" {
		return nil
	}
	m := &ManagedHost{BMC: rec.Host, Confidence: Identity}
	if rec.Final != nil {
		m.BMCClass = string(rec.Final.Class)
	}
	if v := rec.Attributes["vendor"]; v != "" {
		m.BMCVendor = v
	}

	extractILO(rec, m)
	extractFindings(rec, m)
	extractAttributes(rec, m)

	if m.Empty() && len(m.Neighbours) == 0 && len(m.BMCMACs) == 0 {
		return nil
	}
	if len(m.Addresses) > 0 {
		m.Confidence = Stated
	}
	sortAll(m)
	return m
}

// extractILO pulls the managed server out of the pre-auth /xmldata RIMP document.
//
// The NICS block is normally read for MAC addresses. Each entry also carries the IP
// configured on that port, and the entries that are not the iLO's own describe the
// server -- which makes this the only channel in the scan that states a managed
// host's address outright.
//
// The iLO publishes itself as a NIC entry too. Identify it by the address we reached
// the iLO on rather than by position: the self entry is not always first, and a naive
// scrape of every IPADDR reports near-total host coverage that is almost all the iLO
// describing itself.
func extractILO(rec *scanfile.Record, m *ManagedHost) {
	x := rec.ILO
	if x == nil {
		// A record produced before scanfile carried the ilo block, or one rebuilt by
		// `oobscan convert`, may still have it only under the evidence bag.
		if raw, ok := rec.Evidence["ilo.xmldata"]; ok && len(raw) > 0 {
			var parsed ilo.XMLData
			if err := json.Unmarshal(raw, &parsed); err == nil {
				x = &parsed
			}
		}
	}
	if x == nil {
		return
	}
	src := Source{Producer: "http.ilo.xmlData", Field: "nics", Auth: preauth}
	for _, n := range x.HSI.NICS.NIC {
		mac := normMAC(n.MACAddr)
		ip := strings.TrimSpace(n.IPAddr)
		self := ip != "" && ip == rec.Host
		if strings.Contains(strings.ToUpper(n.Description), "ILO") || self {
			if mac != "" {
				m.BMCMACs = appendUniq(m.BMCMACs, mac)
			}
			continue
		}
		if mac != "" {
			m.add(&m.MACs, mac, src)
		}
		if isRoutableHostIP(ip) && ip != rec.Host {
			m.add(&m.Addresses, ip, Source{Producer: "http.ilo.xmlData", Field: "nics.ipAddress", Auth: preauth})
		}
	}
	if s := usableID(x.HSI.SBSN); s != "" {
		m.add(&m.Serial, s, Source{Producer: "http.ilo.xmlData", Field: "chassisSerial", Auth: preauth})
	}
	if s := usableID(x.HSI.UUID); s != "" {
		m.add(&m.UUID, s, Source{Producer: "http.ilo.xmlData", Field: "uuid", Auth: preauth})
	}
	if s := usableID(x.HSI.SPN); s != "" {
		m.add(&m.Model, s, Source{Producer: "http.ilo.xmlData", Field: "serverModel", Auth: preauth})
	}
}

// hostFieldSources maps a check field to the managed-host slot it fills. Only
// sources where the BMC is describing the MACHINE IT MANAGES belong here. A name
// that arrives from a service merely co-resident on the same address -- PPTP, NTLM,
// a router's own SNMP sysName -- is that service's identity and produced confident
// nonsense when it was treated as a server name.
var hostFieldSources = map[string]struct {
	slot  string
	auth  string
	field string
}{
	"http.lenovo.xcc.deviceInfo|hostname": {"name", preauth, "hostname"},
	"http.cisco.cimcInfo|hostname":        {"name", preauth, "hostname"},
	"udp.digi.addpLeak|hostname":          {"name", preauth, "hostname"},
	"kvm.avocent.aps|commonName":          {"name", preauth, "commonName"},
	"kvm.usbAnywhere|commonName":          {"name", preauth, "commonName"},
	"kvm.cisco.vkvm|commonName":           {"name", preauth, "commonName"},
	"kvm.ami.vmedia|commonName":           {"name", preauth, "commonName"},
	"dell.redfish.rootOemLeak|hostName":   {"name", preauth, "hostName"},
	"dell.preauth.aimGetProp|oemHostName": {"name", preauth, "OEMHostName"},
	"snmp.host.sysName|managedHostName":   {"name", defcred, "sysName"},

	"http.cisco.cimcInfo|chassisSerial":   {"serial", preauth, "chassisSerial"},
	"http.ilo.xmlData|serialNumber":       {"serial", preauth, "serialNumber"},
	"dell.redfish.rootOemLeak|serviceTag": {"serial", preauth, "Oem.Dell.ServiceTag"},
	"snmp.host.dellChassis|serviceTag":    {"serial", defcred, "serviceTag"},
	"ipmi.postAuth.fru|chassisSerial":     {"serial", postauth, "chassisSerial"},

	"snmp.host.nicTable|macs":           {"mac", defcred, "networkDeviceTable"},
	"smc.bios.registry|hostMacs":        {"mac", preauth, "BiosAttributeRegistry"},
	"lenovo.deviceDescription|hostMacs": {"mac", preauth, "DeviceDescription.json"},

	"snmp.host.osName|hostOS":       {"os", defcred, "hostOSName"},
	"ipmi.postAuth.fru|productName": {"model", postauth, "productName"},
	"http.ilo.xmlData|serverModel":  {"model", preauth, "serverModel"},
	"snmp.host.model|model":         {"model", defcred, "model"},
}

func extractFindings(rec *scanfile.Record, m *ManagedHost) {
	for i := range rec.Findings {
		f := &rec.Findings[i]
		for _, fld := range f.Fields {
			k, v := fld.Key, fld.Val
			key := f.Check + "|" + k
			spec, ok := hostFieldSources[key]
			if !ok {
				// The BMC's own MAC is not a managed-host field, but it anchors the
				// LOM block the server's NICs are allocated from, so it is kept.
				if k == "mac" && (f.Check == "ipmi.postAuth.lanPrint" ||
					strings.HasPrefix(f.Check, "udp.")) {
					if mac := normMAC(v); mac != "" {
						m.BMCMACs = appendUniq(m.BMCMACs, mac)
					}
				}
				if f.Check == "snmp.host.arpCache" && k == "entries" {
					m.Neighbours = append(m.Neighbours, parseNeighbours(v)...)
				}
				continue
			}
			src := Source{Producer: f.Check, Field: spec.field, Auth: spec.auth}
			switch spec.slot {
			case "name":
				if n := usableName(v); n != "" {
					m.add(&m.Names, n, src)
				}
			case "serial":
				if s := usableID(v); s != "" {
					m.add(&m.Serial, s, src)
				}
			case "mac":
				for _, one := range macRE.FindAllString(v, -1) {
					if mac := normMAC(one); mac != "" {
						m.add(&m.MACs, mac, src)
					}
				}
			case "os":
				if s := strings.TrimSpace(v); s != "" {
					m.add(&m.OS, s, src)
				}
			case "model":
				// A model goes through the same placeholder filter as an identifier:
				// an unprovisioned FRU answers productName with "NONE", and taking it
				// literally reports a managed server whose only described property is
				// that its model is not set.
				if s := usableID(v); s != "" {
					m.add(&m.Model, s, src)
				}
			}
		}
	}
}

func extractAttributes(rec *scanfile.Record, m *ManagedHost) {
	a := rec.Attributes
	if a == nil {
		return
	}
	if s := usableID(a["dellServiceTag"]); s != "" {
		m.add(&m.Serial, s, Source{Producer: "identify", Field: "dellServiceTag", Auth: preauth})
	}
	if s := usableID(a["chassisSerial"]); s != "" {
		m.add(&m.Serial, s, Source{Producer: "identify", Field: "chassisSerial", Auth: preauth})
	}
	// A BMC that reports the OS hostname is reporting its server, not itself.
	if n := usableName(a["hostname"]); n != "" {
		m.add(&m.Names, n, Source{Producer: "identify", Field: "hostname", Auth: preauth})
	}
	// The `redfishUuid` attribute is deliberately not read here. It is the Redfish
	// SERVICE root UUID, which is the controller's identity and not the system's --
	// ATEN derives it from the BMC's own NIC, so it arrives as
	// 00000000-0000-0000-0000-<bmc mac> and made every Supermicro in a scan report a
	// managed server whose sole described property was the BMC's MAC address restated.
	// A server's UUID only counts when the channel says it is the server's: the iLO
	// /xmldata HSI block does (see extractILO), a Redfish ServiceRoot never does.
}

// parseNeighbours reads an "ip=mac,ip=mac" neighbour-cache serialization.
func parseNeighbours(s string) []Neighbour {
	var out []Neighbour
	for e := range strings.SplitSeq(s, ",") {
		ip, mac, ok := strings.Cut(strings.TrimSpace(e), "=")
		if !ok {
			continue
		}
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) == nil {
			continue
		}
		if m := normMAC(expandHexMAC(mac)); m != "" {
			out = append(out, Neighbour{IP: ip, MAC: m})
		}
	}
	return out
}

// expandHexMAC accepts both "aabbccddeeff" and "aa:bb:cc:dd:ee:ff"; SNMP renders a
// physical address as bare hex.
func expandHexMAC(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, " ", ""))
	if len(s) != 12 || strings.Contains(s, ":") {
		return s
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(s[i : i+2])
	}
	return b.String()
}

func isRoutableHostIP(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	return !ip.Equal(net.IPv4bcast)
}

func appendUniq(xs []string, v string) []string {
	if slices.Contains(xs, v) {
		return xs
	}
	return append(xs, v)
}

func sortAll(m *ManagedHost) {
	for _, s := range []*[]Value{&m.Names, &m.Addresses, &m.MACs, &m.Serial, &m.UUID, &m.Model, &m.OS} {
		sort.Slice(*s, func(i, j int) bool { return (*s)[i].Value < (*s)[j].Value })
	}
	sort.Strings(m.BMCMACs)
	sort.Slice(m.Neighbours, func(i, j int) bool { return m.Neighbours[i].IP < m.Neighbours[j].IP })
}

// Summary counts what a correlation pass produced, for the one line a scan prints.
type Summary struct {
	OOBDevices int `json:"oobDevices"`
	Described  int `json:"described"`  // BMC disclosed something about its server
	Located    int `json:"located"`    // a managed-host address was stated or resolved
	Stated     int `json:"stated"`     // the BMC named the address itself
	Resolved   int `json:"resolved"`   // an identifier was matched to an address
	Neighbours int `json:"neighbours"` // pooled IP->MAC entries available as an oracle
	// Annotated is how many scan records the pass wrote a managedHost onto. It is
	// filled in by the caller that does the writing, and is normally Described: a lower
	// number means a record could not be edited safely and was left as it was.
	Annotated int `json:"annotated"`
}

func (s Summary) String() string {
	return fmt.Sprintf("%d OOB devices, %d described their server, %d located (%d stated, %d resolved)",
		s.OOBDevices, s.Described, s.Located, s.Stated, s.Resolved)
}

var _ = engine.Finding{}
