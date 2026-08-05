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

type Confidence string

const (
	Stated Confidence = "stated"

	Resolved Confidence = "resolved"

	Identity Confidence = "identity"
)

type Source struct {
	Producer string `json:"producer"`
	Field    string `json:"field,omitempty"`
	Auth     string `json:"auth"`
}

type Value struct {
	Value  string   `json:"value"`
	Source []Source `json:"source"`
}

type ManagedHost struct {
	BMC        string      `json:"bmc"`
	BMCVendor  string      `json:"bmcVendor,omitempty"`
	BMCClass   string      `json:"bmcClass,omitempty"`
	Names      []Value     `json:"names,omitempty"`
	Addresses  []Value     `json:"addresses,omitempty"`
	MACs       []Value     `json:"macs,omitempty"`
	Serial     []Value     `json:"serial,omitempty"`
	UUID       []Value     `json:"uuid,omitempty"`
	Model      []Value     `json:"model,omitempty"`
	OS         []Value     `json:"os,omitempty"`
	BMCMACs    []string    `json:"bmcMacs,omitempty"`
	Neighbours []Neighbour `json:"neighbours,omitempty"`
	Confidence Confidence  `json:"confidence"`
	Note       string      `json:"note,omitempty"`
}

type Neighbour struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

func (m *ManagedHost) Empty() bool {
	return len(m.Names) == 0 && len(m.Addresses) == 0 && len(m.MACs) == 0 &&
		len(m.Serial) == 0 && len(m.UUID) == 0 && len(m.Model) == 0 && len(m.OS) == 0
}

var (
	macRE = regexp.MustCompile(`(?i)\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b`)

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

func extractILO(rec *scanfile.Record, m *ManagedHost) {
	x := rec.ILO
	if x == nil {

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
	if s := strings.TrimSpace(x.HSI.SPN); s != "" {
		m.add(&m.Model, s, Source{Producer: "http.ilo.xmlData", Field: "serverModel", Auth: preauth})
	}
}

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
				if s := strings.TrimSpace(v); s != "" {
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

	if n := usableName(a["hostname"]); n != "" {
		m.add(&m.Names, n, Source{Producer: "identify", Field: "hostname", Auth: preauth})
	}
	for _, k := range []string{"guid", "redfishUuid", "uuid"} {
		v := strings.TrimSpace(a[k])
		if len(v) >= 30 && usableID(v) != "" {
			m.add(&m.UUID, strings.ToLower(v), Source{Producer: "identify", Field: k, Auth: preauth})
		}
	}
}

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

type Summary struct {
	OOBDevices int `json:"oobDevices"`
	Described  int `json:"described"`
	Located    int `json:"located"`
	Stated     int `json:"stated"`
	Resolved   int `json:"resolved"`
	Neighbours int `json:"neighbours"`
}

func (s Summary) String() string {
	return fmt.Sprintf("%d OOB devices, %d described their server, %d located (%d stated, %d resolved)",
		s.OOBDevices, s.Described, s.Located, s.Stated, s.Resolved)
}

var _ = engine.Finding{}
