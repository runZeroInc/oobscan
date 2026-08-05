package report

import (
	"strconv"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/bmcfp"
	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

var vendorDisplayNames = map[string]string{
	"hpe": "HPE", "dell": "Dell", "supermicro": "Supermicro", "huawei": "Huawei",
	"lenovo": "Lenovo", "ibm": "IBM", "cisco": "Cisco", "intel": "Intel",
	"fujitsu": "Fujitsu", "inspur": "Inspur", "gigabyte": "Gigabyte", "ami": "AMI",
	"nokia": "Nokia", "asus": "ASUS", "asrock": "ASRock", "asrockrack": "ASRockRack",
	"quanta": "Quanta", "tyan": "Tyan", "siemens": "Siemens", "rockwell": "Rockwell",
	"veeder-root": "Veeder-Root", "mikrotik": "MikroTik", "lexmark": "Lexmark",
	"oracle": "Oracle", "proxmox": "Proxmox", "openbmc": "OpenBMC", "aten": "ATEN",
	"h3c": "H3C", "oem": "OEM", "nec": "NEC", "smc-incorporated": "SMC",
	"vmware": "VMware", "openssl": "OpenSSL", "centos": "CentOS",
	"rhel-derivative": "RHEL Derivative", "red-hat": "Red Hat", "wind-river": "Wind River",
	"western-digital": "Western Digital", "hitachi-vantara": "Hitachi Vantara",
	"aruba-networks": "Aruba Networks", "check-point": "Check Point",
	"inter-tech": "Inter-Tech", "s2": "S2", "lantronix": "Lantronix", "moxa": "Moxa",
	"opengear": "Opengear", "digi": "Digi", "raritan": "Raritan", "vertiv": "Vertiv",
	"perle": "Perle", "advantech": "Advantech", "apc": "APC", "tripplite": "Tripp Lite",
	"eaton": "Eaton", "cyberpower": "CyberPower", "servertech": "ServerTech",
	"gude": "Gude", "pikvm": "PiKVM", "nanokvm": "NanoKVM", "tinypilot": "TinyPilot",
	"jetkvm": "JetKVM", "blikvm": "bliKVM", "nvidia": "NVIDIA", "nutanix": "Nutanix",
	"broadcom": "Broadcom", "adlink": "ADLINK", "microchip": "Microchip",
	"schneiderpm": "Schneider Electric", "hitachi": "Hitachi", "google": "Google",
	"avocent": "Avocent", "xfusion": "xFusion",
	"honeypot": "Honeypot", "unknown": "Unknown",
}

func vendorSlug(rec *scanfile.Record) string {

	if recordClass(rec) == "honeypot" {
		return "honeypot"
	}
	if slug := recordVendor(rec); slug != "unknown" {
		return slug
	}
	if v := inferVendorSlug(rec); v != "" {
		return v
	}
	return "unknown"
}

func inferVendorSlug(rec *scanfile.Record) string {
	if v := ipmiGUIDVendor(rec); v != "" {
		return v
	}

	inputs := map[bmcfp.Kind]string{}
	if s := firstServiceAttr(rec, "tls.subject"); s != "" {
		inputs[bmcfp.TLSSubjectDN] = s
		if cn := certCN(s); cn != "" {
			inputs[bmcfp.TLSSubjectCN] = cn
		}
	}
	if s := firstServiceAttr(rec, "tls.vhost"); s != "" {
		inputs[bmcfp.TLSSubjectCN] = s
	}
	if s := firstServiceAttr(rec, "tls.issuer"); s != "" {
		inputs[bmcfp.TLSIssuerDN] = s
		if cn := certCN(s); cn != "" {
			inputs[bmcfp.TLSIssuerCN] = cn
		}
	}
	if s := firstServiceAttr(rec, "http.head.server"); s != "" {
		inputs[bmcfp.HTTPServerHeader] = s
	}
	if s := firstServiceAttr(rec, "http.head.wwwAuthenticate", "http.wwwAuthenticate"); s != "" {
		inputs[bmcfp.WWWAuthenticate] = s
	}
	if s := firstServiceAttr(rec, "http.title"); s != "" {
		inputs[bmcfp.HTMLTitle] = s
	}
	if s := firstServiceAttr(rec, "ssh.banner", "ssh.version", "ssh.software"); s != "" {
		inputs[bmcfp.SSHBanner] = s
	}
	if v, _, ok := bmcfp.MatchAll(inputs); ok {
		if slug := normalizeVendorSlug(v); slug != "" {
			return slug
		}
	}
	if v := vendorFromServiceShape(rec); v != "" {
		return v
	}

	blob := strings.ToLower(strings.Join([]string{
		firstServiceAttr(rec, "tls.subject"),
		firstServiceAttr(rec, "tls.issuer"),
		firstServiceAttr(rec, "tls.names"),
		firstServiceAttr(rec, "http.head.server"),
		firstServiceAttr(rec, "http.title"),
	}, " "))
	return vendorFromOrgTokens(blob)
}

func vendorFromServiceShape(rec *scanfile.Record) string {
	server := strings.ToLower(firstServiceAttr(rec, "http.head.server"))
	vhost := strings.TrimSpace(firstServiceAttr(rec, "tls.vhost"))
	vhostLower := strings.ToLower(vhost)
	if strings.EqualFold(vhost, "IPMI") && recordHasProtocol(rec, "ipmi") {
		return "supermicro"
	}
	if strings.EqualFold(vhost, "ILO") || strings.HasPrefix(strings.ToUpper(vhost), "ILO-") ||
		(strings.HasPrefix(strings.ToUpper(vhost), "ILO") && serviceToken(vhost[3:])) {
		return "hpe"
	}
	if recordHasPort(rec, 1900, "udp") && recordHasProtocol(rec, "snmp3") {
		return "hpe"
	}
	if server == "webserver" || recordHasHTMLTitle(rec, "vKVM Server Certificate Load") {
		return "cisco"
	}
	if server == "aps" && recordHasPort(rec, 2068, "tcp") {
		return "cisco"
	}
	switch vhostLower {
	case "megarac.com", "www.ami.com", "ami.com", "ami", "ami-redfish.com":
		return "ami"
	}
	if server == "httpd" || server == "embedthis-http" {
		return "dell"
	}
	if recordHasHTMLTitle(rec, "Moved Temporarily") ||
		(server == "aps" && recordHasProtocol(rec, "snmp1")) {
		return "dell"
	}
	if strings.HasPrefix(server, "linux/3.18.0, upnp/") ||
		strings.HasPrefix(server, "linux/5.1.3-2965b36") {
		return "supermicro"
	}
	if server == "apache" || strings.HasPrefix(server, "apache/") {
		if recordHasProtocol(rec, "snmp1") || recordHasHTTPLocation(rec, "/restgui") {
			return "dell"
		}
	}
	return ""
}

func serviceToken(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if (char < 'A' || char > 'Z') && (char < 'a' || char > 'z') &&
			(char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}

func recordHasProtocol(rec *scanfile.Record, want string) bool {
	for _, protocols := range rec.Ports {
		for protocol := range strings.SplitSeq(protocols, ",") {
			if strings.EqualFold(strings.TrimSpace(protocol), want) {
				return true
			}
		}
	}
	return false
}

func recordHasHTTPLocation(rec *scanfile.Record, fragment string) bool {
	fragment = strings.ToLower(fragment)
	for i := range rec.Services {
		location := strings.ToLower(serviceHTTPHeader(rec.Services[i].Summary, "Location"))
		if strings.Contains(location, fragment) {
			return true
		}
	}
	return false
}

func recordHasPort(rec *scanfile.Record, port int, transport string) bool {
	_, ok := rec.Ports[strconv.Itoa(port)+"/"+transport]
	return ok
}

func recordHasHTMLTitle(rec *scanfile.Record, want string) bool {
	return strings.EqualFold(strings.TrimSpace(firstServiceAttr(rec, "http.title")), want)
}

func ipmiGUIDVendor(rec *scanfile.Record) string {
	for i := range rec.Findings {
		f := &rec.Findings[i]
		if f.Check == "ipmi.guid" {
			if v := normalizeVendorSlug(findingField(f, "vendor")); v != "" {
				return v
			}
		}
	}
	if v := normalizeVendorSlug(rec.Attributes["ipmiGuidVendor"]); v != "" {
		return v
	}
	if v := normalizeVendorSlug(rec.Attributes["ipmiOemName"]); v != "" {
		return v
	}
	return ""
}

func normalizeVendorSlug(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || v == "unknown" || v == "oem" || v == "generic" || strings.Contains(v, "-or-") {
		return ""
	}
	return v
}

func certCN(dn string) string {
	for part := range strings.SplitSeq(dn, ",") {
		part = strings.TrimSpace(part)
		if len(part) > 3 && strings.EqualFold(part[:3], "CN=") {
			return strings.TrimSpace(part[3:])
		}
	}
	return ""
}

func vendorFromOrgTokens(low string) string {
	switch {
	case strings.Contains(low, "super micro"), strings.Contains(low, "supermicro"):
		return "supermicro"
	case strings.Contains(low, "american megatrends"), strings.Contains(low, "megarac"):
		return "ami"
	case strings.Contains(low, "hewlett"), strings.Contains(low, "packard"), strings.Contains(low, "ilo"), strings.Contains(low, "proliant"):
		return "hpe"
	case strings.Contains(low, "dell"), strings.Contains(low, "idrac"):
		return "dell"
	case strings.Contains(low, "xfusion"):
		return "xfusion"
	case strings.Contains(low, "huawei"), strings.Contains(low, "ibmc"):
		return "huawei"
	case strings.Contains(low, "lenovo"), strings.Contains(low, "xclarity"), strings.Contains(low, "system x"):
		return "lenovo"
	case strings.Contains(low, "fujitsu"), strings.Contains(low, "irmc"), strings.Contains(low, "primergy"):
		return "fujitsu"
	case strings.Contains(low, "avocent"):
		return "avocent"
	case strings.Contains(low, "advantech"):
		return "advantech"
	case strings.Contains(low, "western digital"):
		return "western-digital"
	case strings.Contains(low, "nokia"):
		return "nokia"
	case strings.Contains(low, "cisco"), strings.Contains(low, "cimc"):
		return "cisco"
	case strings.Contains(low, "inspur"):
		return "inspur"
	case strings.Contains(low, "gigabyte"), strings.Contains(low, "giga computing"):
		return "gigabyte"
	case strings.Contains(low, "asrockrack"), strings.Contains(low, "asrock rack"):
		return "asrockrack"
	case strings.Contains(low, "asrock"):
		return "asrock"
	case strings.Contains(low, "asus"):
		return "asus"
	case strings.Contains(low, "quanta"):
		return "quanta"
	case strings.Contains(low, "tyan"):
		return "tyan"
	case strings.Contains(low, "oracle"), strings.Contains(low, "ilom"), strings.Contains(low, "sun microsystems"):
		return "oracle"
	case strings.Contains(low, "nvidia"), strings.Contains(low, "bluefield"):
		return "nvidia"
	case strings.Contains(low, "intel"):
		return "intel"
	case strings.Contains(low, "ibm"):
		return "ibm"
	}
	return ""
}

func displayVendor(slug string) string {
	if slug == "" {
		return "Unknown"
	}
	if d, ok := vendorDisplayNames[slug]; ok {
		return d
	}
	parts := strings.FieldsFunc(slug, func(r rune) bool { return r == '-' || r == '_' || r == ' ' })
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	if out := strings.Join(parts, " "); out != "" {
		return out
	}
	return "Unknown"
}

func displayClass(class string) string {
	switch class {
	case "bmc":
		return "BMC"
	case "kvm":
		return "IP-KVM"
	case "pdu":
		return "PDU"
	case "serial":
		return "Serial console"
	case "amt":
		return "Intel AMT"
	case "firmware":
		return "Firmware"
	case "honeypot":
		return "Honeypot"
	case "", "unknown":
		return "Unknown"
	default:
		if len(class) > 0 {
			return strings.ToUpper(class[:1]) + class[1:]
		}
		return class
	}
}
