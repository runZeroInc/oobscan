package creds

import "strings"

// vendorAliases maps a substring of an IPMI/SMBIOS/HTTP manufacturer string to
// the lowercase vendor slug used in Table. First match (longest keys checked by
// the ordered slice) wins.
var vendorAliases = []struct{ match, slug string }{
	{"super micro", "supermicro"},
	{"supermicro", "supermicro"},
	{"american megatrends", "ami"},
	{"megarac", "ami"},
	{"ami", "ami"},
	{"nedam", "ami"},     // Nedam Engineering (PEN 47488) rebrands AMI MegaRAC (community "AMI", MegaRAC fw)
	{"celestica", "ami"}, // Celestica ODM boards seen running AMI MegaRAC (VEP-4600, PEN 12290)
	{"openbmc", "openbmc"},
	{"phosphor", "openbmc"},
	{"bmcweb", "openbmc"},
	{"dell", "dell"},
	{"hewlett", "hpe"},
	{"packard", "hpe"},
	{"hpe", "hpe"},
	{"hp ", "hpe"},
	{"lenovo", "lenovo"},
	{"ibm", "ibm"},
	{"intel", "intel"},
	{"cisco", "cisco"},
	{"fujitsu", "fujitsu"},
	{"huawei", "huawei"},
	{"xfusion", "xfusion"}, // Huawei x86-server spinoff; MUST precede the loose "digi" match ("xFusion Digital...")
	{"inspur", "inspur"},
	{"quanta", "quanta"},
	{"mitac", "tyan"},
	{"tyan", "tyan"},
	{"asrock", "asrockrack"},
	{"gigabyte", "gigabyte"},
	{"nec", "nec"},
	{"oracle", "oracle"},
	{"sun microsystems", "oracle"},
	{"advantech", "advantech"},
	{"avid", "avid"},
	{"adlink", "adlink"},
	{"h3c", "h3c"},
	{"nvidia", "nvidia"},
	{"asus", "asus"},
	{"asmb", "asus"},
	// Modern IP-KVM appliances (Eclypsium 2026 cohort). identify resolves these
	// via bmcfp html.title, but the SNMP sysDescr / HTTP Server fallback needs the
	// alias so the ipkvm.posture default-cred lookup keys on the right slug.
	{"blikvm", "blikvm"},
	{"pikvm", "pikvm"},
	{"nanokvm", "nanokvm"},
	{"jetkvm", "jetkvm"},
	{"tinypilot", "tinypilot"},
	// Serial-console-server and managed-PDU vendors. The Lantronix/Moxa direct
	// probes and the SNMP sysDescr guess feed these slugs through NormalizeVendor,
	// so they must resolve or the vendor attribution (and the console/PDU default-
	// credential lookup) is silently dropped.
	{"lantronix", "lantronix"},
	{"moxa", "moxa"},
	{"opengear", "opengear"},
	{"digi", "digi"},
	{"perle", "perle"},
	{"nodegrid", "zpe"},
	{"zpe", "zpe"},
	{"avocent", "avocent"},
	{"raritan", "raritan"},
	// schneiderpm (Link150 / PowerLogic energy gear) must precede the broad
	// "schneider"->apc alias: NormalizeVendor returns the first substring match,
	// and "schneiderpm" contains "schneider", so without this ordering it would
	// collapse into apc. APC NMC cards still resolve via "schneider electric".
	{"schneiderpm", "schneiderpm"},
	{"schneider", "apc"},
	{"apc", "apc"},
	{"eaton", "eaton"},
	{"gude", "gude"},
	{"tripp lite", "tripplite"},
	{"tripplite", "tripplite"},
	{"server technology", "servertech"},
	{"servertech", "servertech"},
	{"cyberpower", "cyberpower"},
	{"vertiv", "vertiv"},
	{"geist", "vertiv"},
	{"liebert", "vertiv"},
}

// NormalizeVendor maps a free-form manufacturer string (e.g. the IANA-PEN name
// "Super Micro Computer" from IPMI Get Device ID, or an HTTP Server header) to
// the lowercase vendor slug used by Table and CredsFor. Returns "" when no
// alias matches.
func NormalizeVendor(manufacturer string) string {
	m := strings.ToLower(strings.TrimSpace(manufacturer))
	if m == "" {
		return ""
	}
	for _, a := range vendorAliases {
		if strings.Contains(m, a.match) {
			return a.slug
		}
	}
	return ""
}
