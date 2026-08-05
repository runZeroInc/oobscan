package creds

import "strings"

var vendorAliases = []struct{ match, slug string }{
	{"super micro", "supermicro"},
	{"supermicro", "supermicro"},
	{"american megatrends", "ami"},
	{"megarac", "ami"},
	{"ami", "ami"},
	{"nedam", "ami"},
	{"celestica", "ami"},
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
	{"xfusion", "xfusion"},
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

	{"blikvm", "blikvm"},
	{"pikvm", "pikvm"},
	{"nanokvm", "nanokvm"},
	{"jetkvm", "jetkvm"},
	{"tinypilot", "tinypilot"},

	{"lantronix", "lantronix"},
	{"moxa", "moxa"},
	{"opengear", "opengear"},
	{"digi", "digi"},
	{"perle", "perle"},
	{"nodegrid", "zpe"},
	{"zpe", "zpe"},
	{"avocent", "avocent"},
	{"raritan", "raritan"},

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
