package tlscert

import (
	"regexp"
	"strings"
)

var dellServiceTagCN = regexp.MustCompile(`(?i)^i?drac(?:\d+)?-([a-z0-9]{7})$`)

func ClassifyIdentity(subjectCN, issuerCN string) (vendorHint, serviceTag string, notes []string) {
	cn := strings.TrimSpace(subjectCN)
	low := strings.ToLower(cn)
	iss := strings.ToLower(strings.TrimSpace(issuerCN))

	switch {
	case dellServiceTagCN.MatchString(cn):
		vendorHint = "dell"
		serviceTag = strings.ToUpper(dellServiceTagCN.FindStringSubmatch(cn)[1])
		notes = append(notes, "Dell iDRAC per-unit TLS cert - service tag "+serviceTag+
			" disclosed in certificate CN (pre-auth asset leak, in addition to the System GUID)")
	case low == "ipmi":
		vendorHint = "supermicro"
		notes = append(notes, "Supermicro default 'CN=IPMI' certificate identity retained")
	case strings.Contains(low, "ami.com") || strings.Contains(low, "megarac.com") ||
		strings.Contains(iss, "ami.com") || strings.Contains(iss, "megarac.com"):
		vendorHint = "ami"
		notes = append(notes, "AMI MegaRAC default certificate identity (subject "+subjectCN+
			" / issuer "+issuerCN+") - default cert retained")
	}
	return vendorHint, serviceTag, notes
}
