package tlscert

import (
	"regexp"
	"strings"
)

var dellServiceTagCN = regexp.MustCompile(`(?i)^i?drac(?:\d+)?-([a-z0-9]{7})$`)

// ClassifyIdentity derives a vendor hint, an asset identifier, and notes from a
// leaf certificate's subject/issuer CN. It complements the fingerprint/exact-
// subject matching in Inspect for:
//
//   - per-unit certs whose CN encodes asset info - Dell iDRAC "idrac-<servicetag>"
//     leaks the service tag in the cert CN.
//   - default identities not caught by an exact-subject entry - e.g. AMI MegaRAC
//     units serving CN=ami.com / www.ami.com or issued by megarac.com.
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
