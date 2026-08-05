package report

import "strings"

var advisoryTitles = map[string]string{
	"CVE-2024-54085": "AMI Redfish bypass",
	"CVE-2023-34329": "AMI Host-header bypass",
	"CVE-2013-4786":  "RAKP hash disclosure",
	"CVE-2013-4784":  "Cipher-zero session",
	"CVE-2017-12542": "iLO HTTP auth bypass",
	"CVE-2017-5689":  "AMT empty-digest bypass",
}

var exposureAdvisories = map[string][]string{
	"ami_redfish_bypass": {"CVE-2024-54085", "CVE-2023-34329"},
	"ami_mtls_bypass":    {"AMI-mTLS"},
	"ipmi_rakp_hash":     {"CVE-2013-4786"},
	"ipmi_cipher_zero":   {"CVE-2013-4784"},
	"amt_auth_bypass":    {"CVE-2017-5689"},
}

func shortTitle(advisory, fallback string) string {
	if short, ok := advisoryTitles[advisory]; ok {
		return short
	}
	return fallback
}

func findingLabel(advisory, fallback string) string {
	if advisory == "" {
		return fallback
	}
	return advisory + " · " + shortTitle(advisory, fallback)
}

func exposureLabel(key, fallback string) string {
	ids, ok := exposureAdvisories[key]
	if !ok || len(ids) == 0 {
		return fallback
	}
	if len(ids) == 1 {
		return findingLabel(ids[0], stripProtocolPrefix(fallback))
	}
	return strings.Join(ids, " / ") + " · " + stripProtocolPrefix(fallback)
}

func stripProtocolPrefix(label string) string {
	if _, rest, ok := strings.Cut(label, ": "); ok {
		return rest
	}
	return label
}

func bmcPopulation(s *Source) int {
	if s == nil {
		return 0
	}
	for _, p := range s.class.top(0) {
		if p.Value == "BMC" {
			return p.Count
		}
	}
	return 0
}
