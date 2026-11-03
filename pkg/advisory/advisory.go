// Package advisory is the catalog of runZero "Lights Out" BMC/OOB advisories:
// the published CVE, title, CVSS v3.1 rating and advisory URL for each issue
// disclosed at https://www.runzero.com/blog/lights-out-exposed/. Checks,
// reports and explainers resolve CVE identifiers here so every surface uses the
// published wording.
package advisory

import "sort"

// Advisory is one published runZero advisory.
type Advisory struct {
	CVE      string
	Vendor   string
	Title    string // published advisory title
	Severity string // critical | high | medium | low; "" when the advisory publishes no score
	Score    string // CVSS v3.1 base score; "" when unscored
	URL      string
}

const base = "https://www.runzero.com/advisories/"

// LightsOutURL is the summary post that indexes every advisory below.
const LightsOutURL = "https://www.runzero.com/blog/lights-out-exposed/"

var catalog = []Advisory{
	// OpenBMC phosphor-net-ipmid.
	{"CVE-2026-16140", "OpenBMC", "OpenBMC IPMI Privilege Escalation via Retargeted RAKP 1", "", "", base + "openbmc-ipmi-privsec-rakp-cve-2026-16140/"},
	{"CVE-2026-16141", "OpenBMC", "OpenBMC IPMI Authentication Bypass via Default userKey and Stale Challenge Value", "", "", base + "openbmc-ipmi-auth-bypass-rakp-cve-2026-16141/"},

	// Supermicro.
	{"CVE-2026-18449", "Supermicro", "Supermicro BMC Hardcoded RAKP Key", "high", "7.5", base + "smc-rakp-key-cve-2026-18449/"},
	{"CVE-2026-18450", "Supermicro", "Supermicro BMC Unauthenticated IPMI Commands", "high", "8.1", base + "smc-ipmi-auth-bypass-cve-2026-18450/"},
	{"CVE-2026-18451", "Supermicro", "Supermicro BMC Predictable KVM Tokens", "low", "3.1", base + "smc-kvm-token-cve-2026-18451/"},
	{"CVE-2026-65210", "Supermicro", "Supermicro ATEN Arbitrary File Read", "medium", "4.9", base + "smc-fileread-cve-2026-65210/"},
	{"CVE-2026-65211", "Supermicro", "Supermicro ATEN Physical Memory Access", "high", "7.2", base + "smc-memaccess-cve-2026-65211/"},
	{"CVE-2026-65213", "Supermicro", "Supermicro X14 Command Injection", "medium", "6.6", base + "smc-cmdinj-cve-2026-65213/"},
	{"CVE-2026-65219", "Supermicro", "Supermicro ATEN RAKP Authentication Bypass", "high", "7.4", base + "smc-rakp-bypass-cve-2026-65219/"},
	{"CVE-2026-65220", "Supermicro", "Supermicro ATEN Privilege Escalation", "high", "8.8", base + "smc-priv-esc-cve-2026-65220/"},

	// HPE iLO.
	{"CVE-2026-65204", "HPE", "HPE iLO 4/5/6 pre-authentication stack overflow in SSH packet processor", "high", "8.2", base + "hpe-ilo-preauth-overflow-ssh-cve-2026-65204/"},
	{"CVE-2026-65205", "HPE", "HPE iLO 2/3/4 missing RMCP+ integrity enforcement allows IPMI session injection", "high", "8.8", base + "hpe-ilo-ipmi-session-injection-cve-2026-65205/"},
	{"CVE-2026-65206", "HPE", "HPE iLO 2/3/4 RMCP+ type confusion enables passwordless administrator sessions", "critical", "9.8", base + "hpe-ilo-type-confusion-cve-2026-65206/"},
	{"CVE-2026-65207", "HPE", "HPE iLO 4/5 truncated JSON unicode escape denial-of-service", "high", "7.5", base + "hpe-ilo-truncated-json-unicode-escape-dos-cve-2026-65207/"},
	{"CVE-2026-65208", "HPE", "HPE iLO 5 JSON dispatcher mutex leak", "low", "3.7", base + "hpe-ilo-json-dispatcher-mutex-leak-cve-2026-65208/"},
	{"CVE-2026-65209", "HPE", "HPE iLO 4/5 Redfish deeply nested JSON denial-of-service", "high", "7.5", base + "hpe-ilo-redfish-nested-json-dos-cve-2026-65209/"},

	// Huawei openUBMC.
	{"CVE-2026-65198", "Huawei", "Huawei Default SNMPv3 USM key", "high", "8.6", base + "huawei-default-snmpv3-usm-key-cve-2026-65198/"},
	{"CVE-2026-65199", "Huawei", "Huawei openUBMC low-privilege SNMP to administrator privilege escalation", "medium", "5.4", base + "huawei-openubmc-snmp-privsec-cve-2026-65199/"},
	{"CVE-2026-65200", "Huawei", "Huawei malicious on-bus PLDM or NCSI device can drive out-of-bounds-heap reads via short MCTP responses", "low", "3.5", base + "huawei-malicious-device-integer-underflow-cve-2026-65200/"},

	// H3C HDM.
	{"CVE-2026-65197", "H3C", "H3C G3/G5 HDM Firmware Verification Key Replacement", "low", "3.1", base + "h3c-hdm-firmware-verification-key-replacement-cve-2026-65197/"},

	// Avocent.
	{"CVE-2026-65184", "Avocent", "Avocent ACS8000 wsserver command injection", "critical", "9.8", base + "avocent-acs8000-wsserver-cmdinj-cve-2026-65184/"},

	// Dell iDRAC.
	{"CVE-2026-65185", "Dell", "Dell iDRAC PLDM Heap Overflow", "low", "3.1", base + "dell-idrac-pldm-bof-cve-2026-65185/"},
	{"CVE-2026-65186", "Dell", "Dell iDRAC10 Redfish SQL Injection", "medium", "6.5", base + "dell-idrac10-sqli-cve-2026-65186/"},
	{"CVE-2026-65187", "Dell", "Dell iDRAC9 xRC4 Length Underflow", "medium", "5.9", base + "dell-idrac9-xrc4-underflow-cve-2026-65187/"},
	{"CVE-2026-65188", "Dell", "Dell iDRAC9 IPMI Buffer Overflow", "medium", "4.7", base + "dell-idrac9-ipmi-bof-cve-2026-65188/"},
	{"CVE-2026-65189", "Dell", "Dell iDRAC Redfish SQL Injection", "medium", "6.5", base + "dell-idrac-redfish-sqli-cve-2026-65189/"},
	{"CVE-2026-65190", "Dell", "Dell iDRAC9 SSO Memory Exhaustion", "medium", "5.3", base + "dell-idrac9-sso-dos-cve-2026-65190/"},
	{"CVE-2026-65191", "Dell", "Dell iDRAC9 Redfish SSRF", "medium", "5.5", base + "dell-idrac9-ssrf-cve-2026-65191/"},
	{"CVE-2026-65192", "Dell", "Dell iDRAC10 Telemetry Data Exposure", "low", "2.7", base + "dell-idrac10-telemetry-exposure-cve-2026-65192/"},
	{"CVE-2026-65193", "Dell", "Dell iDRAC9 Maser Update Weaknesses", "low", "3.1", base + "dell-idrac9-maser-update-cve-2026-65193/"},
	{"CVE-2026-65194", "Dell", "Dell iDRAC Shared TLS Key", "low", "3.1", base + "dell-idrac-tls-key-cve-2026-65194/"},
	{"CVE-2026-65195", "Dell", "Dell iDRAC10 Predictable Password Generation", "medium", "4.4", base + "dell-idrac10-predictable-password-cve-2026-65195/"},
	{"CVE-2026-65196", "Dell", "Dell iDRAC10 IPv6 IPMI Exposure", "low", "3.7", base + "dell-idrac10-ipv6-ipmi-cve-2026-65196/"},
}

var byCVE = func() map[string]Advisory {
	m := make(map[string]Advisory, len(catalog))
	for _, a := range catalog {
		m[a.CVE] = a
	}
	return m
}()

// Lookup returns the advisory published for a CVE identifier.
func Lookup(cve string) (Advisory, bool) {
	a, ok := byCVE[cve]
	return a, ok
}

// All returns every advisory, sorted by CVE.
func All() []Advisory {
	out := append([]Advisory(nil), catalog...)
	sort.Slice(out, func(i, j int) bool { return out[i].CVE < out[j].CVE })
	return out
}
