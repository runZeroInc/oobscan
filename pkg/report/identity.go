package report

import "strings"

// A single weakness shows up on three different slides -- the compromise-path
// breakdown, the exposure-prevalence comparison, and the new-findings table --
// and each one used to carry its own wording. A reader tracking one finding
// across the deck then has to work out that "SMCRAKP fixed-key RAKP-2 session
// forgery", "IPMI: Supermicro SMCRAKP fixed-key bypass" and "SMCRAKP fixed-key
// bypass" are the same thing. This file is the one place that decides, so every
// slide renders a finding under the same identifier and the same short title.

// advisoryTitles maps an advisory or CVE identifier to the short title used
// everywhere it appears. Short enough for a dense table column, specific enough
// to be unambiguous: the defect, not the mechanism behind it.
var advisoryTitles = map[string]string{
	// This research.
	"CVE-2026-18449": "Hardcoded RAKP key",
	"CVE-2026-18450": "Unauthenticated IPMI commands",
	"SMC-0011":       "Predictable session IDs (disputed)",
	"CVE-2026-18451": "Predictable KVM tokens",
	"CVE-2026-65219": "RAKP authentication bypass",
	"CVE-2026-65220": "RAKP role privilege escalation",
	"CVE-2026-65204": "iLO SSH pre-auth overflow",
	"CVE-2026-65205": "iLO IPMI session injection",
	"CVE-2026-65206": "iLO passwordless admin session",
	"CVE-2026-16140": "Retargeted RAKP 1 escalation",
	"CVE-2026-16141": "Default userKey auth bypass",
	"AMI-mTLS":       "AMI mTLS CA bypass",
	// Already public.
	"CVE-2024-54085": "AMI Redfish bypass",
	"CVE-2023-34329": "AMI Host-header bypass",
	"CVE-2013-4786":  "RAKP hash disclosure",
	"CVE-2013-4784":  "Cipher-zero session",
	"CVE-2017-12542": "iLO HTTP auth bypass",
	"CVE-2017-5689":  "AMT empty-digest bypass",
}

// exposureAdvisories maps a taxonomy exposure key onto every advisory that feeds
// it. Several columns are deliberately broader than one finding -- "iLO auth
// bypass" is fed by both CVE-2026-65205 and CVE-2026-65206 -- so this is a list, not a single
// id: naming only the first would attribute one advisory's prevalence to the
// other. A key absent here has no advisory of ours behind it (a broad protocol
// weakness, or a set of public CVEs) and keeps the taxonomy's own label.
var exposureAdvisories = map[string][]string{
	"ipmi_smcrakp_bypass":       {"CVE-2026-18449"},
	"ipmi_smc_integrity_bypass": {"CVE-2026-18450"},
	"ipmi_sid_weak":             {"SMC-0011"},
	"ipmi_state_machine":        {"CVE-2026-65219"},
	"ipmi_ilo_auth_bypass":      {"CVE-2026-65205", "CVE-2026-65206"},
	"ipmi_openbmc_bypass":       {"CVE-2026-16140", "CVE-2026-16141"},
	"ipmi_role_escalation":      {"CVE-2026-65220", "CVE-2026-16140"},
	"ssh_ilo_overflow":          {"CVE-2026-65204"},
	"ami_redfish_bypass":        {"CVE-2024-54085", "CVE-2023-34329"},
	"ami_mtls_bypass":           {"AMI-mTLS"},
	"ipmi_rakp_hash":            {"CVE-2013-4786"},
	"ipmi_cipher_zero":          {"CVE-2013-4784"},
	"amt_auth_bypass":           {"CVE-2017-5689"},
}

// shortTitle is the finding's canonical short title alone, for a table that
// renders the identifier in its own column or line.
func shortTitle(advisory, fallback string) string {
	if short, ok := advisoryTitles[advisory]; ok {
		return short
	}
	return fallback
}

// findingLabel renders a finding as "ID · Short title", for a table with no
// separate identifier column. The identifier leads because it is the stable
// handle a reader carries between slides and into the advisory text; the title
// is what makes it readable.
func findingLabel(advisory, fallback string) string {
	if advisory == "" {
		return fallback
	}
	return advisory + " · " + shortTitle(advisory, fallback)
}

// exposureLabel prefixes a taxonomy exposure row with the advisories behind it.
// A column fed by exactly one advisory takes that advisory's canonical short
// title, so it reads identically to the compromise-path and new-findings slides.
// A column fed by several keeps the taxonomy's own wording, because no single
// finding's title describes the whole population -- but it still lists every id.
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

// stripProtocolPrefix drops the taxonomy's "PROTOCOL: " lead-in. The advisory id
// already says which plane the defect is on, and the prefix crowds out the part
// of the label that identifies the bug.
func stripProtocolPrefix(label string) string {
	if _, rest, ok := strings.Cut(label, ": "); ok {
		return rest
	}
	return label
}

// bmcPopulation is the count of hosts that classified as an actual BMC, which is
// the honest denominator for a BMC claim: a sweep also lands on honeypots, serial
// consoles and PDUs, and a share quoted against the whole responder count
// understates every rate.
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
