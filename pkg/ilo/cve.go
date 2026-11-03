// Package ilo contains HPE iLO-specific probes and CVE mapping.
//
// The /xmldata?item=all endpoint is unauthenticated on every iLO since iLO1 and
// exposes FWRI (firmware version), SBSN (chassis serial), SPN (product name), PN
// (part number), and cUUID, which is what maps a host to known-vulnerable firmware.
//
// Version strings:
//
//	iLO2 :  2.NN    (e.g. 2.33)
//	iLO3 :  1.NN    (e.g. 1.88) / 1.90
//	iLO4 :  2.NN    (e.g. 2.55, 2.70, 2.77, 2.82)
//	iLO5 :  2.NN    (e.g. 2.18, 2.44, 2.55, 2.72, 2.82, 3.03)
//	iLO6 :  1.xx    (e.g. 1.35, 1.56, 1.62)
//	iLO7 :  1.xx.yy (e.g. 1.25.01)
//
// Generation is disambiguated via the SPN / PN string.
package ilo

import (
	"strconv"
	"strings"
)

// AffectedRange describes the band of one iLO generation's firmware that a
// CVE applies to. Many HPE iLO advisories cover more than one generation at
// once, each with its own fixed (and sometimes introduced-in) version, so a
// single CVE carries one AffectedRange per affected generation rather than a
// single generation+FixedIn pair.
type AffectedRange struct {
	Generation string // "iLO2" | "iLO3" | "iLO4" | "iLO5" | "iLO6" | "iLO7"

	// Severity overrides the CVE's severity for this band; empty keeps it.
	Severity string

	// IntroducedIn is the earliest firmware the defect is present in,
	// inclusive. Empty means "from the beginning of the generation" (no
	// lower bound).
	IntroducedIn string

	// FixedIn is the earliest firmware that ships the fix, exclusive: a
	// firmware string parses as affected when it is strictly less than
	// FixedIn. When HPE's advisory only publishes an inclusive affected
	// ceiling (e.g. "2.63 through 3.00") and no later fixed build is named,
	// FixedIn is set to a synthetic just-past-ceiling sentinel (e.g.
	// "3.00.1") purely for the exclusive-bound comparison -- it does not
	// assert that a real "3.00.1" build exists. Empty means HPE released no
	// fix for the generation (end of life), so every firmware in the band is
	// affected.
	FixedIn string
}

// NoFix is the fixed-in label reported for a band with no fixed firmware.
const NoFix = "none (no fixed firmware)"

// CVE describes a single known iLO vulnerability and every generation/firmware
// band it applies to. All entries below are traced to their HPE Security
// Bulletin / NVD record (see the reference in each comment); do not add an
// entry without confirming it is actually an HPE iLO advisory (HPE issues CVEs
// for many unrelated products -- OneView, SSMC/3PAR, Aruba, StoreEasy -- under
// the same CNA, and reserved/placeholder CVE numbers can be non-existent).
type CVE struct {
	ID          string
	Affected    []AffectedRange
	Severity    string // "critical" | "high" | "medium" | "low"
	Title       string
	AuthBypass  bool
	Exploitable bool // public PoC / Metasploit module exists
}

// KnownCVEs is the curated iLO CVE table. Ordered chronologically.
var KnownCVEs = []CVE{
	// iLO4 -- 2017 29-char Connection header auth-bypass + RCE (Metasploit:
	// hp_ilo_auth_bypass). NVD CVE-2017-12542 / HPE hpesbhf03769: iLO4 < 2.53.
	{
		ID:          "CVE-2017-12542",
		Affected:    []AffectedRange{{Generation: "iLO4", FixedIn: "2.53"}},
		Severity:    "critical",
		AuthBypass:  true,
		Exploitable: true,
		Title:       "iLO4 'A' x 29 Connection: Authorization header auth bypass + RCE",
	},
	// 2018 RCE reachable via a crafted HTTP POST. NVD CVE-2018-7078 / HPE
	// hpesbhf03844: iLO4 < 2.60 and iLO5 < 1.30.
	{
		ID: "CVE-2018-7078",
		Affected: []AffectedRange{
			{Generation: "iLO4", FixedIn: "2.60"},
			{Generation: "iLO5", FixedIn: "1.30"},
		},
		Severity: "high",
		Title:    "iLO4/5 authenticated remote code execution via crafted HTTP POST",
	},
	// 2018 shared-component RCE/info-disclosure. NVD CVE-2018-7105 / HPE
	// hpesbhf03866: iLO3 < 1.90, iLO4 < 2.61, iLO5 < 1.35.
	{
		ID: "CVE-2018-7105",
		Affected: []AffectedRange{
			{Generation: "iLO3", FixedIn: "1.90"},
			{Generation: "iLO4", FixedIn: "2.61"},
			{Generation: "iLO5", FixedIn: "1.35"},
		},
		Severity: "high",
		Title:    "iLO3/4/5  authenticated remote code execution and information disclosure",
	},
	// 2018 local firmware-update security-restriction bypass. NVD
	// CVE-2018-7113 / HPE hpesbhf03894: iLO5 < 1.37.
	{
		ID:       "CVE-2018-7113",
		Affected: []AffectedRange{{Generation: "iLO5", FixedIn: "1.37"}},
		Severity: "medium",
		Title:    "iLO5 local firmware-update security-restriction bypass",
	},
	// 2018 reflected XSS in the iLO5 web UI. NVD CVE-2018-7117 / HPE
	// hpesbhf03907 & hpesbhf03917: iLO5 < 1.40.
	{
		ID:       "CVE-2018-7117",
		Affected: []AffectedRange{{Generation: "iLO5", FixedIn: "1.40"}},
		Severity: "medium",
		Title:    "iLO5 web UI reflected cross-site scripting",
	},
	// 2020 remote serial-number/info disclosure. NVD CVE-2020-7202 / HPE
	// hpesbhf04069: iLO4 < 2.76 and iLO5 < 2.31.
	// (Not to be confused with CVE-2020-7197, which is HPE StoreServ
	// Management Console -- a 3PAR storage-array manager, not iLO.)
	{
		ID: "CVE-2020-7202",
		Affected: []AffectedRange{
			{Generation: "iLO4", FixedIn: "2.76"},
			{Generation: "iLO5", FixedIn: "2.31"},
		},
		Severity: "medium",
		Title:    "iLO4/5 remote serial-number and information disclosure",
	},
	// 2022 "Insight" quartet, all iLO5-only, all fixed in 2.71/2.72. NVD
	// CVE-2022-28626 / CVE-2022-28633 / CVE-2022-28636 / CVE-2022-28639, HPE
	// hpesbhf04333 & hpesbhf04365.
	// (CVE-2022-28625 is HPE OneView, not iLO -- excluded.)
	{
		ID:       "CVE-2022-28626",
		Affected: []AffectedRange{{Generation: "iLO5", FixedIn: "2.71"}},
		Severity: "medium",
		Title:    "iLO5 local arbitrary code execution by a highly privileged user",
	},
	{
		ID:       "CVE-2022-28633",
		Affected: []AffectedRange{{Generation: "iLO5", FixedIn: "2.71"}},
		Severity: "high",
		Title:    "iLO5 local unprivileged read/write of the iLO firmware file system",
	},
	{
		ID:       "CVE-2022-28636",
		Affected: []AffectedRange{{Generation: "iLO5", FixedIn: "2.71"}},
		Severity: "high",
		Title:    "iLO5 local unprivileged code execution / DoS within an isolated process",
	},
	{
		ID:       "CVE-2022-28639",
		Affected: []AffectedRange{{Generation: "iLO5", FixedIn: "2.72"}},
		Severity: "high",
		Title:    "iLO5 network-adjacent denial of service and potential arbitrary code execution",
	},
	// 2023 reflected XSS across the whole line. NVD CVE-2023-28083 / HPE
	// hpesbhf04456: iLO4 < 2.82, iLO5 < 2.78, iLO6 < 1.20.
	{
		ID: "CVE-2023-28083",
		Affected: []AffectedRange{
			{Generation: "iLO4", FixedIn: "2.82"},
			{Generation: "iLO5", FixedIn: "2.78"},
			{Generation: "iLO6", FixedIn: "1.20"},
		},
		Severity: "medium",
		Title:    "iLO4/5/6 reflected cross-site scripting",
	},
	// 2023 remote authentication bypass. NVD CVE-2023-50272 / HPE
	// hpesbhf04584: iLO5 firmware 2.63-3.00 inclusive, iLO6 firmware
	// 1.05-1.55 inclusive; HPE's advisory does not name a later fixed build
	// for either band as of this writing, so FixedIn below is a synthetic
	// just-past-ceiling sentinel for the exclusive-bound comparison (see
	// AffectedRange.FixedIn) -- re-verify against the live advisory before
	// asserting a specific fixed version to a customer.
	{
		ID: "CVE-2023-50272",
		Affected: []AffectedRange{
			{Generation: "iLO5", IntroducedIn: "2.63", FixedIn: "3.00.1"},
			{Generation: "iLO6", IntroducedIn: "1.05", FixedIn: "1.55.1"},
		},
		Severity:   "critical",
		AuthBypass: true,
		Title:      "iLO5/6 remote authentication bypass",
	},
	// 2026 runZero Lights Out disclosures (HPE hpesbhf05170). iLO5/6/7 bands and
	// fixed builds follow the HPE bulletin, which lists every CVE for iLO5 < 3.22,
	// iLO6 < 1.79 and iLO7 < 1.25.01 except CVE-2026-65204 on iLO7. iLO2/3/4 bands
	// follow the runZero advisories; those generations are end of life with no
	// fixed firmware. runZero could not decrypt iLO5/6/7 firmware to confirm the
	// RMCP+ defects there, so a critical rating drops to high on those bands.
	{
		ID: "CVE-2026-65204",
		Affected: []AffectedRange{
			{Generation: "iLO4"},
			{Generation: "iLO5", FixedIn: "3.22"},
			{Generation: "iLO6", FixedIn: "1.79"},
		},
		Severity:    "high",
		Exploitable: true,
		Title:       "iLO pre-authentication stack overflow in SSH packet processor",
	},
	{
		ID: "CVE-2026-65205",
		Affected: []AffectedRange{
			{Generation: "iLO2"},
			{Generation: "iLO3"},
			{Generation: "iLO4"},
			{Generation: "iLO5", FixedIn: "3.22"},
			{Generation: "iLO6", FixedIn: "1.79"},
			{Generation: "iLO7", FixedIn: "1.25.01"},
		},
		Severity:    "high",
		Exploitable: true,
		Title:       "iLO missing RMCP+ integrity enforcement allows IPMI session injection",
	},
	{
		ID: "CVE-2026-65206",
		Affected: []AffectedRange{
			{Generation: "iLO2"},
			{Generation: "iLO3"},
			{Generation: "iLO4"},
			{Generation: "iLO5", FixedIn: "3.22", Severity: "high"},
			{Generation: "iLO6", FixedIn: "1.79", Severity: "high"},
			{Generation: "iLO7", FixedIn: "1.25.01", Severity: "high"},
		},
		Severity:    "critical",
		AuthBypass:  true,
		Exploitable: true,
		Title:       "iLO RMCP+ type confusion enables passwordless administrator sessions",
	},
	{
		ID: "CVE-2026-65207",
		Affected: []AffectedRange{
			{Generation: "iLO4"},
			{Generation: "iLO5", FixedIn: "3.22"},
			{Generation: "iLO6", FixedIn: "1.79"},
			{Generation: "iLO7", FixedIn: "1.25.01"},
		},
		Severity:    "high",
		Exploitable: true,
		Title:       "iLO truncated JSON unicode escape denial of service",
	},
	{
		ID: "CVE-2026-65208",
		Affected: []AffectedRange{
			{Generation: "iLO5", FixedIn: "3.22"},
			{Generation: "iLO6", FixedIn: "1.79"},
			{Generation: "iLO7", FixedIn: "1.25.01"},
		},
		Severity:    "low",
		Exploitable: true,
		Title:       "iLO JSON dispatcher mutex leak denial of service",
	},
	{
		ID: "CVE-2026-65209",
		Affected: []AffectedRange{
			{Generation: "iLO4"},
			{Generation: "iLO5", FixedIn: "3.22"},
			{Generation: "iLO6", FixedIn: "1.79"},
			{Generation: "iLO7", FixedIn: "1.25.01"},
		},
		Severity:    "high",
		Exploitable: true,
		Title:       "iLO Redfish deeply nested JSON denial of service",
	},
}

// Match is a CVE paired with the specific AffectedRange (generation, and its
// FixedIn/IntroducedIn) it matched on a given host, so a caller can report the
// exact band that applies instead of an ambiguous single-generation FixedIn.
type Match struct {
	CVE
	Generation   string
	IntroducedIn string
	FixedIn      string
}

// MatchCVEs returns every CVE with an AffectedRange whose generation matches
// gen and whose firmware band contains the supplied firmware string
// (semantic-ish compare). Unparseable firmware strings produce an empty list. A
// band with no fixed firmware reports NoFix as its FixedIn, and a band Severity
// replaces the CVE's.
func MatchCVEs(gen, firmware string) []Match {
	runVer, ok := parseILO(firmware)
	if !ok {
		return nil
	}
	var out []Match
	for _, c := range KnownCVEs {
		for _, r := range c.Affected {
			if !strings.EqualFold(r.Generation, gen) {
				continue
			}
			fixedIn := NoFix
			if r.FixedIn != "" {
				fixed, ok := parseILO(r.FixedIn)
				if !ok || runVer >= fixed {
					continue
				}
				fixedIn = r.FixedIn
			}
			if r.IntroducedIn != "" {
				introduced, ok := parseILO(r.IntroducedIn)
				if !ok || runVer < introduced {
					continue
				}
			}
			mc := c
			if r.Severity != "" {
				mc.Severity = r.Severity
			}
			out = append(out, Match{
				CVE:          mc,
				Generation:   r.Generation,
				IntroducedIn: r.IntroducedIn,
				FixedIn:      fixedIn,
			})
		}
	}
	return out
}

// parseILO converts "2.18" / "2.18.1" into a comparable integer
// (major*1_000_000 + minor*1000 + patch). Returns (0,false) on parse error.
func parseILO(s string) (int, bool) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) == 0 {
		return 0, false
	}
	n := 0
	for i, p := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return 0, false
		}
		switch i {
		case 0:
			n += v * 1_000_000
		case 1:
			n += v * 1000
		case 2:
			n += v
		}
	}
	return n, true
}
