package ilo

import (
	"strconv"
	"strings"
)

type AffectedRange struct {
	Generation string

	IntroducedIn string

	FixedIn string
}

type CVE struct {
	ID          string
	Affected    []AffectedRange
	Severity    string
	Title       string
	AuthBypass  bool
	Exploitable bool
}

var KnownCVEs = []CVE{

	{
		ID:          "CVE-2017-12542",
		Affected:    []AffectedRange{{Generation: "iLO4", FixedIn: "2.53"}},
		Severity:    "critical",
		AuthBypass:  true,
		Exploitable: true,
		Title:       "iLO4 'A' x 29 Connection: Authorization header auth bypass + RCE",
	},

	{
		ID: "CVE-2018-7078",
		Affected: []AffectedRange{
			{Generation: "iLO4", FixedIn: "2.60"},
			{Generation: "iLO5", FixedIn: "1.30"},
		},
		Severity: "high",
		Title:    "iLO4/5 authenticated remote code execution via crafted HTTP POST",
	},

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

	{
		ID:       "CVE-2018-7113",
		Affected: []AffectedRange{{Generation: "iLO5", FixedIn: "1.37"}},
		Severity: "medium",
		Title:    "iLO5 local firmware-update security-restriction bypass",
	},

	{
		ID:       "CVE-2018-7117",
		Affected: []AffectedRange{{Generation: "iLO5", FixedIn: "1.40"}},
		Severity: "medium",
		Title:    "iLO5 web UI reflected cross-site scripting",
	},

	{
		ID: "CVE-2020-7202",
		Affected: []AffectedRange{
			{Generation: "iLO4", FixedIn: "2.76"},
			{Generation: "iLO5", FixedIn: "2.31"},
		},
		Severity: "medium",
		Title:    "iLO4/5 remote serial-number and information disclosure",
	},

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
}

type Match struct {
	CVE
	Generation   string
	IntroducedIn string
	FixedIn      string
}

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
			fixed, ok := parseILO(r.FixedIn)
			if !ok {
				continue
			}
			if r.IntroducedIn != "" {
				introduced, ok := parseILO(r.IntroducedIn)
				if !ok || runVer < introduced {
					continue
				}
			}
			if runVer < fixed {
				out = append(out, Match{
					CVE:          c,
					Generation:   r.Generation,
					IntroducedIn: r.IntroducedIn,
					FixedIn:      r.FixedIn,
				})
			}
		}
	}
	return out
}

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
