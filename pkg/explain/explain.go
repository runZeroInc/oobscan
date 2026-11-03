// Package explain produces human-readable markdown validation guides from
// oobscan findings. The actual per-finding explainer functions live in the
// same file as the check that emits each finding (pkg/check/*.go) and
// self-register via check.RegisterExplain so they stay in sync with the check.
// This package is the thin consumer: it dispatches to those registered
// explainers and provides a generic fallback for unregistered findings.
package explain

import (
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/advisory"
	"github.com/runZeroInc/oobscan/pkg/check"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/output"
)

// Section returns a self-contained markdown block for one finding. It
// dispatches to the explainer registered by the check that emits the finding
// (via check.RegisterExplain), falling back to a generic block that lists
// the raw fields. An empty string is returned for risk=none findings. Findings
// that carry a runZero advisory CVE end with a link to that advisory.
func Section(host string, r *output.Result, f engine.Finding) string {
	if f.Risk == "none" {
		return ""
	}
	var s string
	if fn, ok := check.GetExplainer(f.Check); ok {
		s = fn(host, f)
	} else {
		s = genericSection(host, r, f)
	}
	return s + advisoryRefs(f)
}

// advisoryRefs renders a markdown block linking each runZero advisory the
// finding's CVEs resolve to, or "" when none do.
func advisoryRefs(f engine.Finding) string {
	var b strings.Builder
	for _, cve := range f.CVE {
		a, ok := advisory.Lookup(cve)
		if !ok {
			continue
		}
		if b.Len() == 0 {
			b.WriteString("\n### runZero advisory\n\n")
		}
		rating := ""
		if a.Score != "" {
			rating = fmt.Sprintf(" (CVSS %s, %s)", a.Score, strings.ToUpper(a.Severity[:1])+a.Severity[1:])
		}
		fmt.Fprintf(&b, "- %s: %s%s: %s\n", a.CVE, a.Title, rating, a.URL)
	}
	return b.String()
}

// MatchLine builds the plain-text representation of a finding used for
// --match= filtering. Format mirrors the tty emitter's human output so
// operators can copy-paste a scan line and use it as a filter:
//
//	CRITICAL 192.168.0.1 ipmi.v15.authNoneSession 623/udp ipmi priv=admin proof="..."
func MatchLine(host string, f engine.Finding) string {
	parts := []string{strings.ToUpper(f.Risk), host, f.Check}
	if f.Port != 0 {
		parts = append(parts, fmt.Sprintf("%d/%s", f.Port, f.Transport))
	}
	if f.Protocol != "" {
		parts = append(parts, f.Protocol)
	}
	if s := f.Fields.String(); s != "" {
		parts = append(parts, s)
	}
	parts = append(parts, f.CVE...)
	return strings.Join(parts, " ")
}

// genericSection is the fallback for findings with no registered explainer.
// It renders the raw finding fields in a structured markdown block so the
// reader still has full detail without a bespoke validation script.
func genericSection(host string, r *output.Result, f engine.Finding) string {
	_ = r // reserved for future cross-finding context
	var b strings.Builder
	b.WriteString(sectionHeading(host, f))
	b.WriteString(fmt.Sprintf("\n**Check:** `%s`  **Risk:** %s\n", f.Check, f.Risk))
	if len(f.CVE) > 0 {
		b.WriteString(fmt.Sprintf("**CVE:** %s\n", strings.Join(f.CVE, ", ")))
	}
	if len(f.Fields) > 0 {
		b.WriteString("\n**Details:**\n\n")
		for _, fld := range f.Fields {
			b.WriteString(fmt.Sprintf("- `%s` = `%s`\n", fld.Key, fld.Val))
		}
	}
	if f.Port != 0 {
		b.WriteString(fmt.Sprintf("\n**Location:** %d/%s %s\n", f.Port, f.Transport, f.Protocol))
	}
	b.WriteString("\nNo automated validation command is available for this finding type.\n")
	b.WriteString(fmt.Sprintf("Re-run with: `oobscan scan --checks %s %s`\n", f.Check, host))
	return b.String()
}

// sectionHeading is the local heading helper for genericSection. Per-check
// explainers use check.explainHeading from the check package directly.
func sectionHeading(host string, f engine.Finding) string {
	loc := ""
	if f.Port != 0 {
		loc = fmt.Sprintf(" %d/%s", f.Port, f.Transport)
	}
	if f.Protocol != "" {
		loc += " " + f.Protocol
	}
	return fmt.Sprintf("## [%s] %s%s -- %s\n", strings.ToUpper(f.Risk), host, loc, f.Check)
}
