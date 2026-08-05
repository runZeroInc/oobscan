package explain

import (
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/check"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/output"
)

func Section(host string, r *output.Result, f engine.Finding) string {
	if f.Risk == "none" {
		return ""
	}
	if fn, ok := check.GetExplainer(f.Check); ok {
		return fn(host, f)
	}
	return genericSection(host, r, f)
}

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

func genericSection(host string, r *output.Result, f engine.Finding) string {
	_ = r
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
