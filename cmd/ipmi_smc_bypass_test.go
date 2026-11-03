package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// TestSMCBypassCommandsAreRegistered checks the two pre-session bypasses are
// reachable as top-level commands under the smc-<tool> naming, and that they do
// NOT take the credential flags: neither authenticates with -u/-P.
func TestSMCBypassCommandsAreRegistered(t *testing.T) {
	for _, name := range []string{"smc-rakp-bypass", "smc-priv-esc"} {
		c := findRootCommand(name)
		if c == nil {
			t.Fatalf("%q is not registered as a top-level command", name)
		}
		if c.Flags().Lookup("port") == nil || c.Flags().Lookup("timeout") == nil {
			t.Errorf("%s must take the transport flags", name)
		}
		if c.Flags().Lookup("user") != nil || c.Flags().Lookup("password") != nil {
			t.Errorf("%s must not offer -u/-P: it opens no authenticated session", name)
		}
		if c.Flags().Lookup("probe-only") == nil {
			t.Errorf("%s lost --probe-only, the credential-free detection path", name)
		}
	}
	if findRootCommand("smc-rakp-bypass").Flags().Lookup("low-user") != nil {
		t.Error("smc-rakp-bypass must not carry smc-priv-esc's escalation credential flags")
	}
	if findRootCommand("smc-priv-esc").Flags().Lookup("record0-keys") != nil {
		t.Error("smc-priv-esc must not carry smc-rakp-bypass's record-0 forge flags")
	}
}

// TestValidateSMC0015Options locks the input rules, including the one that keeps
// the tool honest: the escalation is not runnable without a real credential.
func TestValidateSMC0015Options(t *testing.T) {
	if _, err := validateSMC0015Options(false, "", "0x24"); err == nil {
		t.Error("a missing --low-user must be rejected: CVE-2026-65220 is a privilege escalation, not an auth bypass")
	} else if !strings.Contains(err.Error(), "not an authentication bypass") {
		t.Errorf("the error should say why a credential is required, got %q", err)
	}
	// --probe-only measures the defect only and needs no credential.
	if role, err := validateSMC0015Options(true, "", "0x24"); err != nil || role != 0x24 {
		t.Errorf("probe-only should not require a credential: role=0x%02x err=%v", role, err)
	}
	// Every reserved nibble is accepted. The range is 0x2x-0xFx, not 0x2x-0x7x: the
	// handler implements only the 0x0x and 0x1x arms and everything above falls into
	// the same residual-privilege else-arm.
	for _, in := range []string{"0x24", "0x34", "0x44", "0x54", "0x64", "0x74", "0x84", "0xf4"} {
		if _, err := validateSMC0015Options(false, "lowpriv", in); err != nil {
			t.Errorf("reserved role %s should be accepted: %v", in, err)
		}
	}
	// The two nibbles the handler actually implements must be refused: they take
	// the correctly clamped path and would produce a false negative.
	for _, in := range []string{"0x04", "0x14", "0x12", "0x00", "0x1f"} {
		if _, err := validateSMC0015Options(false, "lowpriv", in); err == nil {
			t.Errorf("role %s is not a reserved nibble and must be refused", in)
		}
	}
	if _, err := validateSMC0015Options(false, "lowpriv", "notabyte"); err == nil {
		t.Error("an unparseable --reserved-role must be refused")
	}
}

func TestPrintSMC0014ReportJSON(t *testing.T) {
	prev := ipmiOutputFormat
	ipmiOutputFormat = "json"
	defer func() { ipmiOutputFormat = prev }()

	rep := &smc0014Report{
		Finding: "CVE-2026-65219", Host: "192.0.2.10", Port: 623,
		Probe: &ipmi.SMCUnorderedRAKP3Probe{
			Answered: true, RAKP4Status: 0x08, RAKP4StatusText: "inactive-session-id",
			SIDEchoed: true, Defect: true,
		},
		ProbeVerdict: "unordered-rakp3-accepted",
		Impact:       "SOL (host serial console) with no account password; NOT full administrative IPMI",
	}
	var buf bytes.Buffer
	if err := printIPMISMCReport(nil, &buf, rep); err != nil {
		t.Fatalf("print: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid json: %v\n%s", err, buf.String())
	}
	if decoded["finding"] != "CVE-2026-65219" {
		t.Errorf("finding = %v", decoded["finding"])
	}
	if got, _ := decoded["impact"].(string); !strings.Contains(got, "NOT full administrative IPMI") {
		t.Errorf("impact must bound the claim to SOL, got %q", got)
	}
}

// TestPrintSMC0014TableShowsProbeAndBound checks the operator-facing table names
// the two things that are easy to overstate: what the probe proved, and that the
// impact stops at SOL.
func TestPrintSMC0014TableShowsProbeAndBound(t *testing.T) {
	rep := &smc0014Report{
		Finding: "CVE-2026-65219", Host: "192.0.2.10", Port: 623,
		Probe: &ipmi.SMCUnorderedRAKP3Probe{
			Answered: true, RAKP4Status: 0x08, RAKP4StatusText: "inactive-session-id",
			SIDEchoed: true, Defect: true,
		},
		ProbeVerdict: "unordered-rakp3-accepted",
		Defect:       true,
		Impact:       "SOL (host serial console) with no account password; NOT full administrative IPMI",
		Notes:        []string{"Requires a session slot that has not been allocated since boot."},
	}
	var buf bytes.Buffer
	if err := printSMC0014Table(&buf, rep); err != nil {
		t.Fatalf("print: %v", err)
	}
	got := buf.String()
	for _, want := range []string{"rakp1 sent            : false", "console sid echoed    : true", "NOT full administrative IPMI", "not been allocated since boot"} {
		if !strings.Contains(got, want) {
			t.Errorf("table output missing %q:\n%s", want, got)
		}
	}
}

// TestPrintSMC0015TableWithholdsUnprovenEscalation is the honesty guard on the
// operator output: when the baseline was never measured, an unmeasured control
// must render as a dash rather than a completion code of zero, and the report
// must say the claim is withheld.
func TestPrintSMC0015TableWithholdsUnprovenEscalation(t *testing.T) {
	rep := &smc0015Report{
		Finding: "CVE-2026-65220", Host: "192.0.2.10", Port: 623,
		Probe: &ipmi.SMCReservedRoleProbe{
			Username: "ADMIN", BaselineRole: 0x14, BaselineAccepted: true,
			ReservedRole: 0x24, ReservedAccepted: true, Defect: true,
		},
		ProbeVerdict: "reserved role 0x24 accepted (rakp2=0x00)",
		Escalation: &ipmi.SMCReservedRoleEscalation{
			LowUser: "lowpriv", Role: 0x24,
			BaselineError:         "connection refused",
			EscalatedUserAccessCC: 0x00,
			Escalated:             false,
			Reached:               "none",
		},
		Impact: "low-privilege account to Administrator; a PRIVILEGE ESCALATION that requires a valid credential",
	}
	var buf bytes.Buffer
	if err := printSMC0015Table(&buf, rep); err != nil {
		t.Fatalf("print: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "escalation withheld") {
		t.Errorf("an unmeasured baseline must withhold the escalation claim:\n%s", got)
	}
	if !strings.Contains(got, "ESCALATED: false") {
		t.Errorf("expected ESCALATED: false:\n%s", got)
	}
	if !strings.Contains(got, "PRIVILEGE ESCALATION") {
		t.Errorf("impact line must classify the finding:\n%s", got)
	}
}

func TestCCOrDash(t *testing.T) {
	if got := ccOrDash(false, 0x00); got != "-" {
		t.Errorf("unmeasured cc = %q, want \"-\" (never render it as 0x00)", got)
	}
	if got := ccOrDash(true, 0xd4); got != "0xd4" {
		t.Errorf("measured cc = %q, want 0xd4", got)
	}
}
