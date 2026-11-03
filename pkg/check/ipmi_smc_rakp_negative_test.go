package check

import (
	"errors"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// A board measured clean must be distinguishable from one that never answered.
func TestSMCUnorderedNegativeFindingDistinguishesOutcomes(t *testing.T) {
	cases := []struct {
		name    string
		probe   *ipmi.SMCUnorderedRAKP3Probe
		err     error
		outcome string
	}{
		{
			name:    "spec-conformant rejection (OpenBMC answers 0x0f)",
			probe:   &ipmi.SMCUnorderedRAKP3Probe{Answered: true, RAKP4Status: 0x0f, SpecConformant: true},
			outcome: "conformant-rejection",
		},
		{
			name:    "never answered",
			probe:   &ipmi.SMCUnorderedRAKP3Probe{Answered: false},
			outcome: "not-measured-no-answer",
		},
		{
			name:    "probe errored",
			probe:   &ipmi.SMCUnorderedRAKP3Probe{Answered: true, RAKP4Status: 0x0f, SpecConformant: true},
			err:     errors.New("i/o timeout"),
			outcome: "not-measured-probe-error",
		},
		{
			name:    "answered with an unexpected status",
			probe:   &ipmi.SMCUnorderedRAKP3Probe{Answered: true, RAKP4Status: 0x12},
			outcome: "inconclusive-unexpected-status",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := smcUnorderedRAKP3NegativeFinding(623, "X11", tc.probe, tc.err)
			if f.Check != "ipmi.smc.rakpUnordered.negative" {
				t.Errorf("check = %q", f.Check)
			}
			if f.Risk != "info" {
				t.Errorf("risk = %q, want info; coverage is not exposure", f.Risk)
			}
			if got := findingField(f, "defect"); got != "false" {
				t.Errorf("defect = %q, want false", got)
			}
			if got := findingField(f, "outcome"); got != tc.outcome {
				t.Errorf("outcome = %q, want %q", got, tc.outcome)
			}
		})
	}
}

// The negative must record whether the valid-role control resolved: without it, a
// reserved-role rejection could just mean the named account does not exist.
func TestSMCReservedRoleNegativeRecordsControl(t *testing.T) {
	probe := &ipmi.SMCReservedRoleProbe{
		Username:                     "ADMIN",
		ReservedRole:                 0x24,
		ReservedStatus:               0x09,
		ConformantStatus:             0x00,
		ConformantAccepted:           true,
		ReservedRejectedConformantly: true,
	}
	f := smcReservedRoleNegativeFinding(623, "X11", probe, nil)
	if f.Check != "ipmi.smc.rakpReservedRole.negative" {
		t.Errorf("check = %q", f.Check)
	}
	if got := findingField(f, "outcome"); got != "conformant-rejection" {
		t.Errorf("outcome = %q, want conformant-rejection", got)
	}
	if got := findingField(f, "controlAccepted"); got != "true" {
		t.Errorf("controlAccepted = %q; the control is what makes the negative meaningful", got)
	}
	if got := findingField(f, "reservedRoleStatus"); got != "0x09" {
		t.Errorf("reservedRoleStatus = %q, want the measured 0x09", got)
	}
	if got := findingField(f, "namedAccount"); got != "ADMIN" {
		t.Errorf("namedAccount = %q, want the account that was named", got)
	}
}

// Without an accepted control the negative cannot claim a conformant rejection.
func TestSMCReservedRoleNegativeWithoutControlIsNotClean(t *testing.T) {
	probe := &ipmi.SMCReservedRoleProbe{
		Username:           "nosuchuser",
		ReservedRole:       0x24,
		ReservedStatus:     0x00,
		ConformantStatus:   0x0d,
		ConformantAccepted: false,
	}
	f := smcReservedRoleNegativeFinding(623, "", probe, nil)
	if got := findingField(f, "controlAccepted"); got != "false" {
		t.Errorf("controlAccepted = %q, want false", got)
	}
	if got := findingField(f, "outcome"); got == "conformant-rejection" {
		t.Error("claimed a conformant rejection while the valid-role control never resolved")
	}
}
