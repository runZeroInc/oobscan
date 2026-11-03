package check

import (
	"context"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/guid"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func TestRunIPMISurfaceGUIDFinding(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10"}
	tgt.SetEvidence("guid", &guid.Result{
		Hex:    "44454c4c53001048804bcac04f4b5858",
		Family: "dell-service-tag",
		Vendor: "dell",
	})

	got := runIPMISurface(context.Background(), tgt)
	if len(got) != 1 {
		t.Fatalf("runIPMISurface() returned %d findings, want 1", len(got))
	}
	if got[0].Check != "ipmi.guid" {
		t.Fatalf("check=%q, want ipmi.guid", got[0].Check)
	}
	if got[0].Risk != "info" {
		t.Fatalf("risk=%q, want info", got[0].Risk)
	}
	if got[0].Port != 623 || got[0].Transport != "udp" || got[0].Protocol != "ipmi" {
		t.Fatalf("stamp mismatch: got port=%d transport=%q protocol=%q", got[0].Port, got[0].Transport, got[0].Protocol)
	}
	if family := explainField(got[0], "family"); family != "dell-service-tag" {
		t.Fatalf("family=%q, want dell-service-tag", family)
	}
	if vendor := explainField(got[0], "vendor"); vendor != "dell" {
		t.Fatalf("vendor=%q, want dell", vendor)
	}
	if rawGUID := explainField(got[0], "guid"); rawGUID != "44454c4c53001048804bcac04f4b5858" {
		t.Fatalf("guid=%q, want raw hex", rawGUID)
	}
}

func TestAuthCapsFindingsReportMD2MD5Plaintext(t *testing.T) {
	got := authCapsFindings(&ipmi.AuthCaps{Channel: 1, AuthTypeMask: 0x02 | 0x04 | 0x10}, false, nil)
	var authMethods *engine.Finding
	for i := range got {
		if got[i].Check == "ipmi.v15.authMethods" {
			authMethods = &got[i]
			break
		}
	}
	if authMethods == nil {
		t.Fatalf("missing ipmi.v15.authMethods finding: %+v", got)
	}
	if authMethods.Risk != "low" {
		t.Fatalf("risk=%q, want low", authMethods.Risk)
	}
	fields := authMethods.Fields.String()
	if !strings.Contains(fields, "methods=md2,md5,plaintext") {
		t.Fatalf("fields=%q, want methods=md2,md5,plaintext", fields)
	}
}

// findingByCheck returns the finding with the given check id, or nil.
func findingByCheck(fs []engine.Finding, name string) *engine.Finding {
	for i := range fs {
		if fs[i].Check == name {
			return &fs[i]
		}
	}
	return nil
}

func TestAuthCapsFindingsUnprobedNullUserStaysLowWithNoMeasurement(t *testing.T) {
	got := authCapsFindings(&ipmi.AuthCaps{Channel: 1, NullUser: true, AnonLogin: true}, true, nil)
	for _, name := range []string{"ipmi.authNull", "ipmi.authAnon"} {
		f := findingByCheck(got, name)
		if f == nil {
			t.Fatalf("missing %s finding: %+v", name, got)
		}
		if f.Risk != "low" {
			t.Errorf("%s risk=%q, want low when nothing was measured", name, f.Risk)
		}
		// The absence of a measurement must stay visible: no privilege field may be
		// invented, least of all a zero that would read as "measured at privilege 0".
		fields := f.Fields.String()
		for _, key := range []string{"measuredPrivilege", "privilegeProbe"} {
			if strings.Contains(fields, key) {
				t.Errorf("%s carries %s without a probe: %q", name, key, fields)
			}
		}
	}
}

func TestAuthCapsFindingsMeasuredPrivilegeZeroStaysLow(t *testing.T) {
	// A null user that is enabled and activates a session, but holds privilege 0
	// and cannot even Get Device ID.
	probe := &ipmi.NullUserPrivProbe{
		Activated:          true,
		Suite:              3,
		OpenSessionMaxPriv: ipmi.PrivAdministrator,
		Privilege:          ipmi.PrivUnspecified,
		PrivilegeOK:        true,
		Protection:         "cleartext",
		DeviceIDSeen:       true,
		DeviceIDCC:         0xd4,
	}
	got := authCapsFindings(&ipmi.AuthCaps{Channel: 1, NullUser: true}, true, probe)
	f := findingByCheck(got, "ipmi.authNull")
	if f == nil {
		t.Fatalf("missing ipmi.authNull finding: %+v", got)
	}
	if f.Risk != "low" {
		t.Fatalf("risk=%q, want low for a privilege-0 null account", f.Risk)
	}
	fields := f.Fields.String()
	for _, want := range []string{
		"measuredPrivilege=unspecified",
		"measuredPrivilegeRaw=0x00",
		"privilegeProbe=measured",
		"privilegeProbeSuite=3",
		// Recording the Open Session ceiling next to the measured level is what
		// stops it being mistaken for the account's own privilege.
		"openSessionMaxPrivilege=administrator",
		"sessionProtection=cleartext",
		"getDeviceIdCc=0xd4",
		"getDeviceIdReadable=false",
	} {
		if !strings.Contains(fields, want) {
			t.Errorf("fields %q missing %q", fields, want)
		}
	}
}

func TestAuthCapsFindingsRiskRisesOnlyAtUserPrivilegeOrAbove(t *testing.T) {
	for _, tc := range []struct {
		priv byte
		want string
	}{
		{ipmi.PrivUnspecified, "low"},
		{ipmi.PrivCallback, "low"},
		{ipmi.PrivUser, "medium"},
		{ipmi.PrivOperator, "high"},
		{ipmi.PrivAdministrator, "high"},
		// Numerically above USER but means no access at all.
		{ipmi.PrivNoAccess, "low"},
	} {
		probe := &ipmi.NullUserPrivProbe{Activated: true, Suite: 3, Privilege: tc.priv, PrivilegeOK: true}
		got := authCapsFindings(&ipmi.AuthCaps{Channel: 1, NullUser: true}, true, probe)
		f := findingByCheck(got, "ipmi.authNull")
		if f == nil {
			t.Fatalf("priv 0x%02x: missing ipmi.authNull finding", tc.priv)
		}
		if f.Risk != tc.want {
			t.Errorf("priv %s (0x%02x): risk=%q, want %q", ipmi.PrivilegeName(tc.priv), tc.priv, f.Risk, tc.want)
		}
	}
}

func TestAuthCapsFindingsSessionFailureRecordsWhyAndStaysLow(t *testing.T) {
	probe := &ipmi.NullUserPrivProbe{Error: "rakp4 status=0x08 (invalid role / username / password (or Kg key required))"}
	got := authCapsFindings(&ipmi.AuthCaps{Channel: 1, NullUser: true}, true, probe)
	f := findingByCheck(got, "ipmi.authNull")
	if f == nil {
		t.Fatalf("missing ipmi.authNull finding: %+v", got)
	}
	if f.Risk != "low" {
		t.Errorf("risk=%q, want low when the session never activated", f.Risk)
	}
	fields := f.Fields.String()
	if !strings.Contains(fields, "privilegeProbe=sessionFailed") {
		t.Errorf("fields %q missing privilegeProbe=sessionFailed", fields)
	}
	if !strings.Contains(fields, "rakp4 status=0x08") {
		t.Errorf("fields %q missing the session error", fields)
	}
	if strings.Contains(fields, "measuredPrivilege") {
		t.Errorf("fields %q reports a privilege for a session that never activated", fields)
	}
}

func TestNullUserSOLFindingsGating(t *testing.T) {
	readable := func() *ipmi.SOLConfig {
		return &ipmi.SOLConfig{
			Enabled: true, EnabledOK: true,
			RequiredPrivilege: ipmi.PrivOperator, RequiredPrivilegeOK: true,
			PayloadChannel: 1, PayloadChannelOK: true,
			PayloadPort: 623, PayloadPortOK: true,
			Params: map[byte]string{ipmi.SOLParamEnable: "1101"},
		}
	}
	for _, tc := range []struct {
		name  string
		probe *ipmi.NullUserPrivProbe
		want  bool
	}{
		{"nil probe", nil, false},
		{"session never activated", &ipmi.NullUserPrivProbe{SOL: readable()}, false},
		{"sol not readable", &ipmi.NullUserPrivProbe{Activated: true, PrivilegeOK: true}, false},
		{
			// No measured privilege means no evidence the read happened below the
			// gate, which is the whole claim.
			"privilege unmeasured",
			&ipmi.NullUserPrivProbe{Activated: true, SOL: readable()},
			false,
		},
		{
			"readable at privilege 0 (the gate failure)",
			&ipmi.NullUserPrivProbe{Activated: true, PrivilegeOK: true, Privilege: ipmi.PrivUnspecified, SOL: readable()},
			true,
		},
		{
			// At USER or above the read is within the account's entitlement and the
			// account finding already carries the raised risk.
			"readable at user privilege",
			&ipmi.NullUserPrivProbe{Activated: true, PrivilegeOK: true, Privilege: ipmi.PrivUser, SOL: readable()},
			false,
		},
	} {
		got := nullUserSOLFindings(tc.probe)
		if tc.want && len(got) != 1 {
			t.Errorf("%s: got %d findings, want 1", tc.name, len(got))
			continue
		}
		if !tc.want {
			if len(got) != 0 {
				t.Errorf("%s: got %d findings, want 0", tc.name, len(got))
			}
			continue
		}
		f := got[0]
		if f.Check != "ipmi.nullUser.solConfigReadable" {
			t.Errorf("%s: check=%q", tc.name, f.Check)
		}
		if f.Risk != "low" {
			t.Errorf("%s: risk=%q, want low (disclosure only)", tc.name, f.Risk)
		}
		fields := f.Fields.String()
		for _, want := range []string{
			"measuredPrivilege=unspecified",
			"solEnabled=true",
			"solRequiredPrivilege=operator",
			"solPayloadChannel=1",
			"solPayloadPort=623",
			"proof=",
		} {
			if !strings.Contains(fields, want) {
				t.Errorf("%s: fields %q missing %q", tc.name, fields, want)
			}
		}
	}
}

func TestNullUserPrivProbeGates(t *testing.T) {
	// Each of these must return without dialing; the addresses are unroutable
	// documentation space, so a regression that probes anyway shows up as a hang
	// rather than a silent pass.
	for _, tc := range []struct {
		name string
		tgt  *engine.Target
		caps *ipmi.AuthCaps
	}{
		{"opt-in flag off", &engine.Target{Host: "192.0.2.10"}, &ipmi.AuthCaps{NullUser: true}},
		{
			"logins disabled",
			&engine.Target{Host: "192.0.2.10", IPMINullPriv: true, DisableLogins: true},
			&ipmi.AuthCaps{NullUser: true},
		},
		{
			"no null or anonymous account advertised",
			&engine.Target{Host: "192.0.2.10", IPMINullPriv: true},
			&ipmi.AuthCaps{NonNullUser: true},
		},
		{"nil auth caps", &engine.Target{Host: "192.0.2.10", IPMINullPriv: true}, nil},
	} {
		if got := nullUserPrivProbe(tc.tgt, tc.caps); got != nil {
			t.Errorf("%s: probe ran, want nil", tc.name)
		}
		if _, ok := tc.tgt.Evidenced("ipmi.nullUserPriv"); ok {
			t.Errorf("%s: probe stashed evidence, want none", tc.name)
		}
	}
}

func TestExplainIPMIAuthNullRendersMeasurementOrPointsAtTheFlag(t *testing.T) {
	// Unmeasured: the explainer must say the bit is not an impact statement and
	// name the flag that measures it.
	unprobed := authCapsFindings(&ipmi.AuthCaps{Channel: 1, NullUser: true}, true, nil)
	f := findingByCheck(unprobed, "ipmi.authNull")
	if f == nil {
		t.Fatal("missing ipmi.authNull finding")
	}
	out := explainIPMIAuthNull("192.0.2.10", *f)
	if !strings.Contains(out, "--ipmi-null-priv") {
		t.Errorf("unmeasured explainer does not point at --ipmi-null-priv:\n%s", out)
	}
	if !strings.Contains(out, "does not establish impact") {
		t.Errorf("unmeasured explainer does not caveat the bit:\n%s", out)
	}

	// Measured at privilege 0: must explain why the risk stays low and warn off
	// the Open Session ceiling.
	clamped := authCapsFindings(&ipmi.AuthCaps{Channel: 1, NullUser: true}, true, &ipmi.NullUserPrivProbe{
		Activated: true, Suite: 3, OpenSessionMaxPriv: ipmi.PrivAdministrator,
		Privilege: ipmi.PrivUnspecified, PrivilegeOK: true, Protection: "cleartext",
		DeviceIDSeen: true, DeviceIDCC: 0xd4,
	})
	out = explainIPMIAuthNull("192.0.2.10", *findingByCheck(clamped, "ipmi.authNull"))
	if !strings.Contains(out, "Below USER privilege") {
		t.Errorf("clamped explainer does not explain the low risk:\n%s", out)
	}
	if !strings.Contains(out, "channel maximum") {
		t.Errorf("clamped explainer does not warn off the Open Session ceiling:\n%s", out)
	}

	// Measured at USER: must state this is real unauthenticated access.
	usable := authCapsFindings(&ipmi.AuthCaps{Channel: 1, NullUser: true}, true, &ipmi.NullUserPrivProbe{
		Activated: true, Suite: 3, Privilege: ipmi.PrivUser, PrivilegeOK: true,
		Protection: "integrity+conf", DeviceIDSeen: true, DeviceIDOK: true,
	})
	out = explainIPMIAuthNull("192.0.2.10", *findingByCheck(usable, "ipmi.authNull"))
	if !strings.Contains(out, "USER privilege or above") {
		t.Errorf("usable-access explainer does not call out measured access:\n%s", out)
	}
}

func TestExplainIPMINullUserSOLConfigRegistered(t *testing.T) {
	fn, ok := GetExplainer("ipmi.nullUser.solConfigReadable")
	if !ok {
		t.Fatal("no explainer registered for ipmi.nullUser.solConfigReadable")
	}
	got := nullUserSOLFindings(&ipmi.NullUserPrivProbe{
		Activated: true, PrivilegeOK: true, Privilege: ipmi.PrivUnspecified,
		SOL: &ipmi.SOLConfig{
			Enabled: true, EnabledOK: true,
			RequiredPrivilege: ipmi.PrivOperator, RequiredPrivilegeOK: true,
			PayloadPort: 623, PayloadPortOK: true,
			Params: map[byte]string{ipmi.SOLParamEnable: "1101"},
		},
	})
	out := fn("192.0.2.10", got[0])
	for _, want := range []string{"0x0c", "0x22", "unspecified", "623", "privilege-gate failure"} {
		if !strings.Contains(out, want) {
			t.Errorf("explainer output missing %q:\n%s", want, out)
		}
	}
}
