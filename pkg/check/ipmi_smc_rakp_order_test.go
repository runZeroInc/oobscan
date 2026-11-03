package check

import (
	"context"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/guid"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func findRegisteredCheck(t *testing.T, name string) *Check {
	t.Helper()
	all := All()
	for i := range all {
		if all[i].Name == name {
			return &all[i]
		}
	}
	t.Fatalf("%s not registered", name)
	return nil
}

func TestSMCRAKPOrderChecksRegistered(t *testing.T) {
	for _, name := range []string{"ipmi.smc.rakpUnordered", "ipmi.smc.rakpReservedRole", "ipmi.smc.rakpUnorderedForge"} {
		c := findRegisteredCheck(t, name)
		if !c.Enabled {
			t.Errorf("%s should be enabled by default", name)
		}
		if c.Category != "auth" {
			t.Errorf("%s category = %q, want auth", name, c.Category)
		}
		if c.Destructive {
			t.Errorf("%s must not be destructive", name)
		}
		if !c.Applies.matches(&engine.Identity{Vendor: "supermicro"}) {
			t.Errorf("%s should apply to vendor supermicro", name)
		}
		if c.Applies.matches(&engine.Identity{Vendor: "hpe"}) {
			t.Errorf("%s should NOT apply to non-supermicro vendors", name)
		}
	}
	// CVE-2026-65220 is a privilege escalation, but the CHECK offers no credential: it
	// only measures whether the reserved role byte is accepted, so it is not
	// registered as an authenticated check.
	if findRegisteredCheck(t, "ipmi.smc.rakpReservedRole").Authenticated {
		t.Error("the reserved-role detection probe offers no credential and must not be marked authenticated")
	}
}

// TestSMCATENGenerationSkipsX14 guards the generation gate: X14 runs OpenBMC
// netipmid, a different stack that answers the unordered message 3 with the
// spec-correct 0x0f, so it must not be probed at all. An unknown or absent board
// code must still be probed (X12/X13 carry the defect in their decompiles, and
// field boards ship codes not in the table).
func TestSMCATENGenerationSkipsX14(t *testing.T) {
	tests := []struct {
		name       string
		prefix     string
		wantGen    string
		wantProbed bool
	}{
		{"x14 openbmc is skipped", "5601MS", "X14", false},
		{"x11 is probed", "4101MS", "X11", true},
		{"h13 is probed", "F401MS", "H13", true},
		{"x13 is probed", "2401MS", "X13", true},
		{"unknown board code is probed", "ZZZZZZ", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tgt := &engine.Target{Host: "192.0.2.10"}
			tgt.SetEvidence("guid", &guid.Result{Fields: map[string]string{"model_prefix": tc.prefix}})
			gen, aten := smcATENGeneration(tgt)
			if gen != tc.wantGen {
				t.Errorf("generation = %q, want %q", gen, tc.wantGen)
			}
			if aten != tc.wantProbed {
				t.Errorf("probed = %t, want %t", aten, tc.wantProbed)
			}
		})
	}
	// No GUID evidence at all must not stop the probe.
	if _, aten := smcATENGeneration(&engine.Target{Host: "192.0.2.10"}); !aten {
		t.Error("a target with no GUID evidence should still be probed")
	}
}

// TestSMCRAKPOrderChecksHonorDisableLogins locks the opt-out. Both probes put
// packets on the wire that name accounts or carry an authentication code, so
// --disable-logins must suppress them.
func TestSMCRAKPOrderChecksHonorDisableLogins(t *testing.T) {
	// 192.0.2.0/24 is the documentation range: nothing answers, so a check that
	// ignored the flag would time out rather than return immediately.
	tgt := &engine.Target{Host: "192.0.2.10", DisableLogins: true}
	if f := runSMCUnorderedRAKP3(context.TODO(), tgt); f != nil {
		t.Errorf("runSMCUnorderedRAKP3 returned %d findings with --disable-logins", len(f))
	}
	if f := runSMCReservedRole(context.TODO(), tgt); f != nil {
		t.Errorf("runSMCReservedRole returned %d findings with --disable-logins", len(f))
	}
}

// TestSMCUnorderedForgeGating locks the ways runSMCUnorderedForge exits before
// ever touching the network: no --ipmi-full (the opt-in gate for a real
// credential guess against user record 0), --disable-logins, and a passive
// probe from earlier in the same scan that already proved the board spec-
// conformant (no key would change that, so the guess must not be spent).
func TestSMCUnorderedForgeGating(t *testing.T) {
	if f := runSMCUnorderedForge(context.TODO(), &engine.Target{Host: "192.0.2.10"}); f != nil {
		t.Errorf("without --ipmi-full: got %d findings, want none", len(f))
	}
	if f := runSMCUnorderedForge(context.TODO(), &engine.Target{Host: "192.0.2.10", IPMIFull: true, DisableLogins: true}); f != nil {
		t.Errorf("with --disable-logins: got %d findings, want none", len(f))
	}
	tgt := &engine.Target{Host: "192.0.2.10", IPMIFull: true}
	tgt.SetEvidence("ipmi.smc.rakpUnordered", &ipmi.SMCUnorderedRAKP3Probe{Answered: true, SpecConformant: true})
	if f := runSMCUnorderedForge(context.TODO(), tgt); f != nil {
		t.Errorf("after a spec-conformant passive probe: got %d findings, want none (no key would change that verdict)", len(f))
	}
}

// TestSMCUnorderedForgeActivatedFindingShape locks the confirmed-exploitation
// finding shape: unlike the passive detection this reports an actual forged session,
// so the risk must escalate accordingly and the reach must still be described as the
// narrow SOL-only lane, never full IPMI.
func TestSMCUnorderedForgeActivatedFindingShape(t *testing.T) {
	forge := &ipmi.SMCForgeResult{Forged: true, Defect: true, KeyLabel: "<empty>"}
	caps := []ipmi.SMCCapabilityResult{
		{Name: "Get System GUID", CC: 0x00},
		{Name: "Get Device ID", CC: 0xd4},
	}
	f := smcUnorderedForgeActivatedFinding(623, "H13", forge, caps)
	if f.Check != "ipmi.smc.rakpUnorderedForge" {
		t.Fatalf("check = %q", f.Check)
	}
	if f.Risk != "critical" {
		t.Errorf("risk = %q, want critical (a forged session is a confirmed compromise)", f.Risk)
	}
	if len(f.CVE) != 1 || f.CVE[0] != "CVE-2026-65219" {
		t.Errorf("CVE = %v, want [CVE-2026-65219]", f.CVE)
	}
	for key, want := range map[string]string{
		"keyLabel":          "<empty>",
		"sessionObtained":   "true",
		"reachableCommands": "Get System GUID",
		"smcGeneration":     "H13",
	} {
		if got := findingField(f, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if impact := findingField(f, "impact"); !strings.Contains(impact, "sol") || strings.Contains(impact, "admin-ipmi") && !strings.Contains(impact, "not-admin-ipmi") {
		t.Errorf("impact must name SOL and must not claim full administrative access, got %q", impact)
	}
}

// TestSMCUnorderedForgeAttemptFindingShape locks the info-level, non-exploited
// outcome: a refused guess must read as "attempted, unresolved," never as a
// clean bill of health, since a single rejection on a lockout-charging
// generation cannot rule out the defect.
func TestSMCUnorderedForgeAttemptFindingShape(t *testing.T) {
	forge := &ipmi.SMCForgeResult{
		Defect: true, Inconclusive: true, Reason: "the single candidate tried was refused",
		Attempts: []ipmi.SMCForgeAttempt{{KeyLabel: "<empty>", RAKP4Observed: true, RAKP4Status: 0x08}},
	}
	f := smcUnorderedForgeAttemptFinding(623, "H13", forge)
	if f.Check != "ipmi.smc.rakpUnorderedForge" || f.Risk != "info" {
		t.Fatalf("finding = %+v", f)
	}
	if len(f.CVE) != 0 {
		t.Errorf("CVE = %v, want none: an attempt that did not obtain a session is not a confirmed compromise", f.CVE)
	}
	for key, want := range map[string]string{
		"forged":        "false",
		"defect":        "true",
		"inconclusive":  "true",
		"keyLabel":      "<empty>",
		"smcGeneration": "H13",
	} {
		if got := findingField(f, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

// TestSMCUnorderedRAKP3FindingShape checks the finding carries proof and, just as
// important, carries the two preconditions and the bounded impact. Overstating
// this finding as unauthenticated administrative IPMI would be wrong.
func TestSMCUnorderedRAKP3FindingShape(t *testing.T) {
	probe := &ipmi.SMCUnorderedRAKP3Probe{
		Answered: true, RAKP4Status: 0x08, RAKP4StatusText: "inactive-session-id",
		SIDEchoed: true, EchoedSID: 0xabcd1234, Defect: true,
	}
	f := smcUnorderedRAKP3Finding(623, "X11", probe)
	if f.Check != "ipmi.smc.rakpUnordered" {
		t.Fatalf("check = %q", f.Check)
	}
	if len(f.CVE) != 1 || f.CVE[0] != "CVE-2026-65219" {
		t.Errorf("CVE = %v, want [CVE-2026-65219]", f.CVE)
	}
	if f.Risk != "medium" {
		t.Errorf("risk = %q, want medium (the mechanism is proven; the key and the cold slot are not)", f.Risk)
	}
	for key, want := range map[string]string{
		"rakp1Skipped":     "true",
		"rakp4Status":      "0x08",
		"consoleSidEchoed": "true",
		"sessionObtained":  "false",
		"smcGeneration":    "X11",
	} {
		if got := findingField(f, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if p := findingField(f, "proof"); p == "" || !strings.Contains(p, "rakp1Sent=false") {
		t.Errorf("proof missing the defining evidence: %q", p)
	}
	// The preconditions and the bounded impact are carried as compact stable tokens;
	// the operator-facing prose lives in the explainer (asserted separately in
	// TestSMCRAKPOrderExplainersAreRegisteredAndHonest). What must not regress is that
	// the caveat stays attached to the finding at all.
	//
	// The impact must name SOL and must not claim full administrative IPMI.
	impact := findingField(f, "impactIfExploited")
	if !strings.Contains(impact, "sol") {
		t.Errorf("impact field must name SOL: %q", impact)
	}
	if strings.Contains(impact, "full-admin") || strings.Contains(impact, "admin-ipmi") && !strings.Contains(impact, "not-admin-ipmi") {
		t.Errorf("impact must not claim full administrative access: %q", impact)
	}
	// The key must not be described as a hardcoded constant.
	if k := findingField(f, "requiredKey"); !strings.Contains(k, "guessable") {
		t.Errorf("requiredKey must describe a short/guessable value, got %q", k)
	}
	if s := findingField(f, "requiredSlotState"); !strings.Contains(s, "rakp1") {
		t.Errorf("requiredSlotState must state the measured precondition - a slot no RAKP message 1 has landed on - got %q", s)
	}
	// The detection caveat is the fix for a confirmed false negative: a rejected forge
	// counts toward a record-0 lock and past the threshold the CORRECT key answers 0x08.
	if c := findingField(f, "detectionCaveat"); !strings.Contains(c, "lock") {
		t.Errorf("detectionCaveat must warn that repeated candidates lock user record 0, got %q", c)
	}
	assertTokenNotProse(t, f, "requiredKey", "requiredSlotState", "detectionCaveat", "impactIfExploited")
}

// assertTokenNotProse guards the field shape: these carry a stable token, never a
// sentence. Prose here is repeated verbatim on every host and belongs in the
// explainer. A field that grows back into prose, or gains a space, has regressed.
func assertTokenNotProse(t *testing.T, f engine.Finding, keys ...string) {
	t.Helper()
	const maxTokenBytes = 48
	for _, k := range keys {
		v := findingField(f, k)
		if v == "" {
			t.Errorf("%s is empty; the caveat must stay attached to the finding", k)
			continue
		}
		if len(v) > maxTokenBytes {
			t.Errorf("%s is %d bytes (%q); keep it a token under %d and put prose in the explainer",
				k, len(v), v, maxTokenBytes)
		}
		if strings.Contains(v, " ") {
			t.Errorf("%s = %q contains a space; it must be a single stable token", k, v)
		}
	}
}

// TestSMCUnorderedRAKP3FindingRaisesOnActivation covers the (unexpected) case
// where the sentinel key activates a session: that IS confirmed no-password
// access and is rated higher.
func TestSMCUnorderedRAKP3FindingRaisesOnActivation(t *testing.T) {
	probe := &ipmi.SMCUnorderedRAKP3Probe{Answered: true, RAKP4Status: 0x00, SIDEchoed: true, Defect: true, Activated: true}
	f := smcUnorderedRAKP3Finding(623, "", probe)
	if f.Risk != "high" {
		t.Errorf("risk = %q, want high when a session actually activated", f.Risk)
	}
	if got := findingField(f, "sessionObtained"); got != "true" {
		t.Errorf("sessionObtained = %q, want true", got)
	}
	if got := findingField(f, "smcGeneration"); got != "" {
		t.Errorf("an unknown generation must be omitted, got %q", got)
	}
}

// TestSMCReservedRoleFindingShape checks the escalation finding states the
// credential prerequisite. Reporting it as an authentication bypass would be
// wrong: RAKP message 3 is signed with the attacker's own real password.
func TestSMCReservedRoleFindingShape(t *testing.T) {
	probe := &ipmi.SMCReservedRoleProbe{
		Username:     "ADMIN",
		BaselineRole: 0x14, BaselineStatus: 0x00, BaselineAccepted: true,
		ConformantRole: 0x12, ConformantStatus: 0x00, ConformantAccepted: true,
		ReservedRole: 0x24, ReservedStatus: 0x00, ReservedAccepted: true,
		Defect: true,
	}
	f := smcReservedRoleFinding(623, "H13", probe)
	if f.Check != "ipmi.smc.rakpReservedRole" {
		t.Fatalf("check = %q", f.Check)
	}
	if len(f.CVE) != 1 || f.CVE[0] != "CVE-2026-65220" {
		t.Errorf("CVE = %v, want [CVE-2026-65220]", f.CVE)
	}
	if f.Risk != "medium" {
		t.Errorf("risk = %q, want medium (it presupposes a valid credential)", f.Risk)
	}
	for key, want := range map[string]string{
		"reservedRoleByte":     "0x24",
		"reservedRoleStatus":   "0x00",
		"reservedRoleAccepted": "true",
		"controlRoleByte":      "0x12",
		"controlRoleStatus":    "0x00",
		"adminRoleStatus":      "0x00",
		"credentialOffered":    "false",
		"surface":              "authenticated",
		"namedAccount":         "ADMIN",
		"smcGeneration":        "H13",
	} {
		if got := findingField(f, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if p := findingField(f, "proof"); !strings.Contains(p, "controlRoleStatus=0x00") {
		t.Errorf("proof must carry the VALID-role control, not just the reserved-role result: %q", p)
	}
	if p := findingField(f, "proof"); !strings.Contains(p, "reservedRoleStatus=0x00") {
		t.Errorf("proof missing the reserved-role acceptance: %q", p)
	}
	// The proof must vary per host: one that never differs is no evidence at all.
	if p := findingField(f, "proof"); !strings.Contains(p, "namedAccount=ADMIN") {
		t.Errorf("proof must carry the host-specific account it named: %q", p)
	}
	pre := findingField(f, "prerequisite")
	if !strings.Contains(pre, "credential") {
		t.Errorf("prerequisite must name the required credential: %q", pre)
	}
	impact := findingField(f, "impactIfExploited")
	if !strings.Contains(impact, "privilege-escalation") || !strings.Contains(impact, "not-auth-bypass") {
		t.Errorf("impact must classify this as escalation, not auth bypass: %q", impact)
	}
	assertTokenNotProse(t, f, "prerequisite", "impactIfExploited", "surface")
}

// TestSMCRAKPOrderExplainersAreRegisteredAndHonest checks the operator-facing
// prose keeps the two constraints that have already been mis-stated once.
func TestSMCRAKPOrderExplainersAreRegisteredAndHonest(t *testing.T) {
	unordered, ok := GetExplainer("ipmi.smc.rakpUnordered")
	if !ok {
		t.Fatal("no explainer registered for ipmi.smc.rakpUnordered")
	}
	text := strings.ToLower(unordered("192.0.2.10", engine.Finding{Check: "ipmi.smc.rakpUnordered", Risk: "medium"}))
	for _, want := range []string{"serial-over-lan", "not equivalent to administrative", "unallocated since boot", "not a fleet constant"} {
		if !strings.Contains(text, want) {
			t.Errorf("unordered explainer missing %q", want)
		}
	}

	reserved, ok := GetExplainer("ipmi.smc.rakpReservedRole")
	if !ok {
		t.Fatal("no explainer registered for ipmi.smc.rakpReservedRole")
	}
	text = strings.ToLower(reserved("192.0.2.10", engine.Finding{Check: "ipmi.smc.rakpReservedRole", Risk: "medium"}))
	for _, want := range []string{"privilege escalation", "requires a valid account", "not an authentication bypass"} {
		if !strings.Contains(text, want) {
			t.Errorf("reserved-role explainer missing %q", want)
		}
	}

	forge, ok := GetExplainer("ipmi.smc.rakpUnorderedForge")
	if !ok {
		t.Fatal("no explainer registered for ipmi.smc.rakpUnorderedForge")
	}
	activated := strings.ToLower(forge("192.0.2.10", engine.Finding{
		Check: "ipmi.smc.rakpUnorderedForge", Risk: "critical",
		Fields: engine.F("forged", "true"),
	}))
	for _, want := range []string{"no\nrakp message 1 and no account password", "not\nfull administrative ipmi"} {
		if !strings.Contains(activated, want) {
			t.Errorf("forge explainer (activated) missing %q in %q", want, activated)
		}
	}
	attempted := strings.ToLower(forge("192.0.2.10", engine.Finding{
		Check: "ipmi.smc.rakpUnorderedForge", Risk: "info",
		Fields: engine.F("forged", "false"),
	}))
	if !strings.Contains(attempted, "not proof the board is") {
		t.Errorf("forge explainer (attempt) missing the not-proof caveat: %q", attempted)
	}
}
