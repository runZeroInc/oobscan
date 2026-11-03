package check

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// The relabel selector draws both of its operands from one list: the low-privilege
// candidate is an entry of auth.Cracked, and the admin nominee is setup.Username,
// which maybeProbeOpenBMCSetupState takes from firstValidRAKPUsername of that same
// report. These tests pin that coupling, so a later reader cannot mistake the
// same-user skip for a rare tie-break and drop it to make the check fire.

// suiteForRelabelCoupling mirrors the negotiated suite the setup-state probe runs on.
func suiteForRelabelCoupling() *ipmi.CipherAlgos {
	return &ipmi.CipherAlgos{
		Suite:     17,
		Auth:      ipmi.RAKPHMACSHA256,
		Integrity: ipmi.IntegrityHMACSHA256128,
		Conf:      ipmi.ConfAESCBC,
	}
}

// targetFromReport wires a target the way a real scan does: the setup probe is
// created for firstValidRAKPUsername, not for an independently discovered account.
func targetFromReport(t *testing.T, rep *ipmi.AuthReport) *engine.Target {
	t.Helper()
	nominee := firstValidRAKPUsername(rep)
	if nominee == "" {
		t.Fatal("fixture has no verified credential for the setup probe to adopt")
	}
	tgt := &engine.Target{Host: "192.0.2.10", Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "openbmc"}}
	tgt.SetEvidence("ipmi.openBmcSetupState", &ipmi.OpenBMCSetupProbe{
		Username:          nominee,
		AdminPrivAccepted: true,
		SetupCommandsWork: true,
	})
	tgt.SetEvidence("ipmi.auth", rep)
	return tgt
}

// TestRelabelAdminNomineeIsFirstCrackedUser records the coupling itself: the name the
// setup probe adopts is exactly the first verified cracked account.
func TestRelabelAdminNomineeIsFirstCrackedUser(t *testing.T) {
	rep := &ipmi.AuthReport{
		Suite: suiteForRelabelCoupling(),
		Cracked: []ipmi.CrackResult{
			{Username: "root", Password: "0penBmc", Verified: true, PasswordType: "default"},
			{Username: "rzlow", Password: "runZero26", Verified: true, PasswordType: "default"},
		},
	}
	if got := firstValidRAKPUsername(rep); got != "root" {
		t.Fatalf("admin nominee = %q, want the first verified cracked account %q", got, "root")
	}
}

// TestSelectRelabelCheckFlow_SoleCrackedCredIsTheAdminNominee is the reason the check
// is rare. With one cracked account, that account is also the relabel target, so there
// is no low-privilege candidate to escalate from and no flow may be selected.
func TestSelectRelabelCheckFlow_SoleCrackedCredIsTheAdminNominee(t *testing.T) {
	rep := &ipmi.AuthReport{
		Suite:   suiteForRelabelCoupling(),
		Cracked: []ipmi.CrackResult{{Username: "root", Password: "0penBmc", Verified: true, PasswordType: "default"}},
	}
	tgt := targetFromReport(t, rep)

	_, flow, ok := selectRelabelCheckFlow(tgt)
	if ok {
		t.Fatalf("flow selected from a single cracked account: low-priv user %q is the relabel target %q itself, "+
			"so the probe would relabel an account to itself and claim escalation without a privilege change",
			flow.Username, flow.RelabelUser)
	}
}

// TestSelectRelabelCheckFlow_SecondDistinctAccountIsReachable constructs the state the
// check actually needs, proving the gate is narrow rather than closed.
func TestSelectRelabelCheckFlow_SecondDistinctAccountIsReachable(t *testing.T) {
	rep := &ipmi.AuthReport{
		Suite: suiteForRelabelCoupling(),
		Cracked: []ipmi.CrackResult{
			{Username: "root", Password: "0penBmc", Verified: true, PasswordType: "default"},
			{Username: "rzlow", Password: "runZero26", Verified: true, PasswordType: "default"},
		},
	}
	tgt := targetFromReport(t, rep)

	_, flow, ok := selectRelabelCheckFlow(tgt)
	if !ok {
		t.Fatal("no flow selected although a second distinct account was cracked; the check would be unreachable in every state")
	}
	if flow.Username != "rzlow" {
		t.Errorf("low-priv user = %q, want the account that is not the admin nominee (%q)", flow.Username, "rzlow")
	}
	if flow.RelabelUser != "root" {
		t.Errorf("relabel target = %q, want the admin nominee %q", flow.RelabelUser, "root")
	}
	if flow.Username == flow.RelabelUser {
		t.Error("low-priv user and relabel target are the same account: no privilege boundary is crossed")
	}
}
