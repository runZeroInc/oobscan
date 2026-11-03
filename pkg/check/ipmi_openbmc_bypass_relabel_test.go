package check

import (
	"bytes"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func bypassRelabelTarget(t *testing.T, withBypass, withSetup bool) *engine.Target {
	t.Helper()
	tg := &engine.Target{
		Host:     "192.0.2.10",
		Timeout:  time.Second,
		Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "openbmc"},
	}
	if withBypass {
		tg.SetEvidence("ipmi.openBmcDefaultUserKey", &DefaultUserKeyBypassProbe{
			Suite:        3,
			AuthBypassed: true,
			UsernameUsed: "root",
			WinBMCRand:   bytes.Repeat([]byte{0xab}, 16),
		})
	}
	if withSetup {
		tg.SetEvidence("ipmi.openBmcSetupState", &ipmi.OpenBMCSetupProbe{
			Username:          "admin",
			AdminPrivAccepted: true,
		})
	}
	return tg
}

// Requiring a cracked password for the relabel misses the passwordless path: the
// default-userKey bypass already yields a live CALLBACK session with no credential.
func TestOpenBMCBypassRelabelFlowSelected(t *testing.T) {
	tg := bypassRelabelTarget(t, true, true)
	auth := &ipmi.AuthReport{Suite: &ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1}}

	flow, ok := selectOpenBMCBypassRelabelFlow(tg, auth)
	if !ok {
		t.Fatal("no bypass-relabel flow selected despite a bypass and a relabel target")
	}
	if flow.Mode != "openbmcBypassRelabel" {
		t.Errorf("mode = %q, want openbmcBypassRelabel", flow.Mode)
	}
	if flow.RelabelUser != "admin" {
		t.Errorf("relabelUser = %q, want the confirmed admin account", flow.RelabelUser)
	}
	if len(flow.StaleBMCRand) != 16 {
		t.Errorf("staleBMCRand = %d bytes, want the recovered 16", len(flow.StaleBMCRand))
	}
	// The whole point: no password is involved.
	if flow.Password != "" {
		t.Errorf("password = %q, want empty; this path needs no credential", flow.Password)
	}
}

// Each half of the chain is required on its own.
func TestOpenBMCBypassRelabelNeedsBothHalves(t *testing.T) {
	auth := &ipmi.AuthReport{Suite: &ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1}}
	for _, tc := range []struct {
		name          string
		bypass, setup bool
	}{
		{"no bypass", false, true},
		{"no relabel target", true, false},
		{"neither", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := selectOpenBMCBypassRelabelFlow(bypassRelabelTarget(t, tc.bypass, tc.setup), auth); ok {
				t.Error("flow selected without both halves of the chain")
			}
		})
	}
}

// Cipher-zero has no auth algorithm, so it cannot carry the bypass HMAC.
func TestOpenBMCBypassRelabelRejectsCipherZero(t *testing.T) {
	tg := bypassRelabelTarget(t, true, true)
	auth := &ipmi.AuthReport{Suite: &ipmi.CipherAlgos{Suite: 0, Auth: ipmi.RAKPNone}}
	if _, ok := selectOpenBMCBypassRelabelFlow(tg, auth); ok {
		t.Error("flow selected on a cipher-zero suite, which cannot compute the bypass HMAC")
	}
}

// --disable-logins must suppress it: reopening the session is an active login.
func TestOpenBMCBypassRelabelHonorsDisableLogins(t *testing.T) {
	tg := bypassRelabelTarget(t, true, true)
	tg.DisableLogins = true
	auth := &ipmi.AuthReport{Suite: &ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1}}
	if _, ok := selectOpenBMCBypassRelabelFlow(tg, auth); ok {
		t.Error("flow selected with --disable-logins")
	}
}

// A bypass that did not actually succeed carries no reusable bmcRandomNum.
func TestOpenBMCBypassRelabelRequiresSuccessfulBypass(t *testing.T) {
	tg := bypassRelabelTarget(t, false, true)
	tg.SetEvidence("ipmi.openBmcDefaultUserKey", &DefaultUserKeyBypassProbe{
		Suite: 3, AuthBypassed: false, UsernameUsed: "root",
	})
	auth := &ipmi.AuthReport{Suite: &ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1}}
	if _, ok := selectOpenBMCBypassRelabelFlow(tg, auth); ok {
		t.Error("flow selected from a bypass that never succeeded")
	}
}

// The finding must record that no credential was needed, which is what separates this
// from the password-based relabel.
func TestOpenBMCBypassRelabelFindingMarksNoCredential(t *testing.T) {
	inv := &ipmi.PostAuthCollection{
		Flow: ipmi.AuthFlow{
			Version: "2.0", Mode: "openbmcBypassRelabel",
			Username: "root", RelabelUser: "admin",
			Suite:        ipmi.CipherAlgos{Suite: 3},
			StaleBMCRand: bytes.Repeat([]byte{0xab}, 16),
		},
		// A relabel that reached Administrator necessarily opened a session and
		// issued a command; the finding is gated on that, so the fixture carries it.
		CommandProtection: "integrity+conf",
	}
	got := openBMCRAKPStateFindings(&engine.Target{Host: "192.0.2.10"}, nil, inv, func(string, ...any) {})
	var f *engine.Finding
	for i := range got {
		if got[i].Check == "ipmi.rakp.state.activeRelabelLowToAdmin" {
			f = &got[i]
			break
		}
	}
	if f == nil {
		t.Fatalf("relabel finding not emitted for the bypass chain: %+v", got)
	}
	if f.Risk != "high" {
		t.Errorf("risk = %q, want high", f.Risk)
	}
	if v := findingField(*f, "credentialRequired"); v != "false" {
		t.Errorf("credentialRequired = %q, want false", v)
	}
	if v := findingField(*f, "lowPrivSource"); v != "ipmi.openbmc.defaultUserKeyAuthBypass" {
		t.Errorf("lowPrivSource = %q, want the bypass check id", v)
	}
	if findingField(*f, "staleBmcRandom") == "" {
		t.Error("the recovered bmcRandomNum must be recorded so the chain is reproducible")
	}
}
