package check

import (
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func TestOpenBMCRelabelCheckRegistered(t *testing.T) {
	byName := map[string]Check{}
	for _, c := range All() {
		byName[c.Name] = c
	}
	c, ok := byName["ipmi.openbmc.rakp1ActiveRelabel"]
	if !ok {
		t.Fatal("ipmi.openbmc.rakp1ActiveRelabel not registered")
	}
	if c.Category != "auth" {
		t.Fatalf("category = %q, want auth", c.Category)
	}
	// It must not be marked Authenticated. That flag means the operator has to supply a
	// credential (Selector.allow skips such checks unless --creds was passed), but this
	// check sources its session from scan evidence via selectRelabelCheckFlow, so the
	// flag would make it dead in every default scan.
	if c.Authenticated {
		t.Error("check must not be Authenticated: it discovers its own session and the flag makes it dead in default scans")
	}
	if !c.Enabled {
		t.Fatal("check should be enabled in default set")
	}
	// The gate that used to kill it: with no operator credentials, the check must still
	// be selected.
	if !(Selector{}).allow(c) {
		t.Error("check is not selected in a default scan with no supplied credentials")
	}
}

func TestOpenBMCRelabelCheckExplainRegistered(t *testing.T) {
	fn, ok := GetExplainer("ipmi.openbmc.rakp1ActiveRelabel")
	if !ok || fn == nil {
		t.Fatal("explainer not registered for ipmi.openbmc.rakp1ActiveRelabel")
	}
}

func TestSelectRelabelCheckFlow_HappyPath(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10", Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "openbmc"}}
	tgt.SetEvidence("ipmi.openBmcSetupState", &ipmi.OpenBMCSetupProbe{
		Username:          "root",
		AdminPrivAccepted: true,
		SetupCommandsWork: true,
	})
	tgt.SetEvidence("ipmi.auth", &ipmi.AuthReport{
		Suite:   &ipmi.CipherAlgos{Suite: 17, Auth: ipmi.RAKPHMACSHA256, Integrity: ipmi.IntegrityHMACSHA256128, Conf: ipmi.ConfAESCBC},
		Cracked: []ipmi.CrackResult{{Username: "rzlow", Password: "runZero26", Verified: true, PasswordType: "default"}},
	})

	auth, flow, ok := selectRelabelCheckFlow(tgt)
	if !ok {
		t.Fatal("expected relabel check flow to be selected")
	}
	if auth == nil {
		t.Fatal("expected non-nil auth report")
	}
	if flow.Mode != "openbmcRelabel" {
		t.Fatalf("mode = %q, want openbmcRelabel", flow.Mode)
	}
	if flow.Username != "rzlow" || flow.Password != "runZero26" || flow.RelabelUser != "root" {
		t.Fatalf("unexpected flow: %+v", flow)
	}
	if flow.Source != "ipmi.openbmc.rakp1ActiveRelabel" {
		t.Fatalf("source = %q, want ipmi.openbmc.rakp1ActiveRelabel", flow.Source)
	}
}

func TestSelectRelabelCheckFlow_NoSetupEvidence(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10", Identity: &engine.Identity{Class: engine.ClassBMC}}
	tgt.SetEvidence("ipmi.auth", &ipmi.AuthReport{
		Suite:   &ipmi.CipherAlgos{Suite: 17, Auth: ipmi.RAKPHMACSHA256, Integrity: ipmi.IntegrityHMACSHA256128, Conf: ipmi.ConfAESCBC},
		Cracked: []ipmi.CrackResult{{Username: "rzlow", Password: "runZero26", Verified: true, PasswordType: "default"}},
	})
	_, _, ok := selectRelabelCheckFlow(tgt)
	if ok {
		t.Fatal("should not select flow without setup state evidence")
	}
}

func TestSelectRelabelCheckFlow_NoAuthSuite(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10"}
	tgt.SetEvidence("ipmi.openBmcSetupState", &ipmi.OpenBMCSetupProbe{
		Username:          "root",
		AdminPrivAccepted: true,
	})
	tgt.SetEvidence("ipmi.auth", &ipmi.AuthReport{})
	_, _, ok := selectRelabelCheckFlow(tgt)
	if ok {
		t.Fatal("should not select flow without cipher suite")
	}
}

func TestSelectRelabelCheckFlow_NoCrackedCreds(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10"}
	tgt.SetEvidence("ipmi.openBmcSetupState", &ipmi.OpenBMCSetupProbe{
		Username:          "root",
		AdminPrivAccepted: true,
	})
	tgt.SetEvidence("ipmi.auth", &ipmi.AuthReport{
		Suite: &ipmi.CipherAlgos{Suite: 17, Auth: ipmi.RAKPHMACSHA256, Integrity: ipmi.IntegrityHMACSHA256128, Conf: ipmi.ConfAESCBC},
	})
	_, _, ok := selectRelabelCheckFlow(tgt)
	if ok {
		t.Fatal("should not select flow without cracked credentials")
	}
}

func TestSelectRelabelCheckFlow_SkipsSameUser(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10"}
	tgt.SetEvidence("ipmi.openBmcSetupState", &ipmi.OpenBMCSetupProbe{
		Username:          "root",
		AdminPrivAccepted: true,
	})
	tgt.SetEvidence("ipmi.auth", &ipmi.AuthReport{
		Suite:   &ipmi.CipherAlgos{Suite: 17, Auth: ipmi.RAKPHMACSHA256, Integrity: ipmi.IntegrityHMACSHA256128, Conf: ipmi.ConfAESCBC},
		Cracked: []ipmi.CrackResult{{Username: "root", Password: "0penBmc", Verified: true, PasswordType: "default"}},
	})
	_, _, ok := selectRelabelCheckFlow(tgt)
	if ok {
		t.Fatal("should not select flow when cracked user == relabel user")
	}
}

func TestSelectRelabelCheckFlow_SkipsUnverifiedCred(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10"}
	tgt.SetEvidence("ipmi.openBmcSetupState", &ipmi.OpenBMCSetupProbe{
		Username:          "root",
		AdminPrivAccepted: true,
	})
	tgt.SetEvidence("ipmi.auth", &ipmi.AuthReport{
		Suite:   &ipmi.CipherAlgos{Suite: 17, Auth: ipmi.RAKPHMACSHA256, Integrity: ipmi.IntegrityHMACSHA256128, Conf: ipmi.ConfAESCBC},
		Cracked: []ipmi.CrackResult{{Username: "rzlow", Password: "runZero26", Verified: false, PasswordType: "default"}},
	})
	_, _, ok := selectRelabelCheckFlow(tgt)
	if ok {
		t.Fatal("should not select flow with unverified credential")
	}
}

func TestSelectRelabelCheckFlow_SkipsSMCRAKPFixedKey(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10"}
	tgt.SetEvidence("ipmi.openBmcSetupState", &ipmi.OpenBMCSetupProbe{
		Username:          "root",
		AdminPrivAccepted: true,
	})
	tgt.SetEvidence("ipmi.auth", &ipmi.AuthReport{
		Suite:   &ipmi.CipherAlgos{Suite: 17, Auth: ipmi.RAKPHMACSHA256, Integrity: ipmi.IntegrityHMACSHA256128, Conf: ipmi.ConfAESCBC},
		Cracked: []ipmi.CrackResult{{Username: "rzlow", Password: "key", Verified: true, PasswordType: "smcrakp-fixed-key"}},
	})
	_, _, ok := selectRelabelCheckFlow(tgt)
	if ok {
		t.Fatal("should not select flow with smcrakp-fixed-key credential")
	}
}

func TestSelectRelabelCheckFlow_DisableLogins(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10", DisableLogins: true}
	tgt.SetEvidence("ipmi.openBmcSetupState", &ipmi.OpenBMCSetupProbe{
		Username:          "root",
		AdminPrivAccepted: true,
	})
	tgt.SetEvidence("ipmi.auth", &ipmi.AuthReport{
		Suite:   &ipmi.CipherAlgos{Suite: 17, Auth: ipmi.RAKPHMACSHA256, Integrity: ipmi.IntegrityHMACSHA256128, Conf: ipmi.ConfAESCBC},
		Cracked: []ipmi.CrackResult{{Username: "rzlow", Password: "runZero26", Verified: true, PasswordType: "default"}},
	})
	_, _, ok := selectRelabelCheckFlow(tgt)
	if ok {
		t.Fatal("should not select flow when logins are disabled")
	}
}

func TestSelectRelabelCheckFlow_SetupNotAccepted(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10"}
	tgt.SetEvidence("ipmi.openBmcSetupState", &ipmi.OpenBMCSetupProbe{
		Username:          "root",
		AdminPrivAccepted: false,
		SetupCommandsWork: true,
	})
	tgt.SetEvidence("ipmi.auth", &ipmi.AuthReport{
		Suite:   &ipmi.CipherAlgos{Suite: 17, Auth: ipmi.RAKPHMACSHA256, Integrity: ipmi.IntegrityHMACSHA256128, Conf: ipmi.ConfAESCBC},
		Cracked: []ipmi.CrackResult{{Username: "rzlow", Password: "runZero26", Verified: true, PasswordType: "default"}},
	})
	_, _, ok := selectRelabelCheckFlow(tgt)
	if ok {
		t.Fatal("should not select flow when AdminPrivAccepted is false")
	}
}

func TestRelabelProbeToFinding_Fields(t *testing.T) {
	probe := &RelabelProbeResult{
		LowPrivUser:          "rzlow",
		AdminUser:            "root",
		Suite:                17,
		BeforeSetPrivCC:      0x81,
		BeforeSetPrivSuccess: false,
		RAKP1Status:          0x00,
		AfterSetPrivCC:       0x00,
		AfterSetPrivSuccess:  true,
		AfterSetPrivGranted:  0x04,
		ProviderCmdCC:        0x00,
		ProviderCmdDataLen:   15,
		UserAccessCC:         0x00,
		UserAccessData:       []byte{0x0f, 0x02, 0x04, 0x04},
	}
	f := relabelProbeToFinding(probe)
	if f.Check != "ipmi.openbmc.rakp1ActiveRelabel" {
		t.Fatalf("check = %q", f.Check)
	}
	if f.Category != "auth" {
		t.Fatalf("category = %q", f.Category)
	}
	if f.Risk != "critical" {
		t.Fatalf("risk = %q", f.Risk)
	}
	fields := fieldsByKey(f.Fields)
	expect := map[string]string{
		"username":            "rzlow",
		"relabelUser":         "root",
		"suite":               "17",
		"beforeSetPrivCc":     "0x81",
		"rakp1Status":         "0x00",
		"afterSetPrivCc":      "0x00",
		"afterSetPrivGranted": "0x04",
		"providerCmdCc":       "0x00",
		"providerCmdDataLen":  "15",
		"userAccessCc":        "0x00",
		"userAccessData":      "0f020404",
	}
	for k, want := range expect {
		if fields[k] != want {
			t.Errorf("field %s = %q, want %q", k, fields[k], want)
		}
	}
	for _, key := range []string{"requiresPassword", "requiresAdminPassword", "defaultEnabled", "scope", "beforeSetPrivSuccess", "afterSetPrivSuccess", "rakp1TargetUser"} {
		if _, ok := fields[key]; ok {
			t.Errorf("static field %s retained in %+v", key, f.Fields)
		}
	}
	// Must not expose passwords.
	for _, fld := range f.Fields {
		if fld.Key == "password" || fld.Key == "pass" {
			t.Errorf("password field exposed: %s=%s", fld.Key, fld.Val)
		}
	}
	if strings.Contains(f.Fields.String(), "runZero26") {
		t.Error("password leaked in field values")
	}
}

func TestRunOpenBMCRelabelCheck_NilTarget(t *testing.T) {
	got := runOpenBMCRelabelCheck(t.Context(), nil)
	if len(got) != 0 {
		t.Fatalf("expected no findings for nil target, got %d", len(got))
	}
}

func TestRunOpenBMCRelabelCheck_DisabledLogins(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10", DisableLogins: true}
	got := runOpenBMCRelabelCheck(t.Context(), tgt)
	if len(got) != 0 {
		t.Fatalf("expected no findings when logins disabled, got %d", len(got))
	}
}

func TestRunOpenBMCRelabelCheck_NoAuth(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10", Identity: &engine.Identity{Class: engine.ClassBMC}}
	got := runOpenBMCRelabelCheck(t.Context(), tgt)
	if len(got) != 0 {
		t.Fatalf("expected no findings without auth evidence, got %d", len(got))
	}
}

func TestExplainOpenBMCRelabelCheck(t *testing.T) {
	f := engine.Finding{
		Check:    "ipmi.openbmc.rakp1ActiveRelabel",
		Category: "auth",
		Risk:     "critical",
		Fields: engine.F(
			"username", "rzlow",
			"relabelUser", "root",
			"beforeSetPrivCc", "0x81",
			"rakp1Status", "0x00",
			"afterSetPrivCc", "0x00",
			"afterSetPrivGranted", "0x04",
			"providerCmdCc", "0x00",
			"providerCmdDataLen", "15",
			"userAccessCc", "0x00",
			"userAccessData", "0f020404",
		),
	}
	md := explainOpenBMCRelabelCheck("192.0.2.10", f)
	if !strings.Contains(md, "Active-Session RAKP1 Relabel") {
		t.Error("explainer missing title")
	}
	if !strings.Contains(md, "192.0.2.10") {
		t.Error("explainer missing host")
	}
	if !strings.Contains(md, "0x81") {
		t.Error("explainer missing before cc")
	}
	if !strings.Contains(md, "0x04") {
		t.Error("explainer missing granted")
	}
}
