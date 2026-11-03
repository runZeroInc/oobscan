package check

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func TestIsLimitedPrivilegePostAuthFailure_SetPrivDenied(t *testing.T) {
	inv := &ipmi.PostAuthCollection{
		CipherMatrix: []ipmi.CipherAttempt{
			{Suite: 8, Success: false, Error: "set-session-privilege: cc=0x80"},
			{Suite: 12, Success: false, Error: "context deadline exceeded"},
		},
		Error: "context deadline exceeded",
	}
	if !isLimitedPrivilegePostAuthFailure(inv, errors.New("context deadline exceeded")) {
		t.Fatalf("expected limited-privilege classifier to be true")
	}
}

func TestIsLimitedPrivilegePostAuthFailure_TimeoutOnly(t *testing.T) {
	inv := &ipmi.PostAuthCollection{
		CipherMatrix: []ipmi.CipherAttempt{
			{Suite: 8, Success: false, Error: "context deadline exceeded"},
		},
		Error: "context deadline exceeded",
	}
	if isLimitedPrivilegePostAuthFailure(inv, errors.New("context deadline exceeded")) {
		t.Fatalf("expected limited-privilege classifier to be false")
	}
}

func TestIsSetPrivDeniedErr(t *testing.T) {
	if !isSetPrivDeniedErr("set-session-privilege: cc=0x81") {
		t.Fatalf("expected cc=0x81 set-session-privilege denial to match")
	}
	if isSetPrivDeniedErr("mc info: cc=0x80 len=0") {
		t.Fatalf("unexpected non set-session-privilege error classification")
	}
}

func TestSetPrivProbeSuccesses(t *testing.T) {
	attempts := []ipmi.SetPrivAttempt{
		{Requested: 0x04, Name: "admin", Success: false, CC: 0x80, Error: "cc=0x80"},
		{Requested: 0x02, Name: "user", Success: true, CC: 0x00, Granted: 0x02},
		{Requested: 0x00, Name: "undefined", Success: true, CC: 0x00, Granted: 0x01},
	}
	got := setPrivProbeSuccesses(attempts)
	if len(got) != 2 {
		t.Fatalf("expected 2 successful probes, got %d (%v)", len(got), got)
	}
	if got[0] != "user->0x02" {
		t.Fatalf("unexpected first success label: %q", got[0])
	}
	if got[1] != "0x00->0x01" {
		t.Fatalf("unexpected second success label: %q", got[1])
	}
}

func TestPostAuthInventorySummary(t *testing.T) {
	inv := &ipmi.PostAuthCollection{
		MCInfo:       &ipmi.MCInfo{},
		LAN:          map[string]string{"ip_address": "192.0.2.10"},
		Completed:    []string{"mcInfo", "users", "lan"},
		IncompleteAt: "lan6",
	}
	if got, want := postAuthInventorySummary(inv), "completed=mcInfo,users,lan missing=chassis,lan6,fru stoppedAt=lan6"; got != want {
		t.Fatalf("summary = %q, want %q", got, want)
	}
	if !hasPostAuthInventory(inv) {
		t.Fatal("expected partial inventory to count as useful data")
	}
	if hasPostAuthInventory(&ipmi.PostAuthCollection{}) {
		t.Fatal("empty collection must not count as useful data")
	}
	setupOnly := &ipmi.PostAuthCollection{
		Flow:            ipmi.AuthFlow{Version: "2.0", Mode: "openbmcSetup"},
		SetPrivAttempts: []ipmi.SetPrivAttempt{{Requested: 0x04, Name: "admin", Success: true, CC: 0x00, Granted: 0x04}},
		OpenBMCSetup:    &ipmi.OpenBMCSetupData{PrivilegeQueryCC: 0x00, PrivilegeQueryDataHex: "04", PayloadStatusCC: 0x00, PayloadStatusDataHex: "010000", ProviderBlocked: true},
	}
	if !hasPostAuthInventory(setupOnly) {
		t.Fatal("openbmc setup local data must count as useful post-auth evidence")
	}
}

func TestSMCIntegrityBypassFinding(t *testing.T) {
	target := &engine.Target{Identity: &engine.Identity{Vendor: "supermicro"}}
	flow := ipmi.AuthFlow{
		Version: "2.0", Mode: "cred", Username: "ADMIN",
		Suite: ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityHMACSHA196, Conf: ipmi.ConfAESCBC},
	}
	finding := smcIntegrityBypassFinding(target, flow, &ipmi.PostAuthCollection{CommandProtection: "cleartext"})
	if finding == nil || finding.Check != "ipmi.smc.integrityBypass" || finding.Risk != "critical" {
		t.Fatalf("finding = %+v", finding)
	}
	if len(finding.CVE) != 1 || finding.CVE[0] != "CVE-2026-18450" {
		t.Errorf("CVE = %v, want [CVE-2026-18450]", finding.CVE)
	}
	if got := smcIntegrityBypassFinding(target, flow, &ipmi.PostAuthCollection{CommandProtection: "integrity+conf"}); got != nil {
		t.Fatalf("protected flow produced finding: %+v", got)
	}
}

func TestIPMIPostAuthDetailFindingsOpenBMCSetupData(t *testing.T) {
	inv := &ipmi.PostAuthCollection{
		Flow:              ipmi.AuthFlow{Version: "2.0", Mode: "openbmcSetup"},
		CommandProtection: "setup-cleartext",
		SetPrivAttempts:   []ipmi.SetPrivAttempt{{Requested: 0x04, Name: "admin", Success: true, CC: 0x00, Granted: 0x04}},
		OpenBMCSetup:      &ipmi.OpenBMCSetupData{PrivilegeQueryCC: 0x00, PrivilegeQueryDataHex: "04", PayloadStatusCC: 0x00, PayloadStatusDataHex: "010000", PayloadInfoDataHex: "010203", ProviderBlocked: true},
	}
	got := ipmiPostAuthDetailFindings(inv)
	var setup *engine.Finding
	for i := range got {
		if got[i].Check == "ipmi.postAuth.openBmcSetup" {
			setup = &got[i]
			break
		}
	}
	if setup == nil {
		t.Fatalf("missing ipmi.postAuth.openBmcSetup in %+v", got)
	}
	fields := map[string]string{}
	for _, f := range setup.Fields {
		fields[f.Key] = f.Val
	}
	for k, want := range map[string]string{"privilegeQueryData": "04", "payloadStatusData": "010000", "payloadInfoData": "010203", "providerBlocked": "true"} {
		if fields[k] != want {
			t.Fatalf("field %s=%q want %q in %+v", k, fields[k], want, setup.Fields)
		}
	}
}

func TestOpenBMCRAKPStateFindingsRelabel(t *testing.T) {
	inv := &ipmi.PostAuthCollection{
		Flow:              ipmi.AuthFlow{Version: "2.0", Mode: "openbmcRelabel", Username: "rzlow", RelabelUser: "root", Suite: ipmi.CipherAlgos{Suite: 17}},
		CommandProtection: "integrity+conf",
		SetPrivAttempts:   []ipmi.SetPrivAttempt{{Requested: 0x02, Name: "user", Success: true, CC: 0x00, Granted: 0x02}, {Requested: 0x04, Name: "admin", Success: true, CC: 0x00, Granted: 0x04}},
	}
	got := openBMCRAKPStateFindings(&engine.Target{}, nil, inv, func(string, ...any) {})
	f := findCheck(got, "ipmi.rakp.state.activeRelabelLowToAdmin")
	if f == nil {
		t.Fatalf("missing relabel finding in %+v", got)
	}
	fields := fieldsByKey(f.Fields)
	for key, want := range map[string]string{"username": "rzlow", "relabelUser": "root", "setPriv2Success": "true"} {
		if fields[key] != want {
			t.Fatalf("field %s=%q want %q in %+v", key, fields[key], want, f.Fields)
		}
	}
	for _, key := range []string{"requiresPassword", "requiresAdminPassword", "defaultEnabled", "scope"} {
		if _, ok := fields[key]; ok {
			t.Fatalf("static field %s retained in %+v", key, f.Fields)
		}
	}
}

func TestOpenBMCRAKPStateFindingsDisabledUserSelection(t *testing.T) {
	inv := &ipmi.PostAuthCollection{Users: []ipmi.UserEntry{{ID: 1, Name: "root", Enabled: true}, {ID: 3, Name: "rzdisabled", Enabled: false}}}
	got, ok := selectDisabledOpenBMCUser(inv)
	if !ok || got != "rzdisabled" {
		t.Fatalf("disabled user selection = %q,%t", got, ok)
	}
	inv.Users[1].Name = ""
	if got, ok := selectDisabledOpenBMCUser(inv); ok || got != "" {
		t.Fatalf("expected unnamed disabled slot to be skipped, got %q,%t", got, ok)
	}
}

func TestIsTimeoutLikeErrContextDeadline(t *testing.T) {
	if !isTimeoutLikeErr(context.DeadlineExceeded) {
		t.Fatal("context deadline should be classified as timeout-like")
	}
}

func TestReportPostAuthIssueUsesProgress(t *testing.T) {
	var status string
	tgt := &engine.Target{Progress: func(msg string) { status = msg }}
	inv := &ipmi.PostAuthCollection{
		Completed:    []string{"mcInfo", "chassis"},
		IncompleteAt: "users",
	}
	reportPostAuthIssue(tgt, ipmi.AuthFlow{Version: "2.0", Mode: "cred"}, inv, errors.New("before users: context deadline exceeded"))
	for _, want := range []string{"post-auth ipmi incomplete", "flow=2.0/cred", "completed=mcInfo,chassis", "stoppedAt=users", "before users: context deadline exceeded"} {
		if !strings.Contains(status, want) {
			t.Fatalf("status %q missing %q", status, want)
		}
	}
}

func TestSelectOpenBMCRelabelFlow(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10", Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "openbmc"}}
	tgt.SetEvidence("ipmi.openBmcSetupState", &ipmi.OpenBMCSetupProbe{Username: "root", AdminPrivAccepted: true, SetupCommandsWork: true, OpenSessionOnlyRejected: true, CrossSocketSetupCommandsWork: true})
	auth := &ipmi.AuthReport{
		Suite:   &ipmi.CipherAlgos{Suite: 17, Auth: ipmi.RAKPHMACSHA256, Integrity: ipmi.IntegrityHMACSHA256128, Conf: ipmi.ConfAESCBC},
		Cracked: []ipmi.CrackResult{{Username: "rzlow", Password: "runZero26", Verified: true, PasswordType: "default"}},
	}
	flow, ok := selectOpenBMCRelabelFlow(tgt, auth)
	if !ok {
		t.Fatalf("expected relabel flow")
	}
	if flow.Mode != "openbmcRelabel" || flow.Username != "rzlow" || flow.Password != "runZero26" || flow.RelabelUser != "root" {
		t.Fatalf("unexpected flow: %+v", flow)
	}
	if flow.Suite.Suite != 17 || flow.Source != "ipmi.rakp.state.setupLocalPreRakp3" {
		t.Fatalf("unexpected suite/source: %+v", flow)
	}
}

func TestSelectOpenBMCSetupFlow(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10", Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "openbmc"}}
	tgt.SetEvidence("ipmi.openBmcSetupState", &ipmi.OpenBMCSetupProbe{Username: "root", AdminPrivAccepted: true, SetupCommandsWork: true, OpenSessionOnlyRejected: true})
	auth := &ipmi.AuthReport{Suite: &ipmi.CipherAlgos{Suite: 17, Auth: ipmi.RAKPHMACSHA256, Integrity: ipmi.IntegrityHMACSHA256128, Conf: ipmi.ConfAESCBC}}
	flow, ok := selectOpenBMCSetupFlow(tgt, auth)
	if !ok {
		t.Fatalf("expected setup flow")
	}
	if flow.Mode != "openbmcSetup" || flow.Username != "root" || flow.Password != "" || flow.Suite.Suite != 17 || flow.Source != "ipmi.rakp.state.setupLocalPreRakp3" {
		t.Fatalf("unexpected flow: %+v", flow)
	}
}

func TestOpenBMCRelabelFlowPreferredWhenLowCredExists(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10", Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "openbmc"}}
	tgt.SetEvidence("ipmi.openBmcSetupState", &ipmi.OpenBMCSetupProbe{Username: "root", AdminPrivAccepted: true, SetupCommandsWork: true, OpenSessionOnlyRejected: true})
	auth := &ipmi.AuthReport{
		Suite:   &ipmi.CipherAlgos{Suite: 17, Auth: ipmi.RAKPHMACSHA256, Integrity: ipmi.IntegrityHMACSHA256128, Conf: ipmi.ConfAESCBC},
		Cracked: []ipmi.CrackResult{{Username: "rzlow", Password: "runZero26", Verified: true, PasswordType: "default"}},
	}
	flow, ok := selectOpenBMCRelabelFlow(tgt, auth)
	if !ok {
		t.Fatalf("expected relabel flow")
	}
	if flow.Mode != "openbmcRelabel" || flow.Username != "rzlow" || flow.RelabelUser != "root" {
		t.Fatalf("unexpected preferred relabel flow: %+v", flow)
	}
}

func TestSelectILORAKPNoneFlow(t *testing.T) {
	tgt := &engine.Target{
		Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "hpe"},
		Findings: []engine.Finding{{
			Check: "ipmi.ilo.rakpNoneBypass",
			Risk:  "critical",
			Fields: engine.F(
				"username", "Administrator",
				"authBypassed", "true",
			),
		}},
	}
	flow, ok := selectILORAKPNoneFlow(tgt)
	if !ok {
		t.Fatal("expected iLO RAKP-none flow to be selected")
	}
	if flow.Version != "2.0" || flow.Mode != "iloRakpNoneBypass" || flow.Source != "ipmi.ilo.rakpNoneBypass" {
		t.Fatalf("unexpected flow identity: %+v", flow)
	}
	if flow.Username != "Administrator" {
		t.Fatalf("unexpected username: %+v", flow)
	}
}

func TestSelectOpenBMCRelabelFlowSkipsSameUser(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10"}
	tgt.SetEvidence("ipmi.openBmcSetupState", &ipmi.OpenBMCSetupProbe{Username: "root", AdminPrivAccepted: true, SetupCommandsWork: true})
	auth := &ipmi.AuthReport{
		Suite:   &ipmi.CipherAlgos{Suite: 17, Auth: ipmi.RAKPHMACSHA256, Integrity: ipmi.IntegrityHMACSHA256128, Conf: ipmi.ConfAESCBC},
		Cracked: []ipmi.CrackResult{{Username: "root", Password: "0penBmc", Verified: true, PasswordType: "default"}},
	}
	if flow, ok := selectOpenBMCRelabelFlow(tgt, auth); ok {
		t.Fatalf("expected same-user relabel to be skipped, got %+v", flow)
	}
}

func findCheck(findings []engine.Finding, check string) *engine.Finding {
	for i := range findings {
		if findings[i].Check == check {
			return &findings[i]
		}
	}
	return nil
}

func fieldsByKey(fields engine.Fields) map[string]string {
	out := map[string]string{}
	for _, field := range fields {
		out[field.Key] = field.Val
	}
	return out
}

func TestIPMIPostAuthDetailFindings_ByCommandSet(t *testing.T) {
	inv := &ipmi.PostAuthCollection{
		Flow: ipmi.AuthFlow{Version: "2.0", Mode: "cred"},
		MCInfo: &ipmi.MCInfo{
			FirmwareRevision: "3.00",
			IPMIVersion:      "2.0",
			ManufacturerID:   1,
			ProductID:        2,
		},
		Chassis: &ipmi.ChassisStatus{PowerOn: true, LastEvent: "none", PowerRestore: "always-off", IdentifyOn: true},
		Users:   []ipmi.UserEntry{{ID: 1, Name: "root", Enabled: true}, {ID: 2, Enabled: false}},
		LAN:     map[string]string{"ip_address": "192.0.2.10"},
		LAN6:    map[string]string{"ipv6_support": "0x06"},
		FRU:     []ipmi.FRUField{{Area: "board", Value: "OpenBMC"}},
		CipherMatrix: []ipmi.CipherAttempt{
			{Suite: 17, Success: true},
		},
		SetPrivAttempts: []ipmi.SetPrivAttempt{{Requested: 0x04, Name: "admin", Success: true, Granted: 0x04}},
		Error:           "fru: context deadline exceeded",
	}

	got := ipmiPostAuthDetailFindings(inv)
	byCheck := map[string]bool{}
	for _, f := range got {
		byCheck[f.Check] = true
	}
	for _, want := range []string{
		"ipmi.postAuth.mcInfo",
		"ipmi.postAuth.chassisStatus",
		"ipmi.postAuth.userList",
		"ipmi.postAuth.lanPrint",
		"ipmi.postAuth.lan6Print",
		"ipmi.postAuth.fru",
		"ipmi.postAuth.cipherMatrix",
		"ipmi.postAuth.setPriv",
	} {
		if !byCheck[want] {
			t.Fatalf("expected detail finding %s in %+v", want, got)
		}
	}
	if byCheck["ipmi.postAuth.partialError"] || byCheck["ipmi.postAuthProbeError"] {
		t.Fatalf("operational error leaked into findings: %+v", got)
	}
}

// The budget has to be large enough to finish: FRU is last and the most
// command-hungry step. Post-auth only runs where a credential already worked, a few
// percent of hosts, so the extra room costs almost nothing scan-wide.
func TestPostAuthBudgetClamp(t *testing.T) {
	for _, tc := range []struct {
		perProbe, want time.Duration
	}{
		{0, 45 * time.Second},
		{2 * time.Second, 30 * time.Second},  // floor
		{4 * time.Second, 40 * time.Second},  // the default scan probe timeout
		{10 * time.Second, 75 * time.Second}, // ceiling
		{60 * time.Second, 75 * time.Second}, // still the ceiling
	} {
		if got := postAuthBudget(tc.perProbe); got != tc.want {
			t.Errorf("postAuthBudget(%s) = %s, want %s", tc.perProbe, got, tc.want)
		}
	}
	// The default 4s probe timeout must leave room for the six collection steps plus a
	// session open and the 25s FRU floor, or FRU is structurally unreachable again.
	if got := postAuthBudget(4 * time.Second); got <= 25*time.Second {
		t.Errorf("budget %s does not exceed the FRU floor; FRU cannot complete", got)
	}
}

// A SMCRAKP-forged session runs forced-cleartext with retries and needs the high end.
func TestPostAuthBudgetForSMCRAKPFlow(t *testing.T) {
	got := postAuthBudgetForFlow(4*time.Second, ipmi.AuthFlow{Mode: "smcrakpFixedKey"})
	if got < 60*time.Second || got > 90*time.Second {
		t.Errorf("smcrakpFixedKey budget = %s, want 60s..90s", got)
	}
	if plain := postAuthBudgetForFlow(4*time.Second, ipmi.AuthFlow{Mode: "cred"}); plain >= got {
		t.Errorf("cred budget %s should be below the smcrakp budget %s", plain, got)
	}
}

// TestPostAuthMCInfoAuxFields checks that the auxiliary firmware revision
// reaches the reported finding. collectMCInfo has always parsed it, but the
// finding carried only the two-component revision, so a reported "1.09" could
// not be matched to a vendor advisory naming 01.09.16.
func TestPostAuthMCInfoAuxFields(t *testing.T) {
	inv := &ipmi.PostAuthCollection{
		Flow: ipmi.AuthFlow{Version: "2.0", Mode: "cred"},
		MCInfo: &ipmi.MCInfo{
			FirmwareRevision:     "1.09",
			FirmwareRevisionFull: "01.09.16",
			IPMIVersion:          "2.0",
			ManufacturerID:       10876,
			ManufacturerName:     "Super Micro Computer",
			ProductID:            1832,
			AuxFirmwareHex:       "16000000",
		},
	}
	var fields map[string]string
	for _, f := range ipmiPostAuthDetailFindings(inv) {
		if f.Check != "ipmi.postAuth.mcInfo" {
			continue
		}
		fields = map[string]string{}
		for _, kv := range f.Fields {
			fields[kv.Key] = kv.Val
		}
	}
	if fields == nil {
		t.Fatal("no ipmi.postAuth.mcInfo finding emitted")
	}
	for k, want := range map[string]string{
		"firmwareVersion":     "1.09",
		"firmwareVersionFull": "01.09.16",
		"auxFirmwareRev":      "16000000",
	} {
		if fields[k] != want {
			t.Errorf("field %s = %q, want %q", k, fields[k], want)
		}
	}

	// No auxiliary revision: no reconstruction field, and nothing empty emitted.
	inv.MCInfo.FirmwareRevisionFull = ""
	inv.MCInfo.AuxFirmwareHex = ""
	for _, f := range ipmiPostAuthDetailFindings(inv) {
		if f.Check != "ipmi.postAuth.mcInfo" {
			continue
		}
		for _, kv := range f.Fields {
			if kv.Key == "firmwareVersionFull" || kv.Key == "auxFirmwareRev" {
				t.Errorf("emitted %s=%q with no auxiliary revision", kv.Key, kv.Val)
			}
		}
	}
}
