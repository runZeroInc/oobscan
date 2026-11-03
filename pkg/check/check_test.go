package check

import (
	"context"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/wsman"
)

func TestProofKV(t *testing.T) {
	got := proofKV("user", "admin", "marker", "Control Panel", "empty", "")
	if got != `username=admin marker="Control Panel"` {
		t.Fatalf("proofKV() = %q", got)
	}
}

// TestCoreChecksRegistered confirms core credential and exposure checks are
// present in the registry.
func TestCoreChecksRegistered(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("no checks registered")
	}
	byName := map[string]bool{}
	for _, c := range all {
		byName[c.Name] = true
	}
	for _, name := range []string{
		"ipmi.defaultCreds", // native credential engine
		"kvm.vnc",
		"ssh.sharedHostKey", // known shipped/compromised SSH host key detection
		"tls.mtls.ami.caBypass",
		"http.cisco.webPresence",
		"ipmi.rmcpPing",
		"http.wsman.detected",     // WS-Man discovery/fingerprinting
		"http.wsman.postAuthEnum", // WS-Man post-auth enrichment with supplied creds
	} {
		if !byName[name] {
			t.Errorf("expected check %q to be registered", name)
		}
	}
}

func TestForIdentityOrdersDeviceSpecificFirst(t *testing.T) {
	id := &engine.Identity{Class: engine.ClassBMC, Vendor: "dell"}
	sel := Selector{}
	got := ForIdentity(id, sel)
	if len(got) == 0 {
		t.Fatal("no checks selected for dell BMC")
	}
	// The dell-specific idrac.default-creds must sort ahead of any cross-vendor
	// check in the returned slice.
	sawCross := false
	for _, c := range got {
		if !c.Applies.deviceSpecific() {
			sawCross = true
		} else if sawCross {
			t.Errorf("device-specific check %q appeared after a cross-vendor check", c.Name)
		}
	}
}

func TestForIdentityHoneypotRunsOnlyID(t *testing.T) {
	// A honeypot must run only the id reporter (which flags it); the whole
	// credential/exposure battery is skipped so we don't waste budget or mint
	// bogus findings from the decoy's emulated services.
	id := &engine.Identity{Class: engine.ClassHoneypot, Vendor: "ami"}
	got := ForIdentity(id, Selector{})
	if len(got) != 1 || got[0].Name != "id" {
		names := make([]string, len(got))
		for i, c := range got {
			names[i] = c.Name
		}
		t.Fatalf("honeypot ForIdentity = %v, want exactly [id]", names)
	}
}

func TestForIdentityUnknownKeepsSelfValidatingCoreChecks(t *testing.T) {
	got := ForIdentity(&engine.Identity{Class: engine.ClassUnknown, Confidence: engine.ConfLow}, Selector{})
	selected := map[string]bool{}
	for _, c := range got {
		selected[c.Name] = true
	}
	for _, name := range []string{
		"amt.authBypass",
		"http.apc.demoBackdoor",
		"http.idrac.defaultCreds",
		"http.gude.defaultCreds",
		"http.ilo.authBypass",
		"http.jetkvm.metricsUnauth",
		"http.nanokvm.universalKey",
		"http.smc.psBlock",
		"ipmi.rmcpPing",
		"ipmi.defaultCreds",
		"ipmi.v15.session",
		"http.redfish.defaultCreds",
		"http.redfish.authPathProbe",
		"tls.mtls.ami.caBypass",
		"udp.moxa.deviceSearch",
		"tcp.moxa.serialBanner",
		"udp.lantronix.setup",
		"tcp.lantronix.setupBanner",
		"udp.digi.addpLeak",
		"tcp.digi.realportBanner",
		"kvm.usbAnywhere",
		"kvm.vnc",
		"pdu.confirm",
		"xdp.exposed",
	} {
		if !selected[name] {
			t.Fatalf("unknown identity did not select %s", name)
		}
	}

	selectedWithCreds := map[string]bool{}
	for _, c := range ForIdentity(&engine.Identity{Class: engine.ClassUnknown, Confidence: engine.ConfLow}, Selector{HasCreds: true}) {
		selectedWithCreds[c.Name] = true
	}
	if !selectedWithCreds["http.redfish.smc.x14.submitTestEvent"] {
		t.Fatal("unknown identity with credentials did not select the bounded SubmitTestEvent check")
	}
}

func TestSelectorTokenOverridesEnabled(t *testing.T) {
	c := Check{Name: "foo.bar", Category: "foo", Enabled: false}
	if !(Selector{Checks: []string{"foo"}}).allow(c) {
		t.Error("category token should enable a disabled check")
	}
	if !(Selector{Checks: []string{"foo.bar"}}).allow(c) {
		t.Error("exact name token should enable a disabled check")
	}
	if (Selector{Checks: []string{"other"}}).allow(c) {
		t.Error("non-matching token should not enable the check")
	}
}

func TestSelectorExplicitCheckCanSelectAuthenticatedWithoutSuppliedCreds(t *testing.T) {
	c := Check{Name: "ipmi.openbmc.rakp1ActiveRelabel", Category: "auth", Authenticated: true, Enabled: true}
	if !(Selector{Checks: []string{"ipmi.openbmc.rakp1ActiveRelabel"}}).allow(c) {
		t.Error("exact --checks token should select requested authenticated check even before credentials are discovered")
	}
	if (Selector{Categories: []string{"auth"}}).allow(c) {
		t.Error("category selection should not bypass the authenticated default gate without supplied credentials")
	}
}

func TestSelectorRAKPStateAliasesSelectIPMICredsProducer(t *testing.T) {
	bmc := &engine.Identity{Class: engine.ClassBMC, Vendor: "openbmc"}
	for _, token := range []string{
		"ipmi.openBmc.rakp1SetupCommands",
		"ipmi.rakp.state.setupLocalPreRakp3",
		"ipmi.rakp.state.activeRelabelLowToAdmin",
		"ipmi.rakp.state",
	} {
		selected := false
		for _, c := range ForIdentity(bmc, Selector{Checks: []string{token}}) {
			if c.Name == "ipmi.defaultCreds" {
				selected = true
			}
		}
		if !selected {
			t.Fatalf("--checks %s did not select ipmi.defaultCreds producer", token)
		}
	}
}

func TestOpenBMCSetupProofAndExtraFieldsIncludePayloadInfo(t *testing.T) {
	probe := &ipmi.OpenBMCSetupProbe{
		RAKPStatus:        0x00,
		PrePrivQueryCC:    0x00,
		SetPrivAdminCC:    0x00,
		PayloadStatusCC:   0x00,
		PayloadStatusData: []byte{0x01, 0x00, 0x00, 0x65},
		PayloadInfoCC:     0x00,
		PayloadInfoData:   []byte{0x02, 0x00, 0x01},
	}
	if got := openBMCSetupProof(probe); got != "rakp1=0x00 cmds=privQuery,setPriv,solStatus,solInfo" {
		t.Fatalf("proof = %q", got)
	}
	probe.PayloadInfoCC = 0xcc
	if got := openBMCSetupProof(probe); got != "rakp1=0x00 cmds=privQuery,setPriv,solStatus" {
		t.Fatalf("proof with failed solInfo = %q", got)
	}
	fields := fieldsByKey(openBMCSetupStateExtraFields(probe))
	if fields["payloadStatusData"] != "01000065" {
		t.Fatalf("payloadStatusData = %q", fields["payloadStatusData"])
	}
	if fields["payloadInfoData"] != "020001" {
		t.Fatalf("payloadInfoData = %q", fields["payloadInfoData"])
	}
}

// TestConsolePDUChecksScoped confirms the serialConsole and PDU exposure checks
// are registered and scoped to their device classes (not cross-vendor), so they
// only fire on ClassSerialConsole / ClassPDU targets.
func TestConsolePDUChecksScoped(t *testing.T) {
	byName := map[string]Check{}
	for _, c := range All() {
		byName[c.Name] = c
	}
	for _, tc := range []struct {
		name  string
		class engine.DeviceClass
	}{
		{"serialconsole.exposure", engine.ClassSerialConsole},
		{"pdu.exposure", engine.ClassPDU},
	} {
		c, ok := byName[tc.name]
		if !ok {
			t.Errorf("%s not registered", tc.name)
			continue
		}
		if c.Applies.CrossVendor || len(c.Applies.Classes) != 1 || c.Applies.Classes[0] != tc.class {
			t.Errorf("%s: applicability = %+v, want class %s only", tc.name, c.Applies, tc.class)
		}
		// A BMC identity must not select these checks.
		bmc := &engine.Identity{Class: engine.ClassBMC, Vendor: "dell"}
		for _, sel := range ForIdentity(bmc, Selector{}) {
			if sel.Name == tc.name {
				t.Errorf("%s should not apply to a BMC", tc.name)
			}
		}
		// The matching class must select it.
		selected := false
		for _, sel := range ForIdentity(&engine.Identity{Class: tc.class}, Selector{}) {
			if sel.Name == tc.name {
				selected = true
			}
		}
		if !selected {
			t.Errorf("%s not selected for class %s", tc.name, tc.class)
		}
	}
}

func TestOOBDeviceExposureDoesNotReportUnverifiedShippedDefaults(t *testing.T) {
	target := &engine.Target{Identity: &engine.Identity{
		Class: engine.ClassSerialConsole, Vendor: "moxa", Product: "NPort",
	}}
	findings := oobDeviceExposure(context.Background(), target, "serialconsole")
	if len(findings) != 1 || findings[0].Check != "serialconsole.fingerprint" {
		t.Fatalf("findings = %+v, want only serialconsole.fingerprint", findings)
	}
}

func TestLikelyAMT(t *testing.T) {
	if !likelyAMT(&engine.Target{Identity: &engine.Identity{Class: engine.ClassAMT}}) {
		t.Fatal("expected AMT class identity to match")
	}
	if !likelyAMT(&engine.Target{Identity: &engine.Identity{Vendor: "intel"}}) {
		t.Fatal("expected intel vendor identity to match")
	}
	tgt := &engine.Target{}
	tgt.Identity = &engine.Identity{Attributes: map[string]string{"http.server": "Intel(R) Standard Manageability 8.1.31"}}
	if !likelyAMT(tgt) {
		t.Fatal("expected AMT marker in attrs to match")
	}
	if likelyAMT(&engine.Target{}) {
		t.Fatal("expected empty target to not match AMT")
	}
}

func TestWSMANAMTVersionFallback(t *testing.T) {
	tgt := &engine.Target{}
	tgt.SetEvidence("wsman", &wsman.Identity{ProductVersion: "Intel(R) AMT 11.8.50"})
	if got := wsmanAMTVersion(tgt); got != "11.8.50" {
		t.Fatalf("wsmanAMTVersion = %q, want 11.8.50", got)
	}

	tgt2 := &engine.Target{}
	tgt2.SetEvidence("wsman", &wsman.Identity{ProductVersion: "12.0.35.1427"})
	if got := wsmanAMTVersion(tgt2); got != "12.0.35.1427" {
		t.Fatalf("wsmanAMTVersion = %q, want 12.0.35.1427", got)
	}

	tgt3 := &engine.Target{}
	tgt3.SetEvidence("wsman", &wsman.Identity{ProductVersion: "Intel AMT"})
	if got := wsmanAMTVersion(tgt3); got != "" {
		t.Fatalf("wsmanAMTVersion = %q, want empty", got)
	}
}

func TestAMTVersionInRange(t *testing.T) {
	if !amtVersionInRange("8.1.31") {
		t.Fatal("8.1.31 should be in vulnerable range")
	}
	if !amtVersionInRange("11.6.27") {
		t.Fatal("11.6.27 should be in vulnerable range")
	}
	if amtVersionInRange("11.8.50") {
		t.Fatal("11.8.50 should be out of vulnerable range")
	}
	if amtVersionInRange("14.1.67.2046") {
		t.Fatal("14.1.67.2046 should be out of vulnerable range")
	}
}
