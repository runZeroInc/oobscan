package check

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func mustRAKP(t *testing.T, user, pass string) *ipmi.RAKPResult {
	t.Helper()
	r := &ipmi.RAKPResult{
		Username:  user,
		AuthAlgo:  ipmi.RAKPHMACSHA1,
		ClientSID: 0x11223344,
		BMCSID:    0x55667788,
		ClientRand: []byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
		BMCRand: []byte{
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		},
		BMCGUID: []byte{
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
			0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		},
	}
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, r.ClientSID)
	_ = binary.Write(&buf, binary.LittleEndian, r.BMCSID)
	buf.Write(r.ClientRand)
	buf.Write(r.BMCRand)
	buf.Write(r.BMCGUID)
	buf.WriteByte(0x14)
	buf.WriteByte(byte(len(r.Username)))
	buf.WriteString(r.Username)
	mac := hmac.New(sha1.New, []byte(pass))
	mac.Write(buf.Bytes())
	r.RAKPHash = mac.Sum(nil)
	if len(r.RAKPHash) == 0 {
		t.Fatalf("failed to compute test RAKP hash")
	}
	return r
}

func TestIPMICrackedSSHPairsReplaysWildcardPasswordsAgainstTinyUserSet(t *testing.T) {
	auth := &ipmi.AuthReport{Cracked: []ipmi.CrackResult{{Username: "", Password: "admin", AcceptsAny: true}}}
	got := ipmiCrackedSSHPairs(auth, 8)
	want := [][2]string{{"admin", "admin"}, {"root", "admin"}, {"ADMIN", "admin"}, {"USERID", "admin"}}
	if len(got) != len(want) {
		t.Fatalf("pairs=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pairs=%v, want %v", got, want)
		}
	}
}

func TestIPMICrackedSSHPairsKeepsAttributedUsernameFirst(t *testing.T) {
	auth := &ipmi.AuthReport{Cracked: []ipmi.CrackResult{{Username: "ADMIN", Password: "PASSW0RD"}}}
	got := ipmiCrackedSSHPairs(auth, 8)
	if len(got) != 1 || got[0] != [2]string{"ADMIN", "PASSW0RD"} {
		t.Fatalf("pairs=%v, want only attributed ADMIN:PASSW0RD", got)
	}
}

func TestShouldRunIPMIPostAuthPostCheck_BasicEligibility(t *testing.T) {
	tgt := &engine.Target{Identity: &engine.Identity{Class: engine.ClassBMC}}
	if !shouldRunIPMIPostAuthPostCheck(tgt) {
		t.Fatal("expected BMC target with no prior post-auth output to be eligible")
	}
}

func TestShouldRunIPMIPostAuthPostCheck_SkipsWhenAlreadyEmitted(t *testing.T) {
	tgt := &engine.Target{Identity: &engine.Identity{Class: engine.ClassBMC}}
	tgt.AddFindings(engine.Finding{Check: "ipmi.postAuthEnum", Risk: "info"})
	if shouldRunIPMIPostAuthPostCheck(tgt) {
		t.Fatal("expected post-check to skip when ipmi.postAuthEnum already emitted")
	}
}

func TestShouldRunIPMIPostAuthPostCheck_SkipsWhenEvidenceExists(t *testing.T) {
	tgt := &engine.Target{Identity: &engine.Identity{Class: engine.ClassBMC}}
	tgt.SetEvidence("ipmi.postAuth", &ipmi.PostAuthCollection{})
	if shouldRunIPMIPostAuthPostCheck(tgt) {
		t.Fatal("expected post-check to skip when ipmi.postAuth evidence already exists")
	}
}

func TestShouldRunIPMIPostAuthPostCheck_SkipsNonBMC(t *testing.T) {
	tgt := &engine.Target{Identity: &engine.Identity{Class: engine.ClassPDU}}
	if shouldRunIPMIPostAuthPostCheck(tgt) {
		t.Fatal("expected non-BMC target to be ineligible")
	}
}

func TestRunSSHWithRecoveredIPMICreds_AttemptedNoSuccess(t *testing.T) {
	old := sshTryDefaults
	t.Cleanup(func() { sshTryDefaults = old })
	sshTryDefaults = func(host string, port int, timeout time.Duration, pairs [][2]string, max int) (string, string, string, bool) {
		return "", "", "", false
	}

	tgt := &engine.Target{
		Host:     "192.0.2.10",
		Timeout:  200 * time.Millisecond,
		Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "supermicro"},
		Ports:    []engine.Port{{Num: 22, Proto: engine.ProtoTCP}},
		Evidence: map[string]any{},
	}
	tgt.SetEvidence("ipmi.auth", &ipmi.AuthReport{Cracked: []ipmi.CrackResult{{Username: "ADMIN", Password: "ADMIN", Verified: true}}})

	got := runSSHWithRecoveredIPMICreds(context.Background(), tgt)
	if len(got) != 1 {
		t.Fatalf("expected one info finding, got %+v", got)
	}
	if got[0].Check != "ssh.defaultCredsAttempted" || got[0].Risk != "info" {
		t.Fatalf("unexpected finding %+v", got[0])
	}
}

func TestRunSSHWithRecoveredIPMICreds_Success(t *testing.T) {
	old := sshTryDefaults
	t.Cleanup(func() { sshTryDefaults = old })
	sshTryDefaults = func(host string, port int, timeout time.Duration, pairs [][2]string, max int) (string, string, string, bool) {
		return "ADMIN", "ADMIN", "uid=0(root)", true
	}

	tgt := &engine.Target{
		Host:     "192.0.2.11",
		Timeout:  200 * time.Millisecond,
		Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "supermicro"},
		Ports:    []engine.Port{{Num: 22, Proto: engine.ProtoTCP}},
		Evidence: map[string]any{},
	}
	tgt.SetEvidence("ipmi.auth", &ipmi.AuthReport{Cracked: []ipmi.CrackResult{{Username: "ADMIN", Password: "ADMIN", Verified: true}}})

	got := runSSHWithRecoveredIPMICreds(context.Background(), tgt)
	if len(got) != 1 {
		t.Fatalf("expected one critical finding, got %+v", got)
	}
	if got[0].Check != "ssh.defaultCreds" || got[0].Risk != "critical" {
		t.Fatalf("unexpected finding %+v", got[0])
	}
}

func TestRunIPMICredsFromRecoveredCreds_EmitsCriticalOnVerifiedReuse(t *testing.T) {
	tgt := &engine.Target{
		Host:     "192.0.2.20",
		Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "supermicro"},
		Findings: []engine.Finding{{
			Check: "http.redfish.defaultCreds", Risk: "critical",
			Fields: engine.F("username", "ADMIN", "password", "ADMIN"),
		}},
		Evidence: map[string]any{},
	}
	r := mustRAKP(t, "ADMIN", "ADMIN")
	tgt.SetEvidence("ipmi.auth", &ipmi.AuthReport{Results: []ipmi.RAKPResult{*r}})

	got := runIPMICredsFromRecoveredCreds(context.Background(), tgt)
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %+v", got)
	}
	if got[0].Check != "ipmi.v20.defaultCreds" || got[0].Risk != "critical" {
		t.Fatalf("unexpected finding %+v", got[0])
	}
	if explainField(got[0], "username") != "ADMIN" || explainField(got[0], "password") != "ADMIN" {
		t.Fatalf("unexpected credential fields %+v", got[0].Fields)
	}
	if explainField(got[0], "via") != "rakpHash+http.redfish.defaultCreds" {
		t.Fatalf("unexpected via field %+v", got[0].Fields)
	}
}

func TestRunIPMICredsFromRecoveredCreds_SkipsOnPasswordMismatch(t *testing.T) {
	tgt := &engine.Target{
		Host:     "192.0.2.21",
		Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "supermicro"},
		Findings: []engine.Finding{{
			Check: "http.redfish.defaultCreds", Risk: "critical",
			Fields: engine.F("username", "ADMIN", "password", "wrong"),
		}},
		Evidence: map[string]any{},
	}
	r := mustRAKP(t, "ADMIN", "ADMIN")
	tgt.SetEvidence("ipmi.auth", &ipmi.AuthReport{Results: []ipmi.RAKPResult{*r}})

	got := runIPMICredsFromRecoveredCreds(context.Background(), tgt)
	if len(got) != 0 {
		t.Fatalf("expected no finding, got %+v", got)
	}
}
