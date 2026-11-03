package ipmi

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeSMCBMC is an in-process UDP responder modelling the RMCP+ key-exchange
// handler of an ATEN BMC (Open Session, RAKP message 1, RAKP message 3) closely
// enough to drive the CVE-2026-65219 and CVE-2026-65220 probes over a real socket, so the
// affected ATEN answer and the unaffected OpenBMC answer are pinned by a round trip
// rather than by byte layout alone.
type fakeSMCBMC struct {
	conn *net.UDPConn
	done chan struct{}

	// supportedAuth is the only authentication algorithm the fake accepts in an
	// Open Session Request; anything else is rejected with status 0x04, which is how
	// a board restricted to suite 17 behaves when asked for suite 3.
	supportedAuth byte
	// dropUnsupportedSuite models a stack that silently discards an Open Session
	// Request naming an algorithm it does not offer, instead of answering status 0x04.
	dropUnsupportedSuite bool
	bmcSID               uint32

	// unorderedRAKP4Status is the status returned for a RAKP message 3 that arrives
	// with no message 1 before it. 0x08 models the affected ATEN stack, 0x0f the
	// spec-conformant OpenBMC one.
	unorderedRAKP4Status byte
	// echoConsoleSID controls whether message 4 carries the console session ID back.
	echoConsoleSID bool

	// knownUsers are the account names RAKP message 1 resolves; anything else gets
	// status 0x0d (unauthorized-name).
	knownUsers map[string]bool
	// adminUsers, when non-nil, are the accounts entitled to the ADMINISTRATOR role
	// lookup (0x14). A known account outside this set is refused 0x0a
	// (unauthorized-role) for 0x14 while still being accepted for the USER lookup
	// (0x12) - which is how a real board answers an ordinary low-privilege account,
	// and the case that used to abort the probe.
	adminUsers map[string]bool
	// acceptReservedRole models the missing default arm: when true a reserved role
	// nibble is accepted with status 0x00, when false it is refused with 0x09.
	acceptReservedRole bool

	// observed state, for assertions. Written by the serve goroutine and read by
	// the test, so it is mutex-guarded to stay clean under -race.
	mu             sync.Mutex
	sawRAKP1       bool
	sawRAKP3       int
	lastRAKP1Rol   byte
	lastConsoleSID []byte
}

// observed returns a snapshot of what the fake saw on the wire.
func (b *fakeSMCBMC) observed() (rakp1 bool, rakp3 int, role byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sawRAKP1, b.sawRAKP3, b.lastRAKP1Rol
}

func newFakeSMCBMC(t *testing.T, b *fakeSMCBMC) *fakeSMCBMC {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	b.conn = conn
	b.done = make(chan struct{})
	if b.bmcSID == 0 {
		b.bmcSID = 0x00000182 // the shape the live X11 counter produced
	}
	if b.supportedAuth == 0 {
		b.supportedAuth = RAKPHMACSHA1
	}
	go b.serve()
	t.Cleanup(b.close)
	return b
}

func (b *fakeSMCBMC) port() int { return b.conn.LocalAddr().(*net.UDPAddr).Port }

func (b *fakeSMCBMC) close() {
	_ = b.conn.Close()
	<-b.done
}

func (b *fakeSMCBMC) frame(ptype byte, payload []byte) []byte {
	var out bytes.Buffer
	out.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	out.WriteByte(IPMI20Format)
	out.WriteByte(ptype)
	out.Write([]byte{0, 0, 0, 0})
	out.Write([]byte{0, 0, 0, 0})
	out.Write(binary.LittleEndian.AppendUint16(nil, uint16(len(payload))))
	out.Write(payload)
	return out.Bytes()
}

func (b *fakeSMCBMC) serve() {
	defer close(b.done)
	buf := make([]byte, 2048)
	for {
		n, addr, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 16 {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		plen := int(binary.LittleEndian.Uint16(pkt[14:16]))
		if n < 16+plen {
			continue
		}
		payload := pkt[16 : 16+plen]
		var reply []byte
		switch pkt[5] {
		case PayloadOpenSessionReq:
			reply = b.openSessionResp(payload)
		case PayloadRAKP1:
			reply = b.rakp2(payload)
		case PayloadRAKP3:
			reply = b.rakp4(payload)
		}
		if reply != nil {
			_, _ = b.conn.WriteToUDP(reply, addr)
		}
	}
}

// openSessionResp answers an Open Session Request, rejecting any authentication
// algorithm other than the configured one.
func (b *fakeSMCBMC) openSessionResp(req []byte) []byte {
	if len(req) < 32 {
		return nil
	}
	consoleSID := binary.LittleEndian.Uint32(req[4:8])
	b.mu.Lock()
	b.lastConsoleSID = append([]byte(nil), req[4:8]...)
	b.mu.Unlock()
	// Algorithm records begin at offset 8; the auth algo is the 5th byte of the first.
	if req[12] != b.supportedAuth {
		if b.dropUnsupportedSuite {
			return nil
		}
		p := []byte{req[0], 0x04, 0x00, 0x00}
		p = binary.LittleEndian.AppendUint32(p, consoleSID)
		return b.frame(0x11, p)
	}
	p := []byte{req[0], 0x00, req[1] & 0x0f, 0x00}
	p = binary.LittleEndian.AppendUint32(p, consoleSID)
	p = binary.LittleEndian.AppendUint32(p, b.bmcSID)
	p = append(p, 0x00, 0x00, 0x00, 0x08, b.supportedAuth, 0, 0, 0)
	p = append(p, 0x01, 0x00, 0x00, 0x08, 0x01, 0, 0, 0)
	p = append(p, 0x02, 0x00, 0x00, 0x08, 0x01, 0, 0, 0)
	return b.frame(0x11, p)
}

// rakp2 answers a RAKP message 1, applying the account-existence check and the
// role-byte dispatch behaviour under test.
func (b *fakeSMCBMC) rakp2(req []byte) []byte {
	// Layout: tag(1) rsvd(3) bmcSID(4) consoleRand(16) role(1) rsvd(2) ulen(1) user(N)
	if len(req) < 28 {
		return nil
	}
	role := req[24]
	ulen := int(req[27])
	if len(req) < 28+ulen {
		return nil
	}
	b.mu.Lock()
	b.sawRAKP1 = true
	b.lastRAKP1Rol = role
	b.mu.Unlock()

	name := string(req[28 : 28+ulen])
	status := byte(0x00)
	switch {
	case !b.knownUsers[name]:
		status = rakpStatusUnauthorizedName
	case role == smcRAKP1BaselineRoleLookup && b.adminUsers != nil && !b.adminUsers[name]:
		status = rakpStatusUnauthorizedRole
	case role&0xf0 >= 0x20 && role&0xf0 <= 0x70 && !b.acceptReservedRole:
		// A spec-conformant handler refuses a role byte with reserved bits set.
		status = rakpStatusInvalidRole
	}

	p := []byte{req[0], status, 0x00, 0x00}
	p = append(p, 0x00, 0x00, 0x00, 0x00) // console SID (not asserted by these probes)
	p = append(p, bytes.Repeat([]byte{0x33}, 16)...)
	p = append(p, bytes.Repeat([]byte{0x44}, 16)...)
	if status == 0x00 {
		p = append(p, bytes.Repeat([]byte{0x55}, 20)...) // key-exchange auth code
	}
	return b.frame(0x13, p)
}

// rakp4 answers a RAKP message 3. This fake never verifies the authentication
// code: the probes under test assert on the ordering behaviour, that is whether and
// how the BMC answers, not on any particular key being right.
func (b *fakeSMCBMC) rakp4(req []byte) []byte {
	if len(req) < 8 {
		return nil
	}
	b.mu.Lock()
	b.sawRAKP3++
	echoed := append([]byte(nil), b.lastConsoleSID...)
	b.mu.Unlock()
	p := []byte{req[0], b.unorderedRAKP4Status, 0x00, 0x00}
	if b.echoConsoleSID && len(echoed) == 4 {
		// A real BMC echoes the console SID it stored at Open Session; the fake keeps
		// the one it just saw, since only one session is ever in flight here.
		p = append(p, echoed...)
	} else {
		p = append(p, 0x99, 0x99, 0x99, 0x99)
	}
	p = append(p, bytes.Repeat([]byte{0x11}, 12)...)
	return b.frame(0x15, p)
}

// TestProbeSMCUnorderedRAKP3AgainstFakeATEN drives the CVE-2026-65219 probe over a real
// socket against a BMC that behaves like the affected ATEN stack: it answers a
// RAKP message 3 that arrived with no message 1, returning the non-standard status
// 0x08 with the console session ID echoed.
func TestProbeSMCUnorderedRAKP3AgainstFakeATEN(t *testing.T) {
	b := newFakeSMCBMC(t, &fakeSMCBMC{
		unorderedRAKP4Status: 0x08,
		echoConsoleSID:       true,
	})
	probe, err := ProbeSMCUnorderedRAKP3("127.0.0.1", b.port(), 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !probe.Answered {
		t.Fatal("probe should have been answered")
	}
	if !probe.Defect {
		t.Fatalf("expected the ordering defect, got %s", probe.Summary())
	}
	if probe.SpecConformant {
		t.Error("an affected board must not be classified spec-conformant")
	}
	if probe.Activated {
		t.Error("the sentinel key must never activate a session")
	}
	if !probe.SIDEchoed {
		t.Error("console session ID should have been recognized as echoed")
	}
	if probe.CipherSuite != 3 {
		t.Errorf("negotiated suite = %d, want 3", probe.CipherSuite)
	}
	if probe.BMCSID != b.bmcSID {
		t.Errorf("bmc SID = 0x%08x, want 0x%08x", probe.BMCSID, b.bmcSID)
	}
	// The whole point: no RAKP message 1 may have been sent.
	rakp1, rakp3, _ := b.observed()
	if rakp1 {
		t.Fatal("the probe sent a RAKP message 1; skipping it IS the probe")
	}
	// Exactly one forged message 3, so no lockout threshold can be reached.
	if rakp3 != 1 {
		t.Fatalf("probe sent %d RAKP message 3 packets, want exactly 1", rakp3)
	}
}

// TestProbeSMCUnorderedRAKP3AgainstSpecConformantStack covers the X14/OpenBMC
// answer: the spec-correct 0x0f must be reported as unaffected, never as the
// defect.
func TestProbeSMCUnorderedRAKP3AgainstSpecConformantStack(t *testing.T) {
	b := newFakeSMCBMC(t, &fakeSMCBMC{
		unorderedRAKP4Status: rakpStatusInvalidICV,
		echoConsoleSID:       true,
	})
	probe, err := ProbeSMCUnorderedRAKP3("127.0.0.1", b.port(), 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if probe.Defect {
		t.Fatal("status 0x0f must NOT be reported as the ordering defect")
	}
	if !probe.SpecConformant {
		t.Errorf("status 0x0f should be classified spec-conformant, got %s", probe.Summary())
	}
}

// TestProbeSMCUnorderedRAKP3IgnoresUnechoedStatus08 pins the second half of the
// signal. Status 0x08 without the console session ID echoed does not prove the
// slot was located, so it must not raise a finding.
func TestProbeSMCUnorderedRAKP3IgnoresUnechoedStatus08(t *testing.T) {
	b := newFakeSMCBMC(t, &fakeSMCBMC{
		unorderedRAKP4Status: 0x08,
		echoConsoleSID:       false,
	})
	probe, err := ProbeSMCUnorderedRAKP3("127.0.0.1", b.port(), 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if probe.Defect {
		t.Fatal("status 0x08 without the echoed console SID must not raise the finding")
	}
	if probe.SIDEchoed {
		t.Error("SIDEchoed should be false")
	}
}

// TestProbeSMCUnorderedRAKP3FallsBackToSuite17 covers the restricted-cipher
// boards (X12/X13/H13 configurations offering only suites 3 and 17): rejecting
// suite 3 must not be read as "not affected".
func TestProbeSMCUnorderedRAKP3FallsBackToSuite17(t *testing.T) {
	b := newFakeSMCBMC(t, &fakeSMCBMC{
		supportedAuth:        RAKPHMACSHA256,
		unorderedRAKP4Status: 0x08,
		echoConsoleSID:       true,
	})
	probe, err := ProbeSMCUnorderedRAKP3("127.0.0.1", b.port(), 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !probe.Defect {
		t.Fatalf("expected the defect on the suite-17 fallback, got %s", probe.Summary())
	}
	if probe.CipherSuite != 17 {
		t.Errorf("negotiated suite = %d, want 17", probe.CipherSuite)
	}
}

// TestProbeSMCReservedRoleAgainstFakeATEN drives the CVE-2026-65220 probe end to end.
// The affected board accepts the reserved role nibble; the probe must find a
// resolvable account first and must never send a RAKP message 3.
func TestProbeSMCReservedRoleAgainstFakeATEN(t *testing.T) {
	b := newFakeSMCBMC(t, &fakeSMCBMC{
		knownUsers:         map[string]bool{"ADMIN": true},
		acceptReservedRole: true,
		// Any RAKP3 the probe wrongly sent would be answered here; the assertion
		// below is that none is.
		unorderedRAKP4Status: 0x00,
	})
	probe, err := ProbeSMCReservedRole("127.0.0.1", b.port(), "", 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if probe.Username != "ADMIN" {
		t.Fatalf("resolved account = %q, want ADMIN", probe.Username)
	}
	if !probe.BaselineAccepted {
		t.Fatalf("baseline role 0x%02x should have been accepted", probe.BaselineRole)
	}
	if !probe.ReservedAccepted || !probe.Defect {
		t.Fatalf("expected the reserved role to be accepted, got %s", probe.Summary())
	}
	if probe.ReservedRejectedConformantly {
		t.Error("an accepted reserved role must not be recorded as a conformant refusal")
	}
	// The safety property: the detection probe offers no credential, so no RAKP
	// message 3 may reach the wire.
	if _, rakp3, _ := b.observed(); rakp3 != 0 {
		t.Fatalf("probe sent %d RAKP message 3 packets; it must offer no credential", rakp3)
	}
}

// TestProbeSMCReservedRoleAgainstConformantStack covers the negative: a handler
// that refuses the reserved nibble must produce no finding, and the refusal must
// be recorded as spec-shaped.
func TestProbeSMCReservedRoleAgainstConformantStack(t *testing.T) {
	b := newFakeSMCBMC(t, &fakeSMCBMC{
		knownUsers:         map[string]bool{"ADMIN": true},
		acceptReservedRole: false,
	})
	probe, err := ProbeSMCReservedRole("127.0.0.1", b.port(), "", 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if probe.Defect {
		t.Fatal("a refused reserved role must not raise the finding")
	}
	if probe.ReservedStatus != rakpStatusInvalidRole {
		t.Errorf("reserved status = 0x%02x, want 0x%02x", probe.ReservedStatus, rakpStatusInvalidRole)
	}
	if !probe.ReservedRejectedConformantly {
		t.Error("status 0x09 should be recorded as a conformant refusal")
	}
}

// TestProbeSMCReservedRoleNoResolvableAccount covers the case that must not be
// reported as a clean bill of health: if no candidate account name resolves, the
// comparison was never made.
func TestProbeSMCReservedRoleNoResolvableAccount(t *testing.T) {
	b := newFakeSMCBMC(t, &fakeSMCBMC{
		knownUsers:         map[string]bool{"someoneelse": true},
		acceptReservedRole: true,
	})
	probe, err := ProbeSMCReservedRole("127.0.0.1", b.port(), "", 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if probe.Defect {
		t.Fatal("no account resolved, so no verdict may be reached")
	}
	if probe.Username != "" {
		t.Errorf("username = %q, want empty", probe.Username)
	}
	if probe.Summary() != "no-resolvable-account" {
		t.Errorf("summary = %q, want no-resolvable-account", probe.Summary())
	}
	if len(probe.UsernameCandidates) == 0 {
		t.Error("the names tried should be recorded so a negative is distinguishable")
	}
}

// TestRAKP1RoleStatusNeverSendsRAKP3 is the safety assertion for the CVE-2026-65220
// probe: it must offer no credential, which means no RAKP message 3 on the wire.
func TestRAKP1RoleStatusNeverSendsRAKP3(t *testing.T) {
	b := newFakeSMCBMC(t, &fakeSMCBMC{knownUsers: map[string]bool{"ADMIN": true}, acceptReservedRole: true})
	st, err := RAKP1RoleStatus("127.0.0.1", b.port(), "ADMIN", SMCReservedRoleByte, 2*time.Second)
	if err != nil {
		t.Fatalf("rakp1: %v", err)
	}
	if st != 0x00 {
		t.Fatalf("status = 0x%02x, want 0x00", st)
	}
	rakp1, rakp3, role := b.observed()
	if !rakp1 {
		t.Fatal("expected a RAKP message 1")
	}
	if role != SMCReservedRoleByte {
		t.Fatalf("role on the wire = 0x%02x, want 0x%02x", role, SMCReservedRoleByte)
	}
	if rakp3 != 0 {
		t.Fatalf("RAKP1RoleStatus sent %d RAKP message 3 packets; it must send none", rakp3)
	}
}

// TestProbeSMCReservedRoleResolvesNonAdminAccount guards account resolution in the
// CVE-2026-65220 probe: the control must be the USER lookup (0x12), which any existing
// account is entitled to. Resolving with the ADMINISTRATOR lookup (0x14) is refused
// 0x0a for a low-privilege account, so a board whose first resolvable candidate is
// not an administrator reports nothing while accepting the reserved role byte.
func TestProbeSMCReservedRoleResolvesNonAdminAccount(t *testing.T) {
	b := newFakeSMCBMC(t, &fakeSMCBMC{
		knownUsers:         map[string]bool{"admin": true}, // resolves, but not an administrator
		adminUsers:         map[string]bool{},
		acceptReservedRole: true,
	})
	probe, err := ProbeSMCReservedRole("127.0.0.1", b.port(), "admin", 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if probe.Username != "admin" {
		t.Fatalf("resolved account = %q, want admin", probe.Username)
	}
	if !probe.ConformantAccepted {
		t.Fatalf("the USER-level control 0x%02x must be accepted for an existing account (got 0x%02x)",
			probe.ConformantRole, probe.ConformantStatus)
	}
	if probe.BaselineAccepted {
		t.Errorf("the ADMINISTRATOR lookup must NOT be accepted for a non-admin account (got 0x%02x)", probe.BaselineStatus)
	}
	if !probe.Defect {
		t.Fatalf("the reserved role was accepted, so the defect must be reported even though the account is not an administrator: %s", probe.Summary())
	}
	if _, rakp3, _ := b.observed(); rakp3 != 0 {
		t.Fatalf("probe sent %d RAKP message 3 packets; it must offer no credential", rakp3)
	}
}

// TestSMCOpenSessionTriesEverySuiteAfterATimeout covers the other false-negative
// path: a stack that discards an Open Session Request naming an algorithm it does
// not offer is indistinguishable from a dead host, so a transport error must not
// stop the loop before suite 17 is tried.
func TestSMCOpenSessionTriesEverySuiteAfterATimeout(t *testing.T) {
	b := newFakeSMCBMC(t, &fakeSMCBMC{
		supportedAuth:        RAKPHMACSHA256, // suite 17 only
		dropUnsupportedSuite: true,           // ... and silently drops suite 3
		unorderedRAKP4Status: 0x08,
		echoConsoleSID:       true,
	})
	probe, err := ProbeSMCUnorderedRAKP3("127.0.0.1", b.port(), 300*time.Millisecond)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !probe.Defect {
		t.Fatalf("a dropped suite-3 request must not end the search: %s", probe.Summary())
	}
	if probe.CipherSuite != 17 {
		t.Errorf("negotiated suite = %d, want 17", probe.CipherSuite)
	}
}
