package check

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// rejectingBMC answers every Open Session Request with the configured status and
// counts how many arrived. Session exhaustion is refused at Open Session, so the
// count is exactly how many cipher candidates the walk spent.
type rejectingBMC struct {
	conn   *net.UDPConn
	status byte
	opens  atomic.Int64
	done   chan struct{}
}

func newRejectingBMC(t *testing.T, status byte) *rejectingBMC {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	b := &rejectingBMC{conn: conn, status: status, done: make(chan struct{})}
	go b.serve()
	t.Cleanup(func() {
		_ = conn.Close()
		<-b.done
	})
	return b
}

func (b *rejectingBMC) port() int { return b.conn.LocalAddr().(*net.UDPAddr).Port }

func (b *rejectingBMC) serve() {
	defer close(b.done)
	buf := make([]byte, 2048)
	for {
		n, addr, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 16 || buf[5]&0x3f != ipmi.PayloadOpenSessionReq {
			continue
		}
		b.opens.Add(1)
		req := append([]byte(nil), buf[16:n]...)
		// A rejection is allowed to stop after the console session ID, which is what
		// real BMCs send.
		p := []byte{0x00, b.status, 0x00, 0x00}
		if len(req) >= 8 {
			p = append(p, req[4:8]...)
		} else {
			p = append(p, 0, 0, 0, 0)
		}
		var out bytes.Buffer
		out.Write([]byte{ipmi.RMCPVersion, ipmi.RMCPReserved, ipmi.RMCPSeqNoAck, ipmi.RMCPClassIPMI})
		out.WriteByte(ipmi.IPMI20Format)
		out.WriteByte(ipmi.PayloadOpenSessionRes)
		out.Write([]byte{0, 0, 0, 0})
		out.Write([]byte{0, 0, 0, 0})
		out.Write(binary.LittleEndian.AppendUint16(nil, uint16(len(p))))
		out.Write(p)
		_, _ = b.conn.WriteToUDP(out.Bytes(), addr)
	}
}

func exhaustionTarget(port int) *engine.Target {
	t := &engine.Target{
		Host:    "127.0.0.1",
		Ports:   []engine.Port{{Proto: engine.ProtoUDP, Num: port}},
		Timeout: 100 * time.Millisecond,
	}
	// Several advertised suites, so a walk that does not bail has plenty to spend.
	t.SetEvidence("ipmi.ciphers", []int{3, 8, 12, 17})
	return t
}

// A BMC that has no session slots left refuses at Open Session, before the cipher
// suite is negotiated, so every remaining candidate would spend a full timeout to
// be told the same thing. The walk has to stop on the first one.
func TestCipherWalkStopsOnSessionExhaustion(t *testing.T) {
	bmc := newRejectingBMC(t, 0x01) // insufficient resources to create a session
	tgt := exhaustionTarget(bmc.port())
	flow := ipmi.AuthFlow{Version: "2.0", Username: "ADMIN", Password: "x",
		Suite: ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityHMACSHA196, Conf: ipmi.ConfAESCBC}}

	inv, err := collectPostAuthWithMatrix(context.Background(), tgt, flow, func(string, ...any) {})
	if err == nil {
		t.Fatal("expected an error from a BMC that refuses every session")
	}

	// The plumbing assertion: the rejection status has to survive the call chain
	// intact, or the bail below can never trigger in production.
	if !ipmi.SessionResourceExhausted(inv, err) {
		t.Fatalf("exhaustion not recognized from the returned error, so the bail is unreachable: err=%v invErr=%q", err, invError(inv))
	}
	if got := bmc.opens.Load(); got != 1 {
		t.Errorf("%d Open Session attempts, want 1: the walk kept trying candidates after the BMC said it had no slots", got)
	}
	if inv == nil {
		t.Fatal("inventory dropped entirely; a refused collection still has to report what it saw")
	}
	if len(inv.CipherMatrix) != 1 {
		t.Errorf("cipherMatrix has %d entries, want 1", len(inv.CipherMatrix))
	}
}

// The bail must be specific to exhaustion. Any other rejection is per-suite, so
// the walk still owes the remaining candidates an attempt -- a blanket
// stop-on-first-error would silently cut post-auth coverage.
func TestCipherWalkKeepsTryingOnNonExhaustionRejection(t *testing.T) {
	bmc := newRejectingBMC(t, 0x02) // invalid payload type: not a resource problem
	tgt := exhaustionTarget(bmc.port())
	flow := ipmi.AuthFlow{Version: "2.0", Username: "ADMIN", Password: "x",
		Suite: ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityHMACSHA196, Conf: ipmi.ConfAESCBC}}

	inv, err := collectPostAuthWithMatrix(context.Background(), tgt, flow, func(string, ...any) {})
	if err == nil {
		t.Fatal("expected an error from a BMC that refuses every session")
	}
	if ipmi.SessionResourceExhausted(inv, err) {
		t.Fatal("a non-0x01 rejection was classified as session exhaustion")
	}
	if got := bmc.opens.Load(); got < 2 {
		t.Errorf("%d Open Session attempts, want more than 1: a per-suite rejection must not abort the walk", got)
	}
}

func invError(inv *ipmi.PostAuthCollection) string {
	if inv == nil {
		return ""
	}
	return inv.Error
}

// authAlgoRecorder records the auth algorithm each Open Session Request asks for,
// so a test can assert which cipher suite actually went out on the wire.
type authAlgoRecorder struct {
	conn  *net.UDPConn
	algos chan byte
	done  chan struct{}
}

func newAuthAlgoRecorder(t *testing.T) *authAlgoRecorder {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	r := &authAlgoRecorder{conn: conn, algos: make(chan byte, 16), done: make(chan struct{})}
	go r.serve()
	t.Cleanup(func() {
		_ = conn.Close()
		<-r.done
	})
	return r
}

func (r *authAlgoRecorder) port() int { return r.conn.LocalAddr().(*net.UDPAddr).Port }

func (r *authAlgoRecorder) serve() {
	defer close(r.done)
	buf := make([]byte, 2048)
	for {
		n, _, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Open Session Request body: tag(1) priv(1) rsvd(2) consoleSID(4)
		// then the auth payload descriptor, whose algorithm byte is at +12.
		if n >= 16+13 && buf[5]&0x3f == ipmi.PayloadOpenSessionReq {
			select {
			case r.algos <- buf[16+12]:
			default:
			}
		}
		// Never reply: the flow fails, but the request is already recorded.
	}
}

// A cipher-zero flow authenticates by requesting no authentication, so it has
// exactly one valid suite. The cipher matrix skips suite 0, so a cipher-zero flow
// routed through it goes out as an authenticated suite carrying no credential and
// the session is lost. This only bites when cipher zero is the primary flow, which
// is the case on hosts where it is the only credential available.
func TestCipherZeroFlowRequestsSuiteZero(t *testing.T) {
	rec := newAuthAlgoRecorder(t)
	tgt := exhaustionTarget(rec.port()) // advertises suites 3, 8, 12, 17
	flow := ipmi.AuthFlow{
		Version: "2.0", Mode: "cipherZero",
		Suite:  ipmi.CipherAlgos{Suite: 0, Auth: ipmi.RAKPNone, Integrity: ipmi.IntegrityNone, Conf: ipmi.ConfNone},
		Source: "ipmi.auth.cipherZero",
	}

	_, _ = collectPostAuthWithMatrix(context.Background(), tgt, flow, func(string, ...any) {})

	select {
	case algo := <-rec.algos:
		if algo != ipmi.RAKPNone {
			t.Fatalf("Open Session requested auth algo 0x%02x, want 0x%02x (RAKP-none): the cipher matrix "+
				"replaced suite 0 with an authenticated suite, so the empty credential cannot work", algo, ipmi.RAKPNone)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no Open Session Request was sent")
	}
}

// The matrix still owns every other 2.0 flow, so a credentialed flow must keep
// walking the advertised suites rather than being pinned to its preferred one.
func TestCredentialedFlowStillUsesTheCipherMatrix(t *testing.T) {
	rec := newAuthAlgoRecorder(t)
	tgt := exhaustionTarget(rec.port())
	flow := ipmi.AuthFlow{
		Version: "2.0", Mode: "cred", Username: "ADMIN", Password: "x",
		Suite: ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityHMACSHA196, Conf: ipmi.ConfAESCBC},
	}

	_, _ = collectPostAuthWithMatrix(context.Background(), tgt, flow, func(string, ...any) {})

	seen := 0
	for draining := true; draining; {
		select {
		case algo := <-rec.algos:
			seen++
			if algo == ipmi.RAKPNone {
				t.Error("a credentialed flow requested RAKP-none")
			}
		default:
			draining = false
		}
	}
	if seen < 2 {
		t.Errorf("%d Open Session attempts, want more than 1: a credentialed flow should still walk the suite candidates", seen)
	}
}

// privCeilingBMC completes an RMCP+ handshake and then answers every in-session
// command with cc=0xd4, insufficient privilege. The replies go out unprotected
// (payload type 0x00) even though the handshake negotiated integrity and
// confidentiality, which is the Supermicro H3 bypass: the completion code says the
// account may not run the command, the payload type says the BMC never enforced the
// protection it agreed to.
//
// It answers only on the cleartext path. Signing a reply would need the session K1,
// which this package cannot derive, so the set-session-privilege probes the handshake
// issues before the protection mode is applied go unanswered; the session tolerates
// that and the inventory commands that follow are the ones under test.
type privCeilingBMC struct {
	conn   *net.UDPConn
	bmcSID uint32
	opens  atomic.Int64
	clear  atomic.Int64 // in-session commands answered on the cleartext path
	done   chan struct{}
}

func newPrivCeilingBMC(t *testing.T) *privCeilingBMC {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	b := &privCeilingBMC{conn: conn, bmcSID: 0x11223344, done: make(chan struct{})}
	go b.serve()
	t.Cleanup(func() {
		_ = conn.Close()
		<-b.done
	})
	return b
}

func (b *privCeilingBMC) port() int { return b.conn.LocalAddr().(*net.UDPAddr).Port }

func (b *privCeilingBMC) serve() {
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
		payload := pkt[16:]
		switch pkt[5] & 0x3f {
		case ipmi.PayloadOpenSessionReq:
			b.opens.Add(1)
			_, _ = b.conn.WriteToUDP(b.openSessionResp(payload), addr)
		case ipmi.PayloadRAKP1:
			_, _ = b.conn.WriteToUDP(b.rakp2(payload), addr)
		case ipmi.PayloadRAKP3:
			_, _ = b.conn.WriteToUDP(b.rakp4(payload), addr)
		case ipmi.PayloadIPMI:
			if pkt[5]&0xc0 != 0 {
				continue
			}
			b.clear.Add(1)
			_, _ = b.conn.WriteToUDP(b.deniedReply(payload), addr)
		}
	}
}

func (b *privCeilingBMC) frame(ptype byte, payload []byte) []byte {
	var out bytes.Buffer
	out.Write([]byte{ipmi.RMCPVersion, ipmi.RMCPReserved, ipmi.RMCPSeqNoAck, ipmi.RMCPClassIPMI})
	out.WriteByte(ipmi.IPMI20Format)
	out.WriteByte(ptype)
	out.Write([]byte{0, 0, 0, 0})
	out.Write([]byte{0, 0, 0, 0})
	out.Write(binary.LittleEndian.AppendUint16(nil, uint16(len(payload))))
	out.Write(payload)
	return out.Bytes()
}

func (b *privCeilingBMC) openSessionResp(req []byte) []byte {
	p := make([]byte, 0, 36)
	p = append(p, 0x00, 0x00, 0x04, 0x00) // tag, status ok, max priv admin, rsvd
	p = append(p, req[4:8]...)            // echo the console session id
	p = binary.LittleEndian.AppendUint32(p, b.bmcSID)
	p = append(p, req[8:]...) // echo the negotiated algorithm payloads
	return b.frame(ipmi.PayloadOpenSessionRes, p)
}

func (b *privCeilingBMC) rakp2(req []byte) []byte {
	p := make([]byte, 0, 60)
	p = append(p, 0x00, 0x00, 0x00, 0x00)
	p = append(p, req[4:8]...)
	p = append(p, bytes.Repeat([]byte{0xb1}, 16)...) // bmcRand
	p = append(p, bytes.Repeat([]byte{0xc2}, 16)...) // bmc guid
	p = append(p, bytes.Repeat([]byte{0xd3}, 20)...) // key exchange auth code
	return b.frame(ipmi.PayloadRAKP2, p)
}

func (b *privCeilingBMC) rakp4(req []byte) []byte {
	p := make([]byte, 0, 24)
	p = append(p, 0x00, 0x00, 0x00, 0x00)
	p = append(p, req[4:8]...)
	p = append(p, bytes.Repeat([]byte{0x00}, 16)...)
	return b.frame(ipmi.PayloadRAKP4, p)
}

// deniedReply mirrors the request's netfn/cmd back with completion code 0xd4. It is
// a parseable in-session answer, which is exactly why it counts: the client latches
// the protection level it got an answer on.
func (b *privCeilingBMC) deniedReply(req []byte) []byte {
	netfn, rqSeq, cmd := byte(0x18), byte(0x04), byte(0x01)
	if len(req) >= 7 {
		netfn, rqSeq, cmd = req[1], req[4], req[5]
	}
	p := []byte{0x81, netfn | 0x04, 0x00, 0x20, rqSeq, cmd, 0xd4, 0x00}
	return b.frame(ipmi.PayloadIPMI, p)
}

func supermicroCeilingTarget(port int) *engine.Target {
	tgt := exhaustionTarget(port)        // advertises suites 3, 8, 12, 17
	tgt.Timeout = 250 * time.Millisecond // long enough for the local handshake to complete
	tgt.Identity = &engine.Identity{Vendor: "supermicro"}
	return tgt
}

// A session that opens, negotiates integrity, and then answers unprotected packets
// has demonstrated the H3 bypass whatever the completion codes say. When every
// section comes back cc=0xd4 the collection carries no inventory, and dropping it
// for that reason throws away the only record of which protection the BMC accepted,
// silently retiring the ipmi.smc.integrityBypass verdict.
func TestCipherMatrixKeepsProtectionFromAPrivilegeCappedSession(t *testing.T) {
	bmc := newPrivCeilingBMC(t)
	tgt := supermicroCeilingTarget(bmc.port())
	flow := ipmi.AuthFlow{
		Version: "2.0", Mode: "cred", Password: "admin", Source: "ipmi.auth.defaultCreds",
		Suite: ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityHMACSHA196, Conf: ipmi.ConfAESCBC},
	}

	inv, err := collectPostAuthWithMatrix(context.Background(), tgt, flow, func(string, ...any) {})
	if err == nil {
		t.Fatal("expected an error: every section was refused")
	}
	if inv == nil {
		t.Fatal("collection dropped entirely")
	}
	if n := bmc.clear.Load(); n == 0 {
		t.Fatal("no in-session command was answered on the cleartext path, so the fixture is not exercising the H3 latch")
	}
	if inv.CommandProtection != "cleartext" {
		t.Fatalf("commandProtection = %q, want \"cleartext\": the session opened and the BMC answered "+
			"%d unprotected in-session commands, but the matrix discarded that collection because no "+
			"section carried data", inv.CommandProtection, bmc.clear.Load())
	}

	// The observable payoff: the finding this evidence exists to produce.
	if f := smcIntegrityBypassFinding(tgt, inv.Flow, inv); f == nil {
		t.Fatal("ipmi.smc.integrityBypass did not fire on a Supermicro session that accepted cleartext commands")
	}

	// The privilege ceiling belongs to the account, so the other suites can only
	// buy the same refusal at the price of a session open each.
	if got := bmc.opens.Load(); got != 1 {
		t.Errorf("%d Open Session attempts, want 1: the walk re-tested an account-level privilege cap on every cipher suite", got)
	}
}

// The stop above must not become a stop-on-any-failure. A suite that never gets a
// session open leaves nothing latched, so the remaining candidates are still owed
// an attempt.
func TestPrivilegeCeilingStopNeedsAnAnsweredSession(t *testing.T) {
	if postAuthPrivilegeCeiling(&ipmi.PostAuthCollection{CommandProtection: "auto"}) {
		t.Error("an unresolved protection latch means no in-session command was ever answered")
	}
	if postAuthPrivilegeCeiling(&ipmi.PostAuthCollection{}) {
		t.Error("a collection from a session that never opened must not stop the walk")
	}
	if postAuthPrivilegeCeiling(&ipmi.PostAuthCollection{CommandProtection: "cleartext", Completed: []string{"lan"}}) {
		t.Error("a session that collected something is not at a privilege ceiling")
	}
	if !postAuthPrivilegeCeiling(&ipmi.PostAuthCollection{CommandProtection: "integrity+conf"}) {
		t.Error("a resolved latch with no data is the account's ceiling, not the suite's")
	}
	if postAuthSessionOpened(&ipmi.PostAuthCollection{}) {
		t.Error("an empty command protection means the session never opened")
	}
}

// A section that was read and answered with nothing still has to reach the finding
// as a coverage annotation. Without one the record reads as a complete measurement
// and a consumer cannot tell a board with no FRU EEPROM from a FRU read that never
// parsed a field.
func TestEmptySectionsAreNamedInTheCoverageSummary(t *testing.T) {
	inv := &ipmi.PostAuthCollection{
		MCInfo:    &ipmi.MCInfo{},
		LAN:       map[string]string{"ip_addr": "192.0.2.10"},
		Completed: []string{"mcInfo", "lan"},
		Empty:     []string{"chassis", "users", "lan6", "fru"},
	}
	if missing := postAuthMissingSections(inv); !slices.Contains(missing, "fru") {
		t.Errorf("missingSections=%v omits fru, so the coverage block never runs and the finding "+
			"ships with no marker at all", missing)
	}
	got := postAuthInventorySummary(inv)
	if !strings.Contains(got, "empty=chassis,users,lan6,fru") {
		t.Errorf("collected=%q does not name the sections that were read and came back empty", got)
	}
}

// ipmi.smc.integrityBypass asserts that a session accepted a cleartext command
// despite negotiating protection. A suite carrying neither integrity nor
// confidentiality has nothing to bypass, so cipher suite 0 and the integrity-none
// suites must not raise it -- they reach cleartext by agreement.
func TestIntegrityBypassNotClaimedWithoutNegotiatedProtection(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.30", Identity: &engine.Identity{Vendor: "supermicro"}}
	inv := &ipmi.PostAuthCollection{CommandProtection: "cleartext"}

	for _, tc := range []struct {
		name  string
		suite ipmi.CipherAlgos
		want  bool
	}{
		{"cipher suite 0", ipmi.CipherAlgos{Suite: 0, Auth: ipmi.RAKPNone, Integrity: ipmi.IntegrityNone, Conf: ipmi.ConfNone}, false},
		{"integrity-none suite", ipmi.CipherAlgos{Suite: 1, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityNone, Conf: ipmi.ConfNone}, false},
		{"integrity only", ipmi.CipherAlgos{Suite: 2, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityHMACSHA196, Conf: ipmi.ConfNone}, true},
		{"integrity and confidentiality", ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityHMACSHA196, Conf: ipmi.ConfAESCBC}, true},
	} {
		flow := ipmi.AuthFlow{Version: "2.0", Mode: "cred", Suite: tc.suite}
		got := smcIntegrityBypassFinding(tgt, flow, inv) != nil
		if got != tc.want {
			verb := "did not fire"
			if got {
				verb = "fired"
			}
			t.Errorf("%s: integrityBypass %s (integrity=0x%02x conf=0x%02x), want fired=%v",
				tc.name, verb, tc.suite.Integrity, tc.suite.Conf, tc.want)
		}
	}
}

// The cipher walk can open on a different suite than the caller selected and records
// it on the collection. Judging the caller's intent instead of the negotiated suite
// lets an integrity-none session that reached cleartext by agreement be reported as
// a critical integrity bypass.
func TestIntegrityBypassJudgesTheNegotiatedSuiteNotTheRequestedOne(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.31", Identity: &engine.Identity{Vendor: "supermicro"}}
	integrity := ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityHMACSHA196, Conf: ipmi.ConfAESCBC}
	none := ipmi.CipherAlgos{Suite: 1, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityNone, Conf: ipmi.ConfNone}

	// Asked for suite 3, but the walk actually opened on the integrity-none suite.
	requested := ipmi.AuthFlow{Version: "2.0", Mode: "cred", Suite: integrity}
	inv := &ipmi.PostAuthCollection{
		CommandProtection: "cleartext",
		Flow:              ipmi.AuthFlow{Version: "2.0", Mode: "cred", Suite: none},
	}
	if f := smcIntegrityBypassFinding(tgt, requested, inv); f != nil {
		t.Error("integrityBypass fired on a session that negotiated no integrity, because the guard read the requested suite instead of the negotiated one")
	}

	// The genuine case still fires: the session negotiated integrity and took cleartext.
	inv.Flow = ipmi.AuthFlow{Version: "2.0", Mode: "cred", Suite: integrity}
	if f := smcIntegrityBypassFinding(tgt, requested, inv); f == nil {
		t.Error("integrityBypass did not fire on a session that negotiated integrity and accepted cleartext")
	}

	// A collection with no suite of its own falls back to the caller's flow.
	if f := smcIntegrityBypassFinding(tgt, requested, &ipmi.PostAuthCollection{CommandProtection: "cleartext"}); f == nil {
		t.Error("integrityBypass did not fall back to the requested suite when the collection carried none")
	}
}

// A relabel flow being selected only records that the escalation was attempted. The
// finding claims Administrator was reached, so a handshake the BMC rejected must not
// produce one -- otherwise a failed attempt is reported as a completed escalation at
// high severity.
func TestRelabelFindingRequiresAnOpenedSession(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.32", Identity: &engine.Identity{Vendor: "openbmc"}}
	nop := func(string, ...any) {}

	for _, mode := range []string{"openbmcRelabel", "openbmcBypassRelabel"} {
		flow := ipmi.AuthFlow{Version: "2.0", Mode: mode, Username: "low", RelabelUser: "root"}

		// Session never opened: CommandProtection is empty because the collection is
		// the synthetic one built after a rejected handshake.
		failed := &ipmi.PostAuthCollection{Flow: flow, Error: "rakp4 status=0x0f"}
		for _, f := range openBMCRAKPStateFindings(tgt, nil, failed, nop) {
			if f.Check == "ipmi.rakp.state.activeRelabelLowToAdmin" {
				t.Errorf("%s: escalation reported for a session that never opened", mode)
			}
		}

		// Session opened and issued a command: the escalation is real.
		opened := &ipmi.PostAuthCollection{Flow: flow, CommandProtection: "integrity+conf"}
		found := false
		for _, f := range openBMCRAKPStateFindings(tgt, nil, opened, nop) {
			if f.Check == "ipmi.rakp.state.activeRelabelLowToAdmin" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no escalation reported for a session that opened and answered", mode)
		}
	}
}
