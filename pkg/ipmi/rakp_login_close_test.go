package ipmi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// fakeLoginBMC completes an RMCP+ handshake far enough for the online login path
// to reach RAKP4, answers with the configured RAKP4 status, and records whether a
// Close Session arrives afterwards.
type fakeLoginBMC struct {
	conn      *net.UDPConn
	rakp4Stat byte
	bmcSID    uint32
	// secret and suite let the responder derive the same session keys the client
	// does, so it can require the Close Session to carry a valid integrity trailer
	// instead of accepting any datagram that merely names the command.
	secret     []byte
	suite      CipherAlgos
	bmcRand    []byte
	clientRand []byte
	closes     atomic.Int64
	closedSIDs chan uint32
	badMAC     atomic.Int64
	done       chan struct{}
}

func newFakeLoginBMC(t *testing.T, rakp4Stat byte, secret []byte, suite CipherAlgos) *fakeLoginBMC {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	b := &fakeLoginBMC{
		conn:       conn,
		rakp4Stat:  rakp4Stat,
		bmcSID:     0x5a5b5c5d,
		secret:     secret,
		suite:      suite,
		bmcRand:    bytes.Repeat([]byte{0xb1}, 16),
		closedSIDs: make(chan uint32, 4),
		done:       make(chan struct{}),
	}
	go b.serve()
	t.Cleanup(func() {
		_ = conn.Close()
		<-b.done
	})
	return b
}

func (b *fakeLoginBMC) port() int { return b.conn.LocalAddr().(*net.UDPAddr).Port }

func (b *fakeLoginBMC) serve() {
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
		case PayloadOpenSessionReq:
			_, _ = b.conn.WriteToUDP(b.openSessionResp(payload), addr)
		case PayloadRAKP1:
			_, _ = b.conn.WriteToUDP(b.rakp2(payload), addr)
		case PayloadRAKP3:
			_, _ = b.conn.WriteToUDP(b.rakp4(payload), addr)
		case PayloadIPMI:
			// In-session request. When the suite carries integrity, the trailer has
			// to verify under the K1 this handshake derived or the real BMC would
			// drop the packet and the slot would stay held.
			body := payload
			if b.suite.Integrity != IntegrityNone {
				if !b.integrityOK(pkt) {
					b.badMAC.Add(1)
					continue
				}
				body = pkt[16 : len(pkt)-14]
			}
			if len(body) >= 10 && body[1] == byte(NetFnApp<<2) && body[5] == CmdCloseSession {
				b.closes.Add(1)
				select {
				case b.closedSIDs <- binary.LittleEndian.Uint32(body[6:10]):
				default:
				}
			}
		}
	}
}

func (b *fakeLoginBMC) frame(ptype byte, payload []byte) []byte {
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

func (b *fakeLoginBMC) openSessionResp(req []byte) []byte {
	p := make([]byte, 0, 36)
	p = append(p, 0x00, 0x00, 0x04, 0x00) // tag, status ok, maxPriv admin, rsvd
	p = append(p, req[4:8]...)            // echo the console SID
	p = binary.LittleEndian.AppendUint32(p, b.bmcSID)
	return b.frame(PayloadOpenSessionRes, p)
}

func (b *fakeLoginBMC) rakp2(req []byte) []byte {
	// RAKP1 layout: tag(1) rsvd(3) bmcSID(4) consoleRand(16) role(1) ...
	if len(req) >= 24 {
		b.clientRand = append([]byte(nil), req[8:24]...)
	}
	p := make([]byte, 0, 60)
	p = append(p, 0x00, 0x00, 0x00, 0x00) // tag, status ok, rsvd x2
	p = append(p, req[4:8]...)            // console SID
	p = append(p, b.bmcRand...)
	p = append(p, bytes.Repeat([]byte{0xc2}, 16)...)
	// Any non-empty auth code satisfies the login path, which does not verify it.
	p = append(p, bytes.Repeat([]byte{0xd3}, 20)...)
	return b.frame(PayloadRAKP2, p)
}

// integrityOK verifies an in-session packet's HMAC-SHA1-96 trailer under the K1
// derived from this handshake at rakpLoginRole. A teardown signed with any other
// role fails here, which is the point.
func (b *fakeLoginBMC) integrityOK(pkt []byte) bool {
	if len(pkt) < 30 || b.clientRand == nil {
		return false
	}
	_, k1, _ := deriveSessionKeysWithRole(b.suite.Auth, b.secret, b.clientRand, b.bmcRand, rakpLoginRole, "ADMIN")
	mac := hmac.New(sha1.New, k1)
	mac.Write(pkt[4 : len(pkt)-12])
	return hmac.Equal(mac.Sum(nil)[:12], pkt[len(pkt)-12:])
}

func (b *fakeLoginBMC) rakp4(req []byte) []byte {
	p := make([]byte, 0, 24)
	p = append(p, 0x00, b.rakp4Stat, 0x00, 0x00)
	p = append(p, req[4:8]...)
	p = append(p, bytes.Repeat([]byte{0x00}, 16)...)
	return b.frame(PayloadRAKP4, p)
}

func (b *fakeLoginBMC) waitForClose(d time.Duration) (uint32, bool) {
	select {
	case sid := <-b.closedSIDs:
		return sid, true
	case <-time.After(d):
		return 0, false
	}
}

// A successful RAKP4 activates a session, and nothing but Close Session or the
// BMC's idle timeout releases it. Without the teardown every accepted credential
// holds a slot for the rest of the scan, which is what drives Open Session into
// answering "insufficient resources" later on.
func TestOnlineLoginClosesTheSessionItActivates(t *testing.T) {
	suite := CipherAlgos{Suite: 1, Auth: RAKPHMACSHA1, Integrity: IntegrityNone, Conf: ConfNone}
	bmc := newFakeLoginBMC(t, 0x00, []byte("s3cret"), suite)

	ok, proof, err := rakpSessionLoginWithSuite("127.0.0.1", bmc.port(), "ADMIN", "s3cret", suite, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !ok {
		t.Fatalf("login did not succeed against a RAKP4=0x00 responder (proof=%q)", proof)
	}

	sid, got := bmc.waitForClose(2 * time.Second)
	if !got {
		t.Fatal("no Close Session arrived, so the activated session was left holding a slot")
	}
	if sid != bmc.bmcSID {
		t.Errorf("Close Session named session 0x%08x, want the BMC-assigned 0x%08x", sid, bmc.bmcSID)
	}
}

// A failed RAKP4 never activates a session, so a Close Session would be traffic
// with nothing to close. It also matters that we not send one: on ATEN the
// failing RAKP3 already released the slot.
func TestOnlineLoginDoesNotCloseOnFailedRAKP4(t *testing.T) {
	suite := CipherAlgos{Suite: 1, Auth: RAKPHMACSHA1, Integrity: IntegrityNone, Conf: ConfNone}
	bmc := newFakeLoginBMC(t, 0x0f, []byte("wrong"), suite) // 0x0f: invalid integrity check value

	ok, _, err := rakpSessionLoginWithSuite("127.0.0.1", bmc.port(), "ADMIN", "wrong", suite, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if ok {
		t.Fatal("login reported success on a non-zero RAKP4 status")
	}
	if _, got := bmc.waitForClose(300 * time.Millisecond); got {
		t.Error("a Close Session was sent for a session that was never activated")
	}
	if n := bmc.closes.Load(); n != 0 {
		t.Errorf("%d in-session Close Session requests sent after a failed login, want 0", n)
	}
}

// The teardown has to sign with the role the handshake signed: RAKP3's auth code
// and the session keys both bind it. This responder accepts the Close Session only
// when its integrity trailer verifies under the K1 derived at that role, so a role
// mismatch shows up as a dropped teardown rather than a silent return of the leak.
func TestOnlineLoginTeardownCarriesValidIntegrity(t *testing.T) {
	suite := CipherAlgos{Suite: 3, Auth: RAKPHMACSHA1, Integrity: IntegrityHMACSHA196, Conf: ConfNone}
	bmc := newFakeLoginBMC(t, 0x00, []byte("s3cret"), suite)

	ok, _, err := rakpSessionLoginWithSuite("127.0.0.1", bmc.port(), "ADMIN", "s3cret", suite, 500*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("login: ok=%v err=%v", ok, err)
	}

	if _, got := bmc.waitForClose(2 * time.Second); !got {
		t.Fatalf("no verifiable Close Session arrived (%d datagrams failed integrity), so a real BMC would have kept the slot",
			bmc.badMAC.Load())
	}
}

// deriveSessionKeysWithRole must actually depend on the role, or the test above
// would pass regardless of which role the teardown signed.
func TestSessionKeyDerivationDependsOnRole(t *testing.T) {
	secret := []byte("s3cret")
	cRand := bytes.Repeat([]byte{0x01}, 16)
	bRand := bytes.Repeat([]byte{0x02}, 16)

	atLogin, _, _ := deriveSessionKeysWithRole(RAKPHMACSHA1, secret, cRand, bRand, rakpLoginRole, "ADMIN")
	atOther, _, _ := deriveSessionKeysWithRole(RAKPHMACSHA1, secret, cRand, bRand, 0x04, "ADMIN")
	if bytes.Equal(atLogin, atOther) {
		t.Fatal("role is not an input to key derivation, so a teardown signed at the wrong role would go undetected")
	}
	if rakpLoginRole != 0x14 {
		t.Errorf("rakpLoginRole = 0x%02x, want 0x14 (name-only lookup | administrator)", rakpLoginRole)
	}
}
