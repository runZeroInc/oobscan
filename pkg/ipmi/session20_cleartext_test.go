package ipmi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSession20BuildPayloadCleartextVsNegotiated verifies the on-wire framing of
// the two protection strategies: cleartext must clear the integrity/encrypt
// header bits (payload type 0x00) and omit the integrity trailer, while the
// negotiated path for an integrity-bearing suite must set the auth bit and append
// a trailer.
func TestSession20BuildPayloadCleartextVsNegotiated(t *testing.T) {
	s := &Session20{
		suite: CipherAlgos{Suite: 3, Auth: RAKPHMACSHA1, Integrity: IntegrityHMACSHA196, Conf: ConfNone},
		k1:    bytes.Repeat([]byte{0xaa}, 20),
		seq:   1,
		rqSeq: 1,
	}
	lan := buildSessionLANMsg(NetFnApp, CmdGetDeviceID, nil, s.rqSeq)

	clear, err := s.buildPayload(lan, true)
	if err != nil {
		t.Fatalf("cleartext buildPayload error: %v", err)
	}
	if clear[5] != PayloadIPMI {
		t.Fatalf("cleartext payload type = 0x%02x, want 0x00", clear[5])
	}
	// header(16) + payload(len(lan)); no trailer.
	if want := 16 + len(lan); len(clear) != want {
		t.Fatalf("cleartext packet len = %d, want %d (no integrity trailer expected)", len(clear), want)
	}

	authed, err := s.buildPayload(lan, false)
	if err != nil {
		t.Fatalf("negotiated buildPayload error: %v", err)
	}
	if authed[5]&0x40 == 0 {
		t.Fatalf("negotiated payload type = 0x%02x, want auth bit 0x40 set", authed[5])
	}
	if authed[5]&0x80 != 0 {
		t.Fatalf("negotiated payload type = 0x%02x, want encrypt bit clear (Conf=None)", authed[5])
	}
	if len(authed) <= 16+len(lan) {
		t.Fatalf("negotiated packet len = %d, want > %d (integrity trailer expected)", len(authed), 16+len(lan))
	}
}

// fakeCmdBMC is an in-process UDP responder that replies to in-session command
// packets according to which header protection bits are set, letting the tests
// model an H3-affected BMC (honors cleartext) and a spec-compliant one (drops
// cleartext, requires integrity).
type fakeCmdBMC struct {
	conn           *net.UDPConn
	k1             []byte
	cc             byte
	honorCleartext bool
	honorAuthed    bool
	done           chan struct{}
}

func newFakeCmdBMC(t *testing.T, k1 []byte, cc byte, honorCleartext, honorAuthed bool) *fakeCmdBMC {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	b := &fakeCmdBMC{conn: conn, k1: k1, cc: cc, honorCleartext: honorCleartext, honorAuthed: honorAuthed, done: make(chan struct{})}
	go b.serve()
	return b
}

func (b *fakeCmdBMC) port() int { return b.conn.LocalAddr().(*net.UDPAddr).Port }

func (b *fakeCmdBMC) close() {
	_ = b.conn.Close()
	<-b.done
}

func (b *fakeCmdBMC) serve() {
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
		ptype := buf[5] // RMCP(4) + auth-type(1); payload type is at offset 5
		cleartext := ptype&0x40 == 0 && ptype&0x80 == 0
		authed := ptype&0x40 != 0
		switch {
		case cleartext && b.honorCleartext:
			_, _ = b.conn.WriteToUDP(b.cleartextReply(), addr)
		case authed && b.honorAuthed:
			_, _ = b.conn.WriteToUDP(b.authedReply(), addr)
		default:
			// Silently drop, modeling a BMC that refuses this protection level.
		}
	}
}

// replyPayload is a minimal Get Device ID response body that extractIPMIData can
// parse: 0x81 .. 0x20 with the completion code at offset +6.
func (b *fakeCmdBMC) replyPayload() []byte {
	data := []byte{0x81, byte(NetFnApp<<2) | 0x04, 0x00, 0x20, 0x04, CmdGetDeviceID, b.cc}
	data = append(data, bytes.Repeat([]byte{0x00}, 15)...) // device-id data bytes
	data = append(data, 0x00)                              // trailing checksum (unused by parser)
	return data
}

func (b *fakeCmdBMC) frameHeader(ptype byte, plen int) []byte {
	var hdr bytes.Buffer
	hdr.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	hdr.WriteByte(IPMI20Format)
	hdr.WriteByte(ptype)
	hdr.Write([]byte{0, 0, 0, 0}) // session id
	hdr.Write([]byte{0, 0, 0, 0}) // session seq
	hdr.Write(binary.LittleEndian.AppendUint16(nil, uint16(plen)))
	return hdr.Bytes()
}

func (b *fakeCmdBMC) cleartextReply() []byte {
	p := b.replyPayload()
	return append(b.frameHeader(PayloadIPMI, len(p)), p...)
}

func (b *fakeCmdBMC) authedReply() []byte {
	p := b.replyPayload()
	base := append(b.frameHeader(PayloadIPMI|0x40, len(p)), p...)
	padLen := byte((4 - ((len(base) + 2) % 4)) % 4)
	msg := append(base, bytes.Repeat([]byte{0xff}, int(padLen))...)
	msg = append(msg, padLen, 0x07)
	mac := hmac.New(sha1.New, b.k1)
	mac.Write(msg[4:])
	return append(msg, mac.Sum(nil)[:12]...)
}

func newTestSession(t *testing.T, port int, k1 []byte, prot commandProtection) *Session20 {
	t.Helper()
	c, err := NewClient("127.0.0.1", port, 250*time.Millisecond)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return &Session20{
		client:     c,
		host:       "127.0.0.1",
		port:       port,
		timeout:    250 * time.Millisecond,
		cmdRetries: 1,
		suite:      CipherAlgos{Suite: 3, Auth: RAKPHMACSHA1, Integrity: IntegrityHMACSHA196, Conf: ConfNone},
		k1:         k1,
		seq:        1,
		rqSeq:      1,
		prot:       prot,
	}
}

func TestSession20AutoUsesCleartextWhenHonored(t *testing.T) {
	k1 := bytes.Repeat([]byte{0x11}, 20)
	bmc := newFakeCmdBMC(t, k1, 0x00, true, false) // H3-affected: honors cleartext, refuses integrity
	defer bmc.close()

	s := newTestSession(t, bmc.port(), k1, protectionAuto)
	cc, data, err := s.exec(NetFnApp, CmdGetDeviceID, nil)
	if err != nil {
		t.Fatalf("exec error: %v", err)
	}
	if cc != 0x00 {
		t.Fatalf("cc = 0x%02x, want 0x00", cc)
	}
	if len(data) == 0 {
		t.Fatalf("expected device-id data")
	}
	if got := s.CommandProtectionUsed(); got != "cleartext" {
		t.Fatalf("CommandProtectionUsed = %q, want cleartext", got)
	}
}

func TestSession20AutoFallsBackToNegotiated(t *testing.T) {
	k1 := bytes.Repeat([]byte{0x22}, 20)
	bmc := newFakeCmdBMC(t, k1, 0x00, false, true) // quirk fixed: drops cleartext, honors integrity
	defer bmc.close()

	s := newTestSession(t, bmc.port(), k1, protectionAuto)
	cc, _, err := s.exec(NetFnApp, CmdGetDeviceID, nil)
	if err != nil {
		t.Fatalf("exec error after fallback: %v", err)
	}
	if cc != 0x00 {
		t.Fatalf("cc = 0x%02x, want 0x00", cc)
	}
	if got := s.CommandProtectionUsed(); got != "integrity+conf" {
		t.Fatalf("CommandProtectionUsed = %q, want integrity+conf", got)
	}
	// The strategy must latch: a second command stays on the negotiated path.
	if _, _, err := s.exec(NetFnApp, CmdGetDeviceID, nil); err != nil {
		t.Fatalf("second exec error: %v", err)
	}
}

// TestCollectPostAuthInventoryCleartextLive exercises the scan-lane 2.0 post-auth
// path (CollectPostAuthInventory) against the live X13 VM on a {3,17}-restricted
// cipher-3 flow, asserting it enumerates fully via the H3 cleartext path. Gated
// so `go test ./...` never touches the VM.
func TestCollectPostAuthInventoryCleartextLive(t *testing.T) {
	if os.Getenv("RUN_X13_LIVE") != "1" {
		t.Skip("set RUN_X13_LIVE=1 to run against the live X13 VM")
	}
	host := envOrDefault("X13_HOST", "127.0.0.1")
	port := envIntOrDefault("X13_PORT", 6623)
	user := envOrDefault("X13_USER", "ADMIN")
	pass := envOrDefault("X13_PASS", "ADMIN")

	suite, ok := CipherAlgosFor(3)
	if !ok {
		t.Fatal("cipher suite 3 unavailable in mapping")
	}
	flow := AuthFlow{Version: "2.0", Mode: "cred", Username: user, Password: pass, Suite: suite, Source: "test.live"}
	inv, err := CollectPostAuthInventory(context.Background(), host, port, flow, 3*time.Second)
	if err != nil {
		t.Fatalf("CollectPostAuthInventory error: %v", err)
	}
	if inv.CommandProtection != "cleartext" {
		t.Fatalf("commandProtection = %q, want cleartext (H3 path expected on {3,17})", inv.CommandProtection)
	}
	if inv.MCInfo == nil || len(inv.Users) == 0 {
		t.Fatalf("expected full inventory via cleartext, got mc=%v users=%d", inv.MCInfo != nil, len(inv.Users))
	}
	t.Logf("cleartext post-auth OK: proto=%s mfr=%q fw=%s users=%d lan=%d lan6=%d fru=%d",
		inv.CommandProtection,
		func() string {
			if inv.MCInfo != nil {
				return inv.MCInfo.ManufacturerName
			}
			return ""
		}(),
		func() string {
			if inv.MCInfo != nil {
				return inv.MCInfo.FirmwareRevision
			}
			return ""
		}(),
		len(inv.Users), len(inv.LAN), len(inv.LAN6), len(inv.FRU))
}

func envOrDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envIntOrDefault(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func TestSession20CleartextOnlyFailsCleanlyWhenRejected(t *testing.T) {
	k1 := bytes.Repeat([]byte{0x33}, 20)
	bmc := newFakeCmdBMC(t, k1, 0x00, false, true) // drops cleartext
	defer bmc.close()

	s := newTestSession(t, bmc.port(), k1, protectionCleartext)
	start := time.Now()
	_, _, err := s.exec(NetFnApp, CmdGetDeviceID, nil)
	if err == nil {
		t.Fatalf("expected error when cleartext is rejected and no fallback is allowed")
	}
	// Must fail bounded (single short timeout), never hang.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cleartext-only rejection took %s, want bounded (~250ms)", elapsed)
	}
}
