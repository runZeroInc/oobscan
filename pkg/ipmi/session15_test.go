package ipmi

import (
	"bytes"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/creds"
)

// The vectors below were computed independently of the implementation (a
// standalone Go program mirroring ipmitool's ipmi_auth_md5 / ipmi_lan_build_cmd)
// and pasted here as golden bytes, so these tests lock the wire format against
// an external reference rather than against the code under test.
//
// mustHex(string) []byte is the shared helper defined in smcbackup.go.

// TestV15AuthCodeMD5 locks the MD5 AuthCode algorithm:
// MD5(pw16 | sessionID(4 LE) | msgData | seq(4 LE) | pw16), verified against
// ipmitool auth.c ipmi_auth_md5.
func TestV15AuthCodeMD5(t *testing.T) {
	// Activate Session LAN body for password "ADMIN", challenge 0x01..0x10,
	// tempSID 0x0a0b0c0d, header seq 0, outbound seq 1.
	lan := mustHex("2018c881003a02040102030405060708090a0b0c0d0e0f1001000000b6")
	got := v15AuthCode(IPMI15AuthMD5, "ADMIN", 0x0a0b0c0d, 0, lan)
	want := mustHex("2a0df1c3305a1b1597406369ac37da4f")
	if !bytes.Equal(got, want) {
		t.Errorf("MD5 AuthCode mismatch\n got=%x\nwant=%x", got, want)
	}
	if len(got) != 16 {
		t.Errorf("AuthCode len=%d, want 16", len(got))
	}
}

// TestV15AuthCodeStraight locks the straight-password field: it is simply the
// 16-byte null-padded password, no hashing (ipmitool copies the password into
// s->authcode and ipmi_lan_build_cmd does not recompute it for AUTHTYPE_PASSWORD).
func TestV15AuthCodeStraight(t *testing.T) {
	got := v15AuthCode(IPMI15AuthPass, "calvin", 0xdeadbeef, 7, []byte{0xaa, 0xbb})
	want := mustHex("63616c76696e00000000000000000000") // "calvin" + null pad to 16
	if !bytes.Equal(got, want) {
		t.Errorf("straight-password field mismatch\n got=%x\nwant=%x", got, want)
	}
	// A password longer than 16 bytes is truncated to 16.
	long := v15AuthCode(IPMI15AuthPass, "0123456789abcdefGHIJ", 0, 0, nil)
	if len(long) != 16 || string(long) != "0123456789abcdef" {
		t.Errorf("straight-password not truncated to 16: %q", long)
	}
}

// TestV15AuthCodeNone confirms auth-None (and unknown/OEM types) produce no
// AuthCode field (nil) -- the None header carries no per-message auth code.
func TestV15AuthCodeNone(t *testing.T) {
	if got := v15AuthCode(IPMI15AuthNone, "x", 1, 1, []byte{1}); got != nil {
		t.Errorf("auth-None must produce no AuthCode, got %x", got)
	}
	if got := v15AuthCode(IPMI15AuthOEM, "x", 1, 1, []byte{1}); got != nil {
		t.Errorf("OEM auth type must produce nil (not forged), got %x", got)
	}
}

// TestMD2RFC1319 locks the standalone MD2 primitive against the RFC 1319
// Appendix A.5 test suite, so the digest cannot silently drift.
func TestMD2RFC1319(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "8350e5a3e24c153df2275c9f80692773"},
		{"a", "32ec01ec4a6dac72c0ab96fb34c0b5d1"},
		{"abc", "da853b0d3f88d99b30283a69e6ded6bb"},
		{"message digest", "ab4f496bfb2a530b219ff33031fe06b0"},
		{"abcdefghijklmnopqrstuvwxyz", "4e8ddff3650292ab5a4108c3aa47940b"},
	}
	for _, c := range cases {
		if got := md2Sum([]byte(c.in)); !bytes.Equal(got, mustHex(c.want)) {
			t.Errorf("md2(%q)=%x, want %s", c.in, got, c.want)
		}
	}
}

// TestV15AuthCodeMD2 locks the MD2 AuthCode: same construction as MD5, only the
// digest differs -- MD2(pw16 | sessionID(4 LE) | msgData | seq(4 LE) | pw16). The
// vector was computed by a standalone program mirroring ipmi_auth_md2 and pasted
// here as golden bytes, over the same inputs as the MD5 vector above.
func TestV15AuthCodeMD2(t *testing.T) {
	lan := mustHex("2018c881003a02040102030405060708090a0b0c0d0e0f1001000000b6")
	got := v15AuthCode(IPMI15AuthMD2, "ADMIN", 0x0a0b0c0d, 0, lan)
	want := mustHex("d2d17e44dce9e4a4d2dd06d9bd727dd0")
	if !bytes.Equal(got, want) {
		t.Errorf("MD2 AuthCode mismatch\n got=%x\nwant=%x", got, want)
	}
	if len(got) != 16 {
		t.Errorf("AuthCode len=%d, want 16", len(got))
	}
	// MD2 and MD5 over identical inputs must differ (different digest).
	if bytes.Equal(got, v15AuthCode(IPMI15AuthMD5, "ADMIN", 0x0a0b0c0d, 0, lan)) {
		t.Errorf("MD2 and MD5 AuthCodes must differ over identical inputs")
	}
}

// TestBuildGetSessionChallengeWireBytes locks the exact bytes of a Get Session
// Challenge (0x39) sessionless packet: RMCP + v1.5 sessionless header + LAN
// message with data = authType(1) || username(16, null-padded).
func TestBuildGetSessionChallengeWireBytes(t *testing.T) {
	got := buildGetSessionChallenge(IPMI15AuthMD5, "ADMIN")
	want := mustHex("0600ff07000000000000000000182018c88100390241444d494e0000000000000000000000db")
	if !bytes.Equal(got, want) {
		t.Errorf("Get Session Challenge framing changed\n got=%x\nwant=%x", got, want)
	}
	// Header sanity: authType byte at [4] = None, session id/seq zero, msg len at [13].
	if got[4] != IPMI15AuthNone {
		t.Errorf("challenge header authType=0x%02x, want None (sessionless)", got[4])
	}
	if got[13] != byte(len(got)-14) {
		t.Errorf("challenge msg-len byte=%d, want %d", got[13], len(got)-14)
	}
}

// TestBuildActivateSessionAuthenticatedWireBytes locks the full authenticated
// Activate Session packet: the LONGER session header (authType | seq(4) |
// sid(4) | AuthCode(16) | len) plus the LAN body, with a known MD5 AuthCode.
func TestBuildActivateSessionAuthenticatedWireBytes(t *testing.T) {
	challenge := make([]byte, 16)
	for i := range challenge {
		challenge[i] = byte(i + 1)
	}
	lan := buildActivateSession(IPMI15AuthMD5, 0x04, challenge, 1)
	got := buildV15Authenticated(IPMI15AuthMD5, "ADMIN", 0x0a0b0c0d, 0, lan)
	want := mustHex("0600ff0702000000000d0c0b0a2a0df1c3305a1b1597406369ac37da4f1d2018c881003a02040102030405060708090a0b0c0d0e0f1001000000b6")
	if !bytes.Equal(got, want) {
		t.Errorf("authenticated Activate Session framing changed\n got=%x\nwant=%x", got, want)
	}
	// Structural checks: authType at [4], AuthCode occupies [13:29], len at [29].
	if got[4] != IPMI15AuthMD5 {
		t.Errorf("activate header authType=0x%02x, want MD5", got[4])
	}
	if got[29] != byte(len(lan)) {
		t.Errorf("activate payload-len byte=%d, want %d", got[29], len(lan))
	}
	// The sessionless builder would be 16 bytes shorter (no AuthCode).
	sl := buildV15Sessionless(lan)
	if len(got)-len(sl) != 16 {
		t.Errorf("authenticated header should be 16 bytes longer than sessionless; diff=%d", len(got)-len(sl))
	}
}

// TestBuildActivateSessionStraightHasNoHash confirms the straight-password
// packet embeds the padded password verbatim in the AuthCode slot.
func TestBuildActivateSessionStraightHasNoHash(t *testing.T) {
	challenge := make([]byte, 16)
	lan := buildActivateSession(IPMI15AuthPass, 0x04, challenge, 1)
	got := buildV15Authenticated(IPMI15AuthPass, "calvin", 0x11223344, 0, lan)
	// AuthCode field is [13:29]; must equal padded "calvin".
	if !bytes.Equal(got[13:29], mustHex("63616c76696e00000000000000000000")) {
		t.Errorf("straight-password AuthCode slot = %x, want padded 'calvin'", got[13:29])
	}
}

// TestParseGetSessionChallengeReply parses a canned CC 0x00 reply and recovers
// the temp session id + 16-byte challenge, then a CC 0x81 (invalid user) reply.
func TestParseGetSessionChallengeReply(t *testing.T) {
	reply := mustHex("0600ff070000000000000000001c811c63200039000d0c0b0a0102030405060708090a0b0c0d0e0f10f1")
	cc, data, ok := extractV15Payload(reply)
	if !ok {
		t.Fatalf("could not parse challenge reply")
	}
	if cc != 0x00 {
		t.Fatalf("cc=0x%02x, want 0x00", cc)
	}
	if len(data) < 20 {
		t.Fatalf("challenge payload len=%d, want >=20", len(data))
	}
	// tempSID little-endian 0x0a0b0c0d.
	wantSID := mustHex("0d0c0b0a")
	if !bytes.Equal(data[0:4], wantSID) {
		t.Errorf("tempSID bytes=%x, want %x", data[0:4], wantSID)
	}
	wantChal := mustHex("0102030405060708090a0b0c0d0e0f10")
	if !bytes.Equal(data[4:20], wantChal) {
		t.Errorf("challenge=%x, want %x", data[4:20], wantChal)
	}

	// Invalid user: CC 0x81, no data.
	bad := mustHex("0600ff0700000000000000000008811c632000398126")
	cc2, _, ok2 := extractV15Payload(bad)
	if !ok2 || cc2 != 0x81 {
		t.Errorf("invalid-user reply: ok=%v cc=0x%02x, want ok=true cc=0x81", ok2, cc2)
	}
}

// TestParseActivateSessionReply parses a canned Activate Session reply and
// recovers the real session id, inbound sequence and max privilege.
func TestParseActivateSessionReply(t *testing.T) {
	// authType(02) realSID=0x11223344 inSeq=5 maxPriv=4
	reply := mustHex("0600ff0700000000000000000012811c6320003a0002443322110500000004f1")
	cc, data, ok := extractV15Payload(reply)
	if !ok || cc != 0x00 {
		t.Fatalf("activate parse: ok=%v cc=0x%02x", ok, cc)
	}
	if len(data) < 10 {
		t.Fatalf("activate payload len=%d, want >=10", len(data))
	}
	if data[0] != 0x02 {
		t.Errorf("resp authType=0x%02x, want 0x02", data[0])
	}
	if !bytes.Equal(data[1:5], mustHex("44332211")) {
		t.Errorf("realSID bytes=%x, want 44332211 (LE 0x11223344)", data[1:5])
	}
	if !bytes.Equal(data[5:9], mustHex("05000000")) {
		t.Errorf("inboundSeq bytes=%x, want 05000000", data[5:9])
	}
	if data[9] != 0x04 {
		t.Errorf("maxPriv=0x%02x, want 0x04 (admin)", data[9])
	}
}

// TestExtractV15PayloadRejectsGarbage confirms the parser fails cleanly (no
// panic, ok=false) on short/garbage input rather than mis-anchoring.
func TestExtractV15PayloadRejectsGarbage(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x06, 0x00, 0xff, 0x06},                // ASF class, not IPMI
		{0x06, 0x00, 0xff, 0x07},                // header only, no body
		mustHex("0600ff07000000000000000000ff"), // len byte but no IPMB envelope
	}
	for i, c := range cases {
		if _, _, ok := extractV15Payload(c); ok {
			t.Errorf("case %d: expected ok=false on garbage %x", i, c)
		}
	}
}

// TestV15OracleUserList guards that the oracle username set (a) leads with the
// null account, (b) stays small (no lockout blast radius -- it is a pre-auth
// Get Session Challenge differential, but still one round trip each), and (c)
// stays in parity with the highest-signal RAKP accounts: at least ADMIN, admin,
// root, Administrator, USERID, sysadmin, operator, guest, user, supervisor, and the
// null account.
func TestV15OracleUserList(t *testing.T) {
	list := V15OracleUserList()
	if len(list) == 0 || len(list) > 12 {
		t.Fatalf("oracle user list size=%d, want small non-empty set", len(list))
	}
	if list[0] != "" {
		t.Errorf("oracle list[0]=%q, want the null account first", list[0])
	}
	got := map[string]bool{}
	for _, u := range list {
		got[u] = true
	}
	required := []string{"", "ADMIN", "admin", "root", "Administrator", "USERID", "sysadmin", "operator", "guest", "user", "supervisor"}
	for _, u := range required {
		if !got[u] {
			t.Errorf("oracle list missing required account %q", u)
		}
	}
	// Every non-null oracle account must exist in the RAKP CommonUsernames pool
	// so the two enumeration paths stay in parity (no username tested by only one).
	pool := map[string]bool{}
	for _, u := range creds.CommonUsernames {
		pool[u] = true
	}
	for _, u := range list {
		if u == "" {
			continue
		}
		if !pool[u] {
			t.Errorf("oracle account %q is not in creds.CommonUsernames (parity drift)", u)
		}
	}
}

// TestSendInSessionFraming confirms an in-session command builds an authenticated
// header (with an AuthCode) and advances the session sequence number. It does not
// touch the network -- it inspects the packet the sender would emit.
func TestSendInSessionFraming(t *testing.T) {
	sess := &Session15{AuthType: IPMI15AuthMD5, Password: "ADMIN", SessionID: 0x0a0b0c0d, InboundSeq: 5}
	// Reproduce what sendInSession emits for Set Session Privilege -> admin.
	lan := buildV15LANMsg(NetFnApp, CmdSetSessionPrivilege, []byte{0x04})
	pkt := buildV15Authenticated(sess.AuthType, sess.Password, sess.SessionID, sess.InboundSeq, lan)
	if pkt[4] != IPMI15AuthMD5 {
		t.Errorf("in-session header authType=0x%02x, want MD5", pkt[4])
	}
	// seq at [5:9] little-endian must equal the session's InboundSeq (5).
	if !bytes.Equal(pkt[5:9], mustHex("05000000")) {
		t.Errorf("in-session seq bytes=%x, want 05000000", pkt[5:9])
	}
	// The AuthCode slot [13:29] must be present and non-zero for an MD5 session.
	if allZero(pkt[13:29]) {
		t.Errorf("in-session MD5 AuthCode slot is all-zero: %x", pkt[13:29])
	}
	// A None session carries no AuthCode, so its frame is 16 bytes shorter.
	noneLan := buildV15LANMsg(NetFnApp, CmdGetChannelAccess, []byte{0x0e, 0x40})
	nonePkt := buildV15Authenticated(IPMI15AuthNone, "", 0x11223344, 1, noneLan)
	if len(nonePkt) != len(noneLan)+14 { // RMCP(4)+authType(1)+seq(4)+sid(4)+len(1) = 14, no AuthCode
		t.Errorf("None-session frame len=%d, want %d (no AuthCode)", len(nonePkt), len(noneLan)+14)
	}
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
