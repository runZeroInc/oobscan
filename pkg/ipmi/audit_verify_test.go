package ipmi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"testing"
)

// buildRAKP2Wire assembles a spec-correct RAKP-2 packet the way a real BMC
// (matching the pyghmi reference) would, so we can confirm oobscan parses and
// verifies it end-to-end.
func buildRAKP2Wire(clientSID, bmcSID uint32, cRand, bmcRand, bmcGUID []byte, username, password string) []byte {
	// pyghmi RAKP-2 HMAC salt:
	//   <II clientSID bmcSID> + cRand + bmcRand + bmcGUID + <2B (nameonly|priv) userlen> + userid
	var salt bytes.Buffer
	_ = binary.Write(&salt, binary.LittleEndian, clientSID)
	_ = binary.Write(&salt, binary.LittleEndian, bmcSID)
	salt.Write(cRand)
	salt.Write(bmcRand)
	salt.Write(bmcGUID)
	salt.WriteByte(0x14) // nameonly(0x10) | privlevel(0x04)
	salt.WriteByte(byte(len(username)))
	salt.WriteString(username)

	key := make([]byte, 20)
	copy(key, password)
	mac := hmac.New(sha1.New, key)
	mac.Write(salt.Bytes())
	hashv := mac.Sum(nil)

	// RAKP-2 payload: tag(1) status(1) rsvd(2) clientSID(4) bmcRand(16) bmcGUID(16) hmac(20)
	var pl bytes.Buffer
	pl.WriteByte(0x00) // tag
	pl.WriteByte(0x00) // status ok
	pl.Write([]byte{0, 0})
	_ = binary.Write(&pl, binary.LittleEndian, clientSID)
	pl.Write(bmcRand)
	pl.Write(bmcGUID)
	pl.Write(hashv)

	// RMCP+ wrapper
	var pkt bytes.Buffer
	pkt.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	pkt.WriteByte(IPMI20Format)
	pkt.WriteByte(PayloadRAKP2)
	pkt.Write([]byte{0, 0, 0, 0}) // SID
	pkt.Write([]byte{0, 0, 0, 0}) // seq
	_ = binary.Write(&pkt, binary.LittleEndian, uint16(pl.Len()))
	pkt.Write(pl.Bytes())
	return pkt.Bytes()
}

func TestRAKP2RoundTrip(t *testing.T) {
	clientSID := uint32(0xa4a3a2a0)
	bmcSID := uint32(0x02000000)
	cRand := bytes.Repeat([]byte{0x11}, 16)
	bmcRand := bytes.Repeat([]byte{0x22}, 16)
	bmcGUID := bytes.Repeat([]byte{0x33}, 16)
	username := "admin"
	password := "s3cr3t"

	wire := buildRAKP2Wire(clientSID, bmcSID, cRand, bmcRand, bmcGUID, username, password)

	res := &RAKPResult{
		Username:   username,
		AuthAlgo:   RAKPHMACSHA1,
		ClientSID:  clientSID,
		BMCSID:     bmcSID,
		ClientRand: cRand,
	}
	if err := parseRAKP2(wire, res); err != nil {
		t.Fatalf("parseRAKP2: %v", err)
	}
	if !bytes.Equal(res.BMCRand, bmcRand) {
		t.Errorf("BMCRand mismatch: %x", res.BMCRand)
	}
	if !bytes.Equal(res.BMCGUID, bmcGUID) {
		t.Errorf("BMCGUID mismatch: %x", res.BMCGUID)
	}
	if !res.VerifyRAKPPassword(password) {
		t.Errorf("VerifyRAKPPassword failed for correct password (SALT/HMAC MISMATCH)")
	}
	if res.VerifyRAKPPassword("wrong") {
		t.Errorf("VerifyRAKPPassword accepted wrong password")
	}
}

func TestHashcatFormatLength(t *testing.T) {
	// Confirm the -m 7300 fields are populated for a SHA1 result.
	clientSID := uint32(0xa4a3a2a0)
	bmcSID := uint32(0x02000000)
	cRand := bytes.Repeat([]byte{0x11}, 16)
	bmcRand := bytes.Repeat([]byte{0x22}, 16)
	bmcGUID := bytes.Repeat([]byte{0x33}, 16)
	wire := buildRAKP2Wire(clientSID, bmcSID, cRand, bmcRand, bmcGUID, "admin", "pw")
	res := &RAKPResult{Username: "admin", AuthAlgo: RAKPHMACSHA1, ClientSID: clientSID, BMCSID: bmcSID, ClientRand: cRand}
	if err := parseRAKP2(wire, res); err != nil {
		t.Fatal(err)
	}
	hc := res.Hashcat()
	t.Logf("hashcat: %s", hc)
	if len(res.RAKPHash) != 20 {
		t.Errorf("SHA1 hash should be 20 bytes, got %d", len(res.RAKPHash))
	}
}

// buildAuthCapsWire builds a spec-correct IPMI 1.5 Get Channel Auth Caps reply
// as it arrives off the wire (RMCP + v1.5 session header + IPMB response body).
func buildAuthCapsWire(authMask byte, ipmi20, anon, nullUser bool) []byte {
	authByte := authMask & 0x7f
	if ipmi20 {
		authByte |= 0x80
	}
	var statusByte byte
	if anon {
		statusByte |= 0x01
	}
	if nullUser {
		statusByte |= 0x02
	}
	// IPMB response body
	body := []byte{
		0x81,                  // rqAddr (console) in response
		NetFnApp<<2 | 0x04,    // netfn|1 << 2 ... response netfn = App+1 = 0x07 -> 0x1C
		0x00,                  // csum1 placeholder
		0x20,                  // rsAddr (BMC)
		0x00,                  // rqSeq/lun
		CmdGetChannelAuthCaps, // cmd 0x38
		0x00,                  // completion code
		0x0e,                  // channel
		authByte,              // auth type support
		statusByte,            // auth status
		0x00,                  // ext capabilities
		0x00, 0x00, 0x00,      // OEM ID
		0x00, // OEM aux
	}
	body[2] = IPMBChecksum(body[:2])
	body = append(body, IPMBChecksum(body[3:]))

	var pkt bytes.Buffer
	pkt.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	pkt.WriteByte(IPMI15AuthNone)
	pkt.Write([]byte{0, 0, 0, 0}) // seq
	pkt.Write([]byte{0, 0, 0, 0}) // sid
	pkt.WriteByte(byte(len(body)))
	pkt.Write(body)
	return pkt.Bytes()
}

// buildRAKP2NoHMAC builds an auth-None RAKP-2 (status ok, no key-exchange auth
// code) as a cipher-suite-0 BMC would send it. parseRAKP2 must surface
// ErrorCode==0 even though it returns an error for the missing HMAC, so the
// cipher-0 audit case can still key off BMCSID.
func buildRAKP2NoHMAC(clientSID uint32, bmcRand, bmcGUID []byte) []byte {
	var pl bytes.Buffer
	pl.WriteByte(0x00) // tag
	pl.WriteByte(0x00) // status ok
	pl.Write([]byte{0, 0})
	_ = binary.Write(&pl, binary.LittleEndian, clientSID)
	pl.Write(bmcRand)
	pl.Write(bmcGUID)
	// no HMAC trailer

	var pkt bytes.Buffer
	pkt.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	pkt.WriteByte(IPMI20Format)
	pkt.WriteByte(PayloadRAKP2)
	pkt.Write([]byte{0, 0, 0, 0})
	pkt.Write([]byte{0, 0, 0, 0})
	_ = binary.Write(&pkt, binary.LittleEndian, uint16(pl.Len()))
	pkt.Write(pl.Bytes())
	return pkt.Bytes()
}

func TestRAKP2AuthNoneNoHMAC(t *testing.T) {
	bmcRand := bytes.Repeat([]byte{0x22}, 16)
	bmcGUID := bytes.Repeat([]byte{0x33}, 16)
	wire := buildRAKP2NoHMAC(0xa4a3a2a0, bmcRand, bmcGUID)
	res := &RAKPResult{AuthAlgo: RAKPNone}
	err := parseRAKP2(wire, res)
	if err == nil {
		t.Fatalf("expected 'no HMAC' error for auth-None RAKP-2")
	}
	// Critical: ErrorCode must reflect the (ok) status so cipher-0 detection
	// isn't confused by the missing-HMAC error.
	if res.ErrorCode != 0 {
		t.Errorf("ErrorCode should be 0 for status-ok RAKP-2, got 0x%02x", res.ErrorCode)
	}
	if !bytes.Equal(res.BMCGUID, bmcGUID) {
		t.Errorf("BMCGUID should still parse from auth-None RAKP-2")
	}
}

func TestAuthCapsParse(t *testing.T) {
	// authMask: None(0x01) + MD5(0x04) + straight(0x10) = 0x15
	wire := buildAuthCapsWire(0x15, true, true, false)
	// mimic fetchCaps: strip 14 bytes
	if len(wire) < 15 {
		t.Fatal("wire too short")
	}
	ac, err := ParseAuthCapsReply(wire[14:])
	if err != nil {
		t.Fatalf("ParseAuthCapsReply: %v", err)
	}
	t.Logf("CC=0x%02x authMask=0x%02x ipmi20=%v anon=%v null=%v oem=%d",
		ac.CompletionCode, ac.AuthTypeMask, ac.IPMI20, ac.AnonLogin, ac.NullUser, ac.OEMID)
	if ac.CompletionCode != 0x00 {
		t.Errorf("CC should be 0x00, got 0x%02x", ac.CompletionCode)
	}
	if ac.AuthTypeMask != 0x15 {
		t.Errorf("authMask should be 0x15, got 0x%02x", ac.AuthTypeMask)
	}
	if !ac.HasAuthNone() {
		t.Errorf("HasAuthNone should be true (0x01 set)")
	}
	if !ac.HasAuthStraight() {
		t.Errorf("HasAuthStraight should be true (0x10 set)")
	}
	if !ac.IPMI20 {
		t.Errorf("IPMI20 should be true")
	}
	if !ac.AnonLogin {
		t.Errorf("AnonLogin should be true")
	}
	if len(ac.GUID) != 0 {
		t.Errorf("GUID should be empty on a spec-correct auth-caps reply, got %x", ac.GUID)
	}
}

// buildAuthCapsBody returns just the IPMB response body (starting at the first
// address byte) with explicit addressing, auth-status (byte 4) and
// extended-capabilities (byte 5) bytes, plus a 3-byte little-endian OEM ID, so a
// test can exercise both the per-bit decode and the header-framing variants.
// addr0/addr3 are the two IPMB address bytes at +0 and +3. ParseAuthCapsReply
// locates the frame itself, so the RMCP + session wrapper is unnecessary here.
func buildAuthCapsBody(addr0, addr3, authByte, statusByte, extByte byte, oemID uint32) []byte {
	body := []byte{
		addr0,                                            // [0] address (console 0x81 / BMC 0x20 / odd 0x00)
		NetFnApp<<2 | 0x04,                               // [1] netfn|1
		0x00,                                             // [2] csum1 placeholder
		addr3,                                            // [3] address
		0x00,                                             // [4] rqSeq/lun
		CmdGetChannelAuthCaps,                            // [5] cmd 0x38
		0x00,                                             // [6] completion code
		0x0e,                                             // [7] channel
		authByte,                                         // [8] auth type support
		statusByte,                                       // [9] auth status  (byte 4: anon/null/non-null + user-level/per-msg/Kg)
		extByte,                                          // [10] ext capabilities (byte 5: connection support)
		byte(oemID), byte(oemID >> 8), byte(oemID >> 16), // [11..13] OEM ID (LE)
		0x00, // [14] OEM aux
	}
	body[2] = IPMBChecksum(body[:2])
	return append(body, IPMBChecksum(body[3:]))
}

// TestAuthCapsStatusByteBits pins the byte the auth-status bits are decoded from:
// all six share the auth-status byte at start+9 (Get Channel Auth Caps response
// byte 4), not the ext-caps byte at start+10. The vectors below set bits 2/3/4/5 in
// the auth-status byte and none of them in ext-caps, so reading +10 flips
// UserLevelAuth, PerMessageAuth and KG and fails here.
func TestAuthCapsStatusByteBits(t *testing.T) {
	const (
		statusByte = 0x04 | 0x08 | 0x10 | 0x20 // non-null, user-level, per-msg, Kg all set
		extByte    = 0x02                      // typical IPMI-2.0 connection-support value; no status bits
	)
	ac, err := ParseAuthCapsReply(buildAuthCapsBody(0x81, 0x20, 0x15, statusByte, extByte, 0))
	if err != nil {
		t.Fatalf("ParseAuthCapsReply: %v", err)
	}
	// Polarity matches the parser: UserLevelAuth/PerMessageAuth are true when the
	// bit is clear (feature disabled); KG is true when the bit is set (non-zero Kg).
	if ac.UserLevelAuth {
		t.Errorf("UserLevelAuth: bit3 set in auth-status byte -> want false, got true (decoded from ext-caps byte?)")
	}
	if ac.PerMessageAuth {
		t.Errorf("PerMessageAuth: bit4 set in auth-status byte -> want false, got true (decoded from ext-caps byte?)")
	}
	if !ac.KG {
		t.Errorf("KG: bit5 set in auth-status byte -> want true, got false (decoded from ext-caps byte?)")
	}
	// Sanity: the fields sharing the same byte must still decode correctly.
	if ac.AnonLogin {
		t.Errorf("AnonLogin: bit0 clear -> want false, got true")
	}
	if ac.NullUser {
		t.Errorf("NullUser: bit1 clear -> want false, got true")
	}
	if !ac.NonNullUser {
		t.Errorf("NonNullUser: bit2 set -> want true, got false")
	}
}

// TestAuthCapsFramingVariants covers two non-standard IPMB framings seen in the
// wild that a strict 0x81..0x20 anchor mishandles: reversed ordering (BMC 0x20
// first, console 0x81 at +3), and an odd requester address (0x00, no console-side
// byte). Both are valid replies and must decode at the standard offsets.
func TestAuthCapsFramingVariants(t *testing.T) {
	const atenOEM = 21317 // ATEN International -- the OEM ID these odd frames carry
	const (
		authByte   = 0x16        // MD2+MD5+straight, the classic ATEN/Supermicro mask
		statusByte = 0x04 | 0x08 // non-null enabled + user-level-auth disabled
		extByte    = 0x02        // IPMI-2.0 connection support; no status bits
	)
	cases := []struct {
		name         string
		addr0, addr3 byte
	}{
		{"standard console..BMC", 0x81, 0x20},
		{"reversed BMC..console", 0x20, 0x81},
		{"odd requester 0x00", 0x00, 0x20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ac, err := ParseAuthCapsReply(buildAuthCapsBody(tc.addr0, tc.addr3, authByte, statusByte, extByte, atenOEM))
			if err != nil {
				t.Fatalf("ParseAuthCapsReply: %v", err)
			}
			if ac.CompletionCode != 0x00 {
				t.Errorf("CC: want 0x00, got 0x%02x (frame mis-anchored?)", ac.CompletionCode)
			}
			if ac.AuthTypeMask != 0x16 {
				t.Errorf("AuthTypeMask: want 0x16, got 0x%02x", ac.AuthTypeMask)
			}
			if ac.Channel != 0x0e&0x0f {
				t.Errorf("Channel: want %d, got %d", 0x0e&0x0f, ac.Channel)
			}
			if !ac.NonNullUser {
				t.Errorf("NonNullUser: bit2 set -> want true")
			}
			if ac.UserLevelAuth {
				t.Errorf("UserLevelAuth: bit3 set (disabled) -> want false")
			}
			if ac.OEMID != atenOEM {
				t.Errorf("OEMID: want %d, got %d (frame mis-anchored?)", atenOEM, ac.OEMID)
			}
		})
	}
}
