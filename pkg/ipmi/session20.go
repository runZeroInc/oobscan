package ipmi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
	"strings"
	"time"
)

type commandProtection int

const (
	protectionNegotiated commandProtection = iota

	protectionCleartext

	protectionAuto
)

type Session20 struct {
	client     *Client
	host       string
	port       int
	timeout    time.Duration
	cmdRetries int
	username   string
	password   string
	suite      CipherAlgos
	consoleSID uint32
	bmcSID     uint32
	seq        uint32
	rqSeq      byte
	sik        []byte
	k1         []byte
	k2         []byte
	setPriv    []SetPrivAttempt

	prot commandProtection

	autoResolved  bool
	autoCleartext bool
}

func (s *Session20) SetCommandProtection(mode commandProtection) {
	if s == nil {
		return
	}
	s.prot = mode
	s.autoResolved = false
	s.autoCleartext = false
}

func (s *Session20) CommandProtectionUsed() string {
	if s == nil {
		return ""
	}
	switch s.prot {
	case protectionCleartext:
		return "cleartext"
	case protectionAuto:
		if !s.autoResolved {
			return "auto"
		}
		if s.autoCleartext {
			return "cleartext"
		}
		return "integrity+conf"
	default:
		if s.suite.Integrity == IntegrityNone && s.suite.Conf == ConfNone {
			return "none"
		}
		return "integrity+conf"
	}
}

func (s *Session20) effectiveCleartext() bool {
	switch s.prot {
	case protectionCleartext:
		return true
	case protectionAuto:
		if s.autoResolved {
			return s.autoCleartext
		}
		return true
	default:
		return false
	}
}

func (s *Session20) canNegotiate() bool {
	if s.suite.Integrity == IntegrityNone && s.suite.Conf == ConfNone {
		return true
	}
	if s.suite.Integrity != IntegrityNone && len(s.k1) == 0 {
		return false
	}
	if s.suite.Conf != ConfNone && len(s.k2) == 0 {
		return false
	}
	return true
}

type SetPrivAttempt struct {
	Requested byte   `json:"requested"`
	Name      string `json:"name,omitempty"`
	Success   bool   `json:"success"`
	CC        byte   `json:"cc,omitempty"`
	Granted   byte   `json:"granted,omitempty"`
	Error     string `json:"error,omitempty"`
}

func OpenSession20(host string, port int, username, password string, suite CipherAlgos, timeout time.Duration) (*Session20, error) {
	return openSession20WithSecret(host, port, username, []byte(password), password, suite, timeout, 0x04)
}

func OpenSession20User(host string, port int, username, password string, suite CipherAlgos, timeout time.Duration) (*Session20, error) {
	return openSession20WithSecret(host, port, username, []byte(password), password, suite, timeout, 0x02)
}

func OpenSession20WithKey(host string, port int, username string, key []byte, suite CipherAlgos, timeout time.Duration) (*Session20, error) {
	return openSession20WithSecret(host, port, username, append([]byte(nil), key...), "<smcrakp-fixed-key>", suite, timeout, 0x04)
}

func openSession20WithSecret(host string, port int, username string, secret []byte, displayPassword string, suite CipherAlgos, timeout time.Duration, reqPriv byte) (*Session20, error) {
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

	var os bytes.Buffer
	os.WriteByte(0x00)
	os.WriteByte(reqPriv & 0x0f)
	os.Write([]byte{0x00, 0x00})
	_ = binary.Write(&os, binary.LittleEndian, cSID)
	os.Write([]byte{0x00, 0x00, 0x00, 0x08, suite.Auth, 0, 0, 0})
	os.Write([]byte{0x01, 0x00, 0x00, 0x08, suite.Integrity, 0, 0, 0})
	os.Write([]byte{0x02, 0x00, 0x00, 0x08, suite.Conf, 0, 0, 0})

	osResp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadOpenSessionReq, 0, 0, os.Bytes()), handshakeRetries)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("open-session: %w", err)
	}
	bmcSID, err := parseOpenSessionResp(osResp)
	if err != nil {
		c.Close()
		return nil, err
	}

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
	res := &RAKPResult{Username: username, AuthAlgo: suite.Auth, IntegrityAlgo: suite.Integrity, ConfAlgo: suite.Conf, ClientSID: cSID, BMCSID: bmcSID, ClientRand: cRand}
	if err := parseRAKP2(r2Resp, res); err != nil {
		c.Close()
		return nil, err
	}

	kec := []byte(nil)
	if suite.Auth != RAKPNone {
		kec = rakpKEC3ByAlgoKey(suite.Auth, secret, res.BMCRand, cSID, 0x10|(reqPriv&0x0f), username)
	}
	var r3 bytes.Buffer
	r3.WriteByte(0x00)
	r3.WriteByte(0x00)
	r3.Write([]byte{0, 0})
	_ = binary.Write(&r3, binary.LittleEndian, bmcSID)
	r3.Write(kec)

	r3pkt := buildRMCPPlus(PayloadRAKP3, 0, 0, r3.Bytes())
	r4Resp, err := sendWithTimeoutRetry(c, r3pkt, handshakeRetries)
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
		password:   displayPassword,
		suite:      suite,
		consoleSID: cSID,
		bmcSID:     bmcSID,
		seq:        1,
		rqSeq:      1,
	}
	s.sik, s.k1, s.k2 = deriveSessionKeysWithRole(suite.Auth, secret, cRand, res.BMCRand, 0x10|(reqPriv&0x0f), username)
	if displayPassword == "<smcrakp-fixed-key>" {
		s.calibrateSMCRAKPKeys(secret, cRand, res.BMCRand)

		s.cmdRetries = 1
		_, _ = s.setSessionPrivilege(0x04)
		return s, nil
	}
	primary, err := s.setSessionPrivilege(reqPriv & 0x0f)
	if err != nil {
		if !isTimeoutErr(err) {
			s.Close()
			return nil, fmt.Errorf("set-session-privilege: %w", err)
		}

		retry, err2 := s.setSessionPrivilege(reqPriv & 0x0f)
		if err2 == nil {
			if !retry.Success {
				s.probeAlternativePrivileges()
			}
		} else if !isTimeoutErr(err2) {
			s.Close()
			return nil, fmt.Errorf("set-session-privilege: %w", err2)
		}
	} else if !primary.Success {

		s.probeAlternativePrivileges()
	}
	return s, nil
}

func (s *Session20) calibrateSMCRAKPKeys(secret, cRand, bRand []byte) {
	if s == nil || s.client == nil {
		return
	}
	type keyVariant struct {
		key  []byte
		role byte
		user string
	}
	keyCandidates := [][]byte{append([]byte(nil), secret...)}
	for _, cand := range []string{s.username, "ADMIN", "admin", "root", ""} {
		if cand == "" {
			continue
		}
		k := []byte(cand)
		dup := false
		for _, existing := range keyCandidates {
			if bytes.Equal(existing, k) {
				dup = true
				break
			}
		}
		if !dup {
			keyCandidates = append(keyCandidates, append([]byte(nil), k...))
		}
	}

	variants := make([]keyVariant, 0, len(keyCandidates)*2)
	for _, key := range keyCandidates {
		variants = append(variants, keyVariant{key: key, role: 0x14, user: s.username})
		variants = append(variants, keyVariant{key: key, role: 0x04, user: s.username})
	}
	origTimeout := s.client.Timeout
	origRetries := s.cmdRetries
	if s.client.Timeout == 0 || s.client.Timeout > 800*time.Millisecond {
		s.client.Timeout = 800 * time.Millisecond
	}
	s.cmdRetries = 1
	probes := 0
	const maxProbes = 8
	for _, v := range variants {
		if probes >= maxProbes {
			break
		}
		probes++
		sik, k1, k2 := deriveSessionKeysWithRole(s.suite.Auth, v.key, cRand, bRand, v.role, v.user)
		s.sik, s.k1, s.k2 = sik, k1, k2
		cc, data, err := s.exec(NetFnApp, CmdGetDeviceID, nil)
		if err == nil && cc == 0x00 && len(data) > 0 {
			break
		}
	}
	s.client.Timeout = origTimeout
	s.cmdRetries = origRetries
}

func setPrivName(v byte) string {
	switch v {
	case 0x01:
		return "callback"
	case 0x02:
		return "user"
	case 0x03:
		return "operator"
	case 0x04:
		return "admin"
	case 0x05:
		return "oem"
	default:
		return "undefined"
	}
}

func (s *Session20) setSessionPrivilege(requested byte) (SetPrivAttempt, error) {
	at := SetPrivAttempt{Requested: requested, Name: setPrivName(requested)}
	cc, data, err := s.exec(NetFnApp, CmdSetSessionPrivilege, []byte{requested})
	if err != nil {
		at.Error = err.Error()
		s.setPriv = append(s.setPriv, at)
		return at, err
	}
	at.CC = cc
	at.Success = cc == 0x00
	if len(data) >= 1 {
		at.Granted = data[0]
	}
	if cc != 0x00 {
		at.Error = fmt.Sprintf("cc=0x%02x", cc)
	}
	s.setPriv = append(s.setPriv, at)
	return at, nil
}

func (s *Session20) probeAlternativePrivileges() {
	if s == nil {
		return
	}

	if s.timeout <= 4*time.Second {
		return
	}

	for _, pv := range []byte{0x02, 0x03, 0x01, 0x05, 0x00, 0x06, 0x0f} {
		_, _ = s.setSessionPrivilege(pv)
	}
}

func (s *Session20) SetPrivilegeAttempts() []SetPrivAttempt {
	if s == nil || len(s.setPriv) == 0 {
		return nil
	}
	out := make([]SetPrivAttempt, len(s.setPriv))
	copy(out, s.setPriv)
	return out
}

func (s *Session20) RequestSessionPrivilege(requested byte) (SetPrivAttempt, error) {
	if s == nil || s.client == nil {
		return SetPrivAttempt{}, errors.New("session20: closed")
	}
	return s.setSessionPrivilege(requested)
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout")
}

func sendWithTimeoutRetry(c *Client, pkt []byte, attempts int) ([]byte, error) {
	if attempts <= 0 {
		attempts = 1
	}
	var (
		reply []byte
		err   error
	)
	for attempt := 0; attempt < attempts; attempt++ {
		reply, err = c.Send(pkt)
		if err == nil {
			return reply, nil
		}
		if !isTimeoutErr(err) {
			return nil, err
		}
	}
	return nil, err
}

func rakpStatusText(code byte) string {
	switch code {
	case 0x00:
		return "no errors"
	case 0x01:
		return "insufficient resources for session"
	case 0x02:
		return "invalid session id"
	case 0x03:
		return "invalid payload type"
	case 0x04:
		return "invalid authentication algorithm"
	case 0x05:
		return "invalid integrity algorithm"

	case 0x06:
		return "no matching authentication payload"
	case 0x07:
		return "no matching integrity payload"
	case 0x08:

		return "inactive session id"
	case 0x09:
		return "invalid role"
	case 0x0a:
		return "unauthorized role or privilege level requested"
	case 0x0b:
		return "insufficient resources to create a session at the requested role"
	case 0x0c:
		return "invalid name length"
	case 0x0d:
		return "unauthorized name"
	case 0x0e:
		return "unauthorized guid"
	case 0x0f:
		return "invalid integrity check value"
	case 0x10:
		return "invalid confidentiality algorithm"
	case 0x11:
		return "no cipher suite match with proposed security algorithms"
	default:
		return "session activation failed"
	}
}

func session20HandshakeRetries(timeout time.Duration) int {

	if timeout <= 4*time.Second {
		return 1
	}
	if timeout <= 5*time.Second {
		return 2
	}
	return 3
}

func session20CommandRetries(timeout time.Duration) int {
	if timeout <= 4*time.Second {
		return 1
	}
	return 2
}

func (s *Session20) Close() {
	if s == nil || s.client == nil {
		return
	}

	_, _, _ = s.execOnce(NetFnApp, CmdCloseSession, binary.LittleEndian.AppendUint32(nil, s.bmcSID), s.effectiveCleartext(), 1)
	_ = s.client.Close()
	s.client = nil
}

func closeActivatedRAKPSession(c *Client, username string, secret, cRand, bRand []byte, suite CipherAlgos, consoleSID, bmcSID uint32, timeout time.Duration) {
	if c == nil {
		return
	}
	s := &Session20{
		client:     c,
		timeout:    timeout,
		cmdRetries: 1,
		username:   username,
		suite:      suite,
		consoleSID: consoleSID,
		bmcSID:     bmcSID,
		seq:        1,
		rqSeq:      1,
	}
	s.sik, s.k1, s.k2 = deriveSessionKeysWithRole(suite.Auth, secret, cRand, bRand, rakpLoginRole, username)
	s.Close()
}

func (s *Session20) Exec(netfn, cmd byte, data []byte) (byte, []byte, error) {
	if s == nil || s.client == nil {
		return 0xff, nil, errors.New("session20: closed")
	}
	return s.exec(netfn, cmd, data)
}

func (s *Session20) exec(netfn, cmd byte, data []byte) (byte, []byte, error) {
	switch s.prot {
	case protectionCleartext:
		return s.execOnce(netfn, cmd, data, true, s.cmdRetries)
	case protectionAuto:
		if s.autoResolved {
			return s.execOnce(netfn, cmd, data, s.autoCleartext, s.cmdRetries)
		}
		return s.execAutoProbe(netfn, cmd, data)
	default:
		return s.execOnce(netfn, cmd, data, false, s.cmdRetries)
	}
}

func (s *Session20) execAutoProbe(netfn, cmd byte, data []byte) (byte, []byte, error) {

	cc, out, err := s.execOnce(netfn, cmd, data, true, 1)
	if err == nil {
		s.autoResolved = true
		s.autoCleartext = true
		return cc, out, nil
	}
	if !s.canNegotiate() {

		return cc, out, err
	}
	cc2, out2, err2 := s.execOnce(netfn, cmd, data, false, s.cmdRetries)
	if err2 == nil {
		s.autoResolved = true
		s.autoCleartext = false
		return cc2, out2, nil
	}
	return cc2, out2, err2
}

func (s *Session20) execOnce(netfn, cmd byte, data []byte, cleartext bool, retries int) (byte, []byte, error) {
	lan := buildSessionLANMsg(netfn, cmd, data, s.rqSeq)
	s.advanceRqSeq()
	pkt, err := s.buildPayload(lan, cleartext)
	if err != nil {
		return 0xff, nil, err
	}
	if retries <= 0 {
		retries = 2
	}
	reply, err := sendWithTimeoutRetry(s.client, pkt, retries)
	if err != nil {
		return 0xff, nil, err
	}
	body, err := s.parseReplyPayload(reply)
	if err != nil {
		return 0xff, nil, err
	}
	dataOut, cc, ok := extractIPMIData(body)
	if !ok {
		return 0xff, nil, errors.New("session20: unparseable ipmi payload")
	}
	return cc, dataOut, nil
}

func (s *Session20) advanceRqSeq() {
	s.rqSeq = (s.rqSeq + 1) & 0x3f
	if s.rqSeq == 0 {
		s.rqSeq = 1
	}
}

func buildSessionLANMsg(netfn, cmd byte, data []byte, rqSeq byte) []byte {
	body := make([]byte, 0, 7+len(data))
	body = append(body, 0x20)
	body = append(body, netfn<<2)
	body = append(body, 0x00)
	body[2] = IPMBChecksum(body[:2])
	body = append(body, 0x81)
	body = append(body, (rqSeq&0x3f)<<2)
	body = append(body, cmd)
	body = append(body, data...)
	body = append(body, IPMBChecksum(body[3:]))
	return body
}

func (s *Session20) buildPayload(ipmiPayload []byte, cleartext bool) ([]byte, error) {

	encrypted := !cleartext && s.suite.Conf != ConfNone
	authed := !cleartext && s.suite.Integrity != IntegrityNone
	if encrypted && s.suite.Conf != ConfAESCBC {
		return nil, fmt.Errorf("session20: unsupported confidentiality algorithm 0x%02x", s.suite.Conf)
	}

	payloadType := PayloadIPMI
	payload := ipmiPayload
	if encrypted {
		enc, err := s.encryptPayload(ipmiPayload)
		if err != nil {
			return nil, err
		}
		payloadType |= 0x80
		payload = enc
	}
	if authed {
		payloadType |= 0x40
	}

	var hdr bytes.Buffer
	hdr.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	hdr.WriteByte(IPMI20Format)
	hdr.WriteByte(payloadType)
	hdr.Write(binary.LittleEndian.AppendUint32(nil, s.bmcSID))
	hdr.Write(binary.LittleEndian.AppendUint32(nil, s.seq))
	hdr.Write(binary.LittleEndian.AppendUint16(nil, uint16(len(payload))))
	s.seq++
	if s.seq == 0 {
		s.seq = 1
	}

	base := append(hdr.Bytes(), payload...)
	if !authed {
		return base, nil
	}
	padLen := byte((4 - ((len(base) + 2) % 4)) % 4)
	trailPad := bytes.Repeat([]byte{0xff}, int(padLen))
	msg := append(base, trailPad...)
	msg = append(msg, padLen, 0x07)
	mac := s.integrityMac(msg[4:])
	msg = append(msg, mac...)
	return msg, nil
}

func (s *Session20) parseReplyPayload(pkt []byte) ([]byte, error) {
	if len(pkt) < 16 {
		return nil, errors.New("session20: short packet")
	}
	if pkt[3] != RMCPClassIPMI || pkt[4] != IPMI20Format {
		return nil, errors.New("session20: not RMCP+ IPMI")
	}
	ptype := pkt[5]
	encrypted := (ptype & 0x80) != 0
	authed := (ptype & 0x40) != 0
	plen := int(binary.LittleEndian.Uint16(pkt[14:16]))
	if len(pkt) < 16+plen {
		return nil, errors.New("session20: truncated payload")
	}
	body := pkt[16:]
	payload := body[:plen]
	rest := body[plen:]

	if authed {
		macLen := s.integrityMacLen()
		if len(rest) < 2+macLen {
			return nil, errors.New("session20: short auth trailer")
		}
		padLen := int(rest[len(rest)-2-macLen])
		if len(rest) < padLen+2+macLen {
			return nil, errors.New("session20: malformed auth trailer")
		}
		msgNoMac := pkt[:16+plen+len(rest)-macLen]
		expect := s.integrityMac(msgNoMac[4:])
		got := rest[len(rest)-macLen:]
		if !hmac.Equal(expect, got) {
			return nil, errors.New("session20: bad integrity MAC")
		}
		_ = padLen
	}
	if !encrypted {
		return payload, nil
	}
	if s.suite.Conf != ConfAESCBC {
		return nil, fmt.Errorf("session20: unsupported confidentiality algorithm 0x%02x", s.suite.Conf)
	}
	return s.decryptPayload(payload)
}

func (s *Session20) encryptPayload(p []byte) ([]byte, error) {
	key := s.confKey()
	if len(key) < 16 {
		return nil, errors.New("session20: short AES key")
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	padLen := (aes.BlockSize - ((len(p) + 1) % aes.BlockSize)) % aes.BlockSize
	plain := make([]byte, 0, len(p)+padLen+1)
	plain = append(plain, p...)
	for i := 1; i <= padLen; i++ {
		plain = append(plain, byte(i))
	}
	plain = append(plain, byte(padLen))
	blk, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, plain)
	return append(iv, ct...), nil
}

func (s *Session20) decryptPayload(p []byte) ([]byte, error) {
	if len(p) < aes.BlockSize || (len(p)-aes.BlockSize)%aes.BlockSize != 0 {
		return nil, errors.New("session20: malformed encrypted payload")
	}
	key := s.confKey()
	if len(key) < 16 {
		return nil, errors.New("session20: short AES key")
	}
	iv := p[:aes.BlockSize]
	ct := p[aes.BlockSize:]
	blk, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(pt, ct)
	if len(pt) < 1 {
		return nil, errors.New("session20: short decrypted payload")
	}
	padLen := int(pt[len(pt)-1])
	if len(pt) < padLen+1 {
		return nil, errors.New("session20: bad decrypted padding")
	}
	return append([]byte(nil), pt[:len(pt)-1-padLen]...), nil
}

func (s *Session20) integrityMac(msg []byte) []byte {
	if s.suite.Integrity == IntegrityNone {
		return nil
	}
	mac := hmacByIntegrityAlgo(s.suite.Integrity, s.k1)
	mac.Write(msg)
	sum := mac.Sum(nil)
	sz := s.integrityMacLen()
	if len(sum) > sz {
		return sum[:sz]
	}
	return sum
}

func (s *Session20) integrityMacLen() int {
	if s.suite.Integrity == IntegrityNone {
		return 0
	}
	switch s.suite.Integrity {
	case IntegrityHMACSHA196:
		return 12
	case IntegrityHMACMD5128, IntegrityMD5128, IntegrityHMACSHA256128:
		return 16
	default:
		return 12
	}
}

func (s *Session20) confKey() []byte {
	if len(s.k2) > 0 {
		return s.k2
	}
	return []byte(s.password)
}

func hmacByIntegrityAlgo(algo byte, key []byte) hash.Hash {
	switch algo {
	case IntegrityHMACSHA196:
		return hmac.New(sha1.New, key)
	case IntegrityHMACMD5128, IntegrityMD5128:
		return hmac.New(md5.New, key)
	case IntegrityHMACSHA256128:
		return hmac.New(sha256.New, key)
	default:
		return hmac.New(sha1.New, key)
	}
}

func deriveSessionKeys(authAlgo byte, password, cRand, bRand []byte, username string) (sik, k1, k2 []byte) {
	return deriveSessionKeysWithRole(authAlgo, password, cRand, bRand, 0x14, username)
}

func deriveSessionKeysWithRole(authAlgo byte, password, cRand, bRand []byte, role byte, username string) (sik, k1, k2 []byte) {
	if authAlgo == RAKPNone {
		return nil, nil, nil
	}
	mac := hmacByAlgo(authAlgo, password)
	mac.Write(cRand)
	mac.Write(bRand)
	mac.Write([]byte{role, byte(len(username))})
	mac.Write([]byte(username))
	sik = mac.Sum(nil)

	const kConstLen = 20
	m1 := hmacByAlgo(authAlgo, sik)
	m1.Write(bytes.Repeat([]byte{0x01}, kConstLen))
	k1 = m1.Sum(nil)
	m2 := hmacByAlgo(authAlgo, sik)
	m2.Write(bytes.Repeat([]byte{0x02}, kConstLen))
	k2 = m2.Sum(nil)
	return sik, k1, k2
}
