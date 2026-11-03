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

// This file measures what an enabled null/anonymous IPMI account can actually
// reach rather than inferring it from the Get Channel Auth Caps byte-2 bits: an
// account can be enabled yet pinned at IPMI privilege 0, while the Open Session
// Response still advertises ADMINISTRATOR as the channel maximum. The reliable
// oracle is in-session Set Session Privilege Level (0x06/0x3b) with request byte
// 0x00, which returns the session's present privilege level and is answered even
// at privilege 0, where every inventory command returns 0xd4.

// Privilege levels as they appear in the Set Session Privilege Level reply and
// the per-user channel access table. Level 0 is what an enabled-but-clamped
// account lands on: the spec calls it "unspecified", and it grants almost
// nothing.
const (
	PrivUnspecified   byte = 0x00
	PrivCallback      byte = 0x01
	PrivUser          byte = 0x02
	PrivOperator      byte = 0x03
	PrivAdministrator byte = 0x04
	PrivOEM           byte = 0x05
	PrivNoAccess      byte = 0x0f
)

// PrivilegeName renders an IPMI privilege level for reporting.
func PrivilegeName(level byte) string {
	switch level & 0x0f {
	case PrivUnspecified:
		return "unspecified"
	case PrivCallback:
		return "callback"
	case PrivUser:
		return "user"
	case PrivOperator:
		return "operator"
	case PrivAdministrator:
		return "administrator"
	case PrivOEM:
		return "oem"
	case PrivNoAccess:
		return "noAccess"
	default:
		return fmt.Sprintf("unknown(0x%02x)", level&0x0f)
	}
}

// SOLConfig is a Get SOL Configuration Parameters readout. Every field is
// optional because a BMC may answer some selectors and refuse others.
type SOLConfig struct {
	// ParamRevision is the parameter-revision byte every reply leads with.
	ParamRevision byte `json:"paramRevision,omitempty"`
	// Enabled reports parameter 1 bit 0 (SOL payload enabled on this channel).
	Enabled   bool `json:"enabled"`
	EnabledOK bool `json:"enabledOk"`
	// RequiredPrivilege is parameter 2 bits 3:0 -- the privilege an account needs
	// to actually activate SOL, which is normally higher than the privilege that
	// was able to read this parameter.
	RequiredPrivilege   byte `json:"requiredPrivilege,omitempty"`
	RequiredPrivilegeOK bool `json:"requiredPrivilegeOk"`
	// PayloadChannel is parameter 7; PayloadPort is parameter 8 (little-endian).
	PayloadChannel   byte   `json:"payloadChannel,omitempty"`
	PayloadChannelOK bool   `json:"payloadChannelOk"`
	PayloadPort      uint16 `json:"payloadPort,omitempty"`
	PayloadPortOK    bool   `json:"payloadPortOk"`
	// Params keeps the raw hex per parameter selector that answered, so a reply
	// this parser does not model is still recorded as evidence.
	Params map[byte]string `json:"params,omitempty"`
}

// Readable reports whether any SOL parameter answered.
func (s *SOLConfig) Readable() bool {
	return s != nil && len(s.Params) > 0
}

// Summary renders the readable SOL parameters as a stable one-line description.
func (s *SOLConfig) Summary() string {
	if !s.Readable() {
		return ""
	}
	var parts []string
	if s.EnabledOK {
		parts = append(parts, fmt.Sprintf("solEnabled=%t", s.Enabled))
	}
	if s.RequiredPrivilegeOK {
		parts = append(parts, fmt.Sprintf("requiredPrivilege=%s", PrivilegeName(s.RequiredPrivilege)))
	}
	if s.PayloadChannelOK {
		parts = append(parts, fmt.Sprintf("payloadChannel=%d", s.PayloadChannel))
	}
	if s.PayloadPortOK {
		parts = append(parts, fmt.Sprintf("payloadPort=%d", s.PayloadPort))
	}
	return strings.Join(parts, " ")
}

// NullUserPrivProbe is the measured impact of an enabled null/anonymous account.
// A nil SOLConfig means the SOL read was not reached or was denied.
type NullUserPrivProbe struct {
	// Username is the account named in RAKP-1: "" for the null user.
	Username string `json:"username"`
	// Suite is the cipher suite that activated the session.
	Suite int `json:"suite"`
	// Activated reports whether RMCP+ session establishment completed. When
	// false, Error says why and no privilege was measured.
	Activated bool   `json:"activated"`
	Error     string `json:"error,omitempty"`
	// OpenSessionMaxPriv is the Maximum Privilege Level from the Open Session
	// Response. It is the channel ceiling and is routinely ADMINISTRATOR even for
	// an account clamped to 0, so it is recorded to document the discrepancy, not
	// as a measurement.
	OpenSessionMaxPriv byte `json:"openSessionMaxPriv"`
	// Privilege is the session's present privilege level from Set Session
	// Privilege Level request 0x00. PrivilegeOK is false when the command itself
	// did not answer (PrivilegeCC carries the completion code if one came back).
	Privilege   byte `json:"privilege"`
	PrivilegeOK bool `json:"privilegeOk"`
	PrivilegeCC byte `json:"privilegeCc,omitempty"`
	// Protection is the wire protection the session's commands actually used:
	// "cleartext" or "integrity+conf". A privilege-0 ATEN session commonly only
	// answers cleartext (payload type 0x00), which is why the probe does not
	// insist on the negotiated path.
	Protection string `json:"protection,omitempty"`
	// DeviceIDCC is the completion code from Get Device ID, the cheapest
	// impact witness: a clamped null account returns 0xd4 (insufficient
	// privilege) where a genuinely useful one returns 0x00.
	DeviceIDCC   byte `json:"deviceIdCc"`
	DeviceIDOK   bool `json:"deviceIdOk"`
	DeviceIDSeen bool `json:"deviceIdSeen"`
	// SOL is the Get SOL Config readout, when it answered.
	SOL *SOLConfig `json:"sol,omitempty"`
}

// UsableAccess reports whether the measured privilege is USER (2) or above -- the
// threshold at which the account can read inventory (sensors, FRU, SEL) rather
// than just the handful of commands a privilege-0 session reaches.
func (p *NullUserPrivProbe) UsableAccess() bool {
	return p != nil && p.Activated && p.PrivilegeOK && p.Privilege >= PrivUser && p.Privilege != PrivNoAccess
}

// Status renders a short machine-stable outcome for reporting.
func (p *NullUserPrivProbe) Status() string {
	switch {
	case p == nil:
		return "notProbed"
	case !p.Activated:
		return "sessionFailed"
	case !p.PrivilegeOK:
		return "privilegeUnmeasured"
	default:
		return "measured"
	}
}

// OpenSession20NullUser activates an RMCP+ session as an empty-password account
// (username "" for the IPMI null user), skipping the privilege escalation
// OpenSession20 performs because that would mutate the state being measured. Open
// Session requests maximum privilege 0x00 (unspecified -- let the BMC clamp to
// whatever the account holds) while RAKP-1 asks for the ADMINISTRATOR role (0x14,
// lookup-by-role). Command protection stays on the cleartext-first auto strategy:
// a privilege-0 ATEN session commonly answers only payload type 0x00.
func OpenSession20NullUser(host string, port int, username string, suite CipherAlgos, timeout time.Duration) (*Session20, byte, error) {
	if suite.Auth == RAKPNone {
		// Cipher-zero needs no account at all, so a "null user" result over it
		// would measure the cipher-zero bypass instead of the account.
		return nil, 0, errors.New("null-user probe requires an authenticated cipher suite (not cipher-zero)")
	}
	const (
		openPriv  = 0x00 // Open Session requested maximum privilege: unspecified
		rakp1Role = 0x14 // RAKP-1 requested role: lookup-by-role, ADMINISTRATOR
	)

	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, 0, err
	}
	handshakeRetries := session20HandshakeRetries(timeout)

	var cSID uint32
	if err := binary.Read(rand.Reader, binary.LittleEndian, &cSID); err != nil || cSID == 0 {
		cSID = 0xc0c1c2c3
	}
	cRand := make([]byte, 16)
	if _, err := rand.Read(cRand); err != nil {
		c.Close()
		return nil, 0, err
	}

	var os bytes.Buffer
	os.WriteByte(0x00)
	os.WriteByte(openPriv)
	os.Write([]byte{0x00, 0x00})
	_ = binary.Write(&os, binary.LittleEndian, cSID)
	os.Write([]byte{0x00, 0x00, 0x00, 0x08, suite.Auth, 0, 0, 0})
	os.Write([]byte{0x01, 0x00, 0x00, 0x08, suite.Integrity, 0, 0, 0})
	os.Write([]byte{0x02, 0x00, 0x00, 0x08, suite.Conf, 0, 0, 0})
	osResp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadOpenSessionReq, 0, 0, os.Bytes()), handshakeRetries)
	if err != nil {
		c.Close()
		return nil, 0, fmt.Errorf("open-session: %w", err)
	}
	bmcSID, maxPriv, err := parseOpenSessionRespFull(osResp)
	if err != nil {
		c.Close()
		return nil, 0, err
	}

	// RAKP-1. The empty password is the account's real key material on a normal
	// null account; on a SMCRAKP-enabled ATEN unit the firmware substitutes its
	// own constant and this succeeds regardless, which is why RAKP4 success alone
	// is not treated as evidence of anything beyond session establishment.
	secret := []byte{}
	var r1 bytes.Buffer
	r1.WriteByte(0x00)
	r1.Write([]byte{0, 0, 0})
	_ = binary.Write(&r1, binary.LittleEndian, bmcSID)
	r1.Write(cRand)
	r1.WriteByte(rakp1Role)
	r1.Write([]byte{0, 0})
	r1.WriteByte(byte(len(username)))
	r1.WriteString(username)
	r2Resp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadRAKP1, 0, 0, r1.Bytes()), handshakeRetries)
	if err != nil {
		c.Close()
		return nil, maxPriv, fmt.Errorf("rakp1: %w", err)
	}
	res := &RAKPResult{
		Username: username, AuthAlgo: suite.Auth, IntegrityAlgo: suite.Integrity,
		ConfAlgo: suite.Conf, ClientSID: cSID, BMCSID: bmcSID, ClientRand: cRand,
	}
	if err := parseRAKP2(r2Resp, res); err != nil {
		c.Close()
		return nil, maxPriv, err
	}

	// RAKP-3.
	var r3 bytes.Buffer
	r3.WriteByte(0x00)
	r3.WriteByte(0x00)
	r3.Write([]byte{0, 0})
	_ = binary.Write(&r3, binary.LittleEndian, bmcSID)
	r3.Write(rakpKEC3ByAlgoKey(suite.Auth, secret, res.BMCRand, cSID, rakp1Role, username))
	r4Resp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadRAKP3, 0, 0, r3.Bytes()), handshakeRetries)
	if err != nil {
		c.Close()
		return nil, maxPriv, fmt.Errorf("rakp3: %w", err)
	}
	p, err := rmcpPlusPayload(r4Resp)
	if err != nil {
		c.Close()
		return nil, maxPriv, err
	}
	if len(p) < 2 {
		c.Close()
		return nil, maxPriv, errors.New("short RAKP4")
	}
	if p[1] != 0x00 {
		c.Close()
		return nil, maxPriv, fmt.Errorf("rakp4 status=0x%02x (%s)", p[1], rakpStatusText(p[1]))
	}

	s := &Session20{
		client:     c,
		host:       host,
		port:       port,
		timeout:    timeout,
		cmdRetries: session20CommandRetries(timeout),
		username:   username,
		password:   "",
		suite:      suite,
		consoleSID: cSID,
		bmcSID:     bmcSID,
		seq:        1,
		rqSeq:      1,
	}
	s.sik, s.k1, s.k2 = deriveSessionKeysWithRole(suite.Auth, secret, cRand, res.BMCRand, rakp1Role, username)
	s.SetCommandProtection(protectionAuto)
	return s, maxPriv, nil
}

// PresentPrivilege measures the session's current privilege level with Set
// Session Privilege Level (0x06/0x3b) request byte 0x00. Request 0 means "return
// the present level" -- it changes nothing and is answered even at privilege 0,
// where Get Device ID and every inventory command return 0xd4.
func (s *Session20) PresentPrivilege() (level byte, cc byte, err error) {
	if s == nil || s.client == nil {
		return 0, 0xff, errors.New("session20: closed")
	}
	cc, data, err := s.Exec(NetFnApp, CmdSetSessionPrivilege, []byte{0x00})
	if err != nil {
		return 0, cc, err
	}
	if cc != 0x00 {
		return 0, cc, fmt.Errorf("set-session-privilege query: cc=0x%02x", cc)
	}
	if len(data) < 1 {
		return 0, cc, errors.New("set-session-privilege query: empty reply")
	}
	return data[0] & 0x0f, cc, nil
}

// ReadSOLConfig reads the SOL exposure parameters over this session. Each
// selector is independent, so a partial answer is kept rather than discarded.
// Returns nil when no selector answered.
func (s *Session20) ReadSOLConfig(channel byte) *SOLConfig {
	if s == nil || s.client == nil {
		return nil
	}
	out := &SOLConfig{Params: map[byte]string{}}
	for _, sel := range []byte{SOLParamEnable, SOLParamAuthentication, SOLParamPayloadChannel, SOLParamPayloadPort} {
		// Request: channel, parameter selector, set selector, block selector.
		cc, data, err := s.Exec(NetFnTransport, CmdGetSOLConfigParams, []byte{channel, sel, 0x00, 0x00})
		if err != nil || cc != 0x00 || len(data) < 1 {
			continue
		}
		out.ParamRevision = data[0]
		out.Params[sel] = fmt.Sprintf("%x", data)
		body := data[1:]
		if len(body) < 1 {
			continue
		}
		switch sel {
		case SOLParamEnable:
			out.Enabled, out.EnabledOK = body[0]&0x01 != 0, true
		case SOLParamAuthentication:
			out.RequiredPrivilege, out.RequiredPrivilegeOK = body[0]&0x0f, true
		case SOLParamPayloadChannel:
			out.PayloadChannel, out.PayloadChannelOK = body[0], true
		case SOLParamPayloadPort:
			if len(body) >= 2 {
				out.PayloadPort, out.PayloadPortOK = binary.LittleEndian.Uint16(body[:2]), true
			}
		}
	}
	if len(out.Params) == 0 {
		return nil
	}
	return out
}

// ProbeNullUserPrivilege opens a session as the named empty-password account and
// measures what it actually holds, keeping the first candidate suite that
// activates. suiteIDs is the advertised cipher-suite list; an empty list falls back
// to the broad default order, since some BMCs do not answer sessionless suite
// enumeration. It always returns a probe record, never nil: a failed session is
// itself the answer that the advertised bit did not translate into access.
func ProbeNullUserPrivilege(host string, port int, username string, suiteIDs []int, timeout time.Duration, logf func(string)) *NullUserPrivProbe {
	probe := &NullUserPrivProbe{Username: username}
	debug := func(format string, args ...any) {
		if logf != nil {
			logf(fmt.Sprintf(format, args...))
		}
	}

	var lastErr error
	for _, suite := range nullUserProbeSuites(suiteIDs) {
		s, maxPriv, err := OpenSession20NullUser(host, port, username, suite, timeout)
		if err != nil {
			lastErr = err
			debug("ipmi.nullUserPriv: suite=%d session failed: %v", suite.Suite, err)
			continue
		}
		probe.Activated = true
		probe.Suite = suite.Suite
		probe.OpenSessionMaxPriv = maxPriv
		measureNullUserSession(s, probe, debug)
		s.Close()
		return probe
	}
	if lastErr != nil {
		probe.Error = lastErr.Error()
	} else {
		probe.Error = "no candidate cipher suite available"
	}
	return probe
}

// measureNullUserSession runs the in-session measurements against an activated
// session: present privilege, then Get Device ID as an impact witness, then the
// SOL parameters. Each is best effort and independent.
func measureNullUserSession(s *Session20, probe *NullUserPrivProbe, debug func(string, ...any)) {
	level, cc, err := s.PresentPrivilege()
	probe.PrivilegeCC = cc
	if err == nil {
		probe.Privilege, probe.PrivilegeOK = level, true
	} else {
		debug("ipmi.nullUserPriv: privilege query failed: %v", err)
	}
	// Read the protection only after the first command, so the auto strategy has
	// latched whichever path the BMC actually honors.
	probe.Protection = s.CommandProtectionUsed()

	if devCC, devData, err := s.Exec(NetFnApp, CmdGetDeviceID, nil); err == nil {
		probe.DeviceIDSeen = true
		probe.DeviceIDCC = devCC
		probe.DeviceIDOK = devCC == 0x00 && len(devData) > 0
	}

	// Get SOL Config is read from the present channel (0x0e): it can answer at
	// privilege 0 despite being outside the documented Privilege::None set, so it
	// is probed regardless of the measured level -- at a low level that is a gate
	// failure, at a high one it is just inventory the account is entitled to.
	probe.SOL = s.ReadSOLConfig(0x0e)
}

// nullUserProbeSuites orders the cipher suites to try. CipherTriples puts
// full-crypto suites first (hardened BMCs reject an Open Session offering
// integrity/conf None) and never yields an unauthenticated triple, since cipher
// suite 0 has no entry in CipherAlgosFor -- so a null-user session can never
// measure the cipher-zero bypass instead of the account. Only the first two are
// tried: boards that rate-limit or lock out a repeat prober make extra attempts
// cost a lockout rather than buy coverage.
func nullUserProbeSuites(ids []int) []CipherAlgos {
	all := CipherTriples(ids)
	if len(all) > 2 {
		return all[:2]
	}
	return all
}
