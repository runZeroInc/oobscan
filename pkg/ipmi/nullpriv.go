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

const (
	PrivUnspecified   byte = 0x00
	PrivCallback      byte = 0x01
	PrivUser          byte = 0x02
	PrivOperator      byte = 0x03
	PrivAdministrator byte = 0x04
	PrivOEM           byte = 0x05
	PrivNoAccess      byte = 0x0f
)

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

type SOLConfig struct {
	ParamRevision byte `json:"paramRevision,omitempty"`

	Enabled   bool `json:"enabled"`
	EnabledOK bool `json:"enabledOk"`

	RequiredPrivilege   byte `json:"requiredPrivilege,omitempty"`
	RequiredPrivilegeOK bool `json:"requiredPrivilegeOk"`

	PayloadChannel   byte   `json:"payloadChannel,omitempty"`
	PayloadChannelOK bool   `json:"payloadChannelOk"`
	PayloadPort      uint16 `json:"payloadPort,omitempty"`
	PayloadPortOK    bool   `json:"payloadPortOk"`

	Params map[byte]string `json:"params,omitempty"`
}

func (s *SOLConfig) Readable() bool {
	return s != nil && len(s.Params) > 0
}

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

type NullUserPrivProbe struct {
	Username string `json:"username"`

	Suite int `json:"suite"`

	Activated bool   `json:"activated"`
	Error     string `json:"error,omitempty"`

	OpenSessionMaxPriv byte `json:"openSessionMaxPriv"`

	Privilege   byte `json:"privilege"`
	PrivilegeOK bool `json:"privilegeOk"`
	PrivilegeCC byte `json:"privilegeCc,omitempty"`

	Protection string `json:"protection,omitempty"`

	DeviceIDCC   byte `json:"deviceIdCc"`
	DeviceIDOK   bool `json:"deviceIdOk"`
	DeviceIDSeen bool `json:"deviceIdSeen"`

	SOL *SOLConfig `json:"sol,omitempty"`
}

func (p *NullUserPrivProbe) UsableAccess() bool {
	return p != nil && p.Activated && p.PrivilegeOK && p.Privilege >= PrivUser && p.Privilege != PrivNoAccess
}

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

func OpenSession20NullUser(host string, port int, username string, suite CipherAlgos, timeout time.Duration) (*Session20, byte, error) {
	if suite.Auth == RAKPNone {

		return nil, 0, errors.New("null-user probe requires an authenticated cipher suite (not cipher-zero)")
	}
	const (
		openPriv  = 0x00
		rakp1Role = 0x14
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

func (s *Session20) ReadSOLConfig(channel byte) *SOLConfig {
	if s == nil || s.client == nil {
		return nil
	}
	out := &SOLConfig{Params: map[byte]string{}}
	for _, sel := range []byte{SOLParamEnable, SOLParamAuthentication, SOLParamPayloadChannel, SOLParamPayloadPort} {

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

func measureNullUserSession(s *Session20, probe *NullUserPrivProbe, debug func(string, ...any)) {
	level, cc, err := s.PresentPrivilege()
	probe.PrivilegeCC = cc
	if err == nil {
		probe.Privilege, probe.PrivilegeOK = level, true
	} else {
		debug("ipmi.nullUserPriv: privilege query failed: %v", err)
	}

	probe.Protection = s.CommandProtectionUsed()

	if devCC, devData, err := s.Exec(NetFnApp, CmdGetDeviceID, nil); err == nil {
		probe.DeviceIDSeen = true
		probe.DeviceIDCC = devCC
		probe.DeviceIDOK = devCC == 0x00 && len(devData) > 0
	}

	probe.SOL = s.ReadSOLConfig(0x0e)
}

func nullUserProbeSuites(ids []int) []CipherAlgos {
	all := CipherTriples(ids)
	if len(all) > 2 {
		return all[:2]
	}
	return all
}
