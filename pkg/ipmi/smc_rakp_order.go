package ipmi

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/guid"
)

const (
	smcATENOutOfOrderRAKP4Status byte = 0x08
	rakpStatusInvalidICV         byte = 0x0f
	rakpStatusUnauthorizedName   byte = 0x0d
	rakpStatusInvalidRole        byte = 0x09
	rakpStatusUnauthorizedRole   byte = 0x0a
	rakpStatusIllegalParameter   byte = 0x12
	smcRAKP1ConformantRoleLookup byte = 0x12
	smcRAKP1BaselineRoleLookup   byte = 0x14

	smcProbeRoleByte byte = 0x24
)

var smcCipherSuite3 = CipherAlgos{Suite: 3, Auth: RAKPHMACSHA1, Integrity: IntegrityHMACSHA196, Conf: ConfAESCBC}

var smcCipherSuite17 = CipherAlgos{Suite: 17, Auth: RAKPHMACSHA256, Integrity: IntegrityHMACSHA256128, Conf: ConfAESCBC}

func rakpAuthCodeLen(algo byte) int {
	switch algo {
	case RAKPHMACSHA256:
		return 32
	case RAKPHMACMD5:
		return 16
	default:
		return 20
	}
}

func smcHandshakeSuites() []CipherAlgos {
	return []CipherAlgos{smcCipherSuite3, smcCipherSuite17}
}

func smcOpenSessionAnySuite(host string, port int, reqPriv byte, timeout time.Duration) (*Client, uint32, uint32, CipherAlgos, error) {
	var lastErr error
	for _, suite := range smcHandshakeSuites() {
		c, err := NewClient(host, port, timeout)
		if err != nil {
			return nil, 0, 0, CipherAlgos{}, err
		}
		cSID := randomConsoleSID(0xabcd1234)
		resp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadOpenSessionReq, 0, 0,
			smcOpenSessionBody(cSID, reqPriv, suite)), session20HandshakeRetries(timeout))
		if err != nil {
			c.Close()

			lastErr = fmt.Errorf("open-session (suite %d): %w", suite.Suite, err)
			continue
		}
		bmcSID, err := parseOpenSessionResp(resp)
		if err != nil {
			c.Close()
			lastErr = err
			continue
		}
		return c, bmcSID, cSID, suite, nil
	}
	if lastErr == nil {
		lastErr = errors.New("open-session rejected on every candidate cipher suite")
	}
	return nil, 0, 0, CipherAlgos{}, lastErr
}

type SMCRAKPOrderProbe struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	ConsoleSID uint32 `json:"consoleSid"`
	BMCSID     uint32 `json:"bmcSid"`

	CipherSuite int `json:"cipherSuite"`

	Answered        bool   `json:"answered"`
	RAKP4Status     byte   `json:"rakp4Status"`
	RAKP4StatusText string `json:"rakp4StatusText,omitempty"`

	SIDEchoed bool   `json:"sidEchoed"`
	EchoedSID uint32 `json:"echoedSid,omitempty"`

	Defect bool `json:"defect"`

	SpecConformant bool `json:"specConformant"`

	Activated bool   `json:"activated"`
	Error     string `json:"error,omitempty"`
}

func (p *SMCRAKPOrderProbe) Summary() string {
	switch {
	case p == nil:
		return "not-probed"
	case p.Error != "" && !p.Answered:
		return "error"
	case !p.Answered:
		return "no-reply"
	case p.Activated:
		return "session-activated"
	case p.Defect:
		return fmt.Sprintf("unordered-rakp3-accepted (rakp4=0x%02x, console-sid echoed)", p.RAKP4Status)
	case p.SpecConformant:
		return "rejected-spec-conformant (rakp4=0x0f)"
	default:
		return fmt.Sprintf("rejected (rakp4=0x%02x)", p.RAKP4Status)
	}
}

func ProbeSMCRAKPOrder(host string, port int, timeout time.Duration) (*SMCRAKPOrderProbe, error) {
	probe := &SMCRAKPOrderProbe{Host: host, Port: port}
	c, bmcSID, cSID, suite, err := smcOpenSessionAnySuite(host, port, 0x04, timeout)
	if err != nil {
		probe.Error = err.Error()
		return probe, err
	}
	defer c.Close()
	retries := session20HandshakeRetries(timeout)
	probe.ConsoleSID = cSID
	probe.BMCSID = bmcSID
	probe.CipherSuite = suite.Suite

	auth := make([]byte, rakpAuthCodeLen(suite.Auth))
	if _, err := rand.Read(auth); err != nil {
		probe.Error = "auth-code: " + err.Error()
		return probe, nil
	}
	r4Resp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadRAKP3, 0, 0,
		smcRAKP3Body(bmcSID, auth)), retries)
	if err != nil {
		probe.Error = fmt.Sprintf("rakp3: %v", err)
		return probe, nil
	}
	pl, err := rmcpPlusPayload(r4Resp)
	if err != nil {
		probe.Error = err.Error()
		return probe, nil
	}
	if !classifySMCRAKPOrderReply(probe, pl, cSID) {
		probe.Error = "short RAKP4"
		return probe, nil
	}
	if probe.Activated {

		_ = CloseSetupSessionAsync(c, bmcSID)
	}
	return probe, nil
}

func classifySMCRAKPOrderReply(probe *SMCRAKPOrderProbe, payload []byte, consoleSID uint32) bool {
	if probe == nil || len(payload) < 2 {
		return false
	}
	probe.Answered = true
	probe.RAKP4Status = payload[1]
	probe.RAKP4StatusText = rakpStatusText(payload[1])
	if len(payload) >= 8 {
		probe.EchoedSID = binary.LittleEndian.Uint32(payload[4:8])
		probe.SIDEchoed = probe.EchoedSID == consoleSID
	}
	switch {
	case probe.RAKP4Status == 0x00:
		probe.Activated = true
		probe.Defect = true
	case probe.RAKP4Status == smcATENOutOfOrderRAKP4Status && probe.SIDEchoed:

		probe.Defect = true
	case probe.RAKP4Status == rakpStatusInvalidICV:

		probe.SpecConformant = true
	}
	return true
}

func SMCDetectGeneration(host string, port int, timeout time.Duration) (generation, modelPrefix string, err error) {

	raw, err := GetSystemGUID15(host, port, timeout)
	if err != nil {
		raw, err = GetSystemGUID15(host, port, timeout)
	}
	if err != nil {
		return "", "", err
	}
	if len(raw) < 16 {
		return "", "", fmt.Errorf("short system guid (%d bytes)", len(raw))
	}
	g := guid.Decode(raw[:16])
	if g != nil && g.Fields != nil {
		modelPrefix = g.Fields["model_prefix"]
	}
	return guid.SMCGenerationFromModelPrefix(modelPrefix), modelPrefix, nil
}

type SMCRoleClampProbe struct {
	Host string `json:"host"`
	Port int    `json:"port"`

	Username string `json:"username"`

	UsernameCandidates []string `json:"usernameCandidates,omitempty"`

	BaselineRole     byte `json:"baselineRole"`
	BaselineStatus   byte `json:"baselineStatus"`
	BaselineAccepted bool `json:"baselineAccepted"`

	ConformantRole     byte `json:"conformantRole"`
	ConformantStatus   byte `json:"conformantStatus"`
	ConformantAccepted bool `json:"conformantAccepted"`
	ReservedRole       byte `json:"probeRole"`
	ReservedStatus     byte `json:"probeRoleStatus"`
	ReservedAccepted   bool `json:"probeRoleAccepted"`

	ProbeRejectedConformantly bool `json:"probeRoleRejectedConformantly"`

	Defect bool   `json:"defect"`
	Error  string `json:"error,omitempty"`
}

func (p *SMCRoleClampProbe) Summary() string {
	switch {
	case p == nil:
		return "not-probed"
	case p.Username == "":
		return "no-resolvable-account"
	case p.Defect:
		return "probe role byte accepted (rakp2=0x00)"
	case p.Error != "":
		return "error"
	case !p.ConformantAccepted:
		return fmt.Sprintf("control role not accepted for %q (rakp2=0x%02x): a rejected probe role would say nothing", p.Username, p.ConformantStatus)
	default:
		return fmt.Sprintf("probe role rejected (rakp2=0x%02x)", p.ReservedStatus)
	}
}

func RAKP1RoleStatus(host string, port int, username string, role byte, timeout time.Duration) (byte, error) {
	c, bmcSID, _, _, err := smcOpenSessionAnySuite(host, port, 0x04, timeout)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	retries := session20HandshakeRetries(timeout)

	cRand := make([]byte, 16)
	if _, err := rand.Read(cRand); err != nil {
		return 0, err
	}
	r2Resp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadRAKP1, 0, 0,
		smcRAKP1Body(bmcSID, cRand, role, username)), retries)
	if err != nil {
		return 0, fmt.Errorf("rakp1: %w", err)
	}
	pl, err := rmcpPlusPayload(r2Resp)
	if err != nil {
		return 0, err
	}
	if len(pl) < 2 {
		return 0, errors.New("short RAKP2")
	}

	_ = CloseSetupSessionAsync(c, bmcSID)
	return pl[1], nil
}

var SMCRoleProbeAccountCandidates = []string{"ADMIN", "admin", "root"}

func ProbeSMCRoleClamp(host string, port int, preferredUser string, timeout time.Duration) (*SMCRoleClampProbe, error) {
	probe := &SMCRoleClampProbe{
		Host: host, Port: port,
		BaselineRole:   smcRAKP1BaselineRoleLookup,
		ConformantRole: smcRAKP1ConformantRoleLookup,
		ReservedRole:   smcProbeRoleByte,
	}
	candidates := SMCRoleProbeAccountCandidates
	if u := strings.TrimSpace(preferredUser); u != "" {
		candidates = append([]string{u}, candidates...)
	}

	var lastErr error
	for _, name := range candidates {
		probe.UsernameCandidates = append(probe.UsernameCandidates, name)
		st, err := RAKP1RoleStatus(host, port, name, smcRAKP1ConformantRoleLookup, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		if st == 0x00 {
			probe.Username = name
			probe.ConformantStatus = st
			probe.ConformantAccepted = true
			break
		}

		if st != rakpStatusUnauthorizedName && probe.Username == "" {
			probe.Username = name
			probe.ConformantStatus = st
		}
	}
	if probe.Username == "" {
		if lastErr != nil {
			probe.Error = lastErr.Error()
			return probe, lastErr
		}
		return probe, nil
	}
	if !probe.ConformantAccepted {
		return probe, nil
	}

	if st, err := RAKP1RoleStatus(host, port, probe.Username, smcRAKP1BaselineRoleLookup, timeout); err == nil {
		probe.BaselineStatus = st
		probe.BaselineAccepted = st == 0x00
	} else {
		probe.Error = err.Error()
	}

	st, err := RAKP1RoleStatus(host, port, probe.Username, smcProbeRoleByte, timeout)
	if err != nil {
		probe.Error = err.Error()
		return probe, nil
	}
	probe.ReservedStatus = st
	probe.ReservedAccepted = st == 0x00
	probe.ProbeRejectedConformantly = smcRoleRejectedConformantly(st)

	probe.Defect = probe.ReservedAccepted && probe.ConformantAccepted
	return probe, nil
}

func smcRoleRejectedConformantly(status byte) bool {
	switch status {
	case rakpStatusInvalidRole, rakpStatusUnauthorizedRole, rakpStatusIllegalParameter:
		return true
	default:
		return false
	}
}

func smcOpenSessionBody(consoleSID uint32, reqPriv byte, suite CipherAlgos) []byte {
	var b bytes.Buffer
	b.WriteByte(0x00)
	b.WriteByte(reqPriv & 0x0f)
	b.Write([]byte{0x00, 0x00})
	_ = binary.Write(&b, binary.LittleEndian, consoleSID)
	b.Write([]byte{0x00, 0x00, 0x00, 0x08, suite.Auth, 0, 0, 0})
	b.Write([]byte{0x01, 0x00, 0x00, 0x08, suite.Integrity, 0, 0, 0})
	b.Write([]byte{0x02, 0x00, 0x00, 0x08, suite.Conf, 0, 0, 0})
	return b.Bytes()
}

func smcRAKP1Body(bmcSID uint32, consoleRand []byte, role byte, username string) []byte {
	var b bytes.Buffer
	b.WriteByte(0x00)
	b.Write([]byte{0, 0, 0})
	_ = binary.Write(&b, binary.LittleEndian, bmcSID)
	b.Write(consoleRand)
	b.WriteByte(role)
	b.Write([]byte{0, 0})
	b.WriteByte(byte(len(username)))
	b.WriteString(username)
	return b.Bytes()
}

func smcRAKP3Body(bmcSID uint32, authCode []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x00)
	b.WriteByte(0x00)
	b.Write([]byte{0, 0})
	_ = binary.Write(&b, binary.LittleEndian, bmcSID)
	b.Write(authCode)
	return b.Bytes()
}

func randomConsoleSID(fallback uint32) uint32 {
	var sid uint32
	_ = binary.Read(rand.Reader, binary.LittleEndian, &sid)
	if sid == 0 {
		return fallback
	}
	return sid
}
