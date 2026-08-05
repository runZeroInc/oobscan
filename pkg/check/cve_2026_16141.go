package check

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func init() {
	Register(Check{
		Name:        "ipmi.openbmc.rakpAuthBypass",
		Description: "OpenBMC-derived RMCP+ authentication bypass (CVE-2026-16141); detected without establishing a session",
		Category:    "auth",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runOpenBMCRAKPAuthBypass,
	})
	RegisterExplain("ipmi.openbmc.rakpAuthBypass", explainOpenBMCRAKPAuthBypass)
}

const (
	openBMCEarlyReturnStatus byte = 0x0a

	openBMCOutOfOrderRAKP4Status byte = 0x0f

	openBMCStateProbeTimeout = 2 * time.Second
)

type OpenBMCRAKPStateProbe struct {
	Suite         int    `json:"suite"`
	AuthAlgo      byte   `json:"authAlgo,omitempty"`
	IntegrityAlgo byte   `json:"integrityAlgo,omitempty"`
	ConfAlgo      byte   `json:"confAlgo,omitempty"`
	BMCSID        uint32 `json:"bmcSid"`
	ClientSID     uint32 `json:"clientSid"`
	UsernameUsed  string `json:"usernameUsed"`

	RAKP1Status     byte   `json:"rakp1Status"`
	RAKP1StatusName string `json:"rakp1StatusName,omitempty"`

	RAKP3Status     byte   `json:"rakp3Status"`
	RAKP3StatusName string `json:"rakp3StatusName,omitempty"`

	Affected bool `json:"affected"`

	Activated bool   `json:"activated"`
	Error     string `json:"error,omitempty"`
}

func runOpenBMCRAKPAuthBypass(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	if t == nil {
		return nil
	}
	port := t.IPMIPort()
	timeout := t.Timeout
	if timeout <= 0 || timeout > openBMCStateProbeTimeout {
		timeout = openBMCStateProbeTimeout
	}

	var advertised []int
	if v, ok := t.Evidenced("ipmi.ciphers"); ok {
		advertised, _ = v.([]int)
	}
	if len(advertised) == 0 {
		if ids, _, err := ipmi.EnumCipherSuites15(t.Host, port, timeout); err == nil {
			advertised = ids
		}
	}
	suites := ipmi.CipherTriples(advertised)
	fallbackSuites := false
	if len(suites) == 0 {

		if !hostSpeaksIPMI(t) {
			return nil
		}
		suites = defaultProbeCipherSuites()
		fallbackSuites = true
	}

	probe := probeOpenBMCRAKPStateOverSuites(t.Host, port, suites, timeout, fallbackSuites)
	if probe == nil {
		return nil
	}
	if t.DebugLog != nil {
		t.DebugLog(fmt.Sprintf("ipmi.openbmc.rakpState: suite=%d rakp1=0x%02x(%s) rakp3=0x%02x(%s) affected=%t err=%q",
			probe.Suite, probe.RAKP1Status, probe.RAKP1StatusName,
			probe.RAKP3Status, probe.RAKP3StatusName, probe.Affected, probe.Error))
	}
	if !probe.Affected {
		return nil
	}
	t.SetEvidence("ipmi.openBmcRakpState", probe)
	return stampIPMI([]engine.Finding{openBMCRAKPAuthBypassFinding(probe)}, port)
}

var openBMCRAKPStateUsernames = []string{"root", "admin", "ADMIN"}

func probeOpenBMCRAKPStateOverSuites(host string, port int, suites []ipmi.CipherAlgos, timeout time.Duration, fallback bool) *OpenBMCRAKPStateProbe {
	var probe *OpenBMCRAKPStateProbe
	for _, suite := range suites {
		for _, user := range openBMCRAKPStateUsernames {
			probe = probeOpenBMCRAKPState(host, port, suite, user, timeout)
			if probe != nil && probe.Affected {
				return probe
			}

			if probe != nil && probe.RAKP1Status == openBMCEarlyReturnStatus {
				break
			}
		}
		if probe != nil && (probe.RAKP1Status != 0 || probe.Error == "") {
			break
		}
		if !fallback {
			break
		}
	}
	return probe
}

func probeOpenBMCRAKPState(host string, port int, suite ipmi.CipherAlgos, username string, timeout time.Duration) *OpenBMCRAKPStateProbe {
	probe := &OpenBMCRAKPStateProbe{
		Suite:         suite.Suite,
		AuthAlgo:      suite.Auth,
		IntegrityAlgo: suite.Integrity,
		ConfAlgo:      suite.Conf,
		UsernameUsed:  username,
	}
	c, err := ipmi.NewClient(host, port, timeout)
	if err != nil {
		probe.Error = "client: " + err.Error()
		return probe
	}
	defer c.Close()

	var cSID uint32
	if err := binary.Read(rand.Reader, binary.LittleEndian, &cSID); err != nil || cSID == 0 {
		cSID = 0xb0b1b2b3
	}
	probe.ClientSID = cSID

	osResp, err := c.Send(ipmi.BuildRMCPPlus(ipmi.PayloadOpenSessionReq,
		buildOpenSessionBodyDefaultKey(cSID, suite, 0x04)))
	if err != nil {
		probe.Error = "open-session: " + err.Error()
		return probe
	}
	bmcSID, err := ipmi.ParseOpenSessionResponse(osResp)
	if err != nil {
		probe.Error = "open-session parse: " + err.Error()
		return probe
	}
	probe.BMCSID = bmcSID

	clientRand := make([]byte, 16)
	if _, err := rand.Read(clientRand); err != nil {
		probe.Error = "client-random: " + err.Error()
		return probe
	}

	r2Resp, err := c.Send(ipmi.BuildRMCPPlus(ipmi.PayloadRAKP1,
		buildRAKP1DefaultKey(bmcSID, clientRand, username, 0x01)))
	if err != nil {
		probe.Error = "rakp1: " + err.Error()
		return probe
	}
	r2, err := ipmi.RmcpPlusPayload(r2Resp)
	if err != nil || len(r2) < 2 {
		probe.Error = "rakp2 short or unparseable"
		return probe
	}
	probe.RAKP1Status = r2[1]
	probe.RAKP1StatusName = rakpStatusName(probe.RAKP1Status)
	if probe.RAKP1Status != openBMCEarlyReturnStatus {

		_ = ipmi.CloseSetupSessionAsync(c, bmcSID)
		return probe
	}

	authCode := make([]byte, rakpAuthCodeLenForAlgo(suite.Auth))
	if _, err := rand.Read(authCode); err != nil {
		probe.Error = "auth-code: " + err.Error()
		return probe
	}
	r3 := []byte{0x00, 0x00, 0x00, 0x00}
	r3 = binary.LittleEndian.AppendUint32(r3, bmcSID)
	r3 = append(r3, authCode...)

	r4Resp, err := c.Send(ipmi.BuildRMCPPlus(ipmi.PayloadRAKP3, r3))
	if err != nil {
		probe.Error = "rakp3: " + err.Error()
		_ = ipmi.CloseSetupSessionAsync(c, bmcSID)
		return probe
	}
	r4, err := ipmi.RmcpPlusPayload(r4Resp)
	if err != nil || len(r4) < 2 {
		probe.Error = "rakp4 short or unparseable"
		_ = ipmi.CloseSetupSessionAsync(c, bmcSID)
		return probe
	}
	probe.RAKP3Status = r4[1]
	probe.RAKP3StatusName = rakpStatusName(probe.RAKP3Status)
	probe.Activated = probe.RAKP3Status == 0x00
	probe.Affected = probe.RAKP3Status == openBMCOutOfOrderRAKP4Status || probe.Activated

	if probe.Activated {

		_, _ = ipmi.CloseSetupSession(c, bmcSID)
	} else {
		_ = ipmi.CloseSetupSessionAsync(c, bmcSID)
	}
	return probe
}

func rakpAuthCodeLenForAlgo(algo byte) int {
	switch algo {
	case ipmi.RAKPHMACSHA256:
		return 32
	case ipmi.RAKPHMACMD5:
		return 16
	default:
		return 20
	}
}

func openBMCRAKPAuthBypassFinding(probe *OpenBMCRAKPStateProbe) engine.Finding {
	return engine.Finding{
		Check:    "ipmi.openbmc.rakpAuthBypass",
		Category: "auth",
		Risk:     "high",
		CVE:      []string{"CVE-2026-16141"},
		Fields: engine.F(
			"suite", fmt.Sprintf("%d", probe.Suite),
			"authAlgo", fmt.Sprintf("0x%02x", probe.AuthAlgo),
			"bmcSid", fmt.Sprintf("0x%08x", probe.BMCSID),
			"usernameUsed", probe.UsernameUsed,
			"rakp1Status", fmt.Sprintf("0x%02x", probe.RAKP1Status),
			"rakp1StatusName", probe.RAKP1StatusName,
			"rakp3Status", fmt.Sprintf("0x%02x", probe.RAKP3Status),
			"rakp3StatusName", probe.RAKP3StatusName,
			"sessionEstablished", ternary(probe.Activated, "true", "false"),
			"requiresCredentials", "false",
			"detectionMethod", "rakp-message-ordering",
			"proof", proofKV(
				"suite", fmt.Sprintf("%d", probe.Suite),
				"bmcSid", fmt.Sprintf("0x%08x", probe.BMCSID),
				"rakp1Status", fmt.Sprintf("0x%02x", probe.RAKP1Status),
				"rakp1StatusName", probe.RAKP1StatusName,
				"rakp3Status", fmt.Sprintf("0x%02x", probe.RAKP3Status),
				"rakp3StatusName", probe.RAKP3StatusName),
		),
	}
}

func explainOpenBMCRAKPAuthBypass(host string, f engine.Finding) string {
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThis host is affected by CVE-2026-16141, an authentication bypass in the RMCP+\n")
	b.WriteString("implementation of OpenBMC-derived BMC firmware.\n")
	b.WriteString("\nThe scanner fingerprinted the defect only: no credential was offered and no\n")
	b.WriteString("session was established.\n")
	b.WriteString("\nUpdate the BMC firmware and restrict UDP/623 to the management network.\n")
	return b.String()
}

func hostSpeaksIPMI(t *engine.Target) bool {
	for portProto, proto := range t.OpenSnapshot() {
		if strings.HasSuffix(portProto, "/udp") && strings.Contains(proto, "ipmi") {
			return true
		}
	}
	for _, key := range []string{"ipmi.authCaps", "ipmi.deviceId", "ipmi.dcmi", "ipmi.ciphers", "guid"} {
		if _, ok := t.Evidenced(key); ok {
			return true
		}
	}
	return false
}

func defaultProbeCipherSuites() []ipmi.CipherAlgos {
	return []ipmi.CipherAlgos{
		{Suite: 17, Auth: ipmi.RAKPHMACSHA256, Integrity: ipmi.IntegrityHMACSHA256128, Conf: ipmi.ConfAESCBC},
		{Suite: 3, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityHMACSHA196, Conf: ipmi.ConfAESCBC},
	}
}

func buildOpenSessionBodyDefaultKey(clientSID uint32, suite ipmi.CipherAlgos, reqPriv byte) []byte {
	var b []byte
	b = append(b, 0x00)
	b = append(b, reqPriv&0x0f)
	b = append(b, 0x00, 0x00)
	b = binary.LittleEndian.AppendUint32(b, clientSID)

	b = append(b, 0x00, 0x00, 0x00, 0x08)
	b = append(b, suite.Auth, 0x00, 0x00, 0x00)

	b = append(b, 0x01, 0x00, 0x00, 0x08)
	b = append(b, suite.Integrity, 0x00, 0x00, 0x00)

	b = append(b, 0x02, 0x00, 0x00, 0x08)
	b = append(b, suite.Conf, 0x00, 0x00, 0x00)
	return b
}

func buildRAKP1DefaultKey(bmcSID uint32, clientRand []byte, username string, reqPriv byte) []byte {
	var b []byte
	b = append(b, 0x00)
	b = append(b, 0x00, 0x00, 0x00)
	b = binary.LittleEndian.AppendUint32(b, bmcSID)
	b = append(b, clientRand...)
	b = append(b, reqPriv&0x0f)
	b = append(b, 0x00, 0x00)
	b = append(b, byte(len(username)))
	b = append(b, []byte(username)...)
	return b
}
func rakpStatusName(code byte) string {
	switch code {
	case 0x00:
		return "no errors"
	case 0x01:
		return "insufficient resources"
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
		return "inactive role"
	case 0x0a:
		return "unauthorized role or privilege"
	case 0x0b:
		return "insufficient resources for role"
	case 0x0c:
		return "invalid username length"
	case 0x0d:
		return "unauthorized username"
	case 0x0e:
		return "unauthorized guid"
	case 0x0f:
		return "invalid integrity check"
	case 0x10:
		return "invalid confidentiality algorithm"
	case 0x11:
		return "no matching confidentiality payload"
	case 0x12:
		return "illegal parameter"
	default:
		return fmt.Sprintf("status 0x%02x", code)
	}
}
