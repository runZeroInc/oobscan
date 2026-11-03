package ipmi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// TestSMCRecord0TranscriptLayout pins the CVE-2026-65219 message-3 authentication-code
// input byte for byte. Every field but the console session ID is a boot value the
// slot still holds because message 1 was never sent, so a drift here silently
// turns the forge into a wrong-transcript guess.
func TestSMCRecord0TranscriptLayout(t *testing.T) {
	const sidc uint32 = 0xabcd1234
	got := smcRecord0Transcript(sidc)
	want := make([]byte, 0, 22)
	want = append(want, make([]byte, 16)...)            // Rc: boot-zero
	want = binary.LittleEndian.AppendUint32(want, sidc) // SIDc, little-endian
	want = append(want, 0x00, 0x00)                     // RoleM, ULen: boot-zero
	if !bytes.Equal(got, want) {
		t.Fatalf("transcript = %x, want %x", got, want)
	}
	if len(got) != 22 {
		t.Fatalf("transcript length = %d, want 22 (16 + 4 + 1 + 1)", len(got))
	}
	// The session ID must be little-endian: the live evidence records SIDc
	// 0xABCD1234 appearing on the wire as 34 12 cd ab.
	if !bytes.Equal(got[16:20], []byte{0x34, 0x12, 0xcd, 0xab}) {
		t.Fatalf("SIDc bytes = %x, want little-endian 34 12 cd ab", got[16:20])
	}
	// No username bytes may follow a zero username length.
	if got[21] != 0x00 {
		t.Fatalf("ULen = 0x%02x, want 0x00", got[21])
	}
}

// TestSMCRecord0AuthCodeMatchesReference recomputes the authentication code
// independently, the way the reference harness does, and compares.
func TestSMCRecord0AuthCodeMatchesReference(t *testing.T) {
	const sidc uint32 = 0xa0a2a3a4
	key := []byte("0") // the value recovered on X11
	mac := hmac.New(sha1.New, key)
	body := append(make([]byte, 16), 0xa4, 0xa3, 0xa2, 0xa0, 0x00, 0x00)
	mac.Write(body)
	want := mac.Sum(nil)
	got := smcRecord0AuthCode(RAKPHMACSHA1, key, sidc)
	if !bytes.Equal(got, want) {
		t.Fatalf("auth code = %x, want %x", got, want)
	}
	if len(got) != sha1.Size {
		t.Fatalf("auth code length = %d, want %d", len(got), sha1.Size)
	}
}

// TestSMCRecord0AuthCodeKeyPaddingEquivalence records the HMAC property that
// bounds the candidate list: any key shorter than the 64-byte block is zero-padded,
// so the empty key, 16 NULs and 20 NULs are one key, not three guesses.
func TestSMCRecord0AuthCodeKeyPaddingEquivalence(t *testing.T) {
	const sidc uint32 = 0xdeadbeef
	empty := smcRecord0AuthCode(RAKPHMACSHA1, []byte{}, sidc)
	nul16 := smcRecord0AuthCode(RAKPHMACSHA1, make([]byte, 16), sidc)
	nul20 := smcRecord0AuthCode(RAKPHMACSHA1, make([]byte, 20), sidc)
	if !bytes.Equal(empty, nul16) || !bytes.Equal(empty, nul20) {
		t.Fatal("expected the empty key, 16 NULs and 20 NULs to be the same HMAC key after block padding")
	}
	if bytes.Equal(empty, smcRecord0AuthCode(RAKPHMACSHA1, []byte("0"), sidc)) {
		t.Fatal("the empty key must not collide with the one-character key \"0\"")
	}
}

// TestSMCOpenSessionBodyLayout pins the Open Session Request wire layout,
// including the requested maximum privilege byte that the forged session keeps
// because the per-user clamp in message 1 never runs.
func TestSMCOpenSessionBodyLayout(t *testing.T) {
	const sidc uint32 = 0x11223344
	body := smcOpenSessionBody(sidc, 0x04, smcCipherSuite3)
	if len(body) != 32 {
		t.Fatalf("open-session body length = %d, want 32", len(body))
	}
	if body[0] != 0x00 {
		t.Fatalf("message tag = 0x%02x, want 0x00", body[0])
	}
	if body[1] != 0x04 {
		t.Fatalf("requested max privilege = 0x%02x, want 0x04", body[1])
	}
	if got := binary.LittleEndian.Uint32(body[4:8]); got != sidc {
		t.Fatalf("console SID = 0x%08x, want 0x%08x", got, sidc)
	}
	// Three 8-byte algorithm records: auth(0x00), integrity(0x01), conf(0x02).
	for i, want := range []struct {
		typ  byte
		algo byte
	}{
		{0x00, RAKPHMACSHA1},
		{0x01, IntegrityHMACSHA196},
		{0x02, ConfAESCBC},
	} {
		off := 8 + i*8
		if body[off] != want.typ {
			t.Fatalf("record %d type = 0x%02x, want 0x%02x", i, body[off], want.typ)
		}
		if body[off+3] != 0x08 {
			t.Fatalf("record %d length = 0x%02x, want 0x08", i, body[off+3])
		}
		if body[off+4] != want.algo {
			t.Fatalf("record %d algo = 0x%02x, want 0x%02x", i, body[off+4], want.algo)
		}
	}
}

// TestSMCHandshakeSuites guards the fallback. X12, X13 and H13 ship
// configurations offering only suites 3 and 17, so a board with suite 3 disabled
// must be retried on 17 rather than reported unaffected: the defect is in the
// RAKP state machine, not in any one algorithm.
func TestSMCHandshakeSuites(t *testing.T) {
	suites := smcHandshakeSuites()
	if len(suites) != 2 {
		t.Fatalf("suite count = %d, want 2", len(suites))
	}
	if suites[0].Suite != 3 || suites[1].Suite != 17 {
		t.Fatalf("suite order = %d,%d, want 3 then 17 (the live work used 3)", suites[0].Suite, suites[1].Suite)
	}
	if suites[0].Auth != RAKPHMACSHA1 || suites[0].Integrity != IntegrityHMACSHA196 || suites[0].Conf != ConfAESCBC {
		t.Errorf("suite 3 algorithms = %+v", suites[0])
	}
	if suites[1].Auth != RAKPHMACSHA256 || suites[1].Integrity != IntegrityHMACSHA256128 || suites[1].Conf != ConfAESCBC {
		t.Errorf("suite 17 algorithms = %+v", suites[1])
	}
	// The transcript layout is algorithm-independent; only the digest changes.
	const sidc uint32 = 0x11223344
	sha1Code := smcRecord0AuthCode(suites[0].Auth, []byte("0"), sidc)
	sha256Code := smcRecord0AuthCode(suites[1].Auth, []byte("0"), sidc)
	if len(sha1Code) != 20 || len(sha256Code) != 32 {
		t.Fatalf("auth code lengths = %d/%d, want 20/32", len(sha1Code), len(sha256Code))
	}
}

// TestSMCRAKP1BodyPreservesReservedRole is the CVE-2026-65220 wire guarantee: the role
// byte must reach the wire unmodified, because a reserved upper nibble is exactly
// what trips the missing default arm. Any masking or normalization here would
// silently turn the probe into a spec-conformant request.
func TestSMCRAKP1BodyPreservesReservedRole(t *testing.T) {
	const sidm uint32 = 0x00000182
	cRand := bytes.Repeat([]byte{0x5a}, 16)
	for _, role := range []byte{0x14, 0x12, 0x24, 0x34, 0x44, 0x54, 0x64, 0x74} {
		body := smcRAKP1Body(sidm, cRand, role, "ADMIN")
		if len(body) != 8+16+3+1+5 {
			t.Fatalf("role 0x%02x: body length = %d, want 33", role, len(body))
		}
		if got := binary.LittleEndian.Uint32(body[4:8]); got != sidm {
			t.Fatalf("role 0x%02x: bmc SID = 0x%08x, want 0x%08x", role, got, sidm)
		}
		if !bytes.Equal(body[8:24], cRand) {
			t.Fatalf("role 0x%02x: console random not carried verbatim", role)
		}
		if body[24] != role {
			t.Fatalf("role byte on the wire = 0x%02x, want 0x%02x (must not be masked)", body[24], role)
		}
		if body[27] != 5 || string(body[28:]) != "ADMIN" {
			t.Fatalf("role 0x%02x: username len/bytes = %d/%q", role, body[27], body[28:])
		}
	}
}

// TestSMCReservedRoleByteIsReserved guards the default reserved role byte: the
// upper nibble must be in 0x2x-0x7x, since 0x0x and 0x1x are the two arms the
// handler actually implements and would take the clamped path.
func TestSMCReservedRoleByteIsReserved(t *testing.T) {
	if hi := SMCReservedRoleByte & 0xf0; hi < 0x20 {
		t.Fatalf("SMCReservedRoleByte = 0x%02x has non-reserved upper nibble 0x%x", SMCReservedRoleByte, hi>>4)
	}
	for _, conformant := range []byte{smcRAKP1BaselineRoleLookup, smcRAKP1ConformantRoleLookup} {
		if hi := conformant & 0xf0; hi != 0x10 {
			t.Fatalf("control role 0x%02x must be a spec-conformant role lookup (upper nibble 0x1)", conformant)
		}
	}
}

// TestSMCRAKP3BodyLayout pins the RAKP message-3 wire layout.
func TestSMCRAKP3BodyLayout(t *testing.T) {
	const sidm uint32 = 0x0000084f
	auth := bytes.Repeat([]byte{0xa5}, sha1.Size)
	body := smcRAKP3Body(sidm, auth)
	if len(body) != 8+sha1.Size {
		t.Fatalf("body length = %d, want %d", len(body), 8+sha1.Size)
	}
	if body[0] != 0x00 || body[1] != 0x00 {
		t.Fatalf("tag/status = 0x%02x/0x%02x, want 0x00/0x00", body[0], body[1])
	}
	if got := binary.LittleEndian.Uint32(body[4:8]); got != sidm {
		t.Fatalf("bmc SID = 0x%08x, want 0x%08x", got, sidm)
	}
	if !bytes.Equal(body[8:], auth) {
		t.Fatalf("auth code not carried verbatim")
	}
}

// buildRAKP4Payload assembles a RAKP message-4 payload the way an ATEN BMC does:
// tag, status, two reserved bytes, the echoed console session ID, then the ICV.
func buildRAKP4Payload(status byte, echoedSID uint32, icv []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x00)
	b.WriteByte(status)
	b.Write([]byte{0x00, 0x00})
	_ = binary.Write(&b, binary.LittleEndian, echoedSID)
	b.Write(icv)
	return b.Bytes()
}

// TestClassifySMCUnorderedRAKP4 drives the CVE-2026-65219 verdict from wire bytes.
//
// The two stacks are separated by the status code: the affected ATEN stack
// answers 0x08 with the console session ID echoed (non-standard, and proof that
// the slot was located and the authentication code compared), while the
// unaffected OpenBMC stack answers the spec-correct 0x0f.
func TestClassifySMCUnorderedRAKP4(t *testing.T) {
	const sidc uint32 = 0xabcd1234
	icv := bytes.Repeat([]byte{0x11}, 12)

	tests := []struct {
		name           string
		payload        []byte
		wantOK         bool
		wantDefect     bool
		wantConformant bool
		wantActivated  bool
		wantEchoed     bool
	}{
		{
			name:       "aten unordered rakp3 accepted, wrong key",
			payload:    buildRAKP4Payload(0x08, sidc, icv),
			wantOK:     true,
			wantDefect: true,
			wantEchoed: true,
		},
		{
			name:          "session activated (key matched)",
			payload:       buildRAKP4Payload(0x00, sidc, icv),
			wantOK:        true,
			wantDefect:    true,
			wantActivated: true,
			wantEchoed:    true,
		},
		{
			name:           "openbmc spec-conformant rejection",
			payload:        buildRAKP4Payload(0x0f, sidc, icv),
			wantOK:         true,
			wantConformant: true,
			wantEchoed:     true,
		},
		{
			name:    "status 0x08 without the console SID echoed is NOT the signal",
			payload: buildRAKP4Payload(0x08, 0x99999999, icv),
			wantOK:  true,
		},
		{
			name:    "unrelated status",
			payload: buildRAKP4Payload(0x02, sidc, icv),
			wantOK:  true,
			// echo present but status is neither the ATEN code nor 0x0f
			wantEchoed: true,
		},
		{
			name:    "truncated payload is unclassifiable",
			payload: []byte{0x00},
			wantOK:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &SMCUnorderedRAKP3Probe{ConsoleSID: sidc}
			ok := classifySMCUnorderedRAKP4(p, tc.payload, sidc)
			if ok != tc.wantOK {
				t.Fatalf("classify ok = %t, want %t", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if p.Defect != tc.wantDefect {
				t.Errorf("Defect = %t, want %t", p.Defect, tc.wantDefect)
			}
			if p.SpecConformant != tc.wantConformant {
				t.Errorf("SpecConformant = %t, want %t", p.SpecConformant, tc.wantConformant)
			}
			if p.Activated != tc.wantActivated {
				t.Errorf("Activated = %t, want %t", p.Activated, tc.wantActivated)
			}
			if p.SIDEchoed != tc.wantEchoed {
				t.Errorf("SIDEchoed = %t, want %t", p.SIDEchoed, tc.wantEchoed)
			}
			if p.Summary() == "" {
				t.Error("Summary() must never be empty for an answered probe")
			}
		})
	}
}

// TestSMCUnorderedProbeSummaryDistinguishesVerdicts guards against the two
// verdicts that must never read alike: an unaffected stack and a defect.
func TestSMCUnorderedProbeSummaryDistinguishesVerdicts(t *testing.T) {
	defect := &SMCUnorderedRAKP3Probe{Answered: true, RAKP4Status: 0x08, SIDEchoed: true, Defect: true}
	clean := &SMCUnorderedRAKP3Probe{Answered: true, RAKP4Status: 0x0f, SpecConformant: true}
	if defect.Summary() == clean.Summary() {
		t.Fatal("affected and unaffected summaries must differ")
	}
	if (*SMCUnorderedRAKP3Probe)(nil).Summary() != "not-probed" {
		t.Fatal("nil probe must report not-probed rather than a verdict")
	}
}

// TestSMCRecord0KeyCandidates guards the built-in candidate list: guesses at a
// short factory value, except the SMCRAKP firmware constant, which is the actual
// key where that mode is enabled. The order matters: on a generation that
// charges for a rejected RAKP3 only the first candidate of a run is interpretable,
// so burying the likeliest key reports a vulnerable board as clean.
func TestSMCRecord0KeyCandidates(t *testing.T) {
	got := SMCRecord0KeyCandidates()
	if len(got) != 5 {
		t.Fatalf("candidate count = %d, want 5", len(got))
	}
	wantLabels := []string{"<empty>", "0", "admin", "ADMIN", "smcrakp-fixed-key"}
	for i, want := range wantLabels {
		if got[i].Label != want {
			t.Errorf("candidate %d label = %q, want %q", i, got[i].Label, want)
		}
	}
	if len(got[0].Key) != 0 {
		t.Errorf("first candidate key = %x, want the empty key", got[0].Key)
	}
	if !bytes.Equal(got[4].Key, smcRAKPFixedKey) {
		t.Errorf("smcrakp candidate must be the CVE-2026-18449 firmware constant")
	}
	// Mutating a returned key must not corrupt the next caller's list.
	got[4].Key[0] ^= 0xff
	if !bytes.Equal(SMCRecord0KeyCandidates()[4].Key, smcRAKPFixedKey) {
		t.Fatal("SMCRecord0KeyCandidates leaks a mutable reference to the firmware constant")
	}
}

// TestSMCRecord0KeyCandidatesForGeneration pins the per-generation ordering against
// the keys recovered on each generation. Getting it wrong is a false negative: the
// attempt budget spends its one interpretable try on candidate 1.
func TestSMCRecord0KeyCandidatesForGeneration(t *testing.T) {
	for gen, wantFirst := range map[string]string{
		"X10": "admin",   // X10DSC+ FW 4.00
		"X11": "0",       // X11DPT-PS FW 01.74
		"H13": "<empty>", // H13 FW 01.03
		"x11": "0",       // case-insensitive
		"X13": "<empty>", // uncatalogued: falls back to the unknown-generation order
		"":    "<empty>", // unknown generation
	} {
		got := SMCRecord0KeyCandidatesForGeneration(gen)
		if len(got) != 5 {
			t.Errorf("generation %q: candidate count = %d, want 5", gen, len(got))
			continue
		}
		if got[0].Label != wantFirst {
			t.Errorf("generation %q: first candidate = %q, want %q", gen, got[0].Label, wantFirst)
		}
		// Every generation must still cover the whole list; ordering may differ but a
		// dropped candidate silently narrows the search.
		seen := map[string]bool{}
		for _, c := range got {
			seen[c.Label] = true
		}
		for _, want := range []string{"<empty>", "0", "admin", "ADMIN", "smcrakp-fixed-key"} {
			if !seen[want] {
				t.Errorf("generation %q: candidate %q dropped from the list", gen, want)
			}
		}
	}
	// The firmware constant must not be aliased across calls.
	g := SMCRecord0KeyCandidatesForGeneration("X10")
	for i := range g {
		if g[i].Label == "smcrakp-fixed-key" {
			g[i].Key[0] ^= 0xff
		}
	}
	for _, c := range SMCRecord0KeyCandidatesForGeneration("X10") {
		if c.Label == "smcrakp-fixed-key" && !bytes.Equal(c.Key, smcRAKPFixedKey) {
			t.Fatal("per-generation list leaks a mutable reference to the firmware constant")
		}
	}
}

// TestSMCRecord0FailureIsFree pins which generation may be swept with several
// candidates back to back. Only X10 qualifies: its RAKP3 path calls no lockout
// function at all, while X11/X12/X13/H13 charge a bad-password record against user
// record 0 and then answer a correct key with the same 0x08.
func TestSMCRecord0FailureIsFree(t *testing.T) {
	if !SMCRecord0FailureIsFree("X10") || !SMCRecord0FailureIsFree(" x10 ") {
		t.Error("X10 FW 4.00 has no lockout call in its RAKP3 path and must be treated as free")
	}
	for _, gen := range []string{"X11", "X12", "X13", "H13", "X14", "", "unknown"} {
		if SMCRecord0FailureIsFree(gen) {
			t.Errorf("generation %q must be treated as charging for a rejected RAKP3", gen)
		}
	}
}

// TestSMCForgeNegativeVerdict guards the negative verdict: a run whose candidates
// were all refused may be read as "not vulnerable" only when every candidate was
// actually sent and no lock on user record 0 could have masked the rejections.
func TestSMCForgeNegativeVerdict(t *testing.T) {
	rejected := SMCForgeAttempt{KeyLabel: "0", RAKP4Observed: true, RAKP4Status: 0x08}
	tests := []struct {
		name             string
		res              *SMCForgeResult
		sent             int
		gen              string
		wantInconclusive bool
	}{
		{
			name:             "one candidate refused, others untried",
			res:              &SMCForgeResult{Attempts: []SMCForgeAttempt{rejected}, Untried: []string{"admin"}, Defect: true},
			sent:             1,
			gen:              "H13",
			wantInconclusive: true,
		},
		{
			name:             "several candidates back to back on a charging generation",
			res:              &SMCForgeResult{Attempts: []SMCForgeAttempt{rejected, rejected, rejected}, Defect: true},
			sent:             3,
			gen:              "H13",
			wantInconclusive: true,
		},
		{
			name:             "several candidates on X10, where failures are free",
			res:              &SMCForgeResult{Attempts: []SMCForgeAttempt{rejected, rejected}, Defect: true},
			sent:             2,
			gen:              "X10",
			wantInconclusive: false,
		},
		{
			name:             "several candidates with a rest longer than the lock window",
			res:              &SMCForgeResult{Attempts: []SMCForgeAttempt{rejected, rejected}, Defect: true, Rest: smcRecord0RestFloor},
			sent:             2,
			gen:              "H13",
			wantInconclusive: false,
		},
		{
			name:             "a rest shorter than the lock window does not help",
			res:              &SMCForgeResult{Attempts: []SMCForgeAttempt{rejected, rejected}, Defect: true, Rest: smcRecord0RestFloor - 1},
			sent:             2,
			gen:              "H13",
			wantInconclusive: true,
		},
		{
			name:             "a spec-conformant stack is a real negative, not an inconclusive one",
			res:              &SMCForgeResult{Attempts: []SMCForgeAttempt{{KeyLabel: "0", RAKP4Observed: true, RAKP4Status: 0x0f}}, SpecConformant: true},
			sent:             1,
			gen:              "H13",
			wantInconclusive: false,
		},
		{
			name:             "nothing came back at all",
			res:              &SMCForgeResult{Attempts: []SMCForgeAttempt{{KeyLabel: "0"}}},
			sent:             1,
			gen:              "H13",
			wantInconclusive: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inconclusive, reason := smcForgeNegativeVerdict(tc.res, tc.sent, tc.gen)
			if inconclusive != tc.wantInconclusive {
				t.Fatalf("inconclusive = %t, want %t (reason %q)", inconclusive, tc.wantInconclusive, reason)
			}
			if inconclusive && reason == "" {
				t.Error("an inconclusive verdict must carry a reason an operator can act on")
			}
			if !inconclusive && reason != "" {
				t.Errorf("a conclusive verdict must not carry an excuse, got %q", reason)
			}
		})
	}
}

func TestParseSMCRecord0KeyCandidates(t *testing.T) {
	if got, err := ParseSMCRecord0KeyCandidates("  "); err != nil || len(got) != 5 {
		t.Fatalf("blank spec should fall back to the built-in list: %v %d", err, len(got))
	}
	got, err := ParseSMCRecord0KeyCandidates("0,,smcrakp,hex:4142")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("candidate count = %d, want 4", len(got))
	}
	if !bytes.Equal(got[0].Key, []byte("0")) {
		t.Errorf("literal candidate = %q", got[0].Key)
	}
	if len(got[1].Key) != 0 || got[1].Label != "<empty>" {
		t.Errorf("empty element should mean the empty key, got %q/%x", got[1].Label, got[1].Key)
	}
	if !bytes.Equal(got[2].Key, smcRAKPFixedKey) {
		t.Errorf("\"smcrakp\" should select the firmware constant")
	}
	if !bytes.Equal(got[3].Key, []byte{0x41, 0x42}) {
		t.Errorf("hex candidate = %x, want 4142", got[3].Key)
	}
	if _, err := ParseSMCRecord0KeyCandidates("hex:zz"); err == nil {
		t.Error("invalid hex should be rejected rather than silently treated as a literal")
	}
}

// TestSMCForgedCapabilityProbesAreReadOnly is a safety guard: the capability
// matrix run automatically against a forged session must contain reads only.
// Activate Payload opens a console on the managed host and stays opt-in.
func TestSMCForgedCapabilityProbesAreReadOnly(t *testing.T) {
	writeCmds := map[byte]string{
		CmdActivatePayload:     "Activate Payload",
		CmdDeactivatePayload:   "Deactivate Payload",
		CmdSetSessionPrivilege: "Set Session Privilege Level",
		0x43:                   "Set User Access",
		0x45:                   "Set User Password",
		0x40:                   "Set Channel Access",
	}
	for _, p := range smcForgedReadOnlyProbes {
		if p.NetFn == NetFnApp {
			if name, bad := writeCmds[p.Cmd]; bad {
				t.Fatalf("read-only capability probe contains %s (0x%02x/0x%02x)", name, p.NetFn, p.Cmd)
			}
		}
	}
	if len(smcForgedReadOnlyProbes) == 0 {
		t.Fatal("capability probe list is empty")
	}
	// The measurement is only meaningful if it spans both the reachable lane and
	// the commands the messaging-bit route denies.
	var sawGUID, sawUserAccess bool
	for _, p := range smcForgedReadOnlyProbes {
		if p.NetFn == NetFnApp && p.Cmd == CmdGetSystemGUID {
			sawGUID = true
		}
		if p.NetFn == NetFnApp && p.Cmd == CmdGetUserAccess {
			sawUserAccess = true
		}
	}
	if !sawGUID || !sawUserAccess {
		t.Fatal("capability probe must cover both a reachable read (Get System GUID) and a denied one (Get User Access)")
	}
}

// TestSMCReservedRoleRejectedConformantly pins which message-2 statuses count as
// a spec-conformant refusal of a reserved role byte.
func TestSMCReservedRoleRejectedConformantly(t *testing.T) {
	for _, st := range []byte{rakpStatusInvalidRole, rakpStatusUnauthorizedRole, rakpStatusIllegalParameter} {
		if !smcReservedRoleRejectedConformantly(st) {
			t.Errorf("status 0x%02x should count as a conformant refusal", st)
		}
	}
	for _, st := range []byte{0x00, rakpStatusUnauthorizedName, 0xff} {
		if smcReservedRoleRejectedConformantly(st) {
			t.Errorf("status 0x%02x must not count as a conformant refusal", st)
		}
	}
}

// TestSMCReservedRoleProbeSummary covers the verdict rendering, including the
// case where no account name resolved (which is not a negative result).
func TestSMCReservedRoleProbeSummary(t *testing.T) {
	if got := (&SMCReservedRoleProbe{}).Summary(); got != "no-resolvable-account" {
		t.Errorf("empty probe summary = %q", got)
	}
	defect := &SMCReservedRoleProbe{Username: "ADMIN", BaselineAccepted: true, ReservedRole: 0x24, ReservedAccepted: true, Defect: true}
	clean := &SMCReservedRoleProbe{Username: "ADMIN", BaselineAccepted: true, ReservedRole: 0x24, ReservedStatus: 0x09}
	if defect.Summary() == clean.Summary() {
		t.Fatal("accepted and rejected reserved-role summaries must differ")
	}
}

// TestOpenSession20SMCReservedRoleAllowsNullUsername locks that the CVE-2026-65220
// escalation accepts an empty low-privilege username: the null/anonymous account is
// a real IPMI identity with its own password, framed with a zero-length username
// field like any other login here. A call with neither user nor password must still
// be rejected; one with a password and no username must reach the network attempt.
func TestOpenSession20SMCReservedRoleAllowsNullUsername(t *testing.T) {
	if _, err := OpenSession20SMCReservedRole("127.0.0.1", 1, "", "", "ADMIN", 0x24, 10*time.Millisecond); err == nil {
		t.Fatal("expected an error for an entirely empty credential")
	} else if !strings.Contains(err.Error(), "credential is required") {
		t.Fatalf("empty user+pass should fail input validation, got: %v", err)
	}

	_, err := OpenSession20SMCReservedRole("127.0.0.1", 1, "", "somepassword", "ADMIN", 0x24, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected a network-level error (nothing listening on this port)")
	}
	if strings.Contains(err.Error(), "credential is required") {
		t.Fatalf("null-username escalation rejected by input validation: %v", err)
	}
}

// TestSMCEscalationProven guards the CVE-2026-65220 verdict: a privileged read
// succeeding proves nothing unless the same read was denied on a normal login,
// since the account may already have held the privilege.
func TestSMCEscalationProven(t *testing.T) {
	tests := []struct {
		name string
		in   *SMCReservedRoleEscalation
		want bool
	}{
		{"nil", nil, false},
		{
			name: "baseline denied, escalated allowed",
			in:   &SMCReservedRoleEscalation{BaselineMeasured: true, BaselineUserAccessCC: 0xd4, EscalatedUserAccessCC: 0x00},
			want: true,
		},
		{
			name: "baseline already allowed: account was not low-privilege",
			in:   &SMCReservedRoleEscalation{BaselineMeasured: true, BaselineUserAccessCC: 0x00, EscalatedUserAccessCC: 0x00},
			want: false,
		},
		{
			// 0xcc is "invalid data field", not a privilege denial. Accepting it would
			// manufacture an escalation out of a command that merely started working.
			name: "baseline refused for a NON-privilege reason",
			in:   &SMCReservedRoleEscalation{BaselineMeasured: true, BaselineUserAccessCC: 0xcc, EscalatedUserAccessCC: 0x00},
			want: false,
		},
		{
			name: "escalated still denied",
			in:   &SMCReservedRoleEscalation{BaselineMeasured: true, BaselineUserAccessCC: 0xd4, EscalatedUserAccessCC: 0xd4},
			want: false,
		},
		{
			name: "baseline never measured: claim withheld",
			in:   &SMCReservedRoleEscalation{BaselineUserAccessCC: 0xd4, EscalatedUserAccessCC: 0x00},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SMCEscalationProven(tc.in); got != tc.want {
				t.Fatalf("SMCEscalationProven = %t, want %t", got, tc.want)
			}
		})
	}
}

// TestSMCProbeKeyIsNotACandidate guards the safety property of the default
// detection path: the sentinel used to force a RAKP3 mismatch must not be one of
// the plausible record-0 values, or the "safe" probe could activate a session.
func TestSMCProbeKeyIsNotACandidate(t *testing.T) {
	if len(smcRAKP3ProbeKey) == 0 {
		t.Fatal("probe key must not be empty (the empty key is a real candidate)")
	}
	for _, cand := range SMCRecord0KeyCandidates() {
		if bytes.Equal(cand.Key, smcRAKP3ProbeKey) {
			t.Fatalf("probe key collides with candidate %q", cand.Label)
		}
	}
}

// TestSMCOperatorControlCredibility guards the Operator control: a control session
// clamped to USER answers 0xd4 to commands a real Operator is granted, which would
// promote those into "Administrator witnesses" and manufacture an Operator ceiling.
// The control counts only if it was granted something the baseline was refused.
func TestSMCOperatorControlCredibility(t *testing.T) {
	// A credible control: refused to the baseline, granted to the control.
	credible := []SMCPrivWitness{
		{Name: "Get User Access", BaselineMeasured: true, BaselineCC: 0xd4, OperatorMeasured: true, OperatorCC: 0x00},
		{Name: "Get Device SDR Info", BaselineMeasured: true, BaselineCC: 0xd4, OperatorMeasured: true, OperatorCC: 0xd4, AdminMeasured: true, AdminCC: 0x00},
	}
	// A control clamped to USER: it mirrors the baseline exactly.
	clamped := []SMCPrivWitness{
		{Name: "Get User Access", BaselineMeasured: true, BaselineCC: 0xd4, OperatorMeasured: true, OperatorCC: 0xd4, AdminMeasured: true, AdminCC: 0x00},
		{Name: "Get Device SDR Info", BaselineMeasured: true, BaselineCC: 0xd4, OperatorMeasured: true, OperatorCC: 0xd4, AdminMeasured: true, AdminCC: 0x00},
	}
	for _, tc := range []struct {
		name string
		ws   []SMCPrivWitness
		want bool
	}{{"credible", credible, true}, {"clamped to user", clamped, false}} {
		t.Run(tc.name, func(t *testing.T) {
			above := false
			for _, w := range tc.ws {
				if w.BaselineMeasured && smcWitnessDenied(w.BaselineCC) && w.OperatorMeasured && w.OperatorCC == 0x00 {
					above = true
				}
			}
			if above != tc.want {
				t.Fatalf("operator-above-baseline = %t, want %t", above, tc.want)
			}
		})
	}
}

// TestSMCEscalationCeiling pins the ceiling rule: a command decides the
// Administrator/Operator boundary only if an Operator-privilege session was proven
// refused it on the unit under test. Get Device SDR Info is refused 0xd4 even to an
// ADMIN session on H13 FW 01.03, so counting it as a witness downgrades a genuine
// Administrator result to "operator".
func TestSMCEscalationCeiling(t *testing.T) {
	tests := []struct {
		name             string
		ws               []SMCPrivWitness
		wantReached      string
		wantUsed         string
		wantInconclusive bool
	}{
		{
			name: "a proven administrator-gated witness is granted",
			ws: []SMCPrivWitness{
				{Name: "Get User Access", OperatorMeasured: true, OperatorCC: 0xd4, AdminMeasured: true, AdminCC: 0x00, Discriminates: true, EscalatedMeasured: true, EscalatedCC: 0x00},
			},
			wantReached: "administrator",
			wantUsed:    "Get User Access",
		},
		{
			name: "a proven administrator-gated witness is refused: a real operator ceiling",
			ws: []SMCPrivWitness{
				{Name: "Get User Access", OperatorMeasured: true, OperatorCC: 0xd4, AdminMeasured: true, AdminCC: 0x00, Discriminates: true, EscalatedMeasured: true, EscalatedCC: 0xd4},
			},
			wantReached: "operator",
			wantUsed:    "Get User Access",
		},
		{
			// The H13 FW 01.03 shape, fully controlled: an Operator is granted the
			// user-config reads, and the one command an Operator is refused is refused to
			// ADMIN too, so it is unavailable rather than Administrator-gated. No read
			// separates the two and the ceiling stays unresolved.
			name: "both controls measured and nothing discriminated",
			ws: []SMCPrivWitness{
				{Name: "Get User Access", OperatorMeasured: true, OperatorCC: 0x00, AdminMeasured: true, AdminCC: 0x00, EscalatedMeasured: true, EscalatedCC: 0x00},
				{Name: "Get Device SDR Info", OperatorMeasured: true, OperatorCC: 0xd4, AdminMeasured: true, AdminCC: 0xd4, EscalatedMeasured: true, EscalatedCC: 0xd4},
			},
			wantReached:      "operator-or-administrator (no read-only witness separates them on this firmware)",
			wantInconclusive: true,
		},
		{
			// An operator control without the administrator reference cannot settle it
			// either: "refused to Operator" alone is ambiguous.
			name: "operator control but no administrator reference",
			ws: []SMCPrivWitness{
				{Name: "Get Device SDR Info", OperatorMeasured: true, OperatorCC: 0xd4, EscalatedMeasured: true, EscalatedCC: 0xd4},
			},
			wantReached:      "administrator (witness inconclusive on this firmware)",
			wantInconclusive: true,
		},
		{
			// A proven witness refused to the escalated session for a reason other than
			// privilege (0xcc) must not be read as an operator ceiling.
			name: "proven witness refused for a non-privilege reason",
			ws: []SMCPrivWitness{
				{Name: "Get LAN Config param 24", OperatorMeasured: true, OperatorCC: 0xd4, AdminMeasured: true, AdminCC: 0x00, Discriminates: true, EscalatedMeasured: true, EscalatedCC: 0xcc},
			},
			wantReached:      "operator-or-administrator (no read-only witness separates them on this firmware)",
			wantInconclusive: true,
		},
		{
			name: "no operator control supplied: administrator with the caveat, never a downgrade",
			ws: []SMCPrivWitness{
				{Name: "Get User Access", EscalatedMeasured: true, EscalatedCC: 0x00},
				{Name: "Get Device SDR Info", EscalatedMeasured: true, EscalatedCC: 0xd4},
			},
			wantReached:      "administrator (witness inconclusive on this firmware)",
			wantInconclusive: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reached, used, inconclusive := smcEscalationCeiling(tc.ws)
			if reached != tc.wantReached {
				t.Errorf("reached = %q, want %q", reached, tc.wantReached)
			}
			if used != tc.wantUsed {
				t.Errorf("witness used = %q, want %q", used, tc.wantUsed)
			}
			if inconclusive != tc.wantInconclusive {
				t.Errorf("inconclusive = %t, want %t", inconclusive, tc.wantInconclusive)
			}
			// The one thing that must never happen: claiming an Operator ceiling from a
			// witness that was not proven to discriminate.
			if reached == "operator" {
				proven := false
				for _, w := range tc.ws {
					if w.Discriminates && w.EscalatedMeasured {
						proven = true
					}
				}
				if !proven {
					t.Error("reported an operator ceiling with no proven discriminating witness")
				}
			}
		})
	}
}

// TestSMCClassifyEscalation covers the verdict arms that must report inconclusive
// rather than "not escalated", because each is a measurement failure and not a
// negative result.
func TestSMCClassifyEscalation(t *testing.T) {
	adminWitness := func(escalatedCC byte) []SMCPrivWitness {
		return []SMCPrivWitness{{Name: "Get User Access", BaselineMeasured: true, BaselineCC: 0xd4, OperatorMeasured: true, OperatorCC: 0xd4, AdminMeasured: true, AdminCC: 0x00, Discriminates: true, EscalatedMeasured: true, EscalatedCC: escalatedCC}}
	}
	tests := []struct {
		name             string
		in               *SMCReservedRoleEscalation
		wantReached      string
		wantEscalated    bool
		wantInconclusive bool
	}{
		{
			name: "closed command lane: the messaging bit is clear, not a negative",
			in: &SMCReservedRoleEscalation{
				BaselineMeasured: true, BaselineUserAccessCC: 0xd4,
				EscalatedUserAccessCC: 0xd4,
				LaneBaselineCC:        0x00, LaneEscalatedCC: 0xd4,
			},
			wantReached: "inconclusive", wantInconclusive: true,
		},
		{
			name:        "baseline never measured",
			in:          &SMCReservedRoleEscalation{EscalatedUserAccessCC: 0x00, BaselineError: "connection refused"},
			wantReached: "inconclusive", wantInconclusive: true,
		},
		{
			// Every candidate was granted on a normal login, so there is no baseline denial
			// to build a proof on. Reporting "not escalated" here would be a false negative.
			name: "baseline account already held every candidate: no proof command exists",
			in: &SMCReservedRoleEscalation{
				BaselineMeasured: true, BaselineUserAccessCC: 0x00, EscalatedUserAccessCC: 0x00,
				LaneBaselineCC: 0x00, LaneEscalatedCC: 0x00,
				Witnesses: []SMCPrivWitness{
					{Name: "Get User Access", BaselineMeasured: true, BaselineCC: 0x00, EscalatedMeasured: true, EscalatedCC: 0x00},
				},
			},
			wantReached: "inconclusive", wantInconclusive: true,
		},
		{
			// The adaptive selection: Get User Access is granted at USER on this firmware,
			// so the proof falls through to the next candidate the baseline was refused.
			name: "proof command selected past a candidate the baseline was granted",
			in: &SMCReservedRoleEscalation{
				BaselineMeasured: true, BaselineUserAccessCC: 0x00, EscalatedUserAccessCC: 0x00,
				LaneBaselineCC: 0x00, LaneEscalatedCC: 0x00,
				Witnesses: []SMCPrivWitness{
					{Name: "Get User Access", BaselineMeasured: true, BaselineCC: 0x00, EscalatedMeasured: true, EscalatedCC: 0x00},
					{Name: "Get PEF Config param 1", BaselineMeasured: true, BaselineCC: 0xd4, OperatorMeasured: true, OperatorCC: 0x00, AdminMeasured: true, AdminCC: 0x00, EscalatedMeasured: true, EscalatedCC: 0x00},
				},
			},
			// The escalation is proven; only the ceiling is unresolved, which is
			// WitnessInconclusive, not Inconclusive.
			wantReached: "operator-or-administrator (no read-only witness separates them on this firmware)", wantEscalated: true,
		},
		{
			name: "escalation refused with the lane open: a genuine negative",
			in: &SMCReservedRoleEscalation{
				BaselineMeasured: true, BaselineUserAccessCC: 0xd4, EscalatedUserAccessCC: 0xd4,
				LaneBaselineCC: 0x00, LaneEscalatedCC: 0x00,
				Witnesses: adminWitness(0xd4),
			},
			wantReached: "none",
		},
		{
			name: "proven administrator",
			in: &SMCReservedRoleEscalation{
				BaselineMeasured: true, BaselineUserAccessCC: 0xd4, EscalatedUserAccessCC: 0x00,
				LaneBaselineCC: 0x00, LaneEscalatedCC: 0x00,
				Witnesses: adminWitness(0x00),
			},
			wantReached: "administrator", wantEscalated: true,
		},
		{
			name: "proven operator ceiling",
			in: &SMCReservedRoleEscalation{
				BaselineMeasured: true, BaselineUserAccessCC: 0xd4, EscalatedUserAccessCC: 0x00,
				LaneBaselineCC: 0x00, LaneEscalatedCC: 0x00,
				Witnesses: []SMCPrivWitness{
					{Name: "Get User Access", BaselineMeasured: true, BaselineCC: 0xd4, OperatorMeasured: true, OperatorCC: 0x00, AdminMeasured: true, AdminCC: 0x00, EscalatedMeasured: true, EscalatedCC: 0x00},
					{Name: "Get Channel Access", BaselineMeasured: true, BaselineCC: 0xd4, OperatorMeasured: true, OperatorCC: 0xd4, AdminMeasured: true, AdminCC: 0x00, Discriminates: true, EscalatedMeasured: true, EscalatedCC: 0xd4},
				},
			},
			wantReached: "operator", wantEscalated: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			smcClassifyEscalation(tc.in)
			if tc.in.Reached != tc.wantReached {
				t.Errorf("reached = %q, want %q", tc.in.Reached, tc.wantReached)
			}
			if tc.in.Escalated != tc.wantEscalated {
				t.Errorf("escalated = %t, want %t", tc.in.Escalated, tc.wantEscalated)
			}
			if tc.in.Inconclusive != tc.wantInconclusive {
				t.Errorf("inconclusive = %t, want %t (reason %q)", tc.in.Inconclusive, tc.wantInconclusive, tc.in.Reason)
			}
			if tc.in.Inconclusive && tc.in.Reason == "" {
				t.Error("an inconclusive verdict must carry a reason")
			}
		})
	}
	// A nil result must not panic.
	smcClassifyEscalation(nil)
}

// TestSMCAdminWitnessCandidatesAreReadOnly is a safety guard: the witness matrix is
// run against three live sessions, so every entry must be a get.
func TestSMCAdminWitnessCandidatesAreReadOnly(t *testing.T) {
	writes := map[[2]byte]string{
		{NetFnApp, 0x43}: "Set User Access",
		{NetFnApp, 0x45}: "Set User Password",
		{NetFnApp, 0x40}: "Set Channel Access",
		{NetFnApp, 0x3b}: "Set Session Privilege Level",
		{0x0c, 0x01}:     "Set LAN Configuration Parameters",
		{0x0c, 0x21}:     "Set SOL Configuration Parameters",
	}
	if len(smcAdminWitnessCandidates) == 0 {
		t.Fatal("witness candidate list is empty")
	}
	for _, w := range smcAdminWitnessCandidates {
		if name, bad := writes[[2]byte{w.NetFn, w.Cmd}]; bad {
			t.Errorf("witness list contains the write command %s (0x%02x/0x%02x)", name, w.NetFn, w.Cmd)
		}
	}
	if name, bad := writes[[2]byte{smcLaneWitness.NetFn, smcLaneWitness.Cmd}]; bad {
		t.Errorf("lane witness is a write command: %s", name)
	}
	// Get User Access has to stay first: it is also the escalation proof, and the
	// baseline/escalated completion codes are lifted from index 0.
	if smcAdminWitnessCandidates[0].NetFn != NetFnApp || smcAdminWitnessCandidates[0].Cmd != CmdGetUserAccess {
		t.Fatalf("witness 0 = 0x%02x/0x%02x, want Get User Access (it is also the escalation proof)",
			smcAdminWitnessCandidates[0].NetFn, smcAdminWitnessCandidates[0].Cmd)
	}
}

// TestSMCForgeVerdictUsesFirstAnsweredAttempt guards a small but real
// false-negative path: a board that dropped the first packet and answered the second
// must still get its ordering verdict read off the answer, not off the drop.
func TestSMCForgeVerdictUsesFirstAnsweredAttempt(t *testing.T) {
	res := &SMCForgeResult{Attempts: []SMCForgeAttempt{
		{KeyLabel: "<empty>", Error: "i/o timeout"},
		{KeyLabel: "0", RAKP4Observed: true, RAKP4Status: 0x08},
	}}
	if got := smcFirstAnsweredAttempt(res.Attempts); got == nil || got.KeyLabel != "0" {
		t.Fatalf("first answered attempt = %+v, want the second entry", got)
	}
	inconclusive, reason := smcForgeNegativeVerdict(res, 2, "H13")
	if !inconclusive {
		t.Error("two back-to-back rejections on H13 must be inconclusive")
	}
	if reason == "" {
		t.Error("missing reason")
	}
	// Nothing answered at all must be reported as nothing measured, not as a rejection.
	none := &SMCForgeResult{Attempts: []SMCForgeAttempt{{KeyLabel: "<empty>", Error: "i/o timeout"}}}
	if smcFirstAnsweredAttempt(none.Attempts) != nil {
		t.Fatal("no attempt was answered")
	}
	inconclusive, reason = smcForgeNegativeVerdict(none, 1, "H13")
	if !inconclusive || !strings.Contains(reason, "no RAKP message 4") {
		t.Errorf("a run with no answer must say so, got inconclusive=%t reason=%q", inconclusive, reason)
	}
}
