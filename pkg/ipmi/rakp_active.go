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

const maxOnlineAttempts = 6

const maxOnlineUsersAfterSMCRAKP = 2

const maxSMCRAKPOnlinePasswordAttempts = 256

const maxOracleUsernames = 4

const rakpLoginRole byte = 0x14

type AuthOptions struct {
	Usernames      []string
	Vendor         string
	Ciphers        []int
	Online         bool
	OfflineCrack   bool
	Permute        bool
	ExtraPasswords []string
	Timeout        time.Duration
}

type AuthReport struct {
	Host         string       `json:"host"`
	Port         int          `json:"port"`
	Suite        *CipherAlgos `json:"suite,omitempty"`
	CipherZero   bool         `json:"cipherZero"`
	FakeUsername bool         `json:"fakeUsername"`

	CipherZeroSID   uint32 `json:"cipherZeroSid,omitempty"`
	FakeUsernameSID uint32 `json:"fakeUsernameSid,omitempty"`

	FakeUsernameProbe string        `json:"fakeUsernameProbe,omitempty"`
	Results           []RAKPResult  `json:"results"`
	Cracked           []CrackResult `json:"cracked"`
}

func RunAuth(ctx context.Context, host string, port int, opts AuthOptions) (*AuthReport, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	rep := &AuthReport{Host: host, Port: port}

	if z, _ := DoRAKP12(host, port, "", RAKPNone, IntegrityNone, ConfNone, opts.Timeout); z != nil && z.BMCSID != 0 && z.ErrorCode == 0 {
		rep.CipherZero = true
		rep.CipherZeroSID = z.BMCSID
	}

	var suite *CipherAlgos
	for _, ca := range CipherTriples(opts.Ciphers) {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		r, _ := DoRAKP12(host, port, "", ca.Auth, ca.Integrity, ca.Conf, opts.Timeout)
		if r != nil && r.BMCSID != 0 {
			ca := ca
			suite = &ca
			break
		}
	}
	if suite == nil {
		return rep, nil
	}
	rep.Suite = suite

	var fakeUser string
	rep.FakeUsername, fakeUser, rep.FakeUsernameSID = detectFakeUsername(host, port, *suite, opts.Timeout)
	rep.FakeUsernameProbe = fakeUser

	users := preferredUsernames(opts.Usernames, creds.UsernamesFor(opts.Vendor))

	consecDrop, totalDrop := 0, 0
	for i, u := range users {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		r, err := DoRAKP12(host, port, u, suite.Auth, suite.Integrity, suite.Conf, opts.Timeout)

		if (r == nil || r.BMCSID == 0) && i < 2 && ctx.Err() == nil {
			r, err = DoRAKP12(host, port, u, suite.Auth, suite.Integrity, suite.Conf, opts.Timeout)
		}

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
			continue
		}

		if opts.OfflineCrack {
			if cr := CrackRAKP(r, CrackOptions{Vendor: opts.Vendor, ExtraPasswords: opts.ExtraPasswords, Permute: opts.Permute}); cr != nil {
				cr.AcceptsAny = rep.FakeUsername
				switch {
				case cr.PasswordType == "smcrakp-fixed-key":
					cr.LoginTested = true
					if ok, proof, verr := rakpSessionLoginWithSuiteKey(host, port, cr.Username, smcRAKPFixedKey, *suite, opts.Timeout); verr == nil && ok {
						cr.Verified = true
						cr.Proof = proof

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

					cr.Verified = true
					cr.Proof = rakp2Proof(r)
				case opts.Online:

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

		if len(rep.Cracked) > 0 {
			break
		}

		if rep.FakeUsername && len(rep.Results) >= maxOracleUsernames {
			break
		}
	}

	if len(rep.Results) == 0 && opts.Online {
		for i, u := range users {
			if i >= 3 || ctx.Err() != nil {
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

type SMCRAKPOnlinePasswordReport struct {
	Attempted  bool         `json:"attempted"`
	Usernames  []string     `json:"usernames,omitempty"`
	Suites     []int        `json:"suites,omitempty"`
	Candidates int          `json:"candidates"`
	Attempts   int          `json:"attempts"`
	SessionOK  bool         `json:"sessionOk"`
	Credential *CrackResult `json:"credential,omitempty"`
}

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

func smcrakpCommandCapable(host string, port int, username string, negotiated CipherAlgos, timeout time.Duration) (bool, string) {
	auth := negotiated.Auth
	if auth == 0 {
		auth = RAKPHMACSHA1
	}

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

			return &CrackResult{Username: user, Password: c.Password, PasswordType: "online", Vendor: opts.Vendor, Attempts: n, Verified: true, LoginTested: true, Proof: proof}
		}
	}
	return nil
}

func rakpSessionLoginWithSuite(host string, port int, username, password string, suite CipherAlgos, timeout time.Duration) (bool, string, error) {
	return rakpSessionLoginWithSuiteSecret(host, port, username, []byte(password), suite, timeout, false)
}

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

	var os bytes.Buffer
	os.WriteByte(0x00)
	os.WriteByte(0x04)
	os.Write([]byte{0x00, 0x00})
	_ = binary.Write(&os, binary.LittleEndian, cSID)
	os.Write([]byte{0x00, 0x00, 0x00, 0x08, suite.Auth, 0, 0, 0})
	os.Write([]byte{0x01, 0x00, 0x00, 0x08, suite.Integrity, 0, 0, 0})
	os.Write([]byte{0x02, 0x00, 0x00, 0x08, suite.Conf, 0, 0, 0})
	osResp, err := c.Send(buildRMCPPlus(PayloadOpenSessionReq, 0, 0, os.Bytes()))
	if err != nil {
		return false, "", fmt.Errorf("open-session: %w", err)
	}
	bmcSID, err := parseOpenSessionResp(osResp)
	if err != nil {
		return false, "", err
	}

	var r1 bytes.Buffer
	r1.WriteByte(0x00)
	r1.Write([]byte{0, 0, 0})
	_ = binary.Write(&r1, binary.LittleEndian, bmcSID)
	r1.Write(cRand)
	r1.WriteByte(rakpLoginRole)
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

	kec := rakpKEC3ByAlgoKey(suite.Auth, secret, res.BMCRand, cSID, rakpLoginRole, username)
	var r3 bytes.Buffer
	r3.WriteByte(0x00)
	r3.WriteByte(0x00)
	r3.Write([]byte{0, 0})
	_ = binary.Write(&r3, binary.LittleEndian, bmcSID)
	r3.Write(kec)
	r4Resp, err := c.Send(buildRMCPPlus(PayloadRAKP3, 0, 0, r3.Bytes()))
	if err != nil {
		return false, "", fmt.Errorf("rakp3: %w", err)
	}

	p, err := rmcpPlusPayload(r4Resp)
	if err != nil {
		return false, "", err
	}
	if len(p) < 2 {
		return false, "", errors.New("short RAKP4")
	}
	if p[1] == 0x00 {

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
