package ipmi

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	CmdSetSOLConfigParams byte = 0x21
	CmdGetSOLConfigParams byte = 0x22

	CmdMasterWriteRead byte = 0x52
)

type CmdSessOptions struct {
	Host           string
	Port           int
	Username       string
	Password       string
	Timeout        time.Duration
	MaxRetries     int
	IPMIVersion    string
	Auth           string
	Cipher         int
	DisableSMCRAKP bool

	CommandProtection string
}

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

func (s *CmdSess) CommandProtection() string {
	if s == nil {
		return ""
	}
	if s20, ok := s.runner.(*Session20); ok {
		return s20.CommandProtectionUsed()
	}
	return s.commandProtection
}

type CmdSess struct {
	runner            cmdRunner
	flow              AuthFlow
	advertisedCiphers []int
	smcrakpDetected   bool
	commandProtection string
	host              string
}

func (s *CmdSess) Host() string {
	if s == nil {
		return ""
	}
	return s.host
}

func (s *CmdSess) Flow() AuthFlow {
	if s == nil {
		return AuthFlow{}
	}
	return s.flow
}

func (s *CmdSess) AdvertisedCiphers() []int {
	if s == nil || len(s.advertisedCiphers) == 0 {
		return nil
	}
	out := make([]int, len(s.advertisedCiphers))
	copy(out, s.advertisedCiphers)
	return out
}

func (s *CmdSess) SMCRAKPDetected() bool {
	if s == nil {
		return false
	}
	return s.smcrakpDetected
}

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

	if flow.Mode == "cred" && suite.Auth != RAKPNone && strings.TrimSpace(flow.Username) == "" {
		return nil, fmt.Errorf("--user is required for authenticated IPMI 2.0 sessions")
	}
	r, err := openRunner(host, opts.Port, flow, opts.Timeout, prot)

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
		if s20, ok := r.(*Session20); ok && s20 != nil {
			s20.cmdRetries = opts.MaxRetries
		}
		return &CmdSess{runner: r, flow: flow, advertisedCiphers: ciphers, host: host}, nil
	}
	if opts.DisableSMCRAKP || !isRAKPAuthFailure(err) {
		return nil, err
	}
	if !detectSMCRAKPFixedKey(host, opts.Port, opts.Timeout, opts.Username) {
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

var blindCipherFallback = []int{3, 2, 1}

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

func (s *CmdSess) ExecRaw(netfn, cmd byte, req []byte) (byte, []byte, error) {
	if s == nil || s.runner == nil {
		return 0xff, nil, fmt.Errorf("session closed")
	}
	return s.runner.Exec(netfn, cmd, req)
}

func (s *CmdSess) MCInfo(ctx context.Context) (*MCInfo, error) {
	return collectMCInfo(ctx, s.runner)
}

func (s *CmdSess) ChassisStatus(ctx context.Context) (*ChassisStatus, error) {
	return collectChassisStatus(ctx, s.runner)
}

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

func (s *CmdSess) UserList(ctx context.Context) ([]UserEntry, error) {
	return collectUsers(ctx, s.runner)
}

func (s *CmdSess) LANPrint(ctx context.Context) (map[string]string, map[string]string, error) {
	return collectLAN(ctx, s.runner)
}

func (s *CmdSess) FRUPrint(ctx context.Context, maxFields int) ([]FRUField, error) {
	if maxFields <= 0 {
		maxFields = 64
	}
	return collectFRUDevice(ctx, s.runner, 0, maxFields)
}

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

func (s *CmdSess) UserEnable(id int) error { return s.userEnableDisable(id, true) }

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

func (s *CmdSess) SPDRead(slaveAddr, offset, length byte) ([]byte, error) {
	return s.I2CMasterWriteRead(0x0e, slaveAddr, length, []byte{offset})
}

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

func (s *CmdSess) SOLActivate() ([]byte, error) {

	cc, d, err := s.runner.Exec(NetFnApp, CmdActivatePayload, []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return nil, err
	}
	if cc != 0x00 {
		return nil, fmt.Errorf("activate-sol cc=0x%02x", cc)
	}
	return d, nil
}

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
