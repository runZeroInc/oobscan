package ipmi

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/runZeroInc/oobscan/pkg/creds"
)

const v15MaxLoginAttempts = maxOnlineAttempts

type Session15 struct {
	AuthType   byte
	Password   string
	SessionID  uint32
	InboundSeq uint32
	MaxPriv    byte
}

func pad16(s string) []byte {
	b := make([]byte, 16)
	copy(b, s)
	return b
}

func v15AuthCode(authType byte, password string, sessionID, sessionSeq uint32, msgData []byte) []byte {
	switch authType {
	case IPMI15AuthPass:
		return pad16(password)
	case IPMI15AuthMD5:
		pw := pad16(password)
		var sid, seq [4]byte
		binary.LittleEndian.PutUint32(sid[:], sessionID)
		binary.LittleEndian.PutUint32(seq[:], sessionSeq)
		h := md5.New()
		h.Write(pw)
		h.Write(sid[:])
		h.Write(msgData)
		h.Write(seq[:])
		h.Write(pw)
		return h.Sum(nil)
	case IPMI15AuthMD2:

		pw := pad16(password)
		var sid, seq [4]byte
		binary.LittleEndian.PutUint32(sid[:], sessionID)
		binary.LittleEndian.PutUint32(seq[:], sessionSeq)
		buf := make([]byte, 0, 16+4+len(msgData)+4+16)
		buf = append(buf, pw...)
		buf = append(buf, sid[:]...)
		buf = append(buf, msgData...)
		buf = append(buf, seq[:]...)
		buf = append(buf, pw...)
		return md2Sum(buf)
	default:

		return nil
	}
}

func buildV15LANMsg(netfn, cmd byte, data []byte) []byte {
	body := make([]byte, 0, 7+len(data))
	body = append(body, 0x20)
	body = append(body, netfn<<2)
	body = append(body, 0x00)
	body[2] = IPMBChecksum(body[:2])
	body = append(body, 0x81)
	body = append(body, 0x00)
	body = append(body, cmd)
	body = append(body, data...)
	body = append(body, IPMBChecksum(body[3:]))
	return body
}

func buildV15Sessionless(lanMsg []byte) []byte {
	var pkt bytes.Buffer
	pkt.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	pkt.WriteByte(IPMI15AuthNone)
	pkt.Write([]byte{0, 0, 0, 0})
	pkt.Write([]byte{0, 0, 0, 0})
	pkt.WriteByte(byte(len(lanMsg)))
	pkt.Write(lanMsg)
	return pkt.Bytes()
}

func buildV15Authenticated(authType byte, password string, sessionID, seq uint32, lanMsg []byte) []byte {
	var pkt bytes.Buffer
	pkt.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	pkt.WriteByte(authType)
	pkt.Write(binary.LittleEndian.AppendUint32(nil, seq))
	pkt.Write(binary.LittleEndian.AppendUint32(nil, sessionID))
	if authType != IPMI15AuthNone {
		pkt.Write(v15AuthCode(authType, password, sessionID, seq, lanMsg))
	}
	pkt.WriteByte(byte(len(lanMsg)))
	pkt.Write(lanMsg)
	return pkt.Bytes()
}

func buildGetSessionChallenge(authType byte, username string) []byte {
	data := make([]byte, 0, 17)
	data = append(data, authType)
	data = append(data, pad16(username)...)
	return buildV15Sessionless(buildV15LANMsg(NetFnApp, CmdGetSessionChallenge, data))
}

func buildActivateSession(authType, maxPriv byte, challenge []byte, outboundSeq uint32) []byte {
	data := make([]byte, 0, 22)
	data = append(data, authType, maxPriv)
	ch := make([]byte, 16)
	copy(ch, challenge)
	data = append(data, ch...)
	data = binary.LittleEndian.AppendUint32(data, outboundSeq)
	return buildV15LANMsg(NetFnApp, CmdActivateSession, data)
}

func extractV15Payload(reply []byte) (cc byte, data []byte, ok bool) {
	if len(reply) < 4 || reply[3] != RMCPClassIPMI {
		return 0, nil, false
	}

	body := reply
	for i := 0; i+7 < len(body); i++ {
		if (body[i] == 0x81 || body[i] == 0x8c) && body[i+3] == 0x20 {
			cc = body[i+6]

			if i+7 < len(body) {
				end := len(body) - 1
				if end > i+7 {
					data = append([]byte(nil), body[i+7:end]...)
				}
			}
			return cc, data, true
		}
	}
	return 0, nil, false
}

func GetSessionChallenge15(c *Client, authType byte, username string) (cc byte, tempSID uint32, challenge []byte, err error) {
	reply, err := c.Send(buildGetSessionChallenge(authType, username))
	if err != nil {
		return 0, 0, nil, err
	}
	code, data, ok := extractV15Payload(reply)
	if !ok {
		return 0, 0, nil, errors.New("v1.5 challenge: unparseable reply")
	}
	if code != 0x00 {
		return code, 0, nil, nil
	}
	if len(data) < 20 {
		return code, 0, nil, errors.New("v1.5 challenge: short payload")
	}
	tempSID = binary.LittleEndian.Uint32(data[0:4])
	challenge = append([]byte(nil), data[4:20]...)
	return code, tempSID, challenge, nil
}

func Login15(host string, port int, authType byte, username, password string, timeout time.Duration) (*Session15, byte, error) {
	c, sess, cc, err := login15Conn(host, port, authType, username, password, timeout)
	if c != nil {
		c.Close()
	}
	return sess, cc, err
}

func login15Conn(host string, port int, authType byte, username, password string, timeout time.Duration) (*Client, *Session15, byte, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, nil, 0xFF, err
	}
	closeAndNil := func() (*Client, *Session15, byte, error) { return nil, nil, 0xFF, err }

	cc, tempSID, challenge, gerr := GetSessionChallenge15(c, authType, username)
	if gerr != nil {
		err = gerr
		c.Close()
		return closeAndNil()
	}
	if cc != 0x00 {
		c.Close()
		return nil, nil, cc, nil
	}

	const outboundSeq = 1
	actMsg := buildActivateSession(authType, 0x04, challenge, outboundSeq)
	actPkt := buildV15Authenticated(authType, password, tempSID, 0, actMsg)
	reply, serr := c.Send(actPkt)
	if serr != nil {
		err = serr
		c.Close()
		return closeAndNil()
	}
	cc2, data, ok := extractV15Payload(reply)
	if !ok {
		err = errors.New("v1.5 activate: unparseable reply")
		c.Close()
		return closeAndNil()
	}
	if cc2 != 0x00 {
		c.Close()
		return nil, nil, cc2, nil
	}
	if len(data) < 10 {
		err = errors.New("v1.5 activate: short payload")
		c.Close()
		return closeAndNil()
	}

	sess := &Session15{
		AuthType:   authType,
		Password:   password,
		SessionID:  binary.LittleEndian.Uint32(data[1:5]),
		InboundSeq: binary.LittleEndian.Uint32(data[5:9]),
		MaxPriv:    data[9],
	}

	return c, sess, cc2, nil
}

func sendInSession(c *Client, sess *Session15, netfn, cmd byte, data []byte) (cc byte, out []byte, err error) {
	seq := sess.InboundSeq
	if seq == 0 {
		seq = 1
	}
	lan := buildV15LANMsg(netfn, cmd, data)
	pkt := buildV15Authenticated(sess.AuthType, sess.Password, sess.SessionID, seq, lan)
	reply, err := c.Send(pkt)
	if err != nil {
		return 0xFF, nil, err
	}

	sess.InboundSeq = seq + 1
	if sess.InboundSeq == 0 {
		sess.InboundSeq = 1
	}
	code, payload, ok := extractV15Payload(reply)
	if !ok {
		return 0xFF, nil, errors.New("in-session reply: unparseable")
	}
	return code, payload, nil
}

type V15Capabilities struct {
	ConfirmedPriv byte `json:"confirmedPriv"`

	SetPrivOK bool `json:"setPrivOk"`

	SetPrivCC byte `json:"setPrivCc"`

	ReadOK bool `json:"readOk"`

	ReadCC byte `json:"readCc"`

	Detail string `json:"detail,omitempty"`
}

func (c *V15Capabilities) Proof() string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("setPrivCc=0x%02x grantedPriv=%s readCc=0x%02x", c.SetPrivCC, priv15Name(c.ConfirmedPriv), c.ReadCC)
}

func priv15Name(p byte) string {
	switch p & 0x0f {
	case 0x01:
		return "callback"
	case 0x02:
		return "user"
	case 0x03:
		return "operator"
	case 0x04:
		return "admin"
	case 0x05:
		return "oem"
	default:
		return fmt.Sprintf("0x%02x", p)
	}
}

func probeCapabilities15(c *Client, sess *Session15) *V15Capabilities {
	if c == nil || sess == nil {
		return nil
	}
	caps := &V15Capabilities{ConfirmedPriv: sess.MaxPriv}

	if cc, data, err := sendInSession(c, sess, NetFnApp, CmdSetSessionPrivilege, []byte{0x04}); err == nil {
		caps.SetPrivCC = cc
		if cc == 0x00 {
			caps.SetPrivOK = true
			if len(data) >= 1 {
				caps.ConfirmedPriv = data[0] & 0x0f
				sess.MaxPriv = caps.ConfirmedPriv
			}
		}
	}

	if cc, _, err := sendInSession(c, sess, NetFnApp, CmdGetChannelAccess, []byte{0x0e, 0x40}); err == nil {
		caps.ReadCC = cc
		if cc == 0x00 {
			caps.ReadOK = true
		}
	}

	switch {
	case caps.SetPrivOK && caps.ReadOK:
		caps.Detail = "in-session commands executed (set-priv + get-channel-access)"
	case caps.SetPrivOK:
		caps.Detail = "set-session-privilege confirmed"
	case caps.ReadOK:
		caps.Detail = "in-session read confirmed"
	default:
		caps.Detail = "session activated; in-session commands not confirmed"
	}
	return caps
}

func CloseSession15(host string, port int, sess *Session15, timeout time.Duration) {
	if sess == nil {
		return
	}
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return
	}
	defer c.Close()

	seq := sess.InboundSeq
	if seq == 0 {
		seq = 1
	}
	closeMsg := buildV15LANMsg(NetFnApp, CmdCloseSession, binary.LittleEndian.AppendUint32(nil, sess.SessionID))
	pkt := buildV15Authenticated(sess.AuthType, sess.Password, sess.SessionID, seq, closeMsg)
	_, _ = c.Send(pkt)
}

type V15Report struct {
	Host           string           `json:"host"`
	Port           int              `json:"port"`
	AuthNoneOK     bool             `json:"authNoneSession"`
	AuthNonePriv   byte             `json:"authNonePriv"`
	AuthNoneCaps   *V15Capabilities `json:"authNoneCaps,omitempty"`
	DefaultCred    *V15CredResult   `json:"defaultCred,omitempty"`
	ValidUsernames []V15OracleEntry `json:"validUsernames,omitempty"`

	OracleInvalidUser string `json:"oracleInvalidUser,omitempty"`
	OracleInvalidCC   byte   `json:"oracleInvalidCc,omitempty"`
}

type V15CredResult struct {
	Username string           `json:"username"`
	Password string           `json:"password"`
	Via      string           `json:"via"`
	Priv     byte             `json:"priv"`
	Caps     *V15Capabilities `json:"caps,omitempty"`
}

type V15OracleEntry struct {
	Username string `json:"username"`
	CC       byte   `json:"cc"`
}

type V15Options struct {
	Vendor  string
	Caps    *AuthCaps
	Online  bool
	Timeout time.Duration
}

func RunSession15(ctx context.Context, host string, port int, opts V15Options) *V15Report {
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	rep := &V15Report{Host: host, Port: port}
	ac := opts.Caps

	if ac == nil || ac.HasAuthNone() || ac.AnonLogin || ac.NullUser {
		if ctx.Err() == nil {
			if c, sess, _, err := login15Conn(host, port, IPMI15AuthNone, "", "", opts.Timeout); err == nil && sess != nil {
				rep.AuthNoneOK = true

				rep.AuthNoneCaps = probeCapabilities15(c, sess)
				rep.AuthNonePriv = sess.MaxPriv
				c.Close()
				CloseSession15(host, port, sess, opts.Timeout)
			}
		}
	}

	rep.ValidUsernames, rep.OracleInvalidUser, rep.OracleInvalidCC = v15UsernameOracle(ctx, host, port, opts)

	if opts.Online && ctx.Err() == nil {
		rep.DefaultCred = v15DefaultCredLogin(ctx, host, port, opts)
	}
	return rep
}

var v15OracleUsers = []string{
	"",
	"ADMIN",
	"admin",
	"root",
	"Administrator",
	"USERID",
	"sysadmin",
	"operator",
	"supervisor",
	"guest",
	"user",
}

func v15UsernameOracle(ctx context.Context, host string, port int, opts V15Options) (valid []V15OracleEntry, invalidUser string, invalidCC byte) {
	c, err := NewClient(host, port, opts.Timeout)
	if err != nil {
		return nil, "", 0
	}
	defer c.Close()

	authType := IPMI15AuthMD5
	if opts.Caps != nil && !opts.Caps.HasAuthMD5() && opts.Caps.HasAuthStraight() {
		authType = IPMI15AuthPass
	}

	var out []V15OracleEntry
	consecDrop := 0
	for _, u := range v15OracleUsers {
		if ctx.Err() != nil {
			break
		}
		cc, _, challenge, err := GetSessionChallenge15(c, authType, u)
		if err != nil {
			consecDrop++
			if consecDrop >= 3 {
				break
			}
			continue
		}
		consecDrop = 0
		if cc == 0x00 && len(challenge) == 16 {
			out = append(out, V15OracleEntry{Username: u, CC: cc})
			continue
		}

		if invalidUser == "" {
			invalidUser, invalidCC = userLabel15(u), cc
		}
	}
	return out, invalidUser, invalidCC
}

func userLabel15(u string) string {
	if u == "" {
		return "(null)"
	}
	return u
}

func v15DefaultCredLogin(ctx context.Context, host string, port int, opts V15Options) *V15CredResult {

	type mode struct {
		t   byte
		via string
	}
	var modes []mode
	if opts.Caps == nil || opts.Caps.HasAuthMD5() {
		modes = append(modes, mode{IPMI15AuthMD5, "md5"})
	}
	if opts.Caps == nil || opts.Caps.HasAuthStraight() {
		modes = append(modes, mode{IPMI15AuthPass, "straight"})
	}

	if opts.Caps != nil && opts.Caps.HasAuthMD2() {
		modes = append(modes, mode{IPMI15AuthMD2, "md2"})
	}
	if len(modes) == 0 {
		return nil
	}

	rows := creds.CredsFor(opts.Vendor, creds.ClassIPMI)
	for _, m := range modes {
		tried := map[[2]string]struct{}{}
		n := 0
		consecDrop := 0
		for _, cr := range rows {
			if n >= v15MaxLoginAttempts || ctx.Err() != nil {
				break
			}
			key := [2]string{cr.Username, cr.Password}
			if _, dup := tried[key]; dup {
				continue
			}
			tried[key] = struct{}{}
			n++
			c, sess, cc, err := login15Conn(host, port, m.t, cr.Username, cr.Password, opts.Timeout)
			if err != nil {
				consecDrop++
				if consecDrop >= 4 {
					break
				}
				continue
			}
			consecDrop = 0
			if sess != nil {

				caps := probeCapabilities15(c, sess)
				res := &V15CredResult{Username: cr.Username, Password: cr.Password, Via: m.via, Priv: sess.MaxPriv, Caps: caps}
				c.Close()
				CloseSession15(host, port, sess, opts.Timeout)
				return res
			}
			if c != nil {
				c.Close()
			}
			_ = cc
		}
	}
	return nil
}

func V15OracleUserList() []string { return append([]string(nil), v15OracleUsers...) }
