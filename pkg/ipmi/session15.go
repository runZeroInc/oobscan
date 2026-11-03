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

// IPMI v1.5 session login (IPMI v1.5 rev 1.1 section 22.16-22.18): Get Session
// Challenge (0x39) -> Activate Session (0x3A) -> Close Session (0x3C). A separate
// protocol from the RMCP+/RAKP path in rakp.go.
//
// Wire details that are easy to get wrong:
//   - Get Session Challenge goes out in the sessionless header; the requested auth
//     type lives in the message data, not the header.
//   - Activate Session uses session sequence 0 in its header and computes its
//     AuthCode with that same 0.
//   - Post-activate messages do not restart at 0/1: InboundSeq is seeded from the
//     Activate Session response's Initial Inbound Sequence field (bumped to 1 if
//     zero) and incremented after every send.
//   - The AuthCode's session-id and msgData inputs are raw wire bytes: the 4-byte
//     session id little-endian, and the encapsulated LAN message body.

// v15MaxLoginAttempts caps Activate-Session logins per username so a password
// spray cannot walk into an account lockout, mirroring maxOnlineAttempts on the
// RAKP path. Activate Session is a real login and does count against BMC lockout
// policy, so the caller must also gate the default-cred path behind
// --disable-logins.
const v15MaxLoginAttempts = maxOnlineAttempts

// Session15 holds the parameters of an established IPMI v1.5 session.
type Session15 struct {
	AuthType   byte   // negotiated header auth type (None / MD5 / straight)
	Password   string // key material for authenticated messages (empty for None)
	SessionID  uint32 // BMC-assigned real session ID (from Activate Session)
	InboundSeq uint32 // next sequence number the BMC expects from us
	MaxPriv    byte   // privilege level granted by Activate Session
}

// pad16 null-pads (or truncates) a string to exactly 16 bytes. IPMI v1.5 uses a
// fixed 16-byte width for both the AuthCode key (the password) and the username
// field of Get Session Challenge; ipmitool stores the password identically in
// s->authcode.
func pad16(s string) []byte {
	b := make([]byte, 16)
	copy(b, s)
	return b
}

// v15AuthCode computes the 16-byte per-message AuthCode for an authenticated
// IPMI v1.5 message:
//
//	MD5( pw16 || sessionID(4 LE) || msgData || sessionSeq(4 LE) || pw16 )
//
// Straight-password (type 4) uses the 16-byte null-padded password with no hash;
// None (type 0) has no AuthCode field. msgData is the encapsulated LAN message
// (rsAddr..data..csum2), i.e. the bytes after the payload-length byte.
func v15AuthCode(authType byte, password string, sessionID, sessionSeq uint32, msgData []byte) []byte {
	switch authType {
	case IPMI15AuthPass: // straight password: the field is the padded password
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
		// Identical construction to MD5, only the digest differs (RFC 1319). Some
		// legacy BMCs advertise MD2-only in Get Channel Auth Caps; without this a
		// login against them is impossible. md2Sum lives in md2_15.go.
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
		// None (type 0) carries no AuthCode; OEM (type 5) is vendor-defined and we
		// do not forge it.
		return nil
	}
}

// buildV15LANMsg constructs the encapsulated IPMI LAN message body (the same
// rsAddr..csum2 body buildSessionlessMsg wraps), for a given NetFn/Cmd/data.
// It is factored out so the AuthCode can hash the exact bytes that go on the
// wire.
func buildV15LANMsg(netfn, cmd byte, data []byte) []byte {
	body := make([]byte, 0, 7+len(data))
	body = append(body, 0x20)     // rsAddr (BMC)
	body = append(body, netfn<<2) // netfn/lun (no lun)
	body = append(body, 0x00)     // csum1 placeholder
	body[2] = IPMBChecksum(body[:2])
	body = append(body, 0x81) // rqAddr (remote console)
	body = append(body, 0x00) // rqSeq/lun
	body = append(body, cmd)  // cmd
	body = append(body, data...)
	body = append(body, IPMBChecksum(body[3:])) // csum2
	return body
}

// buildV15Sessionless wraps a LAN message in the sessionless v1.5 header
// (authType=None, seq=0, sid=0). This is the exact framing buildSessionlessMsg
// produces; kept separate so callers can hand it a prebuilt LAN body.
func buildV15Sessionless(lanMsg []byte) []byte {
	var pkt bytes.Buffer
	pkt.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	pkt.WriteByte(IPMI15AuthNone)
	pkt.Write([]byte{0, 0, 0, 0}) // session seq
	pkt.Write([]byte{0, 0, 0, 0}) // session ID
	pkt.WriteByte(byte(len(lanMsg)))
	pkt.Write(lanMsg)
	return pkt.Bytes()
}

// buildV15Authenticated wraps a LAN message in the AUTHENTICATED v1.5 header,
// which is longer than the sessionless one:
//
//	authType(1) | seq(4 LE) | sessionID(4 LE) | AuthCode(16, iff authType!=None) | payloadLen(1)
//
// The AuthCode is computed over the LAN message with the given session id + seq.
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

// buildGetSessionChallenge builds the Get Session Challenge (0x39) request:
// data = authType(1) || username(16, null-padded), always sent sessionless.
func buildGetSessionChallenge(authType byte, username string) []byte {
	data := make([]byte, 0, 17)
	data = append(data, authType)
	data = append(data, pad16(username)...)
	return buildV15Sessionless(buildV15LANMsg(NetFnApp, CmdGetSessionChallenge, data))
}

// buildActivateSession builds the Activate Session (0x3A) request LAN message:
// data = authType(1) || maxPriv(1) || challenge(16) || outboundSeq(4 LE). The
// outbound seq must be non-zero (section 22.17.1 -- it seeds the sequence numbers
// the BMC will accept from us).
func buildActivateSession(authType, maxPriv byte, challenge []byte, outboundSeq uint32) []byte {
	data := make([]byte, 0, 22)
	data = append(data, authType, maxPriv)
	ch := make([]byte, 16)
	copy(ch, challenge)
	data = append(data, ch...)
	data = binary.LittleEndian.AppendUint32(data, outboundSeq)
	return buildV15LANMsg(NetFnApp, CmdActivateSession, data)
}

// extractV15Payload returns the IPMI response DATA (the bytes after the
// completion code, before the trailing checksum) plus the completion code, from
// a sessionless- or authenticated-framed v1.5 reply. It anchors on the IPMB
// response header (rqAddr 0x81/0x8c followed by rsAddr 0x20) exactly like
// ParseAuthCapsReply / extractCompletionCode, so it is robust to the reply
// carrying (or not carrying) an AuthCode field.
func extractV15Payload(reply []byte) (cc byte, data []byte, ok bool) {
	if len(reply) < 4 || reply[3] != RMCPClassIPMI {
		return 0, nil, false
	}
	// Scan the whole packet for the IPMB response envelope. The response header
	// layout is: rqAddr(0x81) netfn|lun csum rsAddr(0x20) rqSeq cmd CC data csum.
	body := reply
	for i := 0; i+7 < len(body); i++ {
		if (body[i] == 0x81 || body[i] == 0x8c) && body[i+3] == 0x20 {
			cc = body[i+6]
			// Data runs from i+7 up to the trailing checksum (last byte).
			if i+7 < len(body) {
				end := len(body) - 1 // strip csum2
				if end > i+7 {
					data = append([]byte(nil), body[i+7:end]...)
				}
			}
			return cc, data, true
		}
	}
	return 0, nil, false
}

// GetSessionChallenge15 sends a Get Session Challenge for the given username and
// auth type and returns the completion code, temp session id and challenge. This
// is the username-oracle primitive: it establishes no session and touches no
// lockout counter. cc 0x81 = invalid user, 0x82 = null user disabled.
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
		return code, 0, nil, nil // a valid negative answer (e.g. 0x81/0x82)
	}
	if len(data) < 20 {
		return code, 0, nil, errors.New("v1.5 challenge: short payload")
	}
	tempSID = binary.LittleEndian.Uint32(data[0:4])
	challenge = append([]byte(nil), data[4:20]...)
	return code, tempSID, challenge, nil
}

// Login15 runs the full IPMI v1.5 handshake (Get Session Challenge -> Activate
// Session) on one socket and returns the live session on success. authType
// selects the header auth mode: IPMI15AuthNone (no crypto, null-user access),
// IPMI15AuthMD5, or IPMI15AuthPass (straight password).
//
// On success the caller owns the returned *Session15 and must call CloseSession15
// to leave the BMC clean. A nil session with nil error means the BMC processed the
// request but rejected it (bad creds / disabled auth type); an error means a
// transport failure or unparseable reply.
func Login15(host string, port int, authType byte, username, password string, timeout time.Duration) (*Session15, byte, error) {
	c, sess, cc, err := login15Conn(host, port, authType, username, password, timeout)
	if c != nil {
		c.Close() // this caller does not exercise the session in-band
	}
	return sess, cc, err
}

// login15Conn runs the same handshake as Login15 but, on success, leaves the
// socket open and returns it so the caller can send in-session commands with
// correct sequence numbers before tearing the session down. On any non-success path
// the socket is closed and c is nil; otherwise the caller must c.Close() it.
func login15Conn(host string, port int, authType byte, username, password string, timeout time.Duration) (*Client, *Session15, byte, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, nil, 0xFF, err
	}
	closeAndNil := func() (*Client, *Session15, byte, error) { return nil, nil, 0xFF, err }

	// --- Get Session Challenge (sessionless) ---
	cc, tempSID, challenge, gerr := GetSessionChallenge15(c, authType, username)
	if gerr != nil {
		err = gerr
		c.Close()
		return closeAndNil()
	}
	if cc != 0x00 {
		c.Close()
		return nil, nil, cc, nil // invalid user / null-user-disabled / etc.
	}

	// --- Activate Session (authenticated header, session seq = 0) ---
	// The AuthCode is keyed on the temp session id and header seq 0 (the first
	// authenticated message always carries seq 0 -- see the doc comment above).
	const outboundSeq = 1 // must be non-zero
	actMsg := buildActivateSession(authType, 0x04 /*admin*/, challenge, outboundSeq)
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
		return nil, nil, cc2, nil // login rejected (bad password, priv exceeded, etc.)
	}
	if len(data) < 10 {
		err = errors.New("v1.5 activate: short payload")
		c.Close()
		return closeAndNil()
	}
	// Activate Session response: authType(1) | sessionID(4 LE) | inboundSeq(4 LE) | maxPriv(1).
	sess := &Session15{
		AuthType:   authType,
		Password:   password,
		SessionID:  binary.LittleEndian.Uint32(data[1:5]),
		InboundSeq: binary.LittleEndian.Uint32(data[5:9]),
		MaxPriv:    data[9],
	}
	// A live session with a real (non-zero) id is the confirmation we want; some
	// BMCs echo the temp id, which is still a working session.
	return c, sess, cc2, nil
}

// sendInSession sends one authenticated in-session App command on an already-open
// session socket, advancing the session sequence number, and returns the reply's
// completion code and DATA. It mutates sess.InboundSeq to the next expected value
// so consecutive calls stay in sequence. This is the primitive the post-login
// capability probe (and CloseSession15's in-session variant) build on.
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
	// The BMC expects a monotonically increasing sequence; advance for the next
	// message on this session (skip 0, which is reserved for the activate frame).
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

// V15Capabilities is the outcome of the post-login capability probe: what an
// established session can actually DO, confirmed by exercising in-session
// commands rather than trusting the Activate Session privilege echo alone.
type V15Capabilities struct {
	// ConfirmedPriv is the privilege the session actually reached, per Set Session
	// Privilege Level (0x3B). It is authoritative over Session15.MaxPriv, which is
	// only the level the BMC granted at activation.
	ConfirmedPriv byte `json:"confirmedPriv"`
	// SetPrivOK is true iff Set Session Privilege Level completed (CC 0x00): the
	// session is live enough to run a privileged App command, not just activate.
	SetPrivOK bool `json:"setPrivOk"`
	// SetPrivCC is the raw completion code Set Session Privilege Level returned.
	SetPrivCC byte `json:"setPrivCc"`
	// ReadOK is true iff a read-only in-session command (Get Channel Access 0x41)
	// completed, independently confirming command execution inside the session.
	ReadOK bool `json:"readOk"`
	// ReadCC is the raw completion code the Get Channel Access read returned.
	ReadCC byte `json:"readCc"`
	// Detail is a short human summary for finding output.
	Detail string `json:"detail,omitempty"`
}

// Proof renders the capability completion codes.
func (c *V15Capabilities) Proof() string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("setPrivCc=0x%02x grantedPriv=%s readCc=0x%02x", c.SetPrivCC, priv15Name(c.ConfirmedPriv), c.ReadCC)
}

// priv15Name renders an IPMI privilege-level number as its spec name.
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

// probeCapabilities15 exercises an established v1.5 session to confirm real access
// and report the achieved privilege, using two idempotent in-session commands:
//
//   - Set Session Privilege Level (0x3B) requesting Administrator. The reply's data
//     byte is the privilege actually granted, since a session may activate yet be
//     capped at USER. Requesting admin never lowers a session.
//   - Get Channel Access (0x41) on the present channel: a pure read that
//     independently proves in-session commands execute, since some BMCs answer 0x3B
//     from cache.
//
// Nothing is configured, powered or opened. When in-band commands do not work at
// all both flags stay false and the caller falls back to the activation-time
// privilege.
func probeCapabilities15(c *Client, sess *Session15) *V15Capabilities {
	if c == nil || sess == nil {
		return nil
	}
	caps := &V15Capabilities{ConfirmedPriv: sess.MaxPriv}

	// (a) Set Session Privilege Level -> Administrator (0x04). Data = requested
	// privilege; reply data[0] = new (granted) privilege level.
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

	// (b) Get Channel Access for the current channel (0x0E), "active" byte set --
	// a read-only confirmation that in-session commands run.
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

// CloseSession15 tears down an established v1.5 session (Close Session 0x3C) on a
// fresh socket, sent inside the session with the negotiated auth type so the BMC
// accepts and cleans it up. Best-effort: teardown failures are non-fatal.
func CloseSession15(host string, port int, sess *Session15, timeout time.Duration) {
	if sess == nil {
		return
	}
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return
	}
	defer c.Close()
	// The inbound sequence number the BMC expects for the first post-activate
	// message is InboundSeq (it seeded this from our outbound seq / its counter).
	seq := sess.InboundSeq
	if seq == 0 {
		seq = 1
	}
	closeMsg := buildV15LANMsg(NetFnApp, CmdCloseSession, binary.LittleEndian.AppendUint32(nil, sess.SessionID))
	pkt := buildV15Authenticated(sess.AuthType, sess.Password, sess.SessionID, seq, closeMsg)
	_, _ = c.Send(pkt)
}

// V15Report is the result of RunSession15 against one BMC.
type V15Report struct {
	Host           string           `json:"host"`
	Port           int              `json:"port"`
	AuthNoneOK     bool             `json:"authNoneSession"`        // an auth-None session was actually established
	AuthNonePriv   byte             `json:"authNonePriv"`           // privilege granted by that session
	AuthNoneCaps   *V15Capabilities `json:"authNoneCaps,omitempty"` // in-session capability confirmation for the auth-None session
	DefaultCred    *V15CredResult   `json:"defaultCred,omitempty"`
	ValidUsernames []V15OracleEntry `json:"validUsernames,omitempty"`
	// OracleInvalidUser / OracleInvalidCC record one account the oracle probed that
	// the BMC rejected (CC 0x81 invalid user / 0x82 null-user disabled), so the
	// finding can show the valid-vs-invalid completion-code differential.
	OracleInvalidUser string `json:"oracleInvalidUser,omitempty"`
	OracleInvalidCC   byte   `json:"oracleInvalidCc,omitempty"`
}

// V15CredResult records a confirmed default-credential login.
type V15CredResult struct {
	Username string           `json:"username"`
	Password string           `json:"password"`
	Via      string           `json:"via"`  // "md5" | "straight" | "md2"
	Priv     byte             `json:"priv"` // privilege the session reached (post-probe when available)
	Caps     *V15Capabilities `json:"caps,omitempty"`
}

// V15OracleEntry records one username the challenge oracle confirmed exists,
// along with the Get Session Challenge completion code that confirmed it (0x00).
type V15OracleEntry struct {
	Username string `json:"username"`
	CC       byte   `json:"cc"`
}

// V15Options drives RunSession15.
type V15Options struct {
	Vendor  string        // vendor slug for credential prioritization
	Caps    *AuthCaps     // parsed Get Channel Auth Caps (gates which paths run)
	Online  bool          // allow the Activate-Session default-cred login (lockout risk)
	Timeout time.Duration //
}

// RunSession15 performs the IPMI v1.5 assessment against a BMC:
//  1. auth-None session establishment (critical; no lockout risk),
//  2. a small pre-auth username oracle (low; no lockout risk), and
//  3. an online default-credential login (critical; gated and lockout-capped).
//
// Paths 1 and 2 run in the default scan; path 3 runs only when opts.Online. The
// caps gate, when provided, skips paths the BMC's advertised auth modes make
// pointless, e.g. no auth-None probe when auth-None is not advertised.
func RunSession15(ctx context.Context, host string, port int, opts V15Options) *V15Report {
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	rep := &V15Report{Host: host, Port: port}
	ac := opts.Caps

	// (1) auth-None session -- the v1.5 analog of cipher-0. Only probe when the
	// BMC advertises auth-None (or an anonymous/null-user login), since otherwise
	// Get Session Challenge with authType=None is rejected up front.
	if ac == nil || ac.HasAuthNone() || ac.AnonLogin || ac.NullUser {
		if ctx.Err() == nil {
			if c, sess, _, err := login15Conn(host, port, IPMI15AuthNone, "", "", opts.Timeout); err == nil && sess != nil {
				rep.AuthNoneOK = true
				// Confirm real access on the live session (Set Session Privilege +
				// a read-only in-session command) before tearing it down. This is
				// still cheap and safe: no login attempt (auth-None), so no lockout.
				rep.AuthNoneCaps = probeCapabilities15(c, sess)
				rep.AuthNonePriv = sess.MaxPriv // updated by the probe when it confirms a higher/real level
				c.Close()
				CloseSession15(host, port, sess, opts.Timeout)
			}
		}
	}

	// (2) username oracle -- Get Session Challenge CC differential. No Activate
	// Session follows, so this touches no lockout counter. Bounded to a small,
	// high-signal default set. Skipped only if the BMC advertises no usable
	// challenge auth type at all (auth-None-only BMCs still answer the challenge).
	rep.ValidUsernames, rep.OracleInvalidUser, rep.OracleInvalidCC = v15UsernameOracle(ctx, host, port, opts)

	// (3) default-credential login -- a real login (Activate Session), so it is
	// gated behind --disable-logins and capped like the RAKP online path. Prefer
	// MD5 over straight password; only attempt an auth type the BMC advertises.
	if opts.Online && ctx.Err() == nil {
		rep.DefaultCred = v15DefaultCredLogin(ctx, host, port, opts)
	}
	return rep
}

// v15OracleUsers is the username set the oracle enumerates, mirroring the
// highest-signal accounts of the RAKP path's CommonUsernames (pkg/creds/defaults.go)
// so the two agree. The empty string probes the null/anonymous account, told apart
// by CC 0x82. The list stays short deliberately: the oracle costs no lockout, but
// each name is another round trip on a rate-limiting BMC.
var v15OracleUsers = []string{
	"", // null / anonymous account (told apart by CC 0x82)
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

// v15UsernameOracle enumerates a small default username set via Get Session
// Challenge and returns those the BMC confirms exist (CC 0x00 + challenge). CC
// 0x81 (invalid user) and 0x82 (null user disabled) mark non-existent accounts.
// It bails early on consecutive transport drops so it cannot stall on a
// rate-limiting or unreachable BMC.
func v15UsernameOracle(ctx context.Context, host string, port int, opts V15Options) (valid []V15OracleEntry, invalidUser string, invalidCC byte) {
	c, err := NewClient(host, port, opts.Timeout)
	if err != nil {
		return nil, "", 0
	}
	defer c.Close()

	// Prefer MD5 for the challenge; the requested auth type does not change the
	// username-validity answer, but a BMC with MD5 disabled and only straight
	// password enabled still answers the challenge, so fall back to straight.
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
		if err != nil { // transport drop / unparseable -- count toward the bail-out
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
		// A rejected account (CC 0x81 invalid user / 0x82 null-user disabled) is the
		// other half of the differential: keep the first one seen so the finding can
		// show valid-vs-invalid completion codes side by side.
		if invalidUser == "" {
			invalidUser, invalidCC = userLabel15(u), cc
		}
	}
	return out, invalidUser, invalidCC
}

// userLabel15 renders a username for oracle output, showing the null/anonymous
// account as "(null)" instead of an empty string.
func userLabel15(u string) string {
	if u == "" {
		return "(null)"
	}
	return u
}

// v15DefaultCredLogin tries vendor-first default credentials via Activate Session,
// preferring MD5 over straight password. It is capped at v15MaxLoginAttempts per
// auth type and bails on consecutive drops, mirroring rakp_active.go's caps. On
// the first accepted login it returns immediately (and closes that session).
func v15DefaultCredLogin(ctx context.Context, host string, port int, opts V15Options) *V15CredResult {
	// Choose the auth types to try, best-first, honoring the advertised caps.
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
	// MD2 is the weakest defined type, tried last and only when the BMC advertises
	// it (never in the caps==nil broad-probe case). Some legacy stacks offer MD2 with
	// MD5 disabled, so omitting it would leave those with no login path.
	if opts.Caps != nil && opts.Caps.HasAuthMD2() {
		modes = append(modes, mode{IPMI15AuthMD2, "md2"})
	}
	if len(modes) == 0 {
		return nil // BMC advertises no auth type we can drive a login with
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
			if err != nil { // drop/timeout -- do not count as a rejection
				consecDrop++
				if consecDrop >= 4 {
					break // rate-limited / unreachable; stop hammering
				}
				continue
			}
			consecDrop = 0
			if sess != nil { // Activate Session returned CC 0x00 -> login accepted
				// Confirm what the credential's session can actually DO before we
				// report it: turn "login accepted" into "reached <priv>, in-session
				// commands executed".
				caps := probeCapabilities15(c, sess)
				res := &V15CredResult{Username: cr.Username, Password: cr.Password, Via: m.via, Priv: sess.MaxPriv, Caps: caps}
				c.Close()
				CloseSession15(host, port, sess, opts.Timeout)
				return res
			}
			if c != nil {
				c.Close() // defensive: rejected path returns c==nil
			}
			_ = cc // rejected with a completion code; try the next credential
		}
	}
	return nil
}

// V15OracleUserList returns the fixed username set the oracle probes, so the
// check layer can render "N of M probed accounts exist".
func V15OracleUserList() []string { return append([]string(nil), v15OracleUsers...) }
