package ipmi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

// Client is a minimal UDP IPMI speaker. It is not session-aware -- callers
// drive the packet sequence explicitly to keep audit cases transparent.
type Client struct {
	Host    string
	Port    int
	Timeout time.Duration
	conn    *net.UDPConn
}

// NewClient resolves the target and connects a UDP socket.
func NewClient(host string, port int, timeout time.Duration) (*Client, error) {
	if port == 0 {
		port = DefaultPort
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	// JoinHostPort (not "%s:%d"): an IPv6 target needs brackets, and a
	// link-local one keeps its %zone so the resolver picks the right interface.
	addr, err := net.ResolveUDPAddr("udp", netaddr.DialHostPort(host, port))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	return &Client{Host: host, Port: port, Timeout: timeout, conn: conn}, nil
}

// Close releases the socket.
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// Send writes a raw packet and reads the reply. Returns (reply, err).
func (c *Client) Send(pkt []byte) ([]byte, error) {
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.Timeout)); err != nil {
		return nil, err
	}
	if _, err := c.conn.Write(pkt); err != nil {
		return nil, err
	}
	if err := c.conn.SetReadDeadline(time.Now().Add(c.Timeout)); err != nil {
		return nil, err
	}
	buf := make([]byte, 2048)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// SendRaw sends without awaiting a reply. Used by POD / flood / fuzz cases.
func (c *Client) SendRaw(pkt []byte) error {
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.Timeout))
	_, err := c.conn.Write(pkt)
	return err
}

// Recv reads one datagram, waiting at most timeout. Used by the pipelined reader,
// which sends a window of requests with SendRaw and then drains the replies. A
// timeout error is returned as-is so the caller can distinguish it (isTimeoutErr).
func (c *Client) Recv(timeout time.Duration) ([]byte, error) {
	if err := c.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	buf := make([]byte, 2048)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// IPMBChecksum is the classic 2's-complement checksum used within IPMB/IPMI.
func IPMBChecksum(b []byte) byte {
	var s byte
	for _, x := range b {
		s += x
	}
	return (^s) + 1
}

// ASFPingPacket builds the RMCP presence-ping datagram. It is split out from
// ASFPing so callers that own their own socket -- notably the link-local
// multicast sweep in pkg/discover -- can send the same probe.
func ASFPingPacket(msgTag byte) []byte {
	var buf bytes.Buffer
	// RMCP header: 06 00 ff 06 (ASF class)
	buf.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassASF})
	// ASF: IANA (4 bytes, 0x11BE = ASF), msgtype=0x80 ping, msgtag, reserved, datalen
	iana := make([]byte, 4)
	binary.BigEndian.PutUint32(iana, 0x000011BE)
	buf.Write(iana)
	buf.WriteByte(0x80)   // msgtype: presence ping
	buf.WriteByte(msgTag) // msgtag (echoed in the pong)
	buf.WriteByte(0x00)   // reserved
	buf.WriteByte(0x00)   // data len
	return buf.Bytes()
}

// ASFPing is the RMCP presence ping. Returns the raw reply or an error.
// Reply starts with RMCP header + ASF pong (message type 0x40).
func ASFPing(host string, port int, timeout time.Duration) ([]byte, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Send(ASFPingPacket(0x00))
}

// GetChannelAuthCaps15 performs the IPMI 1.5 Get Channel Authentication
// Capabilities request -- the most useful single pre-auth probe. The reply
// carries the auth-type bitmap (bit0=none, bit1=MD2, bit2=MD5, bit4=password),
// the IPMI 2.0 support flag, anonymous-login flags, and the OEM IANA ID.
//
// This is a session-less (session ID = 0, session seq = 0) IPMI message.
func GetChannelAuthCaps15(host string, port int, channel byte, reqPriv byte, timeout time.Duration) ([]byte, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Send(GetChannelAuthCapsPacket(channel, reqPriv))
}

// GetChannelAuthCapsPacket builds the session-less Get Channel Authentication
// Capabilities datagram sent by GetChannelAuthCaps15, for callers that drive
// their own socket (the pkg/discover multicast sweep).
func GetChannelAuthCapsPacket(channel byte, reqPriv byte) []byte {
	if reqPriv == 0 {
		reqPriv = 0x04 // admin
	}
	// IPMI message body: rsAddr(20) | netfn/lun (App<<2) | csum1 |
	//                    rqAddr(81) | rqSeq/lun (00) | cmd(38) | data(ch, priv) | csum2
	body := []byte{
		0x20, NetFnApp << 2, 0, // placeholder csum1
		0x81, 0x00, CmdGetChannelAuthCaps, channel & 0x0F, reqPriv & 0x0F, 0,
	}
	body[2] = IPMBChecksum(body[:2])
	body[len(body)-1] = IPMBChecksum(body[3 : len(body)-1])

	var pkt bytes.Buffer
	pkt.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	// session header (IPMI 1.5 style): authType(0) | seq(4, all zero) | sid(4, all zero) | msg len
	pkt.WriteByte(IPMI15AuthNone)
	pkt.Write([]byte{0, 0, 0, 0})
	pkt.Write([]byte{0, 0, 0, 0})
	pkt.WriteByte(byte(len(body)))
	pkt.Write(body)
	return pkt.Bytes()
}

// AuthCaps holds the parsed channel auth-capabilities reply.
type AuthCaps struct {
	Channel        byte
	AuthTypeMask   byte
	IPMI20         bool
	AnonLogin      bool
	NullUser       bool
	NonNullUser    bool
	UserLevelAuth  bool
	PerMessageAuth bool
	KG             bool
	OEMID          uint32 // 3-byte IANA, zero-extended
	GUID           []byte // legacy/non-standard trailer; normally empty on spec-correct replies
	CompletionCode byte
	Raw            []byte
}

// ParseAuthCapsReply parses the response from GetChannelAuthCaps15. The
// caller must pass only the IPMI message body (post-RMCP + session header).
//
// Layout (IPMI v1.5 Rev 1.1 22.13):
//
//	[0]  rqAddr (BMC = 20)
//	[1]  netfn/lun (reply netfn = App|1)
//	[2]  csum
//	[3]  rsAddr
//	[4]  rqSeq/lun
//	[5]  cmd
//	[6]  completion code
//	[7]  channel number
//	[8]  auth type support (bit7 = IPMI 2.0)
//	[9]  auth status   (byte 4: bit0 anon, bit1 null, bit2 non-null,
//	                    bit3 user-level-auth, bit4 per-message-auth, bit5 Kg status)
//	[10] ext capabilities (byte 5: IPMI 1.5/2.0 connection support only -- the
//	                    user-level/per-msg/Kg bits all live in byte 4 at [9])
//	[11..13] OEM ID (LSB first)
//	[14] OEM aux data
//	[last] csum
func ParseAuthCapsReply(body []byte) (*AuthCaps, error) {
	if len(body) < 11 {
		return nil, errors.New("short auth-caps reply")
	}
	// Locate the IPMB addressing pair so the offsets in the layout above are
	// anchored correctly: `start` is the index of the first address byte, and
	// cmd/cc/status sit at fixed offsets from it regardless of the pair's order.
	// The pair is the console requester (0x81, or 0x8c on some bridged channels)
	// and the BMC responder (0x20), three bytes apart. Both orders occur, and some
	// stacks send no console-side byte at all - see the 0x38 fallback below.
	start := -1
	for i := 0; i+3 < len(body); i++ {
		console := body[i] == 0x81 || body[i] == 0x8c
		switch {
		case console && body[i+3] == 0x20: // standard: console .. BMC
			start = i
		case body[i] == 0x20 && (body[i+3] == 0x81 || body[i+3] == 0x8c): // reversed: BMC .. console
			start = i
		}
		if start >= 0 {
			break
		}
	}
	if start < 0 {
		// Non-standard requester address (e.g. 0x00) leaves no console-side byte
		// to anchor on. Pin the frame on the BMC responder 0x20 at +3 confirmed
		// by the Get Channel Auth Caps command byte (0x38) at +5.
		for i := 0; i+5 < len(body); i++ {
			if body[i+3] == 0x20 && body[i+5] == CmdGetChannelAuthCaps {
				start = i
				break
			}
		}
	}
	if start < 0 {
		// Last resort: the first plausible console-side header byte.
		for i := 0; i+6 < len(body); i++ {
			if body[i] == 0x81 || body[i] == 0x8c {
				start = i
				break
			}
		}
	}
	if start < 0 || start+10 >= len(body) {
		return nil, errors.New("short auth-caps payload")
	}
	cc := body[start+6]
	ac := &AuthCaps{
		CompletionCode: cc,
		Channel:        body[start+7] & 0x0F,
		AuthTypeMask:   body[start+8] & 0x7F,
		IPMI20:         body[start+8]&0x80 != 0,
		AnonLogin:      body[start+9]&0x01 != 0,
		NullUser:       body[start+9]&0x02 != 0,
		NonNullUser:    body[start+9]&0x04 != 0,
		UserLevelAuth:  body[start+9]&0x08 == 0,
		PerMessageAuth: body[start+9]&0x10 == 0,
		KG:             body[start+9]&0x20 != 0,
		Raw:            body,
	}
	// OEM ID occupies start+11..start+13 (LSB first).
	if start+14 <= len(body) {
		ac.OEMID = uint32(body[start+11]) | uint32(body[start+12])<<8 | uint32(body[start+13])<<16
	}
	return ac, nil
}

// HasAuthNone reports whether the reply advertises auth-type None (MAJOR
// compliance failure under the NIST SP 800-193 profile).
func (a *AuthCaps) HasAuthNone() bool { return a.AuthTypeMask&0x01 != 0 }

// HasAuthMD2 reports the legacy MD2 mode.
func (a *AuthCaps) HasAuthMD2() bool { return a.AuthTypeMask&0x02 != 0 }

// HasAuthMD5 reports MD5 (allowed but weak).
func (a *AuthCaps) HasAuthMD5() bool { return a.AuthTypeMask&0x04 != 0 }

// HasAuthStraight reports plaintext-password auth (MAJOR failure).
func (a *AuthCaps) HasAuthStraight() bool { return a.AuthTypeMask&0x10 != 0 }

// HasAuthOEM reports vendor-specific auth, typically cipher suite 0 legacy.
func (a *AuthCaps) HasAuthOEM() bool { return a.AuthTypeMask&0x20 != 0 }
