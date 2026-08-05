package ipmi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

type Client struct {
	Host    string
	Port    int
	Timeout time.Duration
	conn    *net.UDPConn
}

func NewClient(host string, port int, timeout time.Duration) (*Client, error) {
	if port == 0 {
		port = DefaultPort
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}

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

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

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

func (c *Client) SendRaw(pkt []byte) error {
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.Timeout))
	_, err := c.conn.Write(pkt)
	return err
}

func IPMBChecksum(b []byte) byte {
	var s byte
	for _, x := range b {
		s += x
	}
	return (^s) + 1
}

func ASFPingPacket(msgTag byte) []byte {
	var buf bytes.Buffer

	buf.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassASF})

	iana := make([]byte, 4)
	binary.BigEndian.PutUint32(iana, 0x000011BE)
	buf.Write(iana)
	buf.WriteByte(0x80)
	buf.WriteByte(msgTag)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	return buf.Bytes()
}

func ASFPing(host string, port int, timeout time.Duration) ([]byte, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Send(ASFPingPacket(0x00))
}

func GetChannelAuthCaps15(host string, port int, channel byte, reqPriv byte, timeout time.Duration) ([]byte, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Send(GetChannelAuthCapsPacket(channel, reqPriv))
}

func GetChannelAuthCapsPacket(channel byte, reqPriv byte) []byte {
	if reqPriv == 0 {
		reqPriv = 0x04
	}

	body := []byte{
		0x20, NetFnApp << 2, 0,
		0x81, 0x00, CmdGetChannelAuthCaps, channel & 0x0F, reqPriv & 0x0F, 0,
	}
	body[2] = IPMBChecksum(body[:2])
	body[len(body)-1] = IPMBChecksum(body[3 : len(body)-1])

	var pkt bytes.Buffer
	pkt.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})

	pkt.WriteByte(IPMI15AuthNone)
	pkt.Write([]byte{0, 0, 0, 0})
	pkt.Write([]byte{0, 0, 0, 0})
	pkt.WriteByte(byte(len(body)))
	pkt.Write(body)
	return pkt.Bytes()
}

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
	OEMID          uint32
	GUID           []byte
	CompletionCode byte
	Raw            []byte
}

func ParseAuthCapsReply(body []byte) (*AuthCaps, error) {
	if len(body) < 11 {
		return nil, errors.New("short auth-caps reply")
	}

	start := -1
	for i := 0; i+3 < len(body); i++ {
		console := body[i] == 0x81 || body[i] == 0x8c
		switch {
		case console && body[i+3] == 0x20:
			start = i
		case body[i] == 0x20 && (body[i+3] == 0x81 || body[i+3] == 0x8c):
			start = i
		}
		if start >= 0 {
			break
		}
	}
	if start < 0 {

		for i := 0; i+5 < len(body); i++ {
			if body[i+3] == 0x20 && body[i+5] == CmdGetChannelAuthCaps {
				start = i
				break
			}
		}
	}
	if start < 0 {

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

	if start+14 <= len(body) {
		ac.OEMID = uint32(body[start+11]) | uint32(body[start+12])<<8 | uint32(body[start+13])<<16
	}
	return ac, nil
}

func (a *AuthCaps) HasAuthNone() bool { return a.AuthTypeMask&0x01 != 0 }

func (a *AuthCaps) HasAuthMD2() bool { return a.AuthTypeMask&0x02 != 0 }

func (a *AuthCaps) HasAuthMD5() bool { return a.AuthTypeMask&0x04 != 0 }

func (a *AuthCaps) HasAuthStraight() bool { return a.AuthTypeMask&0x10 != 0 }

func (a *AuthCaps) HasAuthOEM() bool { return a.AuthTypeMask&0x20 != 0 }
