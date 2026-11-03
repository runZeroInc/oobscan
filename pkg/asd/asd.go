// Package asd implements a client for the Intel At-Scale-Debug (ASD) wire protocol,
// the JTAG/I2C-over-network service H3C rebrands as "RemoteXDP" on tcp/6868. The
// framing was reconstructed from shipped firmware and validated against a mock
// server; see kb/h3c/ and docs/.
//
// The service is unauthenticated by default; hardened deployments may wrap it in TLS
// plus a PAM prompt. Dial supports plain TCP, TLS and the PAM handshake.
//
// This build implements only JTAG and I2C/I3C primitives -- there is no DMA message,
// as process_message rejects it -- so memory access is composed from CPU-debug JTAG
// scan sequences. On emulated targets with no host CPU on the chain those scans
// return all-ones or a failure, which the client reports as hardware-blocked rather
// than fabricating data.
package asd

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Wire limits.
const (
	HeaderSize   = 4
	MaxDataSize  = 3000 // 0x0BB8, matches MAX_DATA_SIZE in the daemon
	MaxPacket    = HeaderSize + MaxDataSize
	DefaultPort  = 6868
	defaultTagID = 1
)

// Message types (bits 5..7 of header byte 0).
const (
	TypeAgentControl = 0
	TypeJTAG         = 1
	TypeI2C          = 6
	TypeSPP          = 7
	TypeDMA          = 3 // rejected by this build; used only as a negative probe
)

// Agent-control commands (carried in the header cmd_stat byte, not the payload).
const (
	AgentNumInFlight        = 3
	AgentObtainVersion      = 5
	AgentConfiguration      = 8
	AgentMaxDataSize        = 13
	AgentSupportedJTAGChain = 14
	AgentSupportedI2CBuses  = 15
	AgentLoopback           = 18
)

// Response status codes (response cmd_stat byte).
const (
	StatusSuccess            = 0x00
	StatusCryptNotSupported  = 0x25
	StatusInitJTAGHandler    = 0x26
	StatusInitI2CHandler     = 0x27
	StatusMsgNotSupported    = 0x29
	StatusProcessJTAGMsg     = 0x2A
	StatusI2CMsgNotSupported = 0x2D
	StatusHeaderSize         = 0x2F
	StatusXDPPresent         = 0x30
	StatusInitSPPHandler     = 0x3C
)

var statusNames = map[byte]string{
	StatusSuccess:            "ASD_SUCCESS",
	StatusCryptNotSupported:  "ASD_MSG_CRYPT_NOT_SUPPORTED",
	StatusInitJTAGHandler:    "ASD_FAILURE_INIT_JTAG_HANDLER",
	StatusInitI2CHandler:     "ASD_FAILURE_INIT_I2C_HANDLER",
	StatusMsgNotSupported:    "ASD_MSG_NOT_SUPPORTED",
	StatusProcessJTAGMsg:     "ASD_FAILURE_PROCESS_JTAG_MSG",
	StatusI2CMsgNotSupported: "ASD_I2C_MSG_NOT_SUPPORTED",
	StatusHeaderSize:         "ASD_FAILURE_HEADER_SIZE",
	StatusXDPPresent:         "ASD_FAILURE_XDP_PRESENT",
	StatusInitSPPHandler:     "ASD_FAILURE_INIT_SPP_HANDLER",
}

// StatusName returns the symbolic name for an ASD status/completion code.
func StatusName(code byte) string {
	if n, ok := statusNames[code]; ok {
		return n
	}
	return fmt.Sprintf("0x%02x", code)
}

// HardwareBlocked reports whether a JTAG response status indicates the request
// reached the (unauthenticated) handler but the physical JTAG chain / host CPU
// was unavailable - the expected condition on an emulated or powered-down
// target. It is not a protocol failure.
func HardwareBlocked(code byte) bool {
	switch code {
	case StatusInitJTAGHandler, StatusXDPPresent, StatusProcessJTAGMsg:
		return true
	}
	return false
}

// Header is the 4-byte bit-packed ASD message header.
type Header struct {
	Type    byte
	Size    int
	CmdStat byte
	Tag     byte
	Origin  byte
	Enc     byte
}

// Pack serializes the header to its 4-byte wire form.
func (h Header) Pack() []byte {
	b0 := (h.Origin & 0x07) | ((h.Enc & 1) << 4) | ((h.Type & 0x07) << 5)
	b1 := byte(h.Size & 0xFF)
	b2 := byte((h.Size>>8)&0x1F) | ((h.Tag & 0x07) << 5)
	b3 := h.CmdStat
	return []byte{b0, b1, b2, b3}
}

// UnpackHeader parses a 4-byte wire header.
func UnpackHeader(raw []byte) Header {
	return Header{
		Type:    (raw[0] >> 5) & 0x07,
		Size:    int(raw[1]) | (int(raw[2]&0x1F) << 8),
		CmdStat: raw[3],
		Tag:     (raw[2] >> 5) & 0x07,
		Origin:  raw[0] & 0x07,
		Enc:     (raw[0] >> 4) & 1,
	}
}

// Options configures a Conn.
type Options struct {
	Timeout time.Duration
	TLS     bool // wrap the connection in TLS (H3C hardened deployments)
	PAMUser string
	PAMPass string
	Tag     byte
	Origin  byte
}

// Conn is an ASD protocol connection.
type Conn struct {
	c       net.Conn
	timeout time.Duration
	tag     byte
	origin  byte
	// AuthPrompted records whether the server sent a PAM prompt on connect.
	AuthPrompted bool
	// Authenticated records whether a PAM login succeeded.
	Authenticated bool
	// Transport is "tcp" or "tls".
	Transport string
	// PromptBytes is the raw authpam prompt the server sent on connect (set only
	// when AuthPrompted is true). Kept as evidence for triage.
	PromptBytes []byte
}

// Dial connects to an ASD service. It auto-detects a server-initiated PAM
// prompt (authpam) and, if PAM credentials are supplied, completes the login;
// otherwise it proceeds on the authnone path (send messages immediately).
func Dial(host string, port int, opts Options) (*Conn, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	raw, err := net.DialTimeout("tcp", addr, opts.Timeout)
	if err != nil {
		return nil, err
	}
	conn := &Conn{c: raw, timeout: opts.Timeout, tag: opts.Tag, origin: opts.Origin, Transport: "tcp"}
	if opts.Tag == 0 {
		conn.tag = defaultTagID
	}
	if opts.TLS {
		tconn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // BMC self-signed certs
		_ = tconn.SetDeadline(time.Now().Add(opts.Timeout))
		if err := tconn.Handshake(); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		_ = tconn.SetDeadline(time.Time{})
		conn.c = tconn
		conn.Transport = "tls"
	}

	// authnone sends nothing; authpam sends a prompt led by the ASD status byte
	// 0x30. But 0x30 alone is not sufficient evidence: it is also the ASN.1/BER
	// SEQUENCE tag (LDAP/SNMP/Kerberos responses) and ASCII '0' (the leading byte
	// of a bencode length prefix used by some P2P sync daemons). A field
	// internet scan found that every host flagged on a bare 0x30 was in fact an
	// LDAP BindResponse (5123/tcp) or a bencode handshake (6868/tcp), never ASD.
	// isASDAuthPrompt keeps the 0x30 lead but rejects those competing framings.
	if prompt := conn.peekPrompt(); isASDAuthPrompt(prompt) {
		conn.AuthPrompted = true
		conn.PromptBytes = prompt
		if opts.PAMUser != "" {
			if err := conn.pamLogin(opts.PAMUser, opts.PAMPass); err != nil {
				// Preserve the connection so callers can report the auth gate.
				return conn, nil
			}
			conn.Authenticated = true
		}
	}
	return conn, nil
}

// isASDAuthPrompt reports whether a server's connect banner is a genuine ASD
// authpam prompt rather than an unrelated protocol whose first byte merely
// happens to be 0x30. 0x30 is overloaded: it is the ASD StatusXDPPresent byte,
// the ASN.1/BER SEQUENCE tag (LDAP/SNMP/Kerberos), and ASCII '0' (a bencode
// length-prefix digit). A 0x30-led banner is accepted only when it does not
// decode as one of those competing framings. A real ASD prompt continues with
// the PAM handshake marker, so it clears both rejections.
func isASDAuthPrompt(prompt []byte) bool {
	if len(prompt) == 0 || prompt[0] != StatusXDPPresent {
		return false
	}
	if len(prompt) >= 2 {
		// ASN.1/BER definite-length SEQUENCE: 0x30 <len...> 0x02 ... The first
		// element of an LDAP/SNMP/Kerberos message is an INTEGER (messageID /
		// version), so a SEQUENCE whose content opens with the INTEGER tag (0x02)
		// is a foreign BER response. Handle short- and long-form lengths.
		contentOff := 2
		if prompt[1]&0x80 != 0 { // long-form: low 7 bits = number of length bytes
			contentOff = 2 + int(prompt[1]&0x7f)
		}
		if contentOff < len(prompt) && prompt[contentOff] == 0x02 {
			return false
		}
		// bencode length prefix ("<digits>:..."): 0x30 read as ASCII '0' followed
		// by another ASCII digit. A real ASD prompt is not digit-led past 0x30.
		if prompt[1] >= '0' && prompt[1] <= '9' {
			return false
		}
	}
	return true
}

func (c *Conn) peekPrompt() []byte {
	_ = c.c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 256)
	n, _ := c.c.Read(buf)
	_ = c.c.SetReadDeadline(time.Time{})
	return buf[:n]
}

func (c *Conn) pamLogin(user, pass string) error {
	payload := append([]byte(user), 0)
	payload = append(payload, []byte(pass)...)
	payload = append(payload, 0)
	if err := c.writeAll(payload); err != nil {
		return err
	}
	_ = c.c.SetReadDeadline(time.Now().Add(c.timeout))
	status := make([]byte, 1)
	_, err := io.ReadFull(c.c, status)
	_ = c.c.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("pam: reading status: %w", err)
	}
	switch status[0] {
	case 0x30, 0x2B: // '0' success, '+' already authenticated
		return nil
	case 0x24:
		return errors.New("pam auth failed (+60s lockout)")
	case 0x3F:
		return errors.New("pam auth: system error")
	default:
		return fmt.Errorf("pam auth: unknown status 0x%02x", status[0])
	}
}

// Close closes the connection.
func (c *Conn) Close() error {
	if c == nil || c.c == nil {
		return nil
	}
	return c.c.Close()
}

func (c *Conn) writeAll(b []byte) error {
	_ = c.c.SetWriteDeadline(time.Now().Add(c.timeout))
	defer func() { _ = c.c.SetWriteDeadline(time.Time{}) }()
	_, err := c.c.Write(b)
	return err
}

// Send transmits one ASD message.
func (c *Conn) Send(msgType, cmdStat byte, payload []byte) error {
	if len(payload) > MaxDataSize {
		return fmt.Errorf("payload %d exceeds MAX_DATA_SIZE %d", len(payload), MaxDataSize)
	}
	h := Header{Type: msgType, Size: len(payload), CmdStat: cmdStat, Tag: c.tag, Origin: c.origin}
	return c.writeAll(append(h.Pack(), payload...))
}

// Recv reads one ASD message.
func (c *Conn) Recv() (Header, []byte, error) {
	_ = c.c.SetReadDeadline(time.Now().Add(c.timeout))
	defer func() { _ = c.c.SetReadDeadline(time.Time{}) }()
	head := make([]byte, HeaderSize)
	if _, err := io.ReadFull(c.c, head); err != nil {
		return Header{}, nil, err
	}
	h := UnpackHeader(head)
	var body []byte
	if h.Size > 0 {
		body = make([]byte, h.Size)
		if _, err := io.ReadFull(c.c, body); err != nil {
			return h, nil, err
		}
	}
	return h, body, nil
}

// Exchange sends a message and reads the reply.
func (c *Conn) Exchange(msgType, cmdStat byte, payload []byte) (Header, []byte, error) {
	if err := c.Send(msgType, cmdStat, payload); err != nil {
		return Header{}, nil, err
	}
	return c.Recv()
}

// Agent runs an agent-control command (command carried in cmd_stat).
func (c *Conn) Agent(command byte, payload []byte) (Header, []byte, error) {
	return c.Exchange(TypeAgentControl, command, payload)
}

// Version returns the printable portion of the downstream-version reply.
func (c *Conn) Version() (string, error) {
	h, body, err := c.Agent(AgentObtainVersion, nil)
	if err != nil {
		return "", err
	}
	if h.CmdStat != StatusSuccess || len(body) == 0 {
		return "", fmt.Errorf("version query failed: %s", StatusName(h.CmdStat))
	}
	printable := make([]byte, 0, len(body))
	for _, b := range body[1:] {
		if b >= 0x20 && b < 0x7F {
			printable = append(printable, b)
		}
	}
	return string(printable), nil
}

// MaxDataSizeReported returns the negotiated max payload size.
func (c *Conn) MaxDataSizeReported() (int, error) {
	h, body, err := c.Agent(AgentMaxDataSize, nil)
	if err != nil {
		return 0, err
	}
	if h.CmdStat != StatusSuccess || len(body) < 3 {
		return 0, fmt.Errorf("max-data-size failed: %s", StatusName(h.CmdStat))
	}
	return int(binary.LittleEndian.Uint16(body[1:3])), nil
}

// NumInFlight returns the number of in-flight messages the server supports.
func (c *Conn) NumInFlight() (int, error) {
	h, body, err := c.Agent(AgentNumInFlight, nil)
	if err != nil {
		return 0, err
	}
	if h.CmdStat != StatusSuccess || len(body) < 2 {
		return 0, fmt.Errorf("num-in-flight failed: %s", StatusName(h.CmdStat))
	}
	return int(body[1]), nil
}

// SupportedJTAGChains returns the number of JTAG chains the server exposes.
func (c *Conn) SupportedJTAGChains() (int, error) {
	h, body, err := c.Agent(AgentSupportedJTAGChain, nil)
	if err != nil {
		return 0, err
	}
	if h.CmdStat != StatusSuccess || len(body) < 2 {
		return 0, fmt.Errorf("supported-jtag-chains failed: %s", StatusName(h.CmdStat))
	}
	return int(body[1]), nil
}

// Loopback sends the LOOPBACK agent command and returns the echoed body. This
// avoids issuing CPU-debug memory operations.
func (c *Conn) Loopback(data []byte) ([]byte, error) {
	h, body, err := c.Agent(AgentLoopback, data)
	if err != nil {
		return nil, err
	}
	if h.CmdStat != StatusSuccess {
		return nil, fmt.Errorf("loopback failed: %s", StatusName(h.CmdStat))
	}
	return body, nil
}

// JTAG sends a JTAG opcode buffer and returns the response header + TDO body.
func (c *Conn) JTAG(opcodes []byte) (Header, []byte, error) {
	return c.Exchange(TypeJTAG, 0x00, opcodes)
}
