package digi

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/runZeroInc/excrypto/crypto/tls"
)

const (
	// RealPortPort is Digi RealPort cleartext mux port.
	RealPortPort    = 771
	RealPortTLSPort = 1027
	// maxRealPortSerialPorts caps how many serial ports we will enumerate,
	// regardless of the (wire-supplied) PortCount, so a device that over-reports
	// cannot turn the scan into tens of thousands of per-port round-trips. The
	// largest real Digi PortServer TS is 64-port.
	maxRealPortSerialPorts = 64
)

var realportHello = []byte{0xfb, 0x01, 0xfb, 0x02, 0xfb, 0x18}

var realportBaudMap = map[int][2]byte{
	2400:   {0x03, 0x00},
	9600:   {0x00, 0xc0},
	19200:  {0x00, 0x60},
	38400:  {0x00, 0x20},
	57600:  {0x00, 0x30},
	76800:  {0x00, 0x10},
	115200: {0x00, 0x10},
	230400: {0x00, 0x08},
	460800: {0x00, 0x04},
	921600: {0x00, 0x02},
}

// realportBaudOrder is the preferred trial order for baud-rate detection:
// most common rates first, then less common ones. Each port is tried in this
// order and scanning stops at the first baud that produces a readable banner.
var realportBaudOrder = []int{9600, 115200, 38400, 19200, 57600, 2400, 76800, 230400, 460800, 921600}

// RealPortInfo is the parsed RealPort service identity from the initial
// handshake response.
type RealPortInfo struct {
	Port      int
	TLS       bool
	Name      string
	PortCount int
	RawHeader []byte
	RawInfo   []byte
}

// RealPortBanner is captured serial data from one port/speed probe.
type RealPortBanner struct {
	SerialPort int
	Baud       int
	Banner     string
}

// RealPortScan contains the handshake info and any collected banners.
type RealPortScan struct {
	Info    *RealPortInfo
	Banners []RealPortBanner
}

// ProbeRealPort connects to Digi RealPort and parses the product name and
// exposed serial-port count from the handshake.
func ProbeRealPort(host string, port int, useTLS bool, timeout time.Duration) (*RealPortInfo, error) {
	c, err := dialRealPort(host, port, useTLS, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(realportHello); err != nil {
		return nil, err
	}
	return readRealPortInfo(c, port, useTLS)
}

// ScanRealPortBanners performs the Metasploit-style serialport scan against a
// Digi RealPort endpoint: connect, negotiate each serial port at each baud,
// capture short banners, then close the port.
func ScanRealPortBanners(host string, port int, useTLS bool, timeout, bannerTimeout time.Duration, serialPorts []int, baudRates []int, maxData int) (*RealPortScan, error) {
	if maxData <= 0 {
		maxData = 4096
	}
	c, err := dialRealPort(host, port, useTLS, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(realportHello); err != nil {
		return nil, err
	}
	info, err := readRealPortInfo(c, port, useTLS)
	if err != nil {
		return nil, err
	}
	ports := serialPorts
	if len(ports) == 0 {
		for p := 1; p <= info.PortCount; p++ {
			ports = append(ports, p)
		}
	}
	// Build ordered baud candidate list: use the caller's list when provided,
	// otherwise fall back to the standard order (most common rates first).
	orderedBauds := realportBaudOrder
	if len(baudRates) > 0 {
		orderedBauds = baudRates
	}

	out := &RealPortScan{Info: info}
	for _, p := range ports {
		if p < 1 || p > info.PortCount {
			continue
		}
		idx := p - 1
		for _, baud := range orderedBauds {
			if _, ok := realportBaudMap[baud]; !ok {
				continue
			}
			_ = c.SetDeadline(time.Now().Add(timeout))
			open, err := realportOpen(c, idx, baud)
			if err != nil || !open {
				continue
			}
			banner := realportRecvBanner(c, idx, bannerTimeout, maxData)
			_ = realportClose(c, idx)
			if looksReadableBanner(banner) {
				out.Banners = append(out.Banners, RealPortBanner{SerialPort: p, Baud: baud, Banner: banner})
				break // correct baud found; no need to try others for this port
			}
		}
	}
	return out, nil
}

func dialRealPort(host string, port int, useTLS bool, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	if !useTLS {
		return d.Dial("tcp", addr)
	}
	return tls.DialWithDialer(&d, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
}

func readRealPortInfo(c net.Conn, port int, useTLS bool) (*RealPortInfo, error) {
	hdr := make([]byte, 12)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0xfc || hdr[1] != 0x01 {
		return nil, fmt.Errorf("not a realport reply")
	}
	infoLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if infoLen <= 0 || infoLen > 2048 {
		return nil, fmt.Errorf("invalid realport info length %d", infoLen)
	}
	msg := make([]byte, infoLen)
	if _, err := io.ReadFull(c, msg); err != nil {
		return nil, err
	}
	name, fields := splitRealPortInfo(msg)
	if len(fields) < 2 {
		return nil, fmt.Errorf("short realport info")
	}
	r := &RealPortInfo{
		Port:      port,
		TLS:       useTLS,
		Name:      strings.TrimSpace(strings.ReplaceAll(name, "\r", "")),
		PortCount: int(fields[1]),
		RawHeader: append([]byte(nil), hdr...),
		RawInfo:   append([]byte(nil), msg...),
	}
	if r.Name == "" {
		r.Name = "Digi RealPort"
	}
	// PortCount is read straight off the wire (a uint16), so a hostile or
	// broken device could advertise up to 65535 serial ports and drive the
	// per-port enumeration loop into tens of thousands of round-trips against
	// the target. Clamp to the largest real Digi appliance (64-port PortServer)
	// so the scan stays polite regardless of what the device claims.
	if r.PortCount < 0 {
		r.PortCount = 0
	}
	if r.PortCount > maxRealPortSerialPorts {
		r.PortCount = maxRealPortSerialPorts
	}
	return r, nil
}

func realportOpen(c net.Conn, portIndex int, baud int) (bool, error) {
	cprt := byte(0xb0 + portIndex)
	aprt := byte(0xa0 + portIndex)
	spd := realportBaudMap[baud]

	pkt1 := []byte{0xf0, cprt, 0x0a, 0x00}
	if _, err := c.Write(pkt1); err != nil {
		return false, err
	}
	if _, err := readAny(c); err != nil {
		return false, err
	}

	pkt2 := []byte{
		cprt, 0x0e,
		cprt, 0x2a, 0x02, 0xc0, 0xf3,
		cprt, 0x10,
		cprt, 0x14,
		cprt, 0x16,
		cprt, 0x2c, 0x03, 0x00, 0x00,
	}
	if _, err := c.Write(pkt2); err != nil {
		return false, err
	}
	res, err := readAny(c)
	if err != nil {
		return false, err
	}
	if len(res) > 0 && res[0] == 0xff {
		return false, nil
	}

	pkt3 := []byte{
		cprt, 0x30, 0x03, 0xff, 0x00, 0x64,
		cprt, 0x2d, 0x03, 0xff, 0x0b, 0xff,
		cprt, 0x28, spd[0], spd[1], 0x04,
		cprt, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		cprt, 0x2c, 0x00, 0x12, 0x00,
		cprt, 0x2e, 0x11, 0x13, 0x16, 0x00, 0x00,
		cprt, 0x2f, 0x03, 0xff, 0x00, 0x64,
		cprt, 0x40, 0x37, aprt, 0x0f, 0xff,
	}
	if _, err := c.Write(pkt3); err != nil {
		return false, err
	}
	res, err = readAny(c)
	if err != nil {
		return false, err
	}
	if len(res) > 0 && res[0] == 0xff {
		return false, nil
	}
	return true, nil
}

func realportClose(c net.Conn, portIndex int) error {
	cprt := byte(0xb0 + portIndex)
	pkt := []byte{cprt, 0x28, 0x00, 0xc0, 0x00, 0xb0, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, cprt, 0x0a, 0x03}
	if _, err := c.Write(pkt); err != nil {
		return err
	}
	_, _ = readAny(c)
	return nil
}

// realportRecvBanner reads framed serial output from the open RealPort port. It
// first reads any output the device emits on its own, and if nothing arrives it
// sends a framed carriage-return/line-feed nudge and reads again.
//
// The nudge is written with realportSend so it carries the RealPort port byte
// like the reference client's realport_send; writing a bare "\r\n" straight to
// the socket is misread by the service as a command rather than serial input.
func realportRecvBanner(c net.Conn, portIndex int, timeout time.Duration, maxData int) string {
	if maxData <= 0 {
		maxData = 4096
	}
	banner := realportCollect(c, portIndex, timeout, maxData)
	if strings.TrimSpace(banner) == "" {
		realportSend(c, portIndex, []byte("\r\n"))
		banner = realportCollect(c, portIndex, timeout, maxData)
	}
	return strings.TrimSpace(banner)
}

// realportCollect reads framed serial output for a single port. It mirrors the
// reference RealPort client's realport_recv_banner state machine, where the
// stream is a sequence of one-byte markers:
//
//	0xA0+port  followed by a 2-byte packet sequence number (discarded)
//	0xF0       keep-alive frame (ignored)
//	0x80+port  followed by a 1-byte length and that many serial data bytes
//
// Reading the exact framed structure (rather than scanning a TCP buffer for the
// data marker) keeps the stream aligned so that data bytes which happen to equal
// a marker value are not misinterpreted as a new frame header, and so that
// frames spanning TCP segment boundaries are not dropped.
func realportCollect(c net.Conn, portIndex int, timeout time.Duration, maxData int) string {
	if c == nil {
		return ""
	}
	if maxData <= 0 {
		maxData = 4096
	}
	start := time.Now()
	banner := make([]byte, 0, 128)

	seqMarker := byte(0xa0 + portIndex)
	dataMarker := byte(0x80 + portIndex)

	for len(banner) < maxData && time.Since(start) < timeout {
		head, ok := realportReadN(c, 1, time.Second)
		if !ok {
			break
		}
		switch head[0] {
		case seqMarker:
			// Packet sequence number: two bytes we can discard.
			_, _ = realportReadN(c, 2, time.Second)
		case 0xf0:
			// Keep-alive frame, nothing to collect.
		case dataMarker:
			lenBuf, ok := realportReadN(c, 1, time.Second)
			if !ok {
				continue
			}
			ln := int(lenBuf[0])
			if ln <= 0 {
				continue
			}
			data, ok := realportReadN(c, ln, time.Second)
			if !ok || len(data) == 0 {
				continue
			}
			if len(banner)+len(data) > maxData {
				data = data[:maxData-len(banner)]
			}
			banner = append(banner, data...)
		}
	}
	return string(banner)
}

// realportSend writes serial data to a port using the RealPort framing used by
// the reference client's realport_send: the one-byte port index followed by the
// raw data.
func realportSend(c net.Conn, portIndex int, data []byte) {
	if c == nil {
		return
	}
	buf := make([]byte, 0, len(data)+1)
	buf = append(buf, byte(portIndex))
	buf = append(buf, data...)
	_, _ = c.Write(buf)
}

// realportReadN reads up to n bytes within the timeout, returning what it read
// and whether at least one byte was received. Reading the exact number of
// requested bytes keeps the framed stream aligned across TCP segment boundaries.
func realportReadN(c net.Conn, n int, timeout time.Duration) ([]byte, bool) {
	if c == nil || n <= 0 {
		return nil, false
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, n)
	total := 0
	for total < n {
		m, err := c.Read(buf[total:])
		if m > 0 {
			total += m
		}
		if err != nil {
			break
		}
	}
	return buf[:total], total > 0
}

// looksReadableBanner returns true when the banner shows evidence of a real device
// on the serial port: at least one alphanumeric byte, and no single byte dominating
// the total, which is what a baud-rate mismatch produces.
//
// A printable-ratio threshold must not be used instead: serial-attached devices often
// speak binary framing with few printable bytes, and those are real findings.
// Comparison is byte-level so unicode.IsPrint cannot treat the UTF-8 replacement
// character as printable and mask non-ASCII framing bytes.
func looksReadableBanner(banner string) bool {
	banner = strings.TrimSpace(banner)
	if banner == "" {
		return false
	}
	raw := []byte(banner)
	alnum := 0
	var freq [256]int
	for _, b := range raw {
		freq[b]++
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
			alnum++
		}
	}
	if alnum == 0 {
		return false
	}
	// Reject monotone banners: baud-rate mismatch produces streams of one
	// repeated byte (e.g. 0x77 'w' at every attempted speed). A threshold of
	// 75% rejects the observed 80% pattern with headroom while staying well
	// clear of real banners (P0 embedded in binary has max byte freq ~25%).
	if len(raw) > 8 {
		for _, cnt := range freq {
			if float64(cnt)/float64(len(raw)) >= 0.75 {
				return false
			}
		}
	}
	return true
}

func readAny(c net.Conn) ([]byte, error) {
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil {
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			return nil, nil
		}
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

func splitRealPortInfo(msg []byte) (string, []uint16) {
	idx := -1
	for i := 0; i+1 < len(msg); i++ {
		if msg[i] == 0xfc && msg[i+1] == 0x02 {
			idx = i
			break
		}
	}
	if idx < 0 {
		return string(msg), nil
	}
	name := string(msg[:idx])
	meta := msg[idx+2:]
	vals := make([]uint16, 0, len(meta)/2)
	for i := 0; i+1 < len(meta); i += 2 {
		vals = append(vals, binary.BigEndian.Uint16(meta[i:i+2]))
	}
	return name, vals
}
