package check

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/telnet"
)

// TestPerleDiagIACAnnotation exercises the shared telnet helper via the same
// wire shape we expect from a Perle IOLAN diagnostic port: IAC negotiation
// followed by a "diag>" prompt. The finding should embed the annotated
// negotiation ("<DO Echo>") in front of the visible banner instead of
// stripping the IAC bytes silently.
func TestPerleDiagIACAnnotation(t *testing.T) {
	// IAC DO ECHO (0xFF 0xFD 0x01), IAC WILL SGA (0xFF 0xFB 0x03), then text.
	in := []byte{0xFF, 0xFD, 0x01, 0xFF, 0xFB, 0x03, 'd', 'i', 'a', 'g', '>', ' '}
	ir := telnet.ParseIAC(in)
	if !strings.Contains(ir.Annotated, "<DO Echo>") {
		t.Errorf("annotated missing <DO Echo>: %q", ir.Annotated)
	}
	if !strings.Contains(ir.Annotated, "<WILL Suppress Go Ahead>") {
		t.Errorf("annotated missing <WILL Suppress Go Ahead>: %q", ir.Annotated)
	}
	if !strings.Contains(ir.Annotated, "diag> ") {
		t.Errorf("annotated missing visible tail: %q", ir.Annotated)
	}
	// A plain banner passes through unchanged.
	if got := telnet.ParseIAC([]byte("IOLAN diag")).Annotated; got != "IOLAN diag" {
		t.Errorf("plain banner = %q, want IOLAN diag", got)
	}
}

// TestProbePerleDiagTelnetBanner starts a TCP listener that offers IAC DO
// Echo and then a diag prompt, and confirms the probe reports open plus a
// banner that carries the annotated IAC token and the visible prompt.
func TestProbePerleDiagTelnetBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		// telnet IAC DO ECHO then a diag prompt.
		_, _ = c.Write([]byte{0xFF, 0xFD, 0x01})
		_, _ = c.Write([]byte("Perle IOLAN diag>"))
		// Drain the client's negotiation reply so the connection stays open
		// long enough for the client to consume the prompt.
		buf := make([]byte, 32)
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = c.Read(buf)
		time.Sleep(50 * time.Millisecond)
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	open, banner := dialAndReadTelnet(context.Background(), host, port, 2*time.Second)
	if !open {
		t.Fatal("expected the listener connect to report open")
	}
	if !strings.Contains(banner, "<DO Echo>") {
		t.Errorf("banner missing <DO Echo> annotation: %q", banner)
	}
	if !strings.Contains(banner, "Perle IOLAN diag>") {
		t.Errorf("banner missing visible prompt: %q", banner)
	}
}

// dialAndReadTelnet exercises the shared negotiation helper against an
// arbitrary port so tests can point it at an ephemeral listener.
func dialAndReadTelnet(ctx context.Context, host string, port int, timeout time.Duration) (bool, string) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	res := telnet.ReadBannerWithNegotiate(conn, timeout)
	out := res.Annotated
	if out == "" {
		out = string(res.Visible)
	}
	return true, out
}

// TestRunPerleDiagTelnetGate confirms the check does nothing when 10064 is not in
// the scan set (zero-network-cost gate) and fires when the diag listener answers.
func TestRunPerleDiagTelnetGate(t *testing.T) {
	// Not in scan set -> no finding, no connect.
	tgt := &engine.Target{
		Host:    "192.0.2.1", // TEST-NET-1, unroutable
		Timeout: 200 * time.Millisecond,
	}
	if got := runPerleDiagTelnet(context.Background(), tgt); got != nil {
		t.Errorf("expected no finding when 10064 not in scan set, got %v", got)
	}

	// Now run a real listener ON perleDiagPort. Skip if the port is unavailable
	// (privileged/occupied in CI); the banner path is covered by the test above.
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(perleDiagPort))
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:%d: %v", perleDiagPort, err)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("diag>"))
				time.Sleep(50 * time.Millisecond)
			}(c)
		}
	}()

	// A non-Perle device answering on 10064 must not be flagged: port 10064 alone
	// (= 10000 + line 64) is a generic raw-TCP serial slot other console servers
	// (Opengear/Lantronix/Digi) also expose. The diag-port branch is gated on a
	// positive Perle identity, so a bare "diag>" banner from an unidentified host
	// yields no critical Perle misattribution.
	tgtNonPerle := &engine.Target{Host: "127.0.0.1", Timeout: 2 * time.Second}
	tgtNonPerle.MarkOpen(perleDiagPort, "tcp", "")
	if got := runPerleDiagTelnet(context.Background(), tgtNonPerle); hasFinding(got, "telnet.perleDiag") != nil {
		t.Errorf("non-Perle device on 10064 must not be flagged as a Perle diag exposure, got %v", got)
	}

	// A Perle-identified device answering on the diag slot IS the critical exposure.
	tgt2 := &engine.Target{
		Host:     "127.0.0.1",
		Timeout:  2 * time.Second,
		Identity: &engine.Identity{Class: engine.ClassSerialConsole, Vendor: "perle"},
	}
	tgt2.MarkOpen(perleDiagPort, "tcp", "") // put 10064 in the scan set
	got := runPerleDiagTelnet(context.Background(), tgt2)
	f := hasFinding(got, "telnet.perleDiag")
	if f == nil {
		t.Fatal("expected perle.diag_telnet finding when a Perle device's diag listener answers")
	}
	if f.Risk != "critical" || f.Port != perleDiagPort {
		t.Errorf("finding risk/port = %s/%d, want critical/%d", f.Risk, f.Port, perleDiagPort)
	}
}

// TestRunPerleDiagTelnetRawLine covers the 10001 raw-TCP line extension:
// when only 10001/tcp is in the scan set, we should still emit a finding
// tagged with the line label ("line-1") and the correct port.
func TestRunPerleDiagTelnetRawLine(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("IOLAN-DS1 line 1> "))
		buf := make([]byte, 16)
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, _ = c.Read(buf)
		time.Sleep(50 * time.Millisecond)
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// Swap in the ephemeral port as the "raw line" candidate for this test.
	old := perleRawLinePorts
	perleRawLinePorts = []int{port}
	defer func() { perleRawLinePorts = old }()

	tgt := &engine.Target{Host: "127.0.0.1", Timeout: 2 * time.Second}
	tgt.Identity = &engine.Identity{Class: engine.ClassSerialConsole, Vendor: "perle"}
	tgt.MarkOpen(port, "tcp", "")
	got := runPerleDiagTelnet(context.Background(), tgt)
	f := hasFinding(got, "telnet.perleDiag")
	if f == nil {
		t.Fatalf("expected telnet.perleDiag finding on raw-line port, got %+v", got)
	}
	if f.Port != port {
		t.Errorf("port = %d, want %d", f.Port, port)
	}
}

// A raw-line port answering with an SSH banner is not a Perle serial line
// (10001 is a commonly reused port); it must be skipped, not reported.
func TestRunPerleDiagTelnetSSHBannerSkipped(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_8.4p1\r\n"))
		time.Sleep(50 * time.Millisecond)
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	old := perleRawLinePorts
	perleRawLinePorts = []int{port}
	defer func() { perleRawLinePorts = old }()

	tgt := &engine.Target{Host: "127.0.0.1", Timeout: 2 * time.Second}
	tgt.Identity = &engine.Identity{Class: engine.ClassSerialConsole, Vendor: "perle"}
	tgt.MarkOpen(port, "tcp", "")
	if got := runPerleDiagTelnet(context.Background(), tgt); got != nil {
		t.Fatalf("expected no perleDiag finding for an SSH banner, got %+v", got)
	}
}

func TestRunPerleDiagTelnetRawLineNonPerleSkipped(t *testing.T) {
	tgt := &engine.Target{
		Host:     "192.0.2.1",
		Timeout:  200 * time.Millisecond,
		Identity: &engine.Identity{Class: engine.ClassSerialConsole, Vendor: "lantronix"},
	}
	tgt.MarkOpen(10001, "tcp", "")
	if got := runPerleDiagTelnet(context.Background(), tgt); got != nil {
		t.Fatalf("expected no Perle raw-line finding on non-Perle target, got %+v", got)
	}
}

func perleWebTarget(t *testing.T, srvURL string) *engine.Target {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srvURL, "http://"))
	if err != nil {
		t.Fatalf("split %q: %v", srvURL, err)
	}
	return &engine.Target{
		Host:    host,
		Timeout: 2 * time.Second,
		Identity: &engine.Identity{
			Vendor:     "perle",
			Class:      engine.ClassSerialConsole,
			Attributes: map[string]string{"web.port": portStr, "web.scheme": "http"},
		},
	}
}

func TestRunPerleCGIUnauthLeak(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manage.cgi":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Perle IOLAN configuration page"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer vuln.Close()

	got := runPerleCGIUnauthLeak(context.Background(), perleWebTarget(t, vuln.URL))
	f := hasFinding(got, "http.perle.iolan.cgiUnauthLeak")
	if f == nil {
		t.Fatalf("expected perle CGI leak finding, got %+v", got)
	}
	if f.Risk != "medium" {
		t.Errorf("risk = %s, want medium", f.Risk)
	}

	patched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("login required"))
	}))
	defer patched.Close()
	if got := runPerleCGIUnauthLeak(context.Background(), perleWebTarget(t, patched.URL)); len(got) != 0 {
		t.Fatalf("expected no finding for auth-gated CGI, got %+v", got)
	}
}
