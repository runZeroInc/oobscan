package check

import (
	"context"
	"encoding/hex"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// TestMatchTelnetFingerprint covers the vendor detection table against a
// spread of real-world banner shapes. This is the fingerprint contract for
// the tcp.telnetBanner check.
func TestMatchTelnetFingerprint(t *testing.T) {
	cases := []struct {
		name    string
		banner  string
		vendor  string
		product string
	}{
		{"lantronix SLC login prompt", "\r\nWelcome to the SLC console manager\r\nSLC login: ", "lantronix", "SLC"},
		{"lantronix EMG login prompt", "EMG8500 login: ", "lantronix", "EMG"},
		{"lantronix XPort setup mode", "MAC address 00204ACF25D1\r\n Press Enter for Setup Mode", "lantronix", "XPort"},
		{"perle IOLAN prompt", "IOLAN-DS1 login: ", "perle", "IOLAN"},
		{"moxa NPort menu", "\r\n Model name       : NPort 5150\r\n MAC address     : 00:90:E8:1A:2B:3C", "moxa", "NPort"},
		{"digi PortServer", "Welcome! Access-Method: Digi PortServer TS", "digi", "PortServer"},
		{"cisco IOS", "\r\n\r\nUser Access Verification\r\n\r\nUsername: ", "cisco", "IOS"},
		{"apc NMC", "\r\n\r\nAmerican Power Conversion               Network Management Card AOS      v6.9.6\r\n(c) Copyright 2020 All Rights Reserved  Rack PDU APP\r\n", "apc", "NMC"},
		{"cyberpower RMCARD", "\r\nCyberPower Systems, Inc. RMCARD205\r\nLogin Name: ", "cyberpower", "RMCARD"},
		{"servertech CDU", "Sentry Switched CDU Version 8.0e\r\nSentry: ", "servertech", "Sentry Switched CDU"},
		{"mikrotik RouterOS", "MikroTik v6.49.6 (stable)\r\nLogin: ", "mikrotik", "RouterOS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp := matchTelnetFingerprint(tc.banner)
			if fp == nil {
				t.Fatalf("expected a fingerprint hit for banner=%q", tc.banner)
			}
			if fp.vendor != tc.vendor || fp.product != tc.product {
				t.Fatalf("got %s/%s, want %s/%s (note=%q)", fp.vendor, fp.product, tc.vendor, tc.product, fp.note)
			}
		})
	}
}

// TestMatchTelnetFingerprint_Negatives asserts the table doesn't fire on
// generic prompts (Cowrie login: or bare `Password:`), which is the
// honeypot-safety contract for the check.
func TestMatchTelnetFingerprint_Negatives(t *testing.T) {
	for _, banner := range []string{
		"",
		"login: ",
		"Password: ",
		"Access denied",
		"HTTP/1.1 400 Bad Request",
	} {
		if fp := matchTelnetFingerprint(banner); fp != nil {
			t.Errorf("expected no fingerprint hit for %q, got %s/%s", banner, fp.vendor, fp.product)
		}
	}
}

// TestMatchTelnetHoneypot ensures the honeypot pattern list flags common
// Cowrie profiles.
func TestMatchTelnetHoneypot(t *testing.T) {
	for _, banner := range []string{
		"Ubuntu 20.04.6 LTS",
		"\r\nBusyBox v1.30.1 (2020-01-01) built-in shell (ash)\r\n",
		"Siemens Simatic Runtime Version 1.24",
	} {
		if !matchTelnetHoneypot(banner) {
			t.Errorf("expected honeypot=true for %q", banner)
		}
	}
	if matchTelnetHoneypot("SLC login: ") {
		t.Error("real SLC banner should not be flagged as honeypot")
	}
}

func TestTelnetBannerPortsIncludeLantronixRawSerial(t *testing.T) {
	for _, want := range []int{10001, 10002, 10003} {
		found := slices.Contains(telnetBannerPorts, want)
		if !found {
			t.Fatalf("telnetBannerPorts missing %d: %v", want, telnetBannerPorts)
		}
	}
}

func TestRawSerialBannerEvidence(t *testing.T) {
	corpusNoise, err := hex.DecodeString(
		"7f01ff470049fc00000000ffffffff000001c8e0d8fec0fec0fec0fec0fec000" +
			"0001c8e0d7fec0fec0fec0fec0fec0000005a00898014001e002a80008fff000" +
			"0000000000000000000000000000007c7f01ff6f0012ff000000000000000000" +
			"0000000000000000ff7f01ff40001c00000039fc1bffd8ffd8ffd8ffd8ffd8fc")
	if err != nil {
		t.Fatalf("decode corpus fixture: %v", err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		want bool
	}{
		{name: "oob25 binary noise", raw: corpusNoise, want: false},
		{name: "ANSI clear screen only", raw: []byte("\x1b[0m\x1b[2J\x1b[1;1H"), want: false},
		{name: "compact machine frame", raw: []byte("*B1E1+028.4\r"), want: false},
		{name: "router console prompt", raw: []byte("Router console ready\r\nlogin: "), want: true},
		{name: "short sign-on prompt", raw: []byte("SIGN ON:\r\n"), want: true},
		{name: "attached device identity", raw: []byte("Quadlogic Controls Corporation (c)2008 Ver 2.0\r\n"), want: true},
		{name: "attached controller prompt", raw: []byte("WELCOME TO ENTRACOMP SK-ACPE CONTROLLER\r\nENTER PASSWORD: "), want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rawSerialBannerEvidence(tc.raw); got != tc.want {
				t.Fatalf("rawSerialBannerEvidence(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestRunTelnetBanner_LantronixRawSerialHigh(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:10002")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:10002: %v", err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("Router console ready\r\nlogin: "))
		time.Sleep(50 * time.Millisecond)
	}()
	host, _, _ := net.SplitHostPort(ln.Addr().String())
	tgt := &engine.Target{
		Host:    host,
		Timeout: 2 * time.Second,
		Identity: &engine.Identity{
			Class:  engine.ClassSerialConsole,
			Vendor: "lantronix",
		},
	}
	tgt.MarkOpen(10002, "tcp", "")

	got := runTelnetBanner(context.Background(), tgt)
	f := hasFinding(got, "tcp.telnetBanner")
	if f == nil {
		t.Fatalf("expected tcp.telnetBanner finding, got %+v", got)
	}
	if f.Risk != "high" {
		t.Errorf("risk = %s, want high", f.Risk)
	}
	if got := findingField(*f, "banner"); !strings.Contains(got, "Router console ready") {
		t.Errorf("banner = %q, want captured console text", got)
	}
	if got := findingField(*f, "detection"); got != "lantronix raw serial passthrough banner" {
		t.Errorf("detection = %q, want lantronix raw serial passthrough banner", got)
	}
}

func TestRunTelnetBanner_LantronixRawSerialRejectsSSH(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:10001")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:10001: %v", err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.9\r\n"))
		time.Sleep(50 * time.Millisecond)
	}()
	host, _, _ := net.SplitHostPort(ln.Addr().String())
	tgt := &engine.Target{
		Host:    host,
		Timeout: 2 * time.Second,
		Identity: &engine.Identity{
			Class:  engine.ClassSerialConsole,
			Vendor: "lantronix",
		},
	}
	tgt.MarkOpen(10001, "tcp", "")

	got := runTelnetBanner(context.Background(), tgt)
	// An SSH responder on a reused raw-serial port (10001-3) is not a telnet or
	// serial banner: the check must not emit a tcp.telnetBanner finding for it
	// (previously it did, mislabeling 6k+ SSH daemons as protocol=telnet).
	if f := hasFinding(got, "tcp.telnetBanner"); f != nil {
		t.Fatalf("SSH banner on a raw-serial port must not produce a telnet-banner finding, got %+v", f)
	}
	// The port is still recorded (as raw-serial, not telnet) so reachability is
	// not lost.
	if !tgt.IsOpen(10001, "tcp") {
		t.Errorf("raw-serial port 10001 should remain marked open")
	}
}

func TestRunTelnetBanner_LantronixRawSerialEmptySuppressed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:10003")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:10003: %v", err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 16)
		_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		_, _ = c.Read(buf)
		time.Sleep(50 * time.Millisecond)
	}()
	host, _, _ := net.SplitHostPort(ln.Addr().String())
	tgt := &engine.Target{
		Host:    host,
		Timeout: 2 * time.Second,
		Identity: &engine.Identity{
			Class:  engine.ClassSerialConsole,
			Vendor: "lantronix",
		},
	}
	tgt.MarkOpen(10003, "tcp", "")

	if got := runTelnetBanner(context.Background(), tgt); got != nil {
		t.Fatalf("expected no telnet banner finding for empty Lantronix raw port, got %+v", got)
	}
}

// TestRunTelnetBanner_VendorLive spins up a listener that offers IAC DO
// Echo and then a real SLC login prompt, and asserts we emit a
// tcp.telnetBanner finding with vendor=lantronix + medium risk (auth
// prompt). This exercises the whole runner including the IAC negotiator.
func TestRunTelnetBanner_VendorLive(t *testing.T) {
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
		_, _ = c.Write([]byte{0xFF, 0xFD, 0x01}) // IAC DO Echo
		_, _ = c.Write([]byte("\r\nWelcome to the SLC console manager\r\nSLC login: "))
		// Drain the client's rejection so it can finish reading.
		buf := make([]byte, 32)
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = c.Read(buf)
		time.Sleep(50 * time.Millisecond)
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	tgt := &engine.Target{Host: host, Timeout: 2 * time.Second}
	tgt.MarkOpen(port, "tcp", "")
	// Point the check at the ephemeral port by temporarily overriding the
	// candidate list. We restore it at test end.
	old := telnetBannerPorts
	telnetBannerPorts = []int{port}
	defer func() { telnetBannerPorts = old }()

	got := runTelnetBanner(context.Background(), tgt)
	f := hasFinding(got, "tcp.telnetBanner")
	if f == nil {
		t.Fatalf("expected tcp.telnetBanner finding, got %+v", got)
	}
	if f.Risk != "info" {
		t.Errorf("risk = %s, want info (telnet banner is an exposure indicator, not a finding)", f.Risk)
	}
	if got := findingField(*f, "vendor"); got != "lantronix" {
		t.Errorf("vendor = %q, want lantronix", got)
	}
	if got := findingField(*f, "product"); got != "SLC" {
		t.Errorf("product = %q, want SLC", got)
	}
	if !strings.Contains(findingField(*f, "telnetIAC"), "do-echo") {
		t.Errorf("telnetIac missing do-echo: %q", findingField(*f, "telnetIAC"))
	}
	if got := findingField(*f, "telnetIAC"); got == "" {
		t.Errorf("telnetIac = %q, want non-empty IAC summary", got)
	}
}

// TestRunTelnetBanner_Honeypot verifies that a listener producing Cowrie-flavored
// banners is captured but downgraded to info (not medium/high).
func TestRunTelnetBanner_Honeypot(t *testing.T) {
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
		_, _ = c.Write([]byte("Ubuntu 20.04.6 LTS\r\nsvr01 login: "))
		time.Sleep(50 * time.Millisecond)
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	tgt := &engine.Target{Host: host, Timeout: 2 * time.Second}
	tgt.MarkOpen(port, "tcp", "")
	old := telnetBannerPorts
	telnetBannerPorts = []int{port}
	defer func() { telnetBannerPorts = old }()

	got := runTelnetBanner(context.Background(), tgt)
	f := hasFinding(got, "tcp.telnetBanner")
	if f == nil {
		t.Fatalf("expected tcp.telnetBanner finding on honeypot capture, got %+v", got)
	}
	if f.Risk != "info" {
		t.Errorf("risk = %s, want info (honeypot cap)", f.Risk)
	}
	if got := findingField(*f, "honeypot"); got != "true" {
		t.Errorf("honeypot = %q, want true", got)
	}
}

// TestRunTelnetBanner_NoPort confirms the zero-cost gate: without 23/tcp
// (or an alt) in the scan set the runner does nothing.
func TestRunTelnetBanner_NoPort(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.1", Timeout: 200 * time.Millisecond}
	if got := runTelnetBanner(context.Background(), tgt); got != nil {
		t.Errorf("expected no finding without telnet port in scan set, got %+v", got)
	}
}

// TestRunTelnetBanner_DisableLogins confirms the safety switch: the check
// honours the "no active writes" master toggle because the wake-up "\r\n"
// counts as a probe write.
func TestRunTelnetBanner_DisableLogins(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.1", Timeout: 200 * time.Millisecond, DisableLogins: true}
	tgt.MarkOpen(23, "tcp", "")
	if got := runTelnetBanner(context.Background(), tgt); got != nil {
		t.Errorf("expected no finding with DisableLogins, got %+v", got)
	}
}
