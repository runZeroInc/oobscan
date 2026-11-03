package ssh

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// lengthPolicy decides, per connection, whether a mock SSH server accepts a
// declared packet length (then blocks awaiting the body, sending nothing) or
// rejects it (closes the connection). It models the iLO4 SSH length check.
type lengthPolicy func(length uint32) (accept bool)

// vulnerablePolicy: accepts lengths <= 0x800 (legal) and lengths in the
// signed-overflow window 0x7FFFFFFC..0x7FFFFFFF (the bug), rejects anything
// else (e.g. 0x00000FFF, which is > 0x800 but does not wrap).
func vulnerablePolicy(length uint32) bool {
	if length <= 0x800 {
		return true
	}
	return length >= 0x7FFFFFFC
}

// patchedPolicy: accepts only lengths <= 0x800 (unsigned bound), rejects
// everything larger including the signed-overflow window.
func patchedPolicy(length uint32) bool { return length <= 0x800 }

// tarpitPolicy: holds every connection open regardless of length.
func tarpitPolicy(uint32) bool { return true }

// startMockILO starts a mock iLO4-style SSH server that handles `conns`
// sequential connections using policy, and returns its address. Each
// connection: send banner, read the client banner line, send a framed KEXINIT
// packet, read the 4-byte client length, then accept (block until the client
// closes, sending nothing) or reject (close immediately) per policy.
func startMockILO(t *testing.T, conns int, policy lengthPolicy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for range conns {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMockConn(c, policy)
		}
	}()
	return ln.Addr().String()
}

func handleMockConn(c net.Conn, policy lengthPolicy) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	if _, err := c.Write([]byte("SSH-2.0-mpSSH_0.2.1\r\n")); err != nil {
		return
	}
	if _, err := br.ReadString('\n'); err != nil { // client banner
		return
	}
	// Framed KEXINIT: uint32 len | body (contents irrelevant to the probe).
	var kx [4]byte
	binary.BigEndian.PutUint32(kx[:], 16)
	if _, err := c.Write(kx[:]); err != nil {
		return
	}
	if _, err := c.Write(make([]byte, 16)); err != nil {
		return
	}
	// Read the client's 4-byte packet length.
	var lb [4]byte
	if _, err := io.ReadFull(br, lb[:]); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(lb[:])
	if policy(length) {
		// Accept: consume whatever body arrives and block, sending nothing,
		// until the client closes the connection.
		_, _ = io.Copy(io.Discard, br)
		return
	}
	// Reject: close immediately.
}

func TestProbeSSHOverflow_Vulnerable(t *testing.T) {
	addr := startMockILO(t, 3, vulnerablePolicy)
	host, port := splitHostPort(t, addr)
	p := ProbeSSHOverflow(host, port, 200*time.Millisecond)
	if p.Result != SSHVulnerable {
		t.Fatalf("got %v (%s), want vulnerable; A=%v B=%v C=%v",
			p.Result, p.Detail, p.WindowHeld, p.LegalHeld, p.OverHeld)
	}
	if !strings.Contains(p.Banner, "mpSSH") {
		t.Errorf("banner not captured: %q", p.Banner)
	}
}

func TestProbeSSHOverflow_Patched(t *testing.T) {
	addr := startMockILO(t, 3, patchedPolicy)
	host, port := splitHostPort(t, addr)
	p := ProbeSSHOverflow(host, port, 200*time.Millisecond)
	if p.Result != SSHNotVulnerable {
		t.Fatalf("got %v (%s), want not-vulnerable", p.Result, p.Detail)
	}
}

func TestProbeSSHOverflow_Tarpit(t *testing.T) {
	addr := startMockILO(t, 3, tarpitPolicy)
	host, port := splitHostPort(t, addr)
	p := ProbeSSHOverflow(host, port, 200*time.Millisecond)
	if p.Result != SSHInconclusive {
		t.Fatalf("got %v (%s), want inconclusive", p.Result, p.Detail)
	}
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	var port int
	for _, r := range portStr {
		port = port*10 + int(r-'0')
	}
	return host, port
}
