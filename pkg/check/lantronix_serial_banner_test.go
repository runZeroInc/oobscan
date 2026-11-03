package check

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/lantronix"
)

// TestRunLantronixSetupBanner_VendorGate confirms the check only reports a
// Lantronix setup exposure when the TCP/9999 banner carries a Lantronix
// signature; a generic responder (proxy / HTTP / SSH) on 9999 must not be
// flagged.
func TestRunLantronixSetupBanner_VendorGate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(lantronix.SetupTelnetPort))
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:%d: %v", lantronix.SetupTelnetPort, err)
	}
	defer ln.Close()

	replyCh := make(chan string, 1)
	go func() {
		for {
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				select {
				case r := <-replyCh:
					_, _ = c.Write([]byte(r))
				case <-time.After(time.Second):
				}
				time.Sleep(30 * time.Millisecond)
			}(conn)
		}
	}()

	run := func(reply string) []engine.Finding {
		replyCh <- reply
		return runLantronixSetupBanner(context.Background(), &engine.Target{
			Host:    "127.0.0.1",
			Timeout: 2 * time.Second,
		})
	}

	// Non-Lantronix responder -> no finding.
	if got := run("ProxyServer is ready\r\n"); hasFinding(got, "tcp.lantronix.setupBanner") != nil {
		t.Errorf("generic proxy banner on 9999 must not flag Lantronix, got %+v", got)
	}
	// Real Lantronix XPort setup banner -> finding.
	if got := run("*** Lantronix XPort Device Server ***\r\nPress Enter for Setup Mode\r\n"); hasFinding(got, "tcp.lantronix.setupBanner") == nil {
		t.Error("a genuine Lantronix XPort setup banner should still be reported")
	}
}

// TestRunLantronixSetupBanner_RejectsSSHEvidence guards a field false
// positive: a dropbear/OpenSSH banner captured on 9999/tcp and carried in as
// `lantronix.telnet` evidence (the identify-time path, which skips the
// looksLantronix gate) must not be reported as a setup banner.
func TestRunLantronixSetupBanner_RejectsSSHEvidence(t *testing.T) {
	for _, banner := range []string{
		"SSH-2.0-dropbear_2016.74\r\n",
		"SSH-2.0-OpenSSH_8.6\r\n",
	} {
		tgt := &engine.Target{Host: "192.0.2.1", Timeout: time.Second}
		tgt.SetEvidence("lantronix.telnet", banner)
		if got := runLantronixSetupBanner(context.Background(), tgt); hasFinding(got, "tcp.lantronix.setupBanner") != nil {
			t.Errorf("SSH banner %q from evidence must not be reported as a Lantronix setup banner, got %+v", banner, got)
		}
	}
}
