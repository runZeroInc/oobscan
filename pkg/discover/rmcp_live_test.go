package discover

import (
	"context"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

// TestRMCPVectorLive exercises the RMCP vector against a fake BMC on this host:
// a UDP listener that answers any datagram with an RMCP-framed reply. It proves
// the multicast send and the reply matching, which the ICMP vector cannot cover.
// Opt-in, since it depends on the kernel delivering link-local multicast to a
// wildcard-bound socket on a real interface:
//
//	OOBSCAN_LIVE_LINKLOCAL=en0 go test ./pkg/discover -run RMCPVectorLive -v
func TestRMCPVectorLive(t *testing.T) {
	zone := os.Getenv("OOBSCAN_LIVE_LINKLOCAL")
	if zone == "" {
		t.Skip("set OOBSCAN_LIVE_LINKLOCAL=<interface> to run the live RMCP sweep")
	}
	// A high port: 623 needs root to bind, and the sweep takes the port from
	// Options anyway.
	const port = 16230
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: port})
	if err != nil {
		t.Skipf("cannot bind the fake BMC port: %v", err)
	}
	defer conn.Close()

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		buf := make([]byte, 1500)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, peer, rerr := conn.ReadFromUDP(buf)
			if rerr != nil || n < 4 {
				continue
			}
			// RMCP ASF pong: version 0x06, reserved, seq, ASF class.
			_, _ = conn.WriteToUDP([]byte{0x06, 0x00, 0xff, 0x06, 0x00, 0x00, 0x11, 0xbe, 0x40, buf[9], 0x00, 0x00}, peer)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	found, err := LinkLocal(ctx, AllNodes+"%"+zone, Options{
		Wait:     2 * time.Second,
		IPMIPort: port,
		SkipICMP: true,
		Log:      func(s string) { t.Log(s) },
	})
	if err != nil {
		t.Fatalf("LinkLocal: %v", err)
	}
	for _, r := range found {
		t.Logf("%s via rmcp", r.Host())
	}
	if len(found) == 0 {
		// Observed on darwin: a BSD-derived stack only delivers a multicast
		// datagram to a socket that joined the group, so a local listener bound to
		// the wildcard address never sees the probe. That is a property of the
		// listener's OS, not of the sweep, and it is exactly why the RMCP vector
		// supplements the ICMPv6 one instead of replacing it.
		if runtime.GOOS != "linux" {
			t.Skipf("no reply on %s: this platform requires a UDP socket to join the group to receive multicast", runtime.GOOS)
		}
		t.Fatal("the fake BMC did not answer the multicast RMCP probe")
	}
}
