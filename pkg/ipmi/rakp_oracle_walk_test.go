package ipmi

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// oracleBMC answers a RAKP-2 with a hash for every username asked, which is the
// accepts-any-username behaviour, and records the names it was asked for.
type oracleBMC struct {
	conn *net.UDPConn
	mu   sync.Mutex
	seen []string
	done chan struct{}
}

func newOracleBMC(t *testing.T) *oracleBMC {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	b := &oracleBMC{conn: conn, done: make(chan struct{})}
	go b.serve()
	t.Cleanup(func() { _ = conn.Close(); <-b.done })
	return b
}

func (b *oracleBMC) port() int { return b.conn.LocalAddr().(*net.UDPAddr).Port }

func (b *oracleBMC) usernames() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.seen...)
}

func (b *oracleBMC) serve() {
	defer close(b.done)
	buf := make([]byte, 2048)
	for {
		n, addr, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 16 {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		payload := pkt[16:]
		switch pkt[5] & 0x3f {
		case PayloadOpenSessionReq:
			p := []byte{0x00, 0x00, 0x04, 0x00}
			p = append(p, payload[4:8]...)
			p = binary.LittleEndian.AppendUint32(p, 0x5a5b5c5d)
			_, _ = b.conn.WriteToUDP(b.frame(PayloadOpenSessionRes, p), addr)
		case PayloadRAKP1:
			// RAKP1: tag(1) rsvd(3) bmcSID(4) consoleRand(16) role(1) rsvd(2) ulen(1) name
			if len(payload) >= 28 {
				ulen := int(payload[27])
				if 28+ulen <= len(payload) {
					b.mu.Lock()
					b.seen = append(b.seen, string(payload[28:28+ulen]))
					b.mu.Unlock()
				}
			}
			p := []byte{0x00, 0x00, 0x00, 0x00}
			p = append(p, payload[4:8]...)
			p = append(p, bytes.Repeat([]byte{0xb1}, 16)...) // bmcRand
			p = append(p, bytes.Repeat([]byte{0xc2}, 16)...) // guid
			p = append(p, bytes.Repeat([]byte{0xd3}, 20)...) // a hash for any name
			_, _ = b.conn.WriteToUDP(b.frame(PayloadRAKP2, p), addr)
		}
	}
}

func (b *oracleBMC) frame(ptype byte, payload []byte) []byte {
	var out bytes.Buffer
	out.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	out.WriteByte(IPMI20Format)
	out.WriteByte(ptype)
	out.Write([]byte{0, 0, 0, 0})
	out.Write([]byte{0, 0, 0, 0})
	out.Write(binary.LittleEndian.AppendUint16(nil, uint16(len(payload))))
	out.Write(payload)
	return out.Bytes()
}

// A BMC that hands out a RAKP-2 for any name yields duplicate hashes, so the walk is
// bounded -- but stopping on the first one throws away the account names, which are
// what post-auth and the operator use. The walk must take a sample: more than one,
// far fewer than the whole list.
func TestOracleBMCYieldsBoundedUsernameSample(t *testing.T) {
	bmc := newOracleBMC(t)
	rep, err := RunAuth(context.Background(), "127.0.0.1", bmc.port(), AuthOptions{
		Timeout:      400 * time.Millisecond,
		OfflineCrack: false,
		Online:       false,
	})
	if err != nil {
		t.Fatalf("RunAuth: %v", err)
	}
	if !rep.FakeUsername {
		t.Fatal("responder answered every username but was not detected as an oracle")
	}

	got := len(rep.Results)
	if got <= 1 {
		t.Errorf("collected %d username result(s) from an oracle BMC; stopping at the first "+
			"discards the account inventory that post-auth needs", got)
	}
	if got > maxOracleUsernames {
		t.Errorf("collected %d username results, want at most %d: an oracle's extra hashes are "+
			"duplicate disclosures for accounts that need not exist", got, maxOracleUsernames)
	}

	// The names sampled must be real candidates, not the fabricated probe name.
	for _, u := range rep.Results {
		if u.Username == rep.FakeUsernameProbe {
			t.Errorf("the fabricated oracle probe name %q was recorded as a result", u.Username)
		}
	}
}
