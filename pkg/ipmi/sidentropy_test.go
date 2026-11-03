package ipmi

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeSIDBMC is a minimal UDP BMC that answers RMCP+ Open Session Requests with
// a managed session ID drawn from a caller-supplied sequence, and counts the
// Close Session packets (payload type 0x00) it receives back. It exists to prove
// SampleSessionIDs both collects the managed SIDs and closes every session it
// opens.
type fakeSIDBMC struct {
	conn   *net.UDPConn
	sids   []uint32
	mu     sync.Mutex
	opened int
	closed int
	done   chan struct{}
}

func newFakeSIDBMC(t *testing.T, sids []uint32) *fakeSIDBMC {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b := &fakeSIDBMC{conn: conn, sids: sids, done: make(chan struct{})}
	go b.serve()
	return b
}

func (b *fakeSIDBMC) port() int { return b.conn.LocalAddr().(*net.UDPAddr).Port }

func (b *fakeSIDBMC) close() { close(b.done); b.conn.Close() }

func (b *fakeSIDBMC) counts() (opened, closed int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.opened, b.closed
}

func (b *fakeSIDBMC) serve() {
	buf := make([]byte, 2048)
	for {
		select {
		case <-b.done:
			return
		default:
		}
		_ = b.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, addr, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-b.done:
				return
			default:
				continue
			}
		}
		if n < 6 {
			continue
		}
		switch buf[5] { // RMCP+ payload type
		case PayloadOpenSessionReq:
			b.mu.Lock()
			sid := b.sids[b.opened%len(b.sids)]
			b.opened++
			b.mu.Unlock()
			_, _ = b.conn.WriteToUDP(b.openSessionResp(sid), addr)
		case PayloadIPMI:
			b.mu.Lock()
			b.closed++
			b.mu.Unlock()
		}
	}
}

// openSessionResp frames a minimal Open Session Response: status 0, our managed
// SID at payload[8:12], which is exactly what parseOpenSessionResp reads.
func (b *fakeSIDBMC) openSessionResp(managedSID uint32) []byte {
	payload := make([]byte, 12)
	// [0] tag, [1] status=0, [2] maxPriv, [3] rsvd, [4:8] console SID echo, [8:12] managed SID
	binary.LittleEndian.PutUint32(payload[4:8], 0xdeadbeef)
	binary.LittleEndian.PutUint32(payload[8:12], managedSID)
	var pkt bytes.Buffer
	pkt.Write([]byte{RMCPVersion, RMCPReserved, RMCPSeqNoAck, RMCPClassIPMI})
	pkt.WriteByte(IPMI20Format)
	pkt.WriteByte(PayloadOpenSessionRes)
	pkt.Write([]byte{0, 0, 0, 0}) // session id
	pkt.Write([]byte{0, 0, 0, 0}) // session seq
	pkt.Write(binary.LittleEndian.AppendUint16(nil, uint16(len(payload))))
	pkt.Write(payload)
	return pkt.Bytes()
}

// TestSampleSessionIDsCollectsAndCloses proves the sampler reads the managed SID
// out of each Open Session Response and sends a Close Session for each session it
// opens, so it does not leave a session slot occupied.
func TestSampleSessionIDsCollectsAndCloses(t *testing.T) {
	want := []uint32{0x1c1780, 0x1c1790, 0x1c17a0, 0x1c17b0, 0x1c17c0}
	bmc := newFakeSIDBMC(t, want)
	defer bmc.close()

	got := SampleSessionIDs("127.0.0.1", bmc.port(), len(want), 2*time.Second)
	if len(got) != len(want) {
		t.Fatalf("collected %d SIDs, want %d (%x)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sid[%d] = 0x%x, want 0x%x", i, got[i], want[i])
		}
	}
	// Give the fire-and-forget closes a moment to land, then assert one close per open.
	time.Sleep(150 * time.Millisecond)
	opened, closed := bmc.counts()
	if opened != len(want) {
		t.Errorf("BMC saw %d opens, want %d", opened, len(want))
	}
	if closed != opened {
		t.Errorf("BMC saw %d closes for %d opens; every opened session must be closed", closed, opened)
	}

	// And the collected SIDs classify as the small-space weakness.
	if cls, weak := ClassifySessionIDs(got); !weak || cls.Pattern == "" {
		t.Errorf("sampled small-space SIDs did not classify as weak: %+v", cls)
	}
}

// TestClassifySessionIDs covers the shared managed-SID classifier used by the
// live check, the runZero projection, and the report.
func TestClassifySessionIDs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sids    []uint32
		weak    bool
		pattern string
		check   string
	}{
		{name: "too few", sids: []uint32{0x10, 0x20}, weak: false},
		{name: "static", sids: []uint32{0x7, 0x7, 0x7, 0x7}, weak: true, pattern: "static", check: "ipmi.sidEntropy"},
		{name: "fixedStep", sids: []uint32{0x100, 0x110, 0x120, 0x130}, weak: true, pattern: "fixedStep", check: "ipmi.sidPredictable"},
		// Real Supermicro/ATEN capture: top bytes fixed, low byte jitters -> small
		// window, no constant step. The pattern a fixed-step-only test misses.
		{name: "smallSpace", sids: []uint32{0x1c1873, 0x1c17b3, 0x1c17d3, 0x1c1853, 0x1c1783}, weak: true, pattern: "smallSpace", check: "ipmi.sidPredictable"},
		// Well-distributed 32-bit SIDs (a good RNG) must not be flagged.
		{name: "welldistributed", sids: []uint32{0x242d56c6, 0x0a44d43a, 0x90345216, 0x961bc815, 0x26828b32}, weak: false},
		// Even three samples in a tight window are decisive for a uniform 32-bit SID.
		{name: "smallSpace 3 samples", sids: []uint32{0x100, 0x140, 0x120}, weak: true, pattern: "smallSpace", check: "ipmi.sidPredictable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cls, weak := ClassifySessionIDs(tc.sids)
			if weak != tc.weak {
				t.Fatalf("weak = %t, want %t (cls %+v)", weak, tc.weak, cls)
			}
			if !weak {
				return
			}
			if cls.Pattern != tc.pattern {
				t.Errorf("pattern = %q, want %q", cls.Pattern, tc.pattern)
			}
			if cls.CheckID() != tc.check {
				t.Errorf("checkID = %q, want %q", cls.CheckID(), tc.check)
			}
		})
	}
}
