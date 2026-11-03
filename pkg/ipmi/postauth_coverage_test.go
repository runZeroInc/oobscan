package ipmi

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"slices"
	"testing"
	"time"
)

// coverageBMC completes an RMCP+ handshake and then answers in-session commands
// from a table. It exists so the coverage bookkeeping can be exercised against the
// real collector rather than a hand-built collection.
type coverageBMC struct {
	conn *net.UDPConn
	// reply returns the completion code and data for one command. A nil result
	// means "no reply", which the client sees as a timeout.
	reply func(netfn, cmd byte, data []byte) (byte, []byte, bool)
	done  chan struct{}
}

func newCoverageBMC(t *testing.T, reply func(netfn, cmd byte, data []byte) (byte, []byte, bool)) *coverageBMC {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	b := &coverageBMC{conn: conn, reply: reply, done: make(chan struct{})}
	go b.serve()
	t.Cleanup(func() {
		_ = conn.Close()
		<-b.done
	})
	return b
}

func (b *coverageBMC) port() int { return b.conn.LocalAddr().(*net.UDPAddr).Port }

func (b *coverageBMC) serve() {
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
			_, _ = b.conn.WriteToUDP(b.frame(PayloadOpenSessionRes, b.openSessionBody(payload)), addr)
		case PayloadRAKP1:
			_, _ = b.conn.WriteToUDP(b.frame(PayloadRAKP2, b.rakp2Body(payload)), addr)
		case PayloadRAKP3:
			_, _ = b.conn.WriteToUDP(b.frame(PayloadRAKP4, b.rakp4Body(payload)), addr)
		case PayloadIPMI:
			if pkt[5]&0xc0 != 0 {
				continue // this responder only speaks the cleartext command path
			}
			if out, ok := b.commandReply(payload); ok {
				_, _ = b.conn.WriteToUDP(b.frame(PayloadIPMI, out), addr)
			}
		}
	}
}

func (b *coverageBMC) frame(ptype byte, payload []byte) []byte {
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

func (b *coverageBMC) openSessionBody(req []byte) []byte {
	p := []byte{0x00, 0x00, 0x04, 0x00}
	p = append(p, req[4:8]...)
	return binary.LittleEndian.AppendUint32(p, 0x0a0b0c0d)
}

func (b *coverageBMC) rakp2Body(req []byte) []byte {
	p := []byte{0x00, 0x00, 0x00, 0x00}
	p = append(p, req[4:8]...)
	p = append(p, bytes.Repeat([]byte{0xb1}, 16)...) // bmcRand
	p = append(p, bytes.Repeat([]byte{0xc2}, 16)...) // guid
	return append(p, bytes.Repeat([]byte{0xd3}, 20)...)
}

func (b *coverageBMC) rakp4Body(req []byte) []byte {
	p := []byte{0x00, 0x00, 0x00, 0x00}
	p = append(p, req[4:8]...)
	return append(p, bytes.Repeat([]byte{0x00}, 16)...)
}

// commandReply decodes the session LAN message and builds the IPMB-shaped response
// the client parses back out.
func (b *coverageBMC) commandReply(req []byte) ([]byte, bool) {
	if len(req) < 7 {
		return nil, false
	}
	netfn, rqSeq, cmd := req[1]>>2, req[4], req[5]
	body := req[6 : len(req)-1]
	cc, data, ok := b.reply(netfn, cmd, body)
	if !ok {
		return nil, false
	}
	out := []byte{0x81, (netfn | 0x01) << 2, 0x00, 0x20, rqSeq, cmd, cc}
	out = append(out, data...)
	return append(out, 0x00), true // trailing IPMB checksum, unchecked
}

// answeringBMCReply is a board that answers everything the collector asks except
// FRU: device 0 reports an inventory area of zero bytes, so the walk parses no
// fields. That is a real shape -- a board with no populated FRU EEPROM.
func answeringBMCReply(netfn, cmd byte, data []byte) (byte, []byte, bool) {
	switch {
	case netfn == NetFnApp && cmd == CmdSetSessionPrivilege:
		return 0x00, []byte{0x04}, true
	case netfn == NetFnApp && cmd == CmdGetDeviceID:
		// device id, rev, fw major/minor, ipmi 2.0, support, mfr 47488, product.
		return 0x00, []byte{0x20, 0x01, 0x03, 0x59, 0x02, 0xbf, 0x80, 0xb9, 0x00, 0x20, 0x0b, 0x00, 0x00, 0x00, 0x00}, true
	case netfn == NetFnChassis && cmd == CmdGetChassisStatus:
		return 0x00, []byte{0x01, 0x00, 0x40}, true
	case netfn == NetFnApp && cmd == CmdGetChannelInfo:
		if len(data) > 0 && data[0]&0x0f == 0x01 {
			return 0x00, []byte{0x01, 0x04}, true
		}
		return 0x00, []byte{0x0e, 0x0c}, true
	case netfn == NetFnApp && cmd == CmdGetUserAccess:
		if len(data) < 2 {
			return 0xc7, nil, true
		}
		if data[1] == 0x01 {
			// The bootstrap read and slot 1 share a selector; one enabled user is
			// enough for the users section to carry data.
			return 0x00, []byte{0x01, 0x01, 0x14, 0x04}, true
		}
		return 0xcc, nil, true
	case netfn == NetFnApp && cmd == CmdGetUserName:
		return 0x00, append([]byte("ADMIN"), bytes.Repeat([]byte{0x00}, 11)...), true
	case netfn == NetFnTransport && cmd == CmdGetLANConfigParams:
		if len(data) < 2 {
			return 0xc7, nil, true
		}
		if data[1] == 3 { // ip address
			return 0x00, []byte{0x11, 192, 0, 2, 10}, true
		}
		return 0xcc, nil, true // every other parameter, IPv6 included, unsupported
	case netfn == NetFnStorage && cmd == CmdGetFRUInventoryInfo:
		return 0x00, []byte{0x00, 0x00, 0x00}, true // zero-length inventory area
	}
	return 0xcc, nil, true
}

func collectAgainst(t *testing.T, port int) *PostAuthCollection {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	flow := AuthFlow{Version: "2.0", Mode: "cred", Username: "ADMIN", Password: "ADMIN",
		Suite: CipherAlgos{Suite: 3, Auth: RAKPHMACSHA1, Integrity: IntegrityHMACSHA196, Conf: ConfAESCBC}}
	inv, err := CollectPostAuthInventory(ctx, "127.0.0.1", port, flow, 100*time.Millisecond)
	if inv == nil {
		t.Fatalf("no collection returned: %v", err)
	}
	return inv
}

// A section that was read and produced nothing must not be recorded as completed.
// Every section field is omitempty, so a completed-but-absent section serializes
// identically to a full one: the consumer is told the FRU was measured and the board
// had none, when what happened is that no field parsed.
func TestCollectPostAuthInventorySeparatesEmptySectionsFromCompleted(t *testing.T) {
	bmc := newCoverageBMC(t, answeringBMCReply)
	inv := collectAgainst(t, bmc.port())

	if len(inv.FRU) != 0 {
		t.Fatalf("responder was supposed to yield no FRU fields, got %d", len(inv.FRU))
	}
	if slices.Contains(inv.Completed, "fru") {
		t.Errorf("completed=%v claims the fru section, but no field was parsed and the serialized "+
			"record carries no fru key -- the consumer cannot tell this from a full read", inv.Completed)
	}
	if !slices.Contains(inv.Empty, "fru") {
		t.Errorf("empty=%v does not name fru; an attempted section that answered with nothing has to be "+
			"recorded somewhere or it is indistinguishable from one never read", inv.Empty)
	}
	// lan6 is the same lie at larger scale: the IPv6 parameters are refused and the
	// section was being appended alongside lan regardless.
	if slices.Contains(inv.Completed, "lan6") {
		t.Errorf("completed=%v claims lan6 with no IPv6 parameter collected", inv.Completed)
	}
	// The sections that did produce data still have to be recorded as completed.
	for _, want := range []string{"mcInfo", "chassis", "users", "lan"} {
		if !slices.Contains(inv.Completed, want) {
			t.Errorf("completed=%v is missing %q, which did return data", inv.Completed, want)
		}
	}

	raw, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := got["fru"]; ok {
		t.Fatal("the fixture is wrong: a serialized fru key would make the coverage claim moot")
	}
	if _, ok := got["empty"]; !ok {
		t.Errorf("serialized record has no empty key, so a downstream coverage audit still sees a "+
			"missing fru section with nothing said about it: %s", raw)
	}
}
