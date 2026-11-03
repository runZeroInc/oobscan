package snmp

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// fakeAgent is a UDP listener that answers SNMP GETs the way a real agent does,
// including the two behaviours that used to cost us the community: a v1
// whole-PDU error when one requested object is missing, and a system group with
// no sysDescr in it.
type fakeAgent struct {
	t *testing.T
	// values served; an OID absent from the map is treated as unimplemented
	values map[string]string
	// wholePDUError makes a multi-OID GET that touches a missing object fail
	// entirely, which is what SNMPv1 specifies
	wholePDUError bool
	// dropFirst ignores the first N datagrams, to exercise the retransmit
	dropFirst int

	conn  *net.UDPConn
	port  int
	seen  int
	multi int // multi-OID GETs received
	singl int // single-OID GETs received
}

func newFakeAgent(t *testing.T, a *fakeAgent) *fakeAgent {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	a.t, a.conn = t, c
	a.port = c.LocalAddr().(*net.UDPAddr).Port
	go a.serve()
	t.Cleanup(func() { _ = c.Close() })
	return a
}

func (a *fakeAgent) serve() {
	buf := make([]byte, 4096)
	for {
		n, peer, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		a.seen++
		if a.seen <= a.dropFirst {
			continue
		}
		g := &gosnmp.GoSNMP{}
		req, err := g.SnmpDecodePacket(buf[:n])
		if err != nil {
			continue
		}
		if len(req.Variables) > 1 {
			a.multi++
		} else {
			a.singl++
		}

		resp := &gosnmp.SnmpPacket{
			Version:    req.Version,
			Community:  req.Community,
			PDUType:    gosnmp.GetResponse,
			RequestID:  req.RequestID,
			Error:      gosnmp.NoError,
			ErrorIndex: 0,
		}
		missing := 0
		for i, v := range req.Variables {
			name := v.Name
			if len(name) > 0 && name[0] == '.' {
				name = name[1:]
			}
			val, ok := a.values[name]
			if !ok {
				missing = i + 1
				resp.Variables = append(resp.Variables, gosnmp.SnmpPDU{
					Name: v.Name, Type: gosnmp.Null, Value: nil,
				})
				continue
			}
			resp.Variables = append(resp.Variables, gosnmp.SnmpPDU{
				Name: v.Name, Type: gosnmp.OctetString, Value: []byte(val),
			})
		}
		if missing > 0 && a.wholePDUError && len(req.Variables) > 1 {
			resp.Error = gosnmp.NoSuchName
			resp.ErrorIndex = uint8(missing)
		}
		out, err := resp.MarshalMsg()
		if err != nil {
			continue
		}
		_, _ = a.conn.WriteToUDP(out, peer)
	}
}

func (a *fakeAgent) probe(t *testing.T, version int) (*Result, error) {
	t.Helper()
	return Probe("127.0.0.1", a.port, "public", version, 900*time.Millisecond)
}

// A v1 agent that does not implement sysLocation fails the whole four-OID GET.
// Before the per-OID fallback that discarded sysDescr and sysObjectID too, and
// the caller then treated the working community as no community at all.
func TestProbeFallsBackWhenV1FailsTheWholePDU(t *testing.T) {
	a := newFakeAgent(t, &fakeAgent{
		wholePDUError: true,
		values: map[string]string{
			oidSysDescr:    "Integrated Dell Remote Access Controller",
			oidSysObjectID: "1.3.6.1.4.1.674.10892.5",
			oidSysName:     "idrac-ABC1234",
			// sysLocation deliberately absent
		},
	})
	r, err := a.probe(t, 0) // v1
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !r.Responded {
		t.Fatal("Responded is false, so the caller would discard a community that works")
	}
	if r.SysDescr == "" {
		t.Errorf("SysDescr empty; the per-OID fallback did not recover it")
	}
	if r.SysName != "idrac-ABC1234" {
		t.Errorf("SysName = %q, want the value the agent serves", r.SysName)
	}
	if a.multi == 0 || a.singl == 0 {
		t.Errorf("expected a multi-OID GET then per-OID retries, got multi=%d single=%d",
			a.multi, a.singl)
	}
}

// An agent may answer the community while restricting sysDescr. The community is
// still accepted, which is the only thing the caller needs to decide.
func TestProbeRespondedWithoutSysDescr(t *testing.T) {
	a := newFakeAgent(t, &fakeAgent{
		values: map[string]string{
			oidSysObjectID: "1.3.6.1.4.1.674.10892.5",
			oidSysName:     "idrac-XYZ7788",
		},
	})
	r, err := a.probe(t, 1) // v2c
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !r.Responded {
		t.Fatal("Responded is false even though the agent answered")
	}
	if r.SysDescr != "" {
		t.Errorf("SysDescr = %q, want empty", r.SysDescr)
	}
	if r.VendorGuess != "dell" {
		t.Errorf("VendorGuess = %q, want dell from sysObjectID alone", r.VendorGuess)
	}
}

// One dropped datagram is indistinguishable from a refused community, so the
// probe has to retransmit or packet loss reads as a clean host.
func TestProbeRetransmitsAfterALostDatagram(t *testing.T) {
	a := newFakeAgent(t, &fakeAgent{
		dropFirst: 1,
		values:    map[string]string{oidSysDescr: "ILOM"},
	})
	r, err := a.probe(t, 1)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !r.Responded || r.SysDescr != "ILOM" {
		t.Fatalf("lost datagram was not retried: responded=%v sysDescr=%q",
			r.Responded, r.SysDescr)
	}
}

// A host that answers nothing must stay a miss, so the relaxed gate cannot turn
// silence into a default-community finding.
func TestProbeSilentHostDoesNotRespond(t *testing.T) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer c.Close()
	port := c.LocalAddr().(*net.UDPAddr).Port
	if _, err := Probe("127.0.0.1", port, "public", 1, 200*time.Millisecond); err == nil {
		t.Fatal("probe of a silent host returned no error; a refused community would be reported as a hit")
	}
	_ = strconv.Itoa(port)
}
