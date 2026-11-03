package check

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"net"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// udpBlackhole reserves a loopback UDP port without replying, so timeout-path
// tests never send IPMI traffic beyond the local host.
func udpBlackhole(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// The default patch-status handshake runs on any IPMI 2.0 host (the daemon is
// white-labeled, but it must still return fast and emit nothing against a host
// that does not negotiate a RAKP cipher suite. A local no-reply socket has no
// cipher suite, so the check must short-circuit before the bounded handshake.
func TestOpenBMCDefaultUserKey_DefaultProbeSkipsNoCipherSuite(t *testing.T) {
	port := udpBlackhole(t)
	tgt := &engine.Target{
		Host:     "127.0.0.1",
		Timeout:  50 * time.Millisecond,
		Identity: &engine.Identity{Class: engine.ClassBMC},
		Ports:    []engine.Port{{Num: port, Proto: engine.ProtoUDP}},
		// OpenBMCDefaultUserKey left unset (default bounded probe path).
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if got := runOpenBMCDefaultUserKeyBypass(context.Background(), tgt); got != nil {
			t.Errorf("defaultUserKeyAuthBypass must be nil for a host with no RAKP cipher suite, got %+v", got)
		}
	}()

	// The bounded probe retries a transport failure once, so allow a little over
	// two probe timeouts plus scheduling slack.
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cipher-suite gate did not short-circuit against the local no-reply socket")
	}
}

// OpenBMC and the vendor stacks derived from it (iDRAC10, newer Intel/ASUS,
// H3C, BlueField) ignore the sessionless 1.5 cipher-suite enumeration, so the
// check must not depend on it: on any confirmed IPMI responder it falls back to
// the suites phosphor-net-ipmid always supports and still probes. This gate is
// what keeps the fallback from firing an Open Session against every non-IPMI
// host, so it must recognize an IPMI responder from either an open port tag or
// recorded IPMI evidence, and reject a bare target.
func TestHostSpeaksIPMIGate(t *testing.T) {
	if hostSpeaksIPMI(&engine.Target{Host: "192.0.2.1"}) {
		t.Fatal("bare target with no IPMI port or evidence must not be treated as IPMI")
	}

	byPort := &engine.Target{Host: "192.0.2.1"}
	byPort.MarkOpen(623, "udp", "ipmi")
	if !hostSpeaksIPMI(byPort) {
		t.Fatal("target with an open udp/623 ipmi port must be treated as IPMI")
	}

	for _, key := range []string{"ipmi.authCaps", "ipmi.deviceId", "ipmi.dcmi", "ipmi.ciphers", "guid"} {
		byEvidence := &engine.Target{Host: "192.0.2.1"}
		byEvidence.SetEvidence(key, "present")
		if !hostSpeaksIPMI(byEvidence) {
			t.Fatalf("target with %q evidence must be treated as IPMI", key)
		}
	}
}

// The default-suite fallback must cover the suites phosphor-net-ipmid always
// supports, SHA256 first (the modern default) then SHA1.
func TestDefaultProbeCipherSuites(t *testing.T) {
	suites := defaultProbeCipherSuites()
	if len(suites) != 2 {
		t.Fatalf("want 2 default suites, got %d", len(suites))
	}
	if suites[0].Suite != 17 || suites[0].Auth != ipmi.RAKPHMACSHA256 {
		t.Fatalf("first default suite must be 17/HMAC-SHA256, got %+v", suites[0])
	}
	if suites[1].Suite != 3 || suites[1].Auth != ipmi.RAKPHMACSHA1 {
		t.Fatalf("second default suite must be 3/HMAC-SHA1, got %+v", suites[1])
	}
}

// The forged RAKP3 HMAC must use the hash of the negotiated auth algorithm, or a
// suite-3 (SHA1) negotiation would be verified with the wrong hash and a genuine
// bypass missed.
func TestRAKPHashForAlgoMatchesNegotiatedSuite(t *testing.T) {
	key := []byte("0penBmc")
	msg := []byte("rakp3")
	cases := []struct {
		algo byte
		want func() []byte
	}{
		{ipmi.RAKPHMACSHA1, func() []byte { m := hmac.New(sha1.New, key); m.Write(msg); return m.Sum(nil) }},
		{ipmi.RAKPHMACMD5, func() []byte { m := hmac.New(md5.New, key); m.Write(msg); return m.Sum(nil) }},
		{ipmi.RAKPHMACSHA256, func() []byte { m := hmac.New(sha256.New, key); m.Write(msg); return m.Sum(nil) }},
		{0xff, func() []byte { m := hmac.New(sha256.New, key); m.Write(msg); return m.Sum(nil) }}, // unknown -> SHA256
	}
	for _, c := range cases {
		m := hmac.New(rakpHashForAlgo(c.algo), key)
		m.Write(msg)
		if got := m.Sum(nil); !bytes.Equal(got, c.want()) {
			t.Fatalf("algo 0x%02x: HMAC hash mismatch", c.algo)
		}
	}
}

// A confirmed IPMI host whose cipher enumeration is empty must now ATTEMPT the
// default-suite fallback (rather than short-circuiting like a non-IPMI host) and
// still terminate quickly against a no-reply target -- the capped per-suite
// timeout must bound the fallback so it cannot hang the scan.
func TestOpenBMCDefaultUserKey_FallbackFiresOnConfirmedIPMIHost(t *testing.T) {
	port := udpBlackhole(t)
	tgt := &engine.Target{
		Host:     "127.0.0.1",
		Timeout:  50 * time.Millisecond,
		Identity: &engine.Identity{Class: engine.ClassBMC},
		Ports:    []engine.Port{{Num: port, Proto: engine.ProtoUDP}},
	}
	tgt.MarkOpen(port, "udp", "ipmi") // confirmed IPMI responder, but no cipher evidence

	done := make(chan struct{})
	go func() {
		defer close(done)
		if got := runOpenBMCDefaultUserKeyBypass(context.Background(), tgt); got != nil {
			t.Errorf("unreachable target must yield no finding, got %+v", got)
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("default-suite fallback did not terminate: the capped per-suite timeout is not bounding the probe")
	}
}

func TestDefaultUserKeyPatchAbsentRequiresRAKP4IntegrityMismatch(t *testing.T) {
	if !defaultUserKeyPatchAbsent(&DefaultUserKeyBypassProbe{RAKP1Status: 0x0a, RAKP3Status: 0x0f}) {
		t.Fatal("RAKP1 early-exit followed by RAKP4 integrity mismatch should indicate an absent patch")
	}
	for _, probe := range []*DefaultUserKeyBypassProbe{
		nil,
		{RAKP1Status: 0x00, RAKP3Status: 0x0f},
		{RAKP1Status: 0x0a, RAKP3Status: 0x02},
	} {
		if defaultUserKeyPatchAbsent(probe) {
			t.Fatalf("unexpected patch-absence classification for %+v", probe)
		}
	}
}

func TestDefaultUserKeyPatchLeadIncludesFullTestOption(t *testing.T) {
	probe := &DefaultUserKeyBypassProbe{
		Suite: 17, AuthAlgo: 3, BMCSID: 0x12345678,
		RAKP1Status: 0x0a, RAKP1StatusName: "unauthorized role or privilege",
		RAKP3Status: 0x0f, RAKP3StatusName: "invalid integrity check",
	}
	probe.Attempts = 2
	fieldsOf := func(f engine.Finding) map[string]string {
		out := map[string]string{}
		for _, field := range f.Fields {
			out[field.Key] = field.Val
		}
		return out
	}

	// No auto-confirm ran (attempts == the patch probe's own): the lead just
	// recommends the full test.
	fields := fieldsOf(defaultUserKeyPatchLeadFinding(probe, probe.Attempts))
	if fields["patchStatus"] != "likely-unpatched" {
		t.Fatalf("unexpected patch lead fields=%v", fields)
	}
	if fields["fullTestOption"] != "--ipmi-openbmc-default-userkey" {
		t.Fatalf("fullTestOption=%q", fields["fullTestOption"])
	}
	if fields["status"] != "full-test-recommended" {
		t.Fatalf("status=%q, want full-test-recommended", fields["status"])
	}

	// Auto-confirm ran and came up empty: the status must say so, and the total
	// attempts must be carried, or "we did not try" is indistinguishable from
	// "we re-rolled the residue 500 times and it never landed".
	withAuto := defaultUserKeyPatchLeadFinding(probe, 500)
	if withAuto.Risk != "medium" {
		t.Fatalf("risk=%q, want medium", withAuto.Risk)
	}
	fields = fieldsOf(withAuto)
	if fields["status"] != "auto-confirm-exhausted-full-test-recommended" {
		t.Fatalf("status=%q, want the auto-confirm-exhausted form", fields["status"])
	}
	if fields["attempts"] != "500" {
		t.Fatalf("attempts=%q, want 500", fields["attempts"])
	}
}
