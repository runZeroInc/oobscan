package check

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/digi"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ssdp"
	"github.com/runZeroInc/oobscan/pkg/telnet"
)

// The exposure findings in this file all assert that something was reachable or
// disclosed. engine.FindingNeedsProof requires each of them to carry
// device-reported evidence, and the corpus audit additionally rejects an
// evidence field whose value is identical on every host. Both properties are
// checked here: proof must be present on the quiet arm (where nothing came back
// on the wire) and must still differ between two hosts that measured
// differently.

// requireProof fails when a finding that owes evidence carries none. The
// serialized form is checked too: engine.F drops empty values at construction
// and normalizeFields drops them again at marshal, so a proof assembled only
// from empty parts collapses to nothing on the way to disk.
func requireProof(t *testing.T, name string, f engine.Finding) string {
	t.Helper()
	if !engine.FindingNeedsProof(&f) {
		t.Fatalf("%s: expected an evidence-bearing finding (risk=%q category=%q)", name, f.Risk, f.Category)
	}
	if !engine.FindingHasProof(&f) {
		t.Fatalf("%s: emitted with no proof field; fields = %v", name, f.Fields)
	}
	blob, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("%s: marshal: %v", name, err)
	}
	var round struct {
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(blob, &round); err != nil {
		t.Fatalf("%s: unmarshal: %v", name, err)
	}
	var kept engine.Finding
	for k, v := range round.Fields {
		kept.Fields = append(kept.Fields, engine.Field{Key: k, Val: v})
	}
	if !engine.FindingHasProof(&kept) {
		t.Fatalf("%s: proof did not survive serialization; on-disk fields = %s", name, blob)
	}
	return fieldVal(f.Fields, "proof")
}

// requireNoProof is the counterpart for a finding that owes evidence and
// honestly has none. It fails if the finding satisfies the evidence contract, if
// it carries no marker saying why, or if the marker was written into the proof
// value -- where it makes the contract read as satisfied by the very statement
// that it is not. It returns the marker so callers can compare arms.
func requireNoProof(t *testing.T, name string, f engine.Finding) string {
	t.Helper()
	if !engine.FindingNeedsProof(&f) {
		t.Fatalf("%s: expected an evidence-bearing finding (risk=%q category=%q)", name, f.Risk, f.Category)
	}
	if engine.FindingHasProof(&f) {
		t.Fatalf("%s: claims evidence it does not have; proof = %q, fields = %v",
			name, fieldVal(f.Fields, "proof"), f.Fields)
	}
	reason := fieldVal(f.Fields, engine.ProofUnavailableKey)
	if reason == "" {
		t.Fatalf("%s: no proof and no reason given; fields = %v", name, f.Fields)
	}
	// The marker is a fixed per-check label, so it must stay short enough that the
	// audit's constant-value rule reads it as a label and not as prose stored per
	// host.
	if len(reason) >= 60 {
		t.Errorf("%s: marker is %d bytes, long enough for the constant-evidence rule to flag it: %q",
			name, len(reason), reason)
	}
	return reason
}

// requireMarkerNotInProof fails when a finding writes the unavailability marker
// inside its proof value. That is what made the audit count these findings as
// proven: the proof is non-empty, so the contract is satisfied by the sentence
// denying it.
func requireMarkerNotInProof(t *testing.T, name string, f engine.Finding) {
	t.Helper()
	for _, fd := range f.Fields {
		if engine.CanonicalFieldKey(fd.Key) == engine.ProofUnavailableKey {
			continue
		}
		if !slices.Contains(engine.ProofFieldKeys, engine.CanonicalFieldKey(fd.Key)) {
			continue
		}
		if strings.Contains(fd.Val, engine.ProofUnavailableKey) {
			t.Errorf("%s: %q says it has no evidence inside the evidence field: %q", name, fd.Key, fd.Val)
		}
	}
}

// requireDistinct fails when two differently-measured hosts produce the same
// evidence string, which is what the audit's ConstantEvidence rule catches.
func requireDistinct(t *testing.T, name, a, b string) {
	t.Helper()
	if a == "" || b == "" {
		t.Fatalf("%s: empty proof (%q / %q)", name, a, b)
	}
	if a == b {
		t.Fatalf("%s: proof does not vary between hosts; both = %q", name, a)
	}
}

// TestKVMChannelFindingsCarryProof covers the five redirection-channel checks
// that share kvmFieldsFrom. A listener that spoke must ship what it said; a
// listener that spoke only after its client must not be credited with evidence
// it never produced.
func TestKVMChannelFindingsCarryProof(t *testing.T) {
	mute := kvmChannelState{open: true, proto: "tcp", tlsOutcome: "no-reply"}
	tlsUp := kvmChannelState{open: true, proto: "tls", cn: "IPMI00259601ABCD", tlsVersion: "TLS1.2", tlsOutcome: "negotiated"}
	chatty := kvmChannelState{open: true, proto: "tcp", handshakeHex: "524642203030332e303038", tlsOutcome: "no-reply"}

	find := func(channel string, port int, st kvmChannelState) engine.Finding {
		return engine.Finding{
			Check: "kvm." + channel, Category: "exposure", Risk: "info",
			Port: port, Transport: "tcp", Protocol: "tcp",
			Fields: kvmFieldsFrom(channel, "supermicro", port, st),
		}
	}

	tlsProof := requireProof(t, "usbanywhere/tls", find("usbanywhere", 623, tlsUp))
	chattyProof := requireProof(t, "usbanywhere/banner", find("usbanywhere", 623, chatty))
	requireDistinct(t, "usbanywhere tls vs banner", tlsProof, chattyProof)
	if !strings.Contains(chattyProof, "serverBytes=11") {
		t.Errorf("banner proof should record the byte count, got %q", chattyProof)
	}
	if !strings.Contains(tlsProof, "commonName=IPMI00259601ABCD") {
		t.Errorf("tls proof should carry the certificate CN, got %q", tlsProof)
	}

	// The mute arm is admitted precisely when the listener sent nothing, and the
	// port, the channel name and the transport are the probe's own parameters. A
	// proof assembled from those plus a sentence saying there is no proof is what
	// let 100% of these findings pass the evidence contract.
	muteFinding := find("usbanywhere", 623, mute)
	requireMarkerNotInProof(t, "usbanywhere/mute", muteFinding)
	muteReason := requireNoProof(t, "usbanywhere/mute", muteFinding)
	if !strings.Contains(muteReason, "stunnel") {
		t.Errorf("usbanywhere should name its own reason, got %q", muteReason)
	}
	// The refusal is still recorded; it is a reaction, not content, so it rides a
	// plain field rather than standing in for evidence.
	if got := fieldVal(muteFinding.Fields, "tlsHandshake"); got != "no-reply" {
		t.Errorf("mute finding discarded how the peer refused TLS, got %q", got)
	}
	if got := fieldVal(muteFinding.Fields, "proof"); got != "" {
		t.Errorf("mute finding still ships a proof field: %q", got)
	}

	// The port must reach the proof. kvm.hpe.irc reports either 17990 (console +
	// virtual media) or 17988 (legacy console) and kvm.ami.vmedia any of
	// 5120/5122/5123, so a proof that omits the port cannot tell them apart.
	requireDistinct(t, "hpe-irc 17990 vs 17988",
		requireProof(t, "hpe-irc/17990", find("hpe-irc", 17990, chatty)),
		requireProof(t, "hpe-irc/17988", find("hpe-irc", 17988, chatty)))
	requireDistinct(t, "ami-vmedia 5120 vs 5123",
		requireProof(t, "ami-vmedia/5120", find("ami-vmedia", 5120, chatty)),
		requireProof(t, "ami-vmedia/5123", find("ami-vmedia", 5123, chatty)))

	// The five checks that share this helper must not all report one string, and
	// none of them may fall back to the marker while holding a banner.
	ports := map[string]int{"avocent": 3900, "ami-redirect": 7578, "ami-vmedia": 5120, "hpe-irc": 17990, "cisco-vkvm": 2068}
	seen := map[string]string{}
	for channel, port := range ports {
		f := find(channel, port, chatty)
		requireMarkerNotInProof(t, channel, f)
		p := requireProof(t, channel, f)
		for other, prev := range seen {
			requireDistinct(t, channel+" vs "+other, p, prev)
		}
		seen[channel] = p
		// A channel with no reason of its own still has to give one.
		if r := requireNoProof(t, channel+"/mute", find(channel, port, mute)); r == "" {
			t.Errorf("%s: mute arm gave no reason", channel)
		}
	}
}

// muteKVMListener accepts connections and never speaks. hangup makes it close
// each connection immediately instead, which is the other way a listener that
// speaks only after its client can answer a ClientHello.
func muteKVMListener(t *testing.T, hangup bool) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if hangup {
				_ = c.Close()
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				time.Sleep(2 * time.Second)
			}(c)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

// TestUSBAnywhereMuteArmClaimsNoProof drives two hosts through the path
// kvm.usbAnywhere actually emits from -- probeKVMChannel, then the gate, then
// kvmFieldsFrom on the fixed port 623 -- rather than through hand-built states
// that differ before the check ever sees them.
//
// The ATEN vmedia listener speaks only after its client, so the plain-TCP arm is
// admitted precisely when nothing came back. There is no evidence to ship, and
// the finding has to say so where the audit can read it: a proof field built
// from the probe's own parameters plus a disclaimer counts as evidence and hides
// the whole population. What the two hosts did differ in -- how each refused the
// ClientHello -- still has to survive.
func TestUSBAnywhereMuteArmClaimsNoProof(t *testing.T) {
	findingFor := func(hangup bool) (engine.Finding, kvmChannelState) {
		host, port := muteKVMListener(t, hangup)
		st := probeKVMChannel(host, port, 300*time.Millisecond)
		if !st.open {
			t.Fatalf("hangup=%v: probe found the listener closed", hangup)
		}
		if !usbAnywhereLooksLikeATEN(st) {
			t.Fatalf("hangup=%v: the gate rejected a mute listener (state %+v)", hangup, st)
		}
		return engine.Finding{
			Check: "kvm.usbAnywhere", Category: "exposure", Risk: "info",
			Port: 623, Transport: "tcp", Protocol: "aten-vmedia",
			Fields: kvmFieldsFrom("usbanywhere", "supermicro", 623, st),
		}, st
	}

	silent, silentState := findingFor(false)
	closed, closedState := findingFor(true)

	if silentState.handshakeHex != "" || closedState.handshakeHex != "" {
		t.Fatalf("fixture spoke first, so it does not exercise the mute arm: %+v / %+v", silentState, closedState)
	}
	for name, f := range map[string]engine.Finding{"silent": silent, "closed": closed} {
		requireMarkerNotInProof(t, "kvm.usbAnywhere/"+name, f)
		requireNoProof(t, "kvm.usbAnywhere/"+name, f)
		if got := fieldVal(f.Fields, "tlsHandshake"); got == "" {
			t.Errorf("%s host: the finding discarded how the peer refused TLS", name)
		}
	}
	// The reaction is the one thing the two hosts did not share, so losing it
	// would collapse them onto one record.
	requireDistinct(t, "kvm.usbAnywhere silent vs hangup",
		fieldVal(silent.Fields, "tlsHandshake"), fieldVal(closed.Fields, "tlsHandshake"))
}

// TestVNCConsoleFindingCarriesProof covers the kvm.vnc info arm: an auth-gated
// console has no successful login to report, so the handshake itself -- RFB
// version and offered security types, or the TLS certificate on a session-gated
// console that never speaks RFB -- is the evidence.
func TestVNCConsoleFindingCarriesProof(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10"}

	gated := vncConsoleFinding(tgt, 5900, &vncInfo{
		tls: true, auth: "session-gated", cn: "IPMI00259601ABCD", org: "Super Micro Computer",
	})
	if gated.Check != "kvm.vnc" {
		t.Fatalf("session-gated console = %s, want kvm.vnc", gated.Check)
	}
	gatedProof := requireProof(t, "kvm.vnc/session-gated", gated)

	aten := vncConsoleFinding(tgt, 5900, &vncInfo{
		version: "003.008", auth: "aten", secTypes: "16",
	})
	if aten.Check != "kvm.vnc" {
		t.Fatalf("aten console = %s, want kvm.vnc", aten.Check)
	}
	atenProof := requireProof(t, "kvm.vnc/aten", aten)
	requireDistinct(t, "kvm.vnc session-gated vs aten", gatedProof, atenProof)

	if !strings.Contains(atenProof, "rfbSecurityTypes=16") {
		t.Errorf("proof should carry the offered security types, got %q", atenProof)
	}
	// The info arm used to compute secTypes and then discard it, leaving it the
	// only arm of the switch that reported less than it measured.
	if got := fieldVal(aten.Fields, "secTypes"); got != "16" {
		t.Errorf("secTypes field = %q, want the offered types", got)
	}
	// The louder arms keep their own proofs.
	unauth := vncConsoleFinding(tgt, 5900, &vncInfo{auth: "none", secTypes: "1"})
	if unauth.Check != "kvm.vnc.unauth" {
		t.Fatalf("unauth console = %s", unauth.Check)
	}
	requireProof(t, "kvm.vnc.unauth", unauth)
}

// TestSMCWSBypassFindingsCarryProof covers both wstunnel arms, which previously
// parked their evidence under keys the audit does not recognize and then, once
// moved, satisfied the contract with a sentence saying they could not.
func TestSMCWSBypassFindingsCarryProof(t *testing.T) {
	// The RFB greeting is a fixed protocol string for a firmware line, so neither
	// KVM arm has anything that separates one host from another. Both must say so
	// where the audit reads it, and neither may ship a proof field.
	mute := smcWSKVMFinding("supermicro", "", 0)
	spoke := smcWSKVMFinding("supermicro", "003.008", 12)
	for name, f := range map[string]engine.Finding{"kvm-mute": mute, "kvm-banner": spoke} {
		requireMarkerNotInProof(t, "kvm.smc.ws.bypass/"+name, f)
		requireNoProof(t, "kvm.smc.ws.bypass/"+name, f)
	}
	// The greeting is still reported, just not as evidence.
	if got := fieldVal(spoke.Fields, "rfbVersion"); got != "003.008" {
		t.Errorf("kvm arm dropped the version it parsed, got %q", got)
	}
	if got := fieldVal(spoke.Fields, "bannerBytes"); got != "12" {
		t.Errorf("kvm arm dropped the banner length it measured, got %q", got)
	}

	noSlots := smcWSVMediaFinding("supermicro", 0, "")
	slots := smcWSVMediaFinding("supermicro", 4, "slots=3 perSlot=ffffff")
	other := smcWSVMediaFinding("supermicro", 3, "slots=2 perSlot=ff00")
	requireMarkerNotInProof(t, "kvm.smc.ws.bypass/vm-slots", slots)
	slotsProof := requireProof(t, "kvm.smc.ws.bypass/vm-slots", slots)
	requireDistinct(t, "vm arm slot layouts", slotsProof,
		requireProof(t, "kvm.smc.ws.bypass/vm-other", other))

	// The slot bytes are host-chosen, so the arm that got them must not disclaim
	// them -- only the arm that got no payload may.
	noSlotsReason := requireNoProof(t, "kvm.smc.ws.bypass/vm-empty", noSlots)
	if fieldVal(slots.Fields, engine.ProofUnavailableKey) != "" {
		t.Errorf("vm arm disclaims evidence the daemon actually sent: %q", slotsProof)
	}
	// The two arms of this one check must stay distinguishable even when neither
	// has evidence, or every kvm.smc.ws.bypass record reads the same.
	requireDistinct(t, "kvm arm vs vm arm reasons",
		fieldVal(mute.Fields, engine.ProofUnavailableKey), noSlotsReason)

	// Neither arm may pad its evidence with a value its own gate already fixed.
	// The VM arm only runs after a 0x09 reply header, so recording it reads as a
	// measurement while being the same text on every host.
	if strings.Contains(slotsProof, "opcode=") {
		t.Errorf("vm arm records the reply opcode its gate required: %q", slotsProof)
	}
}

// TestIKVMHijackUnreachableCarriesProof covers the high-risk arm that reports
// the leaked .IKVM session when the console's own TLS handshake failed. It
// shipped no evidence field at all, so the token it was reporting never reached
// the record the claim lives on.
func TestIKVMHijackUnreachableCarriesProof(t *testing.T) {
	a := ikvmHijackUnreachableFinding("42", "a1b2c3d4", "https://192.0.2.13/cgi/url_redirect.cgi?url_name=man_ikvm")
	b := ikvmHijackUnreachableFinding("7", "9f8e7d6c", "https://192.0.2.14/cgi/url_redirect.cgi?url_name=man_ikvm")
	if a.Risk != "high" {
		t.Fatalf("risk = %s, want high", a.Risk)
	}
	pa := requireProof(t, "kvm.smc.ikvm.sessionHijack/unreachable-a", a)
	requireDistinct(t, "ikvm hijack a vs b", pa,
		requireProof(t, "kvm.smc.ikvm.sessionHijack/unreachable-b", b))
	if !strings.Contains(pa, "entryValue=a1b2c3d4") {
		t.Errorf("proof should carry the token the device handed out, got %q", pa)
	}
}

// TestVNCDefaultCredsProofIsNotAConstant covers the arm whose whole proof value
// was two literals: the RFB result code the arm is conditioned on and a boolean
// restating the check name. Every host that reached it reported the same string.
func TestVNCDefaultCredsProofIsNotAConstant(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.11"}
	a := vncConsoleFinding(tgt, 5900, &vncInfo{
		version: "003.008", auth: "aten", secTypes: "16",
		defaultUser: "ADMIN", defaultPass: "ADMIN",
	})
	b := vncConsoleFinding(tgt, 5901, &vncInfo{
		version: "055.008", auth: "insyde", secTypes: "1,2,16",
		defaultUser: "admin", defaultPass: "admin",
	})
	if a.Check != "kvm.vnc.defaultCreds" || b.Check != "kvm.vnc.defaultCreds" {
		t.Fatalf("checks = %s / %s, want kvm.vnc.defaultCreds", a.Check, b.Check)
	}
	pa := requireProof(t, "kvm.vnc.defaultCreds/aten", a)
	pb := requireProof(t, "kvm.vnc.defaultCreds/insyde", b)
	requireDistinct(t, "kvm.vnc.defaultCreds aten vs insyde", pa, pb)
	if !strings.Contains(pa, "rfbSecurityTypes=16") || !strings.Contains(pa, "acceptedUsername=ADMIN") {
		t.Errorf("proof should carry the handshake and the accepted credential, got %q", pa)
	}

	// The same two arms of the same handshake, differing only in which console
	// answered, must not fold together either.
	unauthA := vncConsoleFinding(tgt, 5900, &vncInfo{auth: "none", secTypes: "1", version: "003.008"})
	unauthB := vncConsoleFinding(tgt, 5900, &vncInfo{auth: "none", secTypes: "1,2", version: "003.007"})
	requireDistinct(t, "kvm.vnc.unauth 003.008 vs 003.007",
		requireProof(t, "kvm.vnc.unauth/a", unauthA),
		requireProof(t, "kvm.vnc.unauth/b", unauthB))

	cleartextA := vncConsoleFinding(tgt, 5900, &vncInfo{auth: "vncauth", secTypes: "2", version: "003.008"})
	cleartextB := vncConsoleFinding(tgt, 5900, &vncInfo{auth: "vncauth", secTypes: "2", version: "003.003"})
	if cleartextA.Check != "kvm.vnc.cleartextAuth" {
		t.Fatalf("cleartext console = %s", cleartextA.Check)
	}
	requireDistinct(t, "kvm.vnc.cleartextAuth 003.008 vs 003.003",
		requireProof(t, "kvm.vnc.cleartextAuth/a", cleartextA),
		requireProof(t, "kvm.vnc.cleartextAuth/b", cleartextB))
}

// TestSMCVMediaProofCarriesPlatform covers kvm.smc.vmedia. The reply opcode is
// this check's own gate; the platform ID is a board value the daemon reports and
// was recorded everywhere except in the evidence.
func TestSMCVMediaProofCarriesPlatform(t *testing.T) {
	proofFor := func(res *vmediaResult) string {
		t.Helper()
		f := smcVMediaFinding(&engine.Target{Host: "192.0.2.12"}, res)
		requireMarkerNotInProof(t, "kvm.smc.vmedia", f)
		return requireProof(t, "kvm.smc.vmedia", f)
	}
	x13 := proofFor(&vmediaResult{slotCount: 2, slotSummary: "unused,unused", platformID: 80})
	x10 := proofFor(&vmediaResult{slotCount: 2, slotSummary: "unused,unused", platformID: 88})
	requireDistinct(t, "kvm.smc.vmedia x13 vs x10", x13, x10)
	if strings.Contains(x13, "opcode=") {
		t.Errorf("proof records the reply opcode its own gate required: %q", x13)
	}
	if !strings.Contains(x13, "platformId=80") {
		t.Errorf("proof dropped the platform the daemon reported: %q", x13)
	}
}

// TestDeviceFingerprintCarriesProof covers serialconsole.fingerprint and
// pdu.fingerprint. class/vendor/product are labels identify derived; the proof
// has to carry the signals the device actually produced.
func TestDeviceFingerprintCarriesProof(t *testing.T) {
	target := func(class engine.DeviceClass, vendor, product, server string, sig engine.Signal) *engine.Target {
		return &engine.Target{
			Host: "192.0.2.20",
			Identity: &engine.Identity{
				Class: class, Vendor: vendor, Product: product,
				Signals:    []engine.Signal{sig},
				Attributes: map[string]string{"web.port": "443", "web.scheme": "https", "http.server": server},
			},
		}
	}

	for _, kind := range []string{"serialconsole", "pdu"} {
		a := oobDeviceExposure(context.Background(),
			target(engine.ClassSerialConsole, "moxa", "NPort", "MoxaHttp/1.0",
				engine.Signal{Source: "http.server", Vendor: "moxa", Detail: "MoxaHttp/1.0"}), kind)
		b := oobDeviceExposure(context.Background(),
			target(engine.ClassPDU, "apc", "Rack PDU", "Allegro-Software-RomPager/4.34",
				engine.Signal{Source: "snmp.sysdescr", Vendor: "apc", Detail: "APC AP8959 v6.8.2"}), kind)
		if len(a) == 0 || len(b) == 0 {
			t.Fatalf("%s: expected a fingerprint finding", kind)
		}
		pa := requireProof(t, kind+"/moxa", a[0])
		pb := requireProof(t, kind+"/apc", b[0])
		requireDistinct(t, kind+" moxa vs apc", pa, pb)
		if !strings.Contains(pa, "MoxaHttp") {
			t.Errorf("%s proof should carry the identify signal detail, got %q", kind, pa)
		}
	}
}

// TestDeviceFingerprintProofUsesCollectorAttributes covers the largest collapsed
// population of the fingerprint checks: a Lantronix unit that reports no model,
// whose signals therefore carry no detail. Both hosts below have identical
// signals and differ only in what the Lantronix collector read off the device,
// so a summary built from the signals alone gives them the same evidence.
func TestDeviceFingerprintProofUsesCollectorAttributes(t *testing.T) {
	target := func(banner, mac string) *engine.Target {
		return &engine.Target{
			Host: "192.0.2.21",
			Identity: &engine.Identity{
				Class: engine.ClassSerialConsole, Vendor: "lantronix",
				Signals: []engine.Signal{
					{Source: "lantronix", Vendor: "lantronix"},
					{Source: "lantronix.telnet", Vendor: "lantronix"},
				},
				Attributes: map[string]string{"lantronix.setup_telnet": banner, "mac": mac},
			},
		}
	}
	a := oobDeviceExposure(context.Background(), target("MAC address 00204A0000A1 Software version V6.1.0.0", "00:20:4a:00:00:a1"), "serialconsole")
	b := oobDeviceExposure(context.Background(), target("MAC address 00204A0000B2 Software version V6.5.0.2", "00:20:4a:00:00:b2"), "serialconsole")
	if len(a) == 0 || len(b) == 0 {
		t.Fatal("expected a fingerprint finding from both hosts")
	}
	pa := requireProof(t, "serialconsole.fingerprint/unit-a", a[0])
	pb := requireProof(t, "serialconsole.fingerprint/unit-b", b[0])
	requireDistinct(t, "serialconsole.fingerprint unit-a vs unit-b", pa, pb)
	if !strings.Contains(pa, "00204A0000A1") {
		t.Errorf("proof should carry the setup banner the collector read, got %q", pa)
	}

	// With no attribute to fall back on there is genuinely nothing to report,
	// and the summary must still render the signals rather than going empty.
	bare := oobDeviceExposure(context.Background(), &engine.Target{
		Host: "192.0.2.22",
		Identity: &engine.Identity{
			Class: engine.ClassSerialConsole, Vendor: "lantronix",
			Signals: []engine.Signal{{Source: "lantronix", Vendor: "lantronix"}},
		},
	}, "serialconsole")
	if len(bare) == 0 {
		t.Fatal("expected a fingerprint finding with no attributes")
	}
	if got := requireProof(t, "serialconsole.fingerprint/bare", bare[0]); !strings.Contains(got, "lantronix:lantronix") {
		t.Errorf("proof lost the signal it does have, got %q", got)
	}
}

// TestTelnetBannerFindingCarriesProof covers tcp.telnetBanner. The empty-read
// arm is the one that shipped without evidence, but building proof only there
// would give every such host the same string, so both arms are checked.
func TestTelnetBannerFindingCarriesProof(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.30"}

	silent, ok := telnetBannerFinding(tgt, 23, telnet.BannerResult{})
	if !ok {
		t.Fatal("a reachable but silent telnet listener should still be reported")
	}
	silentProof := requireProof(t, "tcp.telnetBanner/empty-read", silent)
	if !strings.Contains(silentProof, "bytesRead=0") {
		t.Errorf("empty-read proof should record the read, got %q", silentProof)
	}

	negotiated, ok := telnetBannerFinding(tgt, 23, telnet.BannerResult{
		Raw: []byte{0xff, 0xfd, 0x18}, SentEnter: true,
	})
	if !ok {
		t.Fatal("an IAC-only telnet listener should still be reported")
	}
	negotiatedProof := requireProof(t, "tcp.telnetBanner/iac-only", negotiated)
	requireDistinct(t, "telnet silent vs iac-only", silentProof, negotiatedProof)

	spoke, ok := telnetBannerFinding(tgt, 23, telnet.BannerResult{
		Raw: []byte("NPort login: "), Visible: []byte("NPort login: "),
	})
	if !ok {
		t.Fatal("a banner-bearing telnet listener should be reported")
	}
	spokeProof := requireProof(t, "tcp.telnetBanner/banner", spoke)
	requireDistinct(t, "telnet silent vs banner", silentProof, spokeProof)

	// A different port must not fold into the same evidence string.
	other, ok := telnetBannerFinding(tgt, 2323, telnet.BannerResult{})
	if !ok {
		t.Fatal("2323 should be reported the same way as 23")
	}
	requireDistinct(t, "telnet port 23 vs 2323", silentProof, requireProof(t, "tcp.telnetBanner/2323", other))
}

// TestMoxaSerialBannerFindingCarriesProof covers tcp.moxa.serialBanner, whose
// silent arm is the majority of its findings.
func TestMoxaSerialBannerFindingCarriesProof(t *testing.T) {
	line1 := moxaSerialBannerFinding(1, 4001, nil)
	line2 := moxaSerialBannerFinding(2, 4002, nil)
	p1 := requireProof(t, "tcp.moxa.serialBanner/line1", line1)
	p2 := requireProof(t, "tcp.moxa.serialBanner/line2", line2)
	requireDistinct(t, "moxa line 1 vs line 2", p1, p2)
	if !strings.Contains(p1, "bytesRead=0") {
		t.Errorf("silent line proof should record the empty read, got %q", p1)
	}

	spoke := moxaSerialBannerFinding(1, 4001, []byte("Router#"))
	requireDistinct(t, "moxa silent vs banner", p1, requireProof(t, "tcp.moxa.serialBanner/banner", spoke))
}

// TestDigiRealPortBannerFindingCarriesProof covers tcp.digi.realportBanner. The
// empty arm used to pass a literal empty "banner" value, which engine.F drops,
// so the finding read in source as if evidence were recorded when none was.
func TestDigiRealPortBannerFindingCarriesProof(t *testing.T) {
	a := digiRealPortNoBannerFinding(&digi.RealPortInfo{Port: 771, Name: "PortServer TS 4", PortCount: 4})
	b := digiRealPortNoBannerFinding(&digi.RealPortInfo{Port: 771, Name: "ConnectPort LTS 16", PortCount: 16})
	pa := requireProof(t, "tcp.digi.realportBanner/empty-ts4", a)
	pb := requireProof(t, "tcp.digi.realportBanner/empty-lts16", b)
	requireDistinct(t, "digi TS4 vs LTS16", pa, pb)

	ri := &digi.RealPortInfo{Port: 771, Name: "PortServer TS 4", PortCount: 4}
	l1 := digiRealPortBannerFinding(ri, digi.RealPortBanner{SerialPort: 1, Baud: 9600})
	l2 := digiRealPortBannerFinding(ri, digi.RealPortBanner{SerialPort: 2, Baud: 115200})
	requireDistinct(t, "digi line 1 vs line 2",
		requireProof(t, "tcp.digi.realportBanner/line1", l1),
		requireProof(t, "tcp.digi.realportBanner/line2", l2))
}

// TestLantronixNTCSkipAuthCarriesProof covers the high-risk pre-auth leak. The
// "envelope matched but empty" fallback previously shipped only the object name.
func TestLantronixNTCSkipAuthCarriesProof(t *testing.T) {
	empty := []byte(`{"result":0,"StsSystemInfo":{}}`)
	f := ntcSkipAuthFinding("https", 443, 200, empty, map[string]any{})
	if f.Risk != "high" {
		t.Fatalf("risk = %s, want high", f.Risk)
	}
	emptyProof := requireProof(t, "http.lantronix.ntcSkipAuth/empty", f)

	populated := []byte(`{"result":0,"StsSystemInfo":{"serialNumber":"NTC1234","deviceModel":"NTC-524"}}`)
	g := ntcSkipAuthFinding("http", 8080, 200, populated,
		map[string]any{"serialNumber": "NTC1234", "deviceModel": "NTC-524"})
	requireDistinct(t, "ntcSkipAuth empty vs populated", emptyProof,
		requireProof(t, "http.lantronix.ntcSkipAuth/populated", g))

	// The served bytes are the disclosure and must survive the empty fallback.
	if got := fieldVal(f.Fields, "response"); !strings.Contains(got, "StsSystemInfo") {
		t.Errorf("response snippet = %q, want the served envelope", got)
	}
}

// TestLenovoXCCPreauthFindingsCarryProof drives the two Lenovo pre-auth
// disclosures end to end against a served response, so the proof is pinned to
// what the endpoint actually returned rather than to a constructed fixture.
func TestLenovoXCCPreauthFindingsCarryProof(t *testing.T) {
	nonceSrv := func(nonce string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/api/providers/get_nonce" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"return":0,"nonce":"` + nonce + `"}`))
				return
			}
			http.NotFound(w, r)
		}))
	}
	a := nonceSrv("aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeee1")
	defer a.Close()
	b := nonceSrv("aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeee2")
	defer b.Close()

	fa := lenovoGetNonce(context.Background(), lenovoTarget(t, a.URL))
	fb := lenovoGetNonce(context.Background(), lenovoTarget(t, b.URL))
	if fa == nil || fb == nil {
		t.Fatal("expected an xcc.nonce finding from both servers")
	}
	pa := requireProof(t, "http.lenovo.xcc.nonce/a", *fa)
	pb := requireProof(t, "http.lenovo.xcc.nonce/b", *fb)
	requireDistinct(t, "xcc.nonce a vs b", pa, pb)
	if !strings.Contains(pa, "eeeeeeeeeee1") {
		t.Errorf("proof should carry the served nonce, got %q", pa)
	}

	infoSrv := func(hostname string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/DeviceDescription.json" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"systemName":"` + hostname + `"}`))
				return
			}
			http.NotFound(w, r)
		}))
	}
	c := infoSrv("node01")
	defer c.Close()
	d := infoSrv("node02")
	defer d.Close()

	gc := hasFinding(runLenovoXCCDeviceInfo(context.Background(), lenovoTarget(t, c.URL)), "http.lenovo.xcc.deviceInfo")
	gd := hasFinding(runLenovoXCCDeviceInfo(context.Background(), lenovoTarget(t, d.URL)), "http.lenovo.xcc.deviceInfo")
	if gc == nil || gd == nil {
		t.Fatal("expected an xcc.deviceInfo finding from both servers")
	}
	requireDistinct(t, "xcc.deviceInfo node01 vs node02",
		requireProof(t, "http.lenovo.xcc.deviceInfo/node01", *gc),
		requireProof(t, "http.lenovo.xcc.deviceInfo/node02", *gd))
	// model/serial/firmware are absent on the endpoint that answers in practice;
	// the body snippet is what makes that visible instead of implying the device
	// withheld them.
	if got := fieldVal(gc.Fields, "response"); !strings.Contains(got, "node01") {
		t.Errorf("response snippet = %q, want the served body", got)
	}
}

// TestOpengearPreAuthLeakCarriesProof covers http.opengear.preAuthLeak, which
// previously satisfied the evidence rule only by accident, when the endpoint
// whose field key is literally spelled "banner" happened to answer.
func TestOpengearPreAuthLeakCarriesProof(t *testing.T) {
	// Only model_name answers: no field named "banner" is emitted at all.
	modelOnly := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/system/model_name") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"system_model_name":{"model_name":"OM2224-24E"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer modelOnly.Close()

	f := hasFinding(runOpengearPreauth(context.Background(), opengearTarget(t, modelOnly.URL)), "http.opengear.preAuthLeak")
	if f == nil {
		t.Fatal("expected a preAuthLeak finding when model_name leaks")
	}
	if fieldVal(f.Fields, "banner") != "" {
		t.Fatal("this fixture must not emit a banner field, or the test proves nothing")
	}
	modelProof := requireProof(t, "http.opengear.preAuthLeak/model-only", *f)

	both := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/system/model_name"):
			_, _ = w.Write([]byte(`{"system_model_name":{"model_name":"CM7196A"}}`))
		case strings.HasSuffix(r.URL.Path, "/system/banner"):
			_, _ = w.Write([]byte(`{"system_banner":{"banner":"Authorized access only"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer both.Close()
	g := hasFinding(runOpengearPreauth(context.Background(), opengearTarget(t, both.URL)), "http.opengear.preAuthLeak")
	if g == nil {
		t.Fatal("expected a preAuthLeak finding when two endpoints leak")
	}
	requireDistinct(t, "opengear one endpoint vs two", modelProof,
		requireProof(t, "http.opengear.preAuthLeak/model+banner", *g))
}

// TestSSDPLenovoXCCLeakCarriesProof covers ssdp.lenovo.xccLeak, whose leaked
// Server header was recorded only under a key the audit does not recognize.
func TestSSDPLenovoXCCLeakCarriesProof(t *testing.T) {
	leak := func(server string) engine.Finding {
		tgt := &engine.Target{Host: "192.0.2.40", Identity: &engine.Identity{Vendor: "lenovo"}}
		tgt.SetEvidence("ssdp", &ssdp.Result{Server: server})
		f := lenovoSSDPLeak(tgt)
		if f == nil {
			t.Fatalf("expected an xccLeak finding for %q", server)
		}
		return *f
	}
	a := requireProof(t, "ssdp.lenovo.xccLeak/node01", leak("node01:5.30 UPnP/1.1 7X99CTO1WW:J300ABCD"))
	b := requireProof(t, "ssdp.lenovo.xccLeak/node02", leak("node02:6.10 UPnP/1.1 7Z01CTO1WW:J900WXYZ"))
	requireDistinct(t, "xccLeak node01 vs node02", a, b)
	if !strings.Contains(a, "7X99CTO1WW") {
		t.Errorf("proof should carry the leaked Server string, got %q", a)
	}
}
