package check

import (
	"context"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/digi"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

// TestRunDigiADDPLeak_FromEvidence exercises the fast path: the identify
// stage already parsed an ADDP reply and left it under `digi.addp` evidence,
// so the check should emit a `udp.digi.addpLeak` finding with the discovery
// fields carried through, without touching the network.
func TestRunDigiADDPLeak_FromEvidence(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10", Timeout: 500 * time.Millisecond}
	tgt.SetEvidence("digi.addp", &digi.ADDPResponse{
		From:              "192.0.2.10",
		Magic:             "DIGI",
		MAC:               "00:40:9d:aa:bb:cc",
		IP:                "192.0.2.10",
		Hostname:          "portserver-lab",
		HWName:            "PortServer TS 16",
		Firmware:          "82000747_S",
		Ports:             16,
		RealPort:          771,
		RealPortEncrypted: false,
		Raw:               []byte{0x44, 0x49, 0x47, 0x49},
	})
	got := runDigiADDPLeak(context.Background(), tgt)
	f := hasFinding(got, "udp.digi.addpLeak")
	if f == nil {
		t.Fatalf("expected udp.digi.addpLeak finding, got %+v", got)
	}
	if f.Risk != "info" {
		t.Errorf("risk = %s, want info", f.Risk)
	}
	if f.Category != "discovery" {
		t.Errorf("category = %s, want discovery", f.Category)
	}
	if f.Port != digi.ADDPPort || f.Transport != "udp" {
		t.Errorf("port/transport = %d/%s, want %d/udp", f.Port, f.Transport, digi.ADDPPort)
	}
	if got := findingField(*f, "product"); got != "PortServer TS 16" {
		t.Errorf("product = %q, want PortServer TS 16", got)
	}
	if got := findingField(*f, "serialPorts"); got != "16" {
		t.Errorf("serialPorts = %q, want 16", got)
	}
	if got := findingField(*f, "realport"); got != "771" {
		t.Errorf("realport = %q, want 771", got)
	}
	if got := findingField(*f, "response"); got != "" {
		t.Errorf("parsed ADDP finding retained raw response %q", got)
	}
}

// TestRunDigiADDPLeak_MinimalEvidenceSkipped confirms that a bare-minimum
// ADDP reply (no hostname/MAC/firmware/RealPort/ports) does not produce a
// finding. This keeps the check quiet on partial replies with no useful
// discovery metadata.
func TestRunDigiADDPLeak_MinimalEvidenceSkipped(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.11", Timeout: 500 * time.Millisecond}
	tgt.SetEvidence("digi.addp", &digi.ADDPResponse{From: "192.0.2.11", Magic: "DIGI"})
	if got := runDigiADDPLeak(context.Background(), tgt); got != nil {
		t.Errorf("expected no finding on empty ADDP reply, got %+v", got)
	}
}
