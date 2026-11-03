package check

import (
	"context"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// TestAMIMTLSBypassRegistered confirms the mTLS bypass check is registered,
// enabled in the default set, and selected independent of identity. The Run body
// self-gates on TLS client-cert request plus AMI cert evidence, so weak identify
// must not suppress it.
func TestAMIMTLSBypassRegistered(t *testing.T) {
	byName := map[string]Check{}
	for _, c := range All() {
		byName[c.Name] = c
	}
	c, ok := byName["tls.mtls.ami.caBypass"]
	if !ok {
		t.Fatal("check \"tls.mtls.ami.caBypass\" not registered")
	}
	if !c.Enabled {
		t.Error("tls.mtls.ami.caBypass should be enabled in the default set")
	}
	if c.Category != "tls" {
		t.Errorf("category = %q, want tls", c.Category)
	}
	// It is an active client-cert login, but the online/authorized gate lives in
	// the Run body (!t.DisableLogins), not the Authenticated/Destructive flags, so it
	// stays in the default set.
	if c.Destructive {
		t.Error("tls.mtls.ami.caBypass should not be marked Destructive")
	}

	selects := func(id *engine.Identity, name string) bool {
		for _, sc := range ForIdentity(id, Selector{}) {
			if sc.Name == name {
				return true
			}
		}
		return false
	}

	// Positive: selects for a BMC identity and for non-BMC/unknown identities;
	// the probe itself decides whether an AMI mTLS bypass is present.
	if !selects(&engine.Identity{Class: engine.ClassBMC, Vendor: "ami"}, "tls.mtls.ami.caBypass") {
		t.Error("tls.mtls.ami.caBypass should select for a BMC identity")
	}
	if !selects(&engine.Identity{Class: engine.ClassSerialConsole, Vendor: "moxa"}, "tls.mtls.ami.caBypass") {
		t.Error("tls.mtls.ami.caBypass should select even when identify reports a non-BMC identity")
	}
}

// TestAMIMTLSBypassOfflineNoFinding confirms the check does not run its active
// confirmation (or emit any finding) unless online/authorized mode is on.
// Offline it returns nil, so it contributes no default-scan noise.
func TestAMIMTLSBypassOfflineNoFinding(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.1", DisableLogins: true, Timeout: time.Second}
	if f := runAMIMTLSBypass(context.Background(), tgt); f != nil {
		t.Fatalf("offline mode: got %d findings, want none", len(f))
	}
}

// TestAMIMTLSBypassNoHTTPSNoFinding confirms a host with no TLS on :443 emits no
// finding (rather than a precondition/info finding). 192.0.2.0/24 is TEST-NET-1
// (RFC 5737): guaranteed unroutable, so the Inspect dial fails fast and we
// exercise the no-HTTPS branch.
func TestAMIMTLSBypassNoHTTPSNoFinding(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.2", DisableLogins: false, Timeout: 500 * time.Millisecond}
	if f := runAMIMTLSBypass(context.Background(), tgt); f != nil {
		t.Fatalf("no-HTTPS host: got %d findings, want none", len(f))
	}
}

// TestAMIClientCertParses guards the //go:embed: the shipped Administrator cert
// must parse into a usable client certificate.
func TestAMIClientCertParses(t *testing.T) {
	if _, ok := amiClientCert(); !ok {
		t.Fatal("embedded AMI Administrator client cert failed to parse")
	}
}
