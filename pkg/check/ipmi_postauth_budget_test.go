package check

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func expiredContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	t.Cleanup(cancel)
	return ctx
}

// Opening a session is not context-aware: the RMCP+ handshake spends a full operation
// timeout before the collector reaches its first clock check. A candidate started after
// the per-host budget is gone can therefore only ever come back "before mcInfo: context
// deadline exceeded", so the walk has to stop rather than buy that answer once per suite.
func TestCipherWalkStopsWhenTheBudgetIsSpent(t *testing.T) {
	// 0x02 is a per-suite rejection, so neither the exhaustion bail nor the privilege
	// bail can be what stops the walk here.
	bmc := newRejectingBMC(t, 0x02)
	tgt := exhaustionTarget(bmc.port())
	flow := ipmi.AuthFlow{Version: "2.0", Mode: "cred", Username: "ADMIN", Password: "x",
		Suite: ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityHMACSHA196, Conf: ipmi.ConfAESCBC}}

	inv, err := collectPostAuthWithMatrix(expiredContext(t), tgt, flow, func(string, ...any) {})

	if got := bmc.opens.Load(); got != 0 {
		t.Errorf("walked %d candidates on an expired context: each one pays a full handshake to be told the budget is gone", got)
	}
	if err == nil {
		t.Fatal("expected an error: the budget was already spent")
	}
	if inv == nil {
		t.Fatal("collection dropped entirely")
	}
	// The reported cause has to be the budget. "no cipher suite candidates worked" reads
	// as a BMC that refused every suite, which is a different diagnosis entirely.
	if !strings.Contains(inv.Error, "deadline") {
		t.Errorf("coverageError = %q, want the deadline named: a walk stopped by the budget must say so", inv.Error)
	}
}

// The Supermicro fixed-key arm walks its own bounded candidate list and needs the same
// guard: its sessions are the expensive kind, opened once per user candidate per suite.
func TestSMCRAKPWalkStopsWhenTheBudgetIsSpent(t *testing.T) {
	bmc := newRejectingBMC(t, 0x02)
	tgt := exhaustionTarget(bmc.port())
	flow := ipmi.AuthFlow{Version: "2.0", Mode: "smcrakpFixedKey", Username: "ADMIN",
		Suite: ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityHMACSHA196, Conf: ipmi.ConfAESCBC}}

	inv, err := collectPostAuthWithMatrix(expiredContext(t), tgt, flow, func(string, ...any) {})

	if got := bmc.opens.Load(); got != 0 {
		t.Errorf("walked %d candidates on an expired context in the smcrakp arm", got)
	}
	if err == nil {
		t.Fatal("expected an error: the budget was already spent")
	}
	if inv == nil {
		t.Fatal("collection dropped entirely")
	}
	if !strings.Contains(inv.Error, "deadline") {
		t.Errorf("coverageError = %q, want the deadline named", inv.Error)
	}
}

// A walk where no candidate ever got a session open still measured something: the
// collector records the step it stopped at. Replacing that with a synthetic collection
// built from the flow and the attempt list throws the marker away, and the finding then
// reports a host that looks like it was never enumerated instead of one whose sessions
// were refused.
func TestCipherMatrixKeepsTheLastFailedCollection(t *testing.T) {
	bmc := newRejectingBMC(t, 0x02)
	tgt := exhaustionTarget(bmc.port())
	flow := ipmi.AuthFlow{Version: "2.0", Mode: "cred", Username: "ADMIN", Password: "x",
		Suite: ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityHMACSHA196, Conf: ipmi.ConfAESCBC}}

	inv, err := collectPostAuthWithMatrix(context.Background(), tgt, flow, func(string, ...any) {})
	if err == nil {
		t.Fatal("expected an error from a BMC that refuses every session")
	}
	if inv == nil {
		t.Fatal("collection dropped entirely")
	}
	if inv.IncompleteAt != "sessionOpen" {
		t.Fatalf("dropped IncompleteAt: got %q, want \"sessionOpen\" -- the walk replaced the collection "+
			"the collector returned with a synthetic one that records nothing about where it stopped", inv.IncompleteAt)
	}
	if summary := postAuthInventorySummary(inv); !strings.Contains(summary, "stoppedAt=sessionOpen") {
		t.Errorf("collected=%q does not name the step the run stopped at", summary)
	}
	if len(inv.CipherMatrix) == 0 {
		t.Error("cipher matrix lost: the kept collection still has to carry every suite that was tried")
	}
}

// Same rule in the fixed-key arm, which builds its own synthetic collection.
func TestSMCRAKPWalkKeepsTheLastFailedCollection(t *testing.T) {
	bmc := newRejectingBMC(t, 0x02)
	tgt := exhaustionTarget(bmc.port())
	flow := ipmi.AuthFlow{Version: "2.0", Mode: "smcrakpFixedKey", Username: "ADMIN",
		Suite: ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityHMACSHA196, Conf: ipmi.ConfAESCBC}}

	inv, err := collectPostAuthWithMatrix(context.Background(), tgt, flow, func(string, ...any) {})
	if err == nil {
		t.Fatal("expected an error from a BMC that refuses every session")
	}
	if inv == nil {
		t.Fatal("collection dropped entirely")
	}
	if inv.IncompleteAt != "sessionOpen" {
		t.Fatalf("dropped IncompleteAt: got %q, want \"sessionOpen\"", inv.IncompleteAt)
	}
	if len(inv.CipherMatrix) == 0 {
		t.Error("cipher matrix lost")
	}
}
