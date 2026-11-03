package check

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// A confirmed bypass has to leave the stale bmcRandomNum behind as evidence: it is what
// lets the post-auth stage reopen the CALLBACK session and apply the RAKP1 relabel. The
// value must round-trip as the pointer type selectOpenBMCBypassRelabelFlow asserts on.
func TestConfirmedBypassPublishesReusableEvidence(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10"}
	conf := &DefaultUserKeyBypassProbe{
		Suite: 3, AuthAlgo: ipmi.RAKPHMACSHA1,
		BMCSID: 0x0a0b0c0d, ClientSID: 0xb0b1b2b3,
		RAKP1Status: 0x0a, RAKP3Status: 0x00,
		AuthBypassed: true, UsernameUsed: "root", ReqPrivLevel: 0x04,
		WinBMCRand: bytes.Repeat([]byte{0xab}, 16),
	}

	got := reportDefaultUserKeyBypass(tgt, conf, 623)
	if len(got) != 1 {
		t.Fatalf("want one finding for a confirmed bypass, got %d", len(got))
	}
	if got[0].Check != "ipmi.openbmc.defaultUserKeyAuthBypass" {
		t.Errorf("check = %q, want ipmi.openbmc.defaultUserKeyAuthBypass", got[0].Check)
	}
	if got[0].Port != 623 {
		t.Errorf("port = %d, want the stamped IPMI port 623", got[0].Port)
	}

	v, ok := tgt.Evidenced("ipmi.openBmcDefaultUserKey")
	if !ok {
		t.Fatal("confirmed bypass recorded no evidence; the relabel chain has nothing to reopen")
	}
	stored, _ := v.(*DefaultUserKeyBypassProbe)
	if stored == nil {
		t.Fatalf("evidence is %T, want *DefaultUserKeyBypassProbe as the consumer asserts", v)
	}
	if !bytes.Equal(stored.WinBMCRand, conf.WinBMCRand) {
		t.Errorf("stored bmcRandomNum = %x, want the winning %x", stored.WinBMCRand, conf.WinBMCRand)
	}
}

// The publish gate turns on a usable residue, not on a nonzero one: the bounded
// patch-status probe guesses all zeroes, and that win is as replayable as any other.
func TestPublishOpenBMCUserKeyEvidenceGates(t *testing.T) {
	for _, tc := range []struct {
		name  string
		probe *DefaultUserKeyBypassProbe
		want  bool
	}{
		{"confirmed with a full residue", &DefaultUserKeyBypassProbe{AuthBypassed: true, WinBMCRand: bytes.Repeat([]byte{0xab}, 16)}, true},
		{"confirmed with the all-zero cold-boot residue", &DefaultUserKeyBypassProbe{AuthBypassed: true, WinBMCRand: make([]byte, 16)}, true},
		{"not confirmed", &DefaultUserKeyBypassProbe{WinBMCRand: bytes.Repeat([]byte{0xab}, 16)}, false},
		{"confirmed but no residue", &DefaultUserKeyBypassProbe{AuthBypassed: true}, false},
		{"confirmed but a short residue", &DefaultUserKeyBypassProbe{AuthBypassed: true, WinBMCRand: make([]byte, 8)}, false},
		{"no probe", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tgt := &engine.Target{Host: "192.0.2.11"}
			publishOpenBMCUserKeyEvidence(tgt, tc.probe)
			if _, ok := tgt.Evidenced("ipmi.openBmcDefaultUserKey"); ok != tc.want {
				t.Errorf("evidence published = %t, want %t", ok, tc.want)
			}
		})
	}
}

// The confirming branches are spread across the bounded probe, the auto-confirm rounds
// and the opt-in sweep, so the invariant is enforced structurally: the critical finding
// may only be built inside reportDefaultUserKeyBypass, which publishes first. A branch
// that calls the constructor directly emits a critical carrying no reusable
// bmcRandomNum, and the relabel chain stops there with nothing to report.
func TestDefaultUserKeyCriticalFindingOnlyBuiltByPublisher(t *testing.T) {
	const (
		src       = "ipmi_openbmc_default_userkey.go"
		builder   = "defaultUserKeyCriticalFinding"
		publisher = "reportDefaultUserKeyBypass"
	)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}
	calls := 0
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name == builder {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || id.Name != builder {
				return true
			}
			calls++
			if fn.Name.Name != publisher {
				t.Errorf("%s builds the critical finding at %s; route it through %s so the winning bmcRandomNum is published",
					fn.Name.Name, fset.Position(call.Pos()), publisher)
			}
			return true
		})
	}
	if calls == 0 {
		t.Fatalf("no %s call found; the invariant this test guards has moved", builder)
	}
}
