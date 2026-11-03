package check

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/snmp"
)

func TestParseOperatorLocalizedKey(t *testing.T) {
	if _, ok := parseOperatorLocalizedKey(""); ok {
		t.Error("empty spec should not parse")
	}
	if _, ok := parseOperatorLocalizedKey("useronly"); ok {
		t.Error("spec without a key should not parse")
	}
	c, ok := parseOperatorLocalizedKey("Administrator:7df2f293")
	if !ok || c.User != "Administrator" || c.AuthKeyHex != "7df2f293" || c.AuthProto != "SHA256" {
		t.Fatalf("auth-only parse = %+v (ok=%v)", c, ok)
	}
	if c.PrivKeyHex != "" {
		t.Errorf("auth-only spec should leave priv key empty, got %q", c.PrivKeyHex)
	}
	c, ok = parseOperatorLocalizedKey("admin:aabb:ccdd")
	if !ok || c.PrivKeyHex != "ccdd" || c.PrivProto != "AES" {
		t.Fatalf("auth+priv parse = %+v (ok=%v)", c, ok)
	}
}

func TestSNMPV3Secret(t *testing.T) {
	if got := snmpV3Secret(snmp.V3Cred{AuthPass: "initial1"}); got != "initial1" {
		t.Errorf("passphrase secret = %q, want initial1", got)
	}
	if got := snmpV3Secret(snmp.V3Cred{AuthKeyHex: "dead"}); got != "localizedKey=dead" {
		t.Errorf("localized secret = %q, want localizedKey=dead", got)
	}
	if got := snmpV3Secret(snmp.V3Cred{}); got != "" {
		t.Errorf("empty cred secret = %q, want empty", got)
	}
}

func TestSNMPV3CandidatesLocalizedDefault(t *testing.T) {
	localizedCount := func(creds []snmp.V3Cred) int {
		n := 0
		for _, c := range creds {
			if c.AuthKeyHex != "" {
				n++
			}
		}
		return n
	}
	nLocalized := len(snmp.LocalizedV3Creds)

	// A Huawei-identified host now gets the localized-key creds by default (no
	// flag required). Huawei ships no passphrase profile, so those are all it gets.
	huawei := &engine.Target{Identity: &engine.Identity{Vendor: "huawei"}}
	if got := snmpV3Candidates(huawei); len(got) != nLocalized || localizedCount(got) != nLocalized {
		t.Fatalf("huawei default: got %d candidates (%d localized), want %d localized", len(got), localizedCount(got), nLocalized)
	}

	// A v3-responsive host of any other vendor also gets the localized creds
	// tried, regardless of vendor fingerprint (APC keeps its passphrase profiles).
	apc := &engine.Target{Identity: &engine.Identity{Vendor: "apc"}}
	if got := snmpV3Candidates(apc); len(got) != 2+nLocalized || localizedCount(got) != nLocalized {
		t.Fatalf("apc default: got %d candidates (%d localized), want %d (2 apc + %d localized)", len(got), localizedCount(got), 2+nLocalized, nLocalized)
	}

	// An unknown-vendor v3 host falls back to the full passphrase list plus the
	// localized creds.
	unknown := &engine.Target{}
	if got := snmpV3Candidates(unknown); localizedCount(got) != nLocalized {
		t.Fatalf("unknown-vendor default: %d localized creds, want %d", localizedCount(got), nLocalized)
	}

	// Operator-supplied key is prepended ahead of the default sweep.
	op := &engine.Target{Identity: &engine.Identity{Vendor: "huawei"}, SNMPV3LocalizedKey: "Administrator:aabb"}
	got := snmpV3Candidates(op)
	if len(got) != 1+nLocalized || got[0].Name != "operator-localized" {
		t.Fatalf("operator key: got %+v, want operator-localized first + %d localized", got, nLocalized)
	}
}
