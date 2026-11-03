package report

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

// loadWithPot loads one source with a potfile predicate attached, so the offline
// recovery path can be exercised without the hashcrack machinery.
func loadWithPot(t *testing.T, name string, pot func(*scanfile.Record) []PotCrack, lines ...string) *Source {
	t.Helper()
	src, _, err := LoadSource(Input{
		Name:     name,
		Path:     writeLines(t, name+".jsonl", lines...),
		PotCheck: pot,
	})
	if err != nil {
		t.Fatalf("LoadSource: %v", err)
	}
	return src
}

// TestEscalationLegAloneIsNotAdmin pins the half of the privilege model that a
// flat OR gets wrong in the generous direction: CVE-2026-65220 turns any low-privilege
// account into an Administrator, but on its own it is not remote access, so it
// must not report as an administrator-equivalent compromise.
func TestEscalationLegAloneIsNotAdmin(t *testing.T) {
	v := loadOne(t, "esc",
		`{"host":"10.0.0.1","identity":{"class":"bmc","vendor":"supermicro"},"findings":[{"check":"ipmi.smc.rakpReservedRole","risk":"medium"}]}`,
	).view()
	if v.Admin != 0 {
		t.Errorf("admin hosts = %d, want 0: an escalation leg with no entry leg is not access", v.Admin)
	}
	if v.EscalationOnly != 1 {
		t.Errorf("escalationOnly = %d, want 1", v.EscalationOnly)
	}
	if v.ImmediateExt != 1 {
		t.Errorf("immediateExt = %d, want 1: the leg is still real exposure and must stay visible", v.ImmediateExt)
	}
	if got := exposureHosts(v.Exposures, "ipmi_role_escalation"); got != 1 {
		t.Errorf("ipmi_role_escalation exposure = %d, want 1", got)
	}
}

// TestChainComposesToAdmin pins the other half: a pre-auth foothold whose
// privilege is unproven, plus a credential-gated escalation on the same host, is
// an administrator-equivalent compromise. Neither leg says so alone.
func TestChainComposesToAdmin(t *testing.T) {
	v := loadOne(t, "chain",
		// Entry leg only: a cracked named account, privilege unproven.
		`{"host":"10.0.0.1","identity":{"class":"bmc","vendor":"supermicro"},"rakp":[{"username":"guest","authAlgo":1,"cracked":"guest"}]}`,
		// Both legs: the same entry plus the reserved-role escalation.
		`{"host":"10.0.0.2","identity":{"class":"bmc","vendor":"supermicro"},"rakp":[{"username":"guest","authAlgo":1,"cracked":"guest"}],"findings":[{"check":"ipmi.smc.rakpReservedRole","risk":"medium"}]}`,
	).view()
	if v.ImmediateExt != 2 {
		t.Fatalf("immediateExt = %d, want 2", v.ImmediateExt)
	}
	if v.Admin != 1 {
		t.Errorf("admin hosts = %d, want 1: only .2 carries both legs", v.Admin)
	}
	if v.Chained != 1 {
		t.Errorf("chained = %d, want 1: .2's administrator reach exists only via the composition", v.Chained)
	}
	if v.EscalationOnly != 0 {
		t.Errorf("escalationOnly = %d, want 0: both hosts have an entry leg", v.EscalationOnly)
	}
}

// TestOpenBMCLegsAreDistinct pins the leg split. Before it, the userKey bypass
// (unauthenticated, privilege unproven) and the RAKP1 relabel (needs a
// credential, reaches Administrator) shared one key, so a host with either read
// identically -- and a host with the full chain was indistinguishable from a
// host with only one half of it.
func TestOpenBMCLegsAreDistinct(t *testing.T) {
	v := loadOne(t, "obmc",
		`{"host":"10.0.0.1","identity":{"class":"bmc","vendor":"openbmc"},"findings":[{"check":"ipmi.openbmc.defaultUserKeyAuthBypass","risk":"critical","fields":{"authBypassed":"true"}}]}`,
		`{"host":"10.0.0.2","identity":{"class":"bmc","vendor":"openbmc"},"findings":[{"check":"ipmi.openbmc.rakp1ActiveRelabel","risk":"medium"}]}`,
		`{"host":"10.0.0.3","identity":{"class":"bmc","vendor":"openbmc"},"findings":[{"check":"ipmi.openbmc.defaultUserKeyAuthBypass","risk":"critical","fields":{"authBypassed":"true"}},{"check":"ipmi.openbmc.rakp1ActiveRelabel","risk":"medium"}]}`,
		// The newer emitter records that the bypass supplied the seed, so the whole
		// chain ran with no credential at all.
		`{"host":"10.0.0.4","identity":{"class":"bmc","vendor":"openbmc"},"findings":[{"check":"ipmi.rakp.state.activeRelabelLowToAdmin","risk":"high","fields":{"credentialRequired":"false"}}]}`,
	).view()
	if got := exposureHosts(v.Compromise, "openbmc_userkey"); got != 2 {
		t.Errorf("openbmc_userkey = %d, want 2 (.1 and .3)", got)
	}
	if got := exposureHosts(v.Compromise, "relabel_admin"); got != 2 {
		t.Errorf("relabel_admin = %d, want 2 (.2 and .3)", got)
	}
	if got := exposureHosts(v.Compromise, "relabel_admin_unauth"); got != 1 {
		t.Errorf("relabel_admin_unauth = %d, want 1 (.4)", got)
	}
	// .3 composes both legs, .4 is unauthenticated-to-Administrator outright.
	// .1 has only a session and .2 has only an escalation leg.
	if v.Admin != 2 {
		t.Errorf("admin hosts = %d, want 2 (.3 composed, .4 direct)", v.Admin)
	}
	if v.Chained != 1 {
		t.Errorf("chained = %d, want 1 (.3 only)", v.Chained)
	}
}

// TestHostReachCountsKVMBypassAndAdmin pins the host axis: the Supermicro
// wstunnel bypass reaches console and virtual media without proving anything
// about privilege on the BMC, and it previously scored no compromise path at all
// despite being the single largest observed path in the external corpus.
func TestHostReachCountsKVMBypassAndAdmin(t *testing.T) {
	v := loadOne(t, "hostreach",
		`{"host":"10.0.0.1","identity":{"class":"bmc","vendor":"supermicro"},"findings":[{"check":"kvm.smc.ws.bypass","risk":"high"}]}`,
		`{"host":"10.0.0.2","identity":{"class":"bmc","vendor":"supermicro"},"findings":[{"check":"ipmi.v20.cipherZero","risk":"critical"}]}`,
	).view()
	if got := exposureHosts(v.Compromise, "smc_kvm_bypass"); got != 1 {
		t.Errorf("smc_kvm_bypass path = %d, want 1", got)
	}
	if v.HostReach != 2 {
		t.Errorf("hostReach = %d, want 2: the KVM bypass reaches the host directly and cipher-zero admin implies it", v.HostReach)
	}
	if v.Admin != 1 {
		t.Errorf("admin hosts = %d, want 1: the KVM bypass proves nothing about BMC privilege", v.Admin)
	}
}

// TestPotfileNamedCrackIsACompromisePath pins the potfile gap. A hash recovered
// offline is the same usable credential as one recovered in the scan window, but
// the plaintext was passed without its account, so the named-account path could
// only ever fire on a live crack.
func TestPotfileNamedCrackIsACompromisePath(t *testing.T) {
	pot := func(rec *scanfile.Record) []PotCrack {
		var out []PotCrack
		for i := range rec.RAKP {
			if rec.RAKP[i].RAKPHash != "" {
				out = append(out, PotCrack{Username: rec.RAKP[i].Username, Password: "recovered"})
			}
		}
		return out
	}
	v := loadWithPot(t, "pot", pot,
		// Named account, hash captured, nothing cracked during the scan.
		`{"host":"10.0.0.1","identity":{"class":"bmc","vendor":"supermicro"},"rakp":[{"username":"ADMIN","authAlgo":1,"rakpHash":"aa"}]}`,
		// Empty/callback account: recovered, but not a usable credential.
		`{"host":"10.0.0.2","identity":{"class":"bmc","vendor":"supermicro"},"rakp":[{"username":"","authAlgo":1,"rakpHash":"bb"}]}`,
	).view()
	if v.Cracks.ScanAny != 0 {
		t.Fatalf("scanAny = %d, want 0: neither host cracked in the scan window", v.Cracks.ScanAny)
	}
	if v.Cracks.PotOnly != 2 {
		t.Fatalf("potOnly = %d, want 2", v.Cracks.PotOnly)
	}
	if got := exposureHosts(v.Compromise, "rakp_named"); got != 1 {
		t.Errorf("rakp_named = %d, want 1: the offline recovery on ADMIN is a usable credential", got)
	}
	if v.ImmediateExt != 1 {
		t.Errorf("immediateExt = %d, want 1", v.ImmediateExt)
	}
}

// TestUnclassifiedFindingsAreCounted pins the runtime guard. A finding whose
// check id maps to nothing must be reported as unclassified rather than
// contributing silently to no rollup, which is how an actively-confirmed defect
// can be absent from every number on the page.
func TestUnclassifiedFindingsAreCounted(t *testing.T) {
	v := loadOne(t, "unclass",
		`{"host":"10.0.0.1","identity":{"class":"bmc","vendor":"supermicro"},"findings":[{"check":"ipmi.somethingBrandNew","risk":"critical"},{"check":"ipmi.v20.cipherZero","risk":"critical"}]}`,
	).view()
	if v.Unclassified != 1 {
		t.Fatalf("unclassified = %d, want 1", v.Unclassified)
	}
	if len(v.UnclassifiedIDs) != 1 || v.UnclassifiedIDs[0].Value != "ipmi.somethingBrandNew" {
		t.Errorf("unclassifiedIds = %+v, want the one unmapped check id", v.UnclassifiedIDs)
	}
	// A generic protocol-presence column is not a classification: the unmapped
	// check set "ipmi" for free via the prefix rule and must still be flagged.
	if got := exposureHosts(v.Exposures, "ipmi"); got != 1 {
		t.Errorf("ipmi exposure = %d, want 1", got)
	}
}

// TestSeverityBucketsSumToBMCPopulation pins the denominator agreement the
// overview slide depends on. Counting severity over every responder while
// dividing by the BMC-only population produced bands summing to 117%, which is
// exactly the kind of arithmetic a reader checks first.
func TestSeverityBucketsSumToBMCPopulation(t *testing.T) {
	src := loadOne(t, "sev",
		// Two BMCs: one critical, one with nothing actionable.
		`{"host":"10.0.0.1","identity":{"class":"bmc","vendor":"supermicro"},"findings":[{"check":"ipmi.v20.cipherZero","risk":"critical"}]}`,
		`{"host":"10.0.0.2","identity":{"class":"bmc","vendor":"supermicro"},"findings":[{"check":"ipmi.versions","risk":"info","fields":{"versions":"2.0"}}]}`,
		// A honeypot and a serial console, which must not land in the BMC bands.
		`{"host":"10.0.0.3","identity":{"class":"honeypot","vendor":"honeypot"},"findings":[{"check":"ipmi.v20.cipherZero","risk":"critical"}]}`,
		`{"host":"10.0.0.4","identity":{"class":"serial console","vendor":"lantronix"},"findings":[{"check":"tcp.telnetBanner","risk":"low"}]}`,
	)
	bmc := bmcPopulation(src)
	if bmc != 2 {
		t.Fatalf("bmcPopulation = %d, want 2", bmc)
	}
	sum := 0
	for _, band := range []string{"critical", "high", "medium", "low", "none"} {
		sum += src.bmcSeverity[band]
	}
	if sum != bmc {
		t.Errorf("BMC severity bands sum to %d, want %d: the overview percentages will not add up", sum, bmc)
	}
	if src.bmcSeverity["critical"] != 1 {
		t.Errorf("bmcSeverity[critical] = %d, want 1 (the honeypot's critical must not count)", src.bmcSeverity["critical"])
	}
	// The all-responder counters exclude honeypots too: a decoy record returns
	// before the severity switch, so it lands in no band. That means those bands
	// sum to (Total - honeypots), not Total -- which is why the BMC-scoped set
	// exists rather than reusing them with a BMC denominator.
	if src.withCritical != 1 {
		t.Errorf("withCritical = %d, want 1: the honeypot's critical finding is withheld", src.withCritical)
	}
	allBands := src.withCritical + src.withHigh + src.withMedium + src.withLow + src.withNone
	if allBands != src.Total-src.honeypotHosts {
		t.Errorf("all-responder bands sum to %d, want %d (Total - honeypots)", allBands, src.Total-src.honeypotHosts)
	}
}
