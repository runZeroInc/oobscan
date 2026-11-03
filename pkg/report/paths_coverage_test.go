package report

import (
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/check"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

// The compromise model is two hand-maintained switches over a check registry
// that grows independently of them, which is a standing invitation to the same
// failure twice over: a check that proves unauthenticated access scores nothing
// and never appears in a rollup, or a path row survives in the taxonomy after
// nothing can produce it any more and reports a permanent zero. The tests here
// pin both directions.

// pathWitness is one finding that must produce one compromise-path key. It
// doubles as the check-id-to-path documentation: the mapping lives in
// scoreCompromiseFinding, and this table is what asserts the mapping is total.
type pathWitness struct {
	check  string
	fields []engine.Field
	want   string
}

func f(pairs ...string) []engine.Field {
	out := make([]engine.Field, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, engine.Field{Key: pairs[i], Val: pairs[i+1]})
	}
	return out
}

var pathWitnesses = []pathWitness{
	{check: "ipmi.v20.cipherZero", want: "cipher_zero"},
	{check: "ipmi.v15.authNoneSession", want: "ipmi_auth_none"},
	{check: "ipmi.v20.defaultCreds", fields: f("username", "ADMIN"), want: "ipmi_default_creds"},
	{check: "ipmi.v15.defaultCreds", fields: f("username", "root"), want: "ipmi_default_creds"},
	{check: "ipmi.v20.smcrakpBypass", want: "smcrakp_bypass"},
	{check: "ipmi.ilo.rakpNoneBypass", want: "ilo_ipmi_bypass"},
	{check: "ipmi.openbmc.defaultUserKeyAuthBypass", fields: f("authBypassed", "true"), want: "openbmc_userkey"},
	{check: "ipmi.openbmc.rakp1ActiveRelabel", want: "relabel_admin"},
	{check: "ipmi.rakp.state.activeRelabelLowToAdmin", fields: f("credentialRequired", "true"), want: "relabel_admin"},
	{check: "ipmi.rakp.state.activeRelabelLowToAdmin", fields: f("credentialRequired", "false"), want: "relabel_admin_unauth"},
	{check: "ipmi.smc.rakpReservedRole", want: "smc_reserved_role"},
	{check: "ipmi.smc.rakpUnorderedForge", want: "smc_rakp_forge"},
	{check: "ipmi.netfnOem", want: "ipmi_oem_preauth"},
	{check: "http.smc.psBlock", want: "smc_psblock_creds"},
	{check: "http.redfish.amiBypass", want: "ami_redfish_bypass"},
	{check: "http.redfish.ami.cve202334329", want: "ami_redfish_bypass"},
	{check: "http.redfish.ami.noXffBypass", want: "ami_redfish_bypass"},
	{check: "tls.mtls.ami.caBypass", want: "ami_mtls_bypass"},
	{check: "http.ilo.authBypass", want: "ilo_http_bypass"},
	{check: "ssh.hpe.iloSSHOverflow", want: "ssh_ilo_overflow"},
	{check: "ssh.defaultCreds", want: "ssh_default_creds"},
	{check: "kvm.vnc.unauth", want: "kvm_no_auth"},
	{check: "ipkvm.noAuth", want: "kvm_no_auth"},
	{check: "kvm.vnc.defaultCreds", want: "vnc_default_creds"},
	{check: "kvm.smc.ws.bypass", want: "smc_kvm_bypass"},
	{check: "kvm.smc.ikvm.sessionHijack", want: "smc_ikvm_hijack"},
	{check: "amt.authBypass", want: "amt_auth_bypass"},
	{check: "http.apc.demoBackdoor", want: "apc_demo_backdoor"},
	{check: "http.idrac.defaultCreds", want: "web_default_creds"},
	// rakp_named comes from recovered RAKP material rather than a finding, so it
	// has no witness here; TestPotfileNamedCrackIsACompromisePath covers it.
}

// TestCompromisePathWitnessesScore asserts every witness produces exactly the
// path it claims. A mapping renamed on one side only fails here.
func TestCompromisePathWitnessesScore(t *testing.T) {
	for _, w := range pathWitnesses {
		got := map[string]bool{}
		scoreCompromiseFinding(&engine.Finding{Check: w.check, Fields: w.fields}, got)
		if !got[w.want] {
			t.Errorf("%s scored %v, want the %q compromise path", w.check, keysOf(got), w.want)
		}
	}
}

// TestCompromisePathsAreProducible asserts no path row is dead. A row nothing
// can set reports a permanent zero, which reads as "measured none" rather than
// "not wired up" -- exactly how the OpenBMC leg split could have gone wrong.
func TestCompromisePathsAreProducible(t *testing.T) {
	produced := map[string]bool{"rakp_named": true} // set from RAKP material, not a finding
	for _, w := range pathWitnesses {
		got := map[string]bool{}
		scoreCompromiseFinding(&engine.Finding{Check: w.check, Fields: w.fields}, got)
		for key := range got {
			produced[key] = true
		}
	}
	for _, p := range CompromisePaths {
		if !produced[p.Key] {
			t.Errorf("compromise path %q is in the taxonomy but no check produces it: it will report a permanent zero", p.Key)
		}
	}
	for key := range produced {
		if _, ok := pathByKey[key]; !ok {
			t.Errorf("scoreCompromiseFinding produces %q but CompromisePaths has no such row: classifyAccess cannot place it on the privilege axis", key)
		}
	}
}

// TestCompromisePathsWellFormed asserts the taxonomy itself is sound: unique
// keys, and an Entry/Gain on every row so classifyAccess can never silently
// drop one out of the administrator rollup.
func TestCompromisePathsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range CompromisePaths {
		if seen[p.Key] {
			t.Errorf("duplicate compromise path key %q", p.Key)
		}
		seen[p.Key] = true
		if p.Label == "" || p.Short == "" {
			t.Errorf("%s: label and short code are both required for the dense headers", p.Key)
		}
		switch p.Entry {
		case EntryNone, EntryLowPriv:
		default:
			t.Errorf("%s: entry %q is not a known precondition", p.Key, p.Entry)
		}
		switch p.Gain {
		case GainSession, GainAdmin, GainHost:
		default:
			t.Errorf("%s: gain %q is not a known reach", p.Key, p.Gain)
		}
	}
}

// accessPathExempt records the auth/creds-category checks that deliberately
// establish no access path, with the reason. Anything else in those categories
// has to be classified, so a newly added authentication defect cannot reach the
// report as a check-histogram row and nothing else.
var accessPathExempt = map[string]string{
	"ipmi.rakpRatelimit":        "absent RAKP throttling is a hardening gap, not an access path",
	"ipmi.smc.rakpUnordered":    "signature only (CVE-2026-65219): proves the state machine is unordered, not that a session opened; the Forge variant is the path",
	"ipmi.postAuthEnum":         "post-auth inventory: presupposes the credential another path supplied",
	"http.redfish.postAuthEnum": "post-auth inventory, as above",
	"http.wsman.postAuthEnum":   "post-auth inventory, as above",
	"ipkvm.posture":             "TLS/auth posture of a standalone KVM, not a confirmed bypass",
	"http.nanokvm.universalKey": "shared content-encryption key: no session and no credential recovered",
	"ssh.sharedHostKey":         "scores the ssh_shared_key exposure; impersonation needs an active MITM position",
}

// producerFindingIDs maps a registered check whose name is not the id it emits
// onto the finding ids it does emit, so the registry sweep resolves the same
// mapping the analysis sees.
var producerFindingIDs = map[string][]string{
	"ipmi.defaultCreds": {"ipmi.v20.defaultCreds", "ipmi.v15.defaultCreds"},
	"ipmi.v15.session":  {"ipmi.v15.authNoneSession", "ipmi.v15.defaultCreds"},
}

// TestAuthChecksAreClassified sweeps the live check registry: every check in the
// auth and creds categories, plus anything whose name reads as an access defect,
// must score an exposure column or a compromise path. This is the guard that
// closes the loop -- the taxonomy tests above only see what the witness table
// already knows about, whereas this one sees checks added after it was written.
func TestAuthChecksAreClassified(t *testing.T) {
	for _, c := range check.All() {
		if !accessRelevantCheck(c) {
			continue
		}
		if reason, ok := accessPathExempt[c.Name]; ok {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s: exemption needs a reason", c.Name)
			}
			continue
		}
		ids := producerFindingIDs[c.Name]
		if len(ids) == 0 {
			ids = []string{c.Name}
		}
		for _, id := range ids {
			exp, paths := map[string]bool{}, map[string]bool{}
			scoreCheck(id, exp)
			scoreCompromiseFinding(&engine.Finding{Check: id, Fields: permissiveFields()}, paths)
			if unclassifiedScore(exp, paths) {
				t.Errorf("check %q (category %s) scores no exposure column and no compromise path: it would reach the report as a check-histogram row and nothing else. Map it in scoreCheck/scoreCompromiseFinding, or add it to accessPathExempt with a reason.",
					id, c.Category)
			}
		}
	}
}

// permissiveFields supplies the field values the positive branch of every
// field-gated mapping wants, so the sweep tests "can this check ever be
// classified" rather than "is it classified with empty fields".
func permissiveFields() []engine.Field {
	return f(
		"username", "ADMIN",
		"authBypassed", "true",
		"exploitable", "true",
		"credentialRequired", "true",
	)
}

// accessRelevantCheck reports whether a registered check has to carry a
// classification: the auth and creds categories by definition, plus any name
// that reads as an authentication or authorization defect regardless of the
// category it was filed under.
func accessRelevantCheck(c check.Check) bool {
	switch c.Category {
	case "auth", "creds":
		return true
	}
	name := strings.ToLower(c.Name)
	for _, tok := range []string{"bypass", "backdoor", "defaultcreds", "noauth", "unauth",
		"skipauth", "forge", "hijack", "escalat", "relabel", "overflow"} {
		if strings.Contains(name, tok) {
			return true
		}
	}
	return false
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
