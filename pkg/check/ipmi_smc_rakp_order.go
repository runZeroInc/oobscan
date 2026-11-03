package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/guid"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// Supermicro/ATEN RMCP+ key-exchange ordering and role-dispatch defects.
//
// The default checks validate protocol behavior without obtaining a session or
// activating a payload. The unordered probe sends a wrong authentication code
// and can increment record 0's failure counter. The reserved-role probe stops
// before credential verification. Session validation is available through
// smc-rakp-bypass, smc-priv-esc, and the opt-in --ipmi-full check.
//
// ipmi.smc.rakpUnordered (CVE-2026-65219) sends Open Session then RAKP message 3 with no
// message 1, signed with a key that cannot be correct. A message 4 echoing our
// console session ID with status 0x08 proves the slot was located and the auth code
// computed for an out-of-order message 3; unaffected stacks answer 0x0f.
//
// ipmi.smc.rakpReservedRole (CVE-2026-65220) compares how RAKP message 1 answers a valid
// role byte against a reserved nibble. A conformant handler refuses the reserved
// byte; the affected ATEN handler accepts it because its dispatch on the upper nibble
// has no default arm.
func init() {
	Register(Check{
		Name:        "ipmi.smc.rakpUnordered",
		Description: "Supermicro/ATEN RMCP+ accepts RAKP message 3 with no preceding message 1 (CVE-2026-65219): the key-exchange state machine is unordered, so on a session slot unallocated since boot the whole message-3 transcript is known and only user record 0's short stored password stands between an attacker and a no-password session with host serial console (SOL)",
		Category:    "auth",
		Applies:     Applicability{Vendors: []string{"supermicro"}},
		Enabled:     true,
		Run:         runSMCUnorderedRAKP3,
	})
	RegisterExplain("ipmi.smc.rakpUnordered", explainSMCUnorderedRAKP3)

	Register(Check{
		Name:        "ipmi.smc.rakpReservedRole",
		Description: "Supermicro/ATEN RMCP+ RAKP message 1 accepts a reserved privilege-role nibble (CVE-2026-65220): the role dispatch has no default arm, so the reserved arm copies the session slot's existing privilege over the per-user clamp and any account holding a valid low-privilege credential escalates to Administrator",
		Category:    "auth",
		Applies:     Applicability{Vendors: []string{"supermicro"}},
		Enabled:     true,
		Run:         runSMCReservedRole,
	})
	RegisterExplain("ipmi.smc.rakpReservedRole", explainSMCReservedRole)

	// ipmi.smc.rakpUnorderedForge is the opt-in (--ipmi-full) validation of
	// CVE-2026-65219: a single record-0 key guess, ordered by the generation this host
	// detected, testing for the same forged SOL session the `oobscan smc-rakp-bypass`
	// subcommand proves by hand. Unlike ipmi.smc.rakpUnordered above it is a real
	// credential guess against user record 0 and carries the lock-window cost
	// documented on ForgeSMCUnorderedRAKP3/smcDefaultForgeAttempts, so it stays out
	// of the default scan.
	Register(Check{
		Name:        "ipmi.smc.rakpUnorderedForge",
		Description: "Supermicro/ATEN CVE-2026-65219 one-shot record-0 forge: tries the single generation-best candidate key and, on success, confirms the forged session's read-only reach (--ipmi-full; a real credential guess against user record 0, so it is opt-in and not part of the default scan)",
		Category:    "auth",
		Applies:     Applicability{Vendors: []string{"supermicro"}},
		Enabled:     true,
		Run:         runSMCUnorderedForge,
	})
	RegisterExplain("ipmi.smc.rakpUnorderedForge", explainSMCUnorderedForge)
}

// smcATENGeneration reports the Supermicro BMC generation from the pre-auth
// System GUID board code, and whether the target is on the ATEN lineage these
// defects live in. X14 runs OpenBMC netipmid and is not affected by either, so it
// is skipped outright rather than probed and reported as negative. An unknown
// generation is probed: X12 and X13 have the defect in their decompiles but no
// hardware confirmation, and field boards carry board codes not in the table.
func smcATENGeneration(t *engine.Target) (gen string, aten bool) {
	v, ok := t.Evidenced("guid")
	if !ok {
		return "", true
	}
	g, ok := v.(*guid.Result)
	if !ok || g == nil {
		return "", true
	}
	gen = guid.SMCGenerationFromModelPrefix(g.Fields["model_prefix"])
	if strings.EqualFold(gen, "X14") {
		return gen, false
	}
	return gen, true
}

func runSMCUnorderedRAKP3(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	// The probe sends a deliberately wrong authentication code, which is an active
	// (if unverifiable) login attempt on the wire, so honor --disable-logins.
	if t.DisableLogins {
		return nil
	}
	gen, aten := smcATENGeneration(t)
	if !aten {
		return nil
	}
	port := t.IPMIPort()
	probe, err := ipmi.ProbeSMCUnorderedRAKP3(t.Host, port, t.Timeout)
	if probe == nil {
		return nil
	}
	// Record the evidence even when the probe failed. An ATEN board that has stopped
	// answering a hammering source produces exactly the same "no finding" as a board
	// that was probed and refused the out-of-order message 3, and without the
	// evidence row those two are indistinguishable afterwards.
	t.SetEvidence("ipmi.smc.rakpUnordered", probe)
	if err != nil || !probe.Defect {
		// Report the negative arm too, so a board measured clean is distinguishable from
		// one that never answered. Findings carry only the positive case otherwise, and
		// an all-positive corpus cannot show the discriminator (0x08+SID affected,
		// 0x0f conformant) ever discriminated.
		return stampIPMI([]engine.Finding{smcUnorderedRAKP3NegativeFinding(port, gen, probe, err)}, port)
	}
	return stampIPMI([]engine.Finding{smcUnorderedRAKP3Finding(port, gen, probe)}, port)
}

// smcUnorderedRAKP3Finding reports the ordering defect at medium, not high: what is
// measured is that message 3 is processed out of order, which is the mechanism.
// Reaching the SOL console with it additionally needs user record 0's stored
// password (short and guessable, but a guess) and a session slot that has
// not been allocated since boot, which in practice means a window after a BMC
// reset. Those preconditions are stated in the fields rather than assumed away.
func smcUnorderedRAKP3Finding(port int, generation string, p *ipmi.SMCUnorderedRAKP3Probe) engine.Finding {
	risk := "medium"
	if p.Activated {
		// The probe key is not a plausible password, so this should not happen; if it
		// does, a no-password session was genuinely obtained.
		risk = "high"
	}
	// The preconditions and the bounded impact are stable tokens, not prose:
	// explainSMCUnorderedRAKP3 below is where an operator reads the wording. Tokens keep
	// the caveat attached to the finding without repeating a paragraph per host, and are
	// machine-readable.
	fields := engine.F(
		"rakp1Skipped", "true",
		"rakp4Status", fmt.Sprintf("0x%02x", p.RAKP4Status),
		"rakp4StatusText", p.RAKP4StatusText,
		"cipherSuite", fmt.Sprintf("%d", p.CipherSuite),
		"consoleSidEchoed", fmt.Sprintf("%t", p.SIDEchoed),
		"authCodeCompared", "true",
		"sessionObtained", fmt.Sprintf("%t", p.Activated),
		"requiredKey", "user-record-0-password-short-guessable",
		"requiredSlotState", "slot-no-rakp1-since-boot",
		"detectionCaveat", "record-0-lockout-masks-correct-key",
		"impactIfExploited", "sol-console-not-admin-ipmi",
	)
	if generation != "" {
		fields = append(fields, engine.Field{Key: "smcGeneration", Val: generation})
	}
	fields = append(fields, engine.Field{Key: "proof", Val: proofKV(
		"rakp1Sent", "false",
		"rakp4Status", fmt.Sprintf("0x%02x", p.RAKP4Status),
		"consoleSidEchoed", fmt.Sprintf("%t", p.SIDEchoed),
		"sessionObtained", fmt.Sprintf("%t", p.Activated))})
	return engine.Finding{
		Check:    "ipmi.smc.rakpUnordered",
		Category: "auth",
		Risk:     risk,
		CVE:      []string{"CVE-2026-65219"},
		Fields:   fields,
	}
}

// smcRAKPOutcome names what a negative probe actually established, so "clean" and
// "could not tell" are never the same value.
func smcRAKPOutcome(answered, conformant bool, err error) string {
	switch {
	case err != nil:
		return "not-measured-probe-error"
	case !answered:
		return "not-measured-no-answer"
	case conformant:
		return "conformant-rejection"
	default:
		return "inconclusive-unexpected-status"
	}
}

// smcUnorderedRAKP3NegativeFinding records a host that was probed and not found
// affected. It is info: the value is coverage, not exposure.
func smcUnorderedRAKP3NegativeFinding(port int, generation string, p *ipmi.SMCUnorderedRAKP3Probe, err error) engine.Finding {
	fields := engine.F(
		"defect", "false",
		"outcome", smcRAKPOutcome(p.Answered, p.SpecConformant, err),
		"rakp1Skipped", "true",
		"rakp4Status", fmt.Sprintf("0x%02x", p.RAKP4Status),
		"rakp4StatusText", p.RAKP4StatusText,
		"consoleSidEchoed", fmt.Sprintf("%t", p.SIDEchoed),
	)
	if generation != "" {
		fields = append(fields, engine.Field{Key: "smcGeneration", Val: generation})
	}
	if err != nil {
		fields = append(fields, engine.Field{Key: "probeError", Val: err.Error()})
	}
	fields = append(fields, engine.Field{Key: "proof", Val: proofKV(
		"rakp1Sent", "false",
		"rakp4Status", fmt.Sprintf("0x%02x", p.RAKP4Status),
		"specConformant", fmt.Sprintf("%t", p.SpecConformant))})
	return engine.Finding{
		Check:    "ipmi.smc.rakpUnordered.negative",
		Category: "auth",
		Risk:     "info",
		Fields:   fields,
	}
}

// runSMCUnorderedForge validates CVE-2026-65219 with one record-0 key guess,
// ordered by the detected generation, testing for a forged SOL session. Gated to
// --ipmi-full because a guess against user record 0 carries the lock-window cost
// documented on ForgeSMCUnorderedRAKP3, and skipped entirely when the detection probe
// already proved the board conformant, since no key changes that outcome.
func runSMCUnorderedForge(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	if !t.IPMIFull || t.DisableLogins {
		return nil
	}
	gen, aten := smcATENGeneration(t)
	if !aten {
		return nil
	}
	if v, ok := t.Evidenced("ipmi.smc.rakpUnordered"); ok {
		if probe, ok := v.(*ipmi.SMCUnorderedRAKP3Probe); ok && probe != nil && probe.SpecConformant {
			return nil
		}
	}
	port := t.IPMIPort()
	candidates := ipmi.SMCRecord0KeyCandidatesForGeneration(gen)
	sess, forge := ipmi.ForgeSMCUnorderedRAKP3(t.Host, port, t.Timeout, ipmi.SMCForgeOptions{
		Candidates: candidates,
		Generation: gen,
		Log:        t.Progress,
	})
	if forge == nil {
		return nil
	}
	if sess == nil {
		return stampIPMI([]engine.Finding{smcUnorderedForgeAttemptFinding(port, gen, forge)}, port)
	}
	defer sess.Close()
	caps := ipmi.ProbeSMCForgedCapabilities(sess)
	return stampIPMI([]engine.Finding{smcUnorderedForgeActivatedFinding(port, gen, forge, caps)}, port)
}

// smcUnorderedForgeActivatedFinding reports a confirmed CVE-2026-65219 session: a
// session forged with no RAKP message 1 and no account password, from the single
// generation-best guess at user record 0's key. It outranks the ordering detection
// (smcUnorderedRAKP3Finding) because a working no-password session is a compromise
// rather than a proven mechanism, even though its command reach is the narrow
// SOL-only lane documented on OpenSession20SMCUnorderedRAKP3.
func smcUnorderedForgeActivatedFinding(port int, generation string, forge *ipmi.SMCForgeResult, caps []ipmi.SMCCapabilityResult) engine.Finding {
	okCmds := make([]string, 0, len(caps))
	for _, c := range caps {
		if c.CC == 0x00 {
			okCmds = append(okCmds, c.Name)
		}
	}
	fields := engine.F(
		"rakp1Skipped", "true",
		"keyLabel", forge.KeyLabel,
		"sessionObtained", "true",
		"reachableCommands", strings.Join(okCmds, ","),
		"impact", "sol-console-not-admin-ipmi",
	)
	if generation != "" {
		fields = append(fields, engine.Field{Key: "smcGeneration", Val: generation})
	}
	fields = append(fields, engine.Field{Key: "proof", Val: proofKV(
		"rakp1Sent", "false",
		"keyLabel", forge.KeyLabel,
		"sessionObtained", "true",
		"reachableCommandCount", fmt.Sprintf("%d", len(okCmds)))})
	return engine.Finding{
		Check:     "ipmi.smc.rakpUnorderedForge",
		Category:  "auth",
		Risk:      "critical",
		CVE:       []string{"CVE-2026-65219"},
		Port:      port,
		Transport: "udp",
		Protocol:  "ipmi",
		Fields:    fields,
	}
}

// smcUnorderedForgeAttemptFinding records that session validation was attempted
// and did not obtain a session. It is info, not a negative-security claim: per
// smcForgeNegativeVerdict a single refused guess on a lockout-charging
// generation is not proof the defect is absent, only that this one key was
// wrong (or the slot was already allocated since boot).
func smcUnorderedForgeAttemptFinding(port int, generation string, forge *ipmi.SMCForgeResult) engine.Finding {
	fields := engine.F(
		"forged", "false",
		"defect", fmt.Sprintf("%t", forge.Defect),
		"specConformant", fmt.Sprintf("%t", forge.SpecConformant),
		"inconclusive", fmt.Sprintf("%t", forge.Inconclusive),
	)
	if forge.Reason != "" {
		fields = append(fields, engine.Field{Key: "reason", Val: forge.Reason})
	}
	for _, att := range forge.Attempts {
		if !att.RAKP4Observed {
			continue
		}
		fields = append(fields,
			engine.Field{Key: "keyLabel", Val: att.KeyLabel},
			engine.Field{Key: "rakp4Status", Val: fmt.Sprintf("0x%02x", att.RAKP4Status)},
		)
		break
	}
	if generation != "" {
		fields = append(fields, engine.Field{Key: "smcGeneration", Val: generation})
	}
	fields = append(fields, engine.Field{Key: "proof", Val: proofKV(
		"rakp1Sent", "false",
		"forged", "false",
		"defect", fmt.Sprintf("%t", forge.Defect))})
	return engine.Finding{
		Check:     "ipmi.smc.rakpUnorderedForge",
		Category:  "auth",
		Risk:      "info",
		Port:      port,
		Transport: "udp",
		Protocol:  "ipmi",
		Fields:    fields,
	}
}

func explainSMCUnorderedForge(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	if explainField(f, "forged") == "false" {
		b.WriteString("\nThe CVE-2026-65219 single-attempt validation did not obtain a session with the\n")
		b.WriteString("generation-best guess at user record 0's key. This is not proof the board is\n")
		b.WriteString("unaffected: a rejected guess is charged against user record 0's lockout counter\n")
		b.WriteString("on every generation but X10, so only the first refusal in a fresh lock window is\n")
		b.WriteString("interpretable.\n")
		b.WriteString("\n**Optional authorized validation:** Agree an attempt budget and lockout recovery plan before retrying.\n")
		b.WriteString(explainSh(fmt.Sprintf("oobscan smc-rakp-bypass %s:%d --record0-max-attempts 5 --record0-rest 60s", host, port)))
		return b.String()
	}
	b.WriteString("\nThe check obtained a session bound to user record 0 with no\n")
	b.WriteString("RAKP message 1 and no account password -- only a single guess at record 0's\n")
	b.WriteString("stored key, ordered by this board's detected generation. The session's reach is\n")
	b.WriteString("the narrow lane record 0 grants (Serial-over-LAN and a handful of reads), not\n")
	b.WriteString("full administrative IPMI, but SOL alone is an interactive console on the\n")
	b.WriteString("managed host.\n")
	b.WriteString("\n**Reproduce and inspect:**\n")
	b.WriteString(explainSh(fmt.Sprintf("oobscan smc-rakp-bypass %s:%d", host, port)))
	return b.String()
}

// smcReservedRoleNegativeFinding records a host that was probed and not found affected,
// including whether the valid-role control resolved -- without that, a reserved-role
// rejection could just mean the named account does not exist.
func smcReservedRoleNegativeFinding(port int, generation string, p *ipmi.SMCReservedRoleProbe, err error) engine.Finding {
	fields := engine.F(
		"defect", "false",
		"outcome", smcRAKPOutcome(p.ConformantAccepted || p.ReservedStatus != 0, p.ReservedRejectedConformantly, err),
		"reservedRoleByte", fmt.Sprintf("0x%02x", p.ReservedRole),
		"reservedRoleStatus", fmt.Sprintf("0x%02x", p.ReservedStatus),
		"controlRoleStatus", fmt.Sprintf("0x%02x", p.ConformantStatus),
		"controlAccepted", fmt.Sprintf("%t", p.ConformantAccepted),
		"namedAccount", p.Username,
	)
	if generation != "" {
		fields = append(fields, engine.Field{Key: "smcGeneration", Val: generation})
	}
	if err != nil {
		fields = append(fields, engine.Field{Key: "probeError", Val: err.Error()})
	}
	fields = append(fields, engine.Field{Key: "proof", Val: proofKV(
		"namedAccount", p.Username,
		"reservedRoleStatus", fmt.Sprintf("0x%02x", p.ReservedStatus),
		"controlAccepted", fmt.Sprintf("%t", p.ConformantAccepted))})
	return engine.Finding{
		Check:    "ipmi.smc.rakpReservedRole.negative",
		Category: "auth",
		Risk:     "info",
		Fields:   fields,
	}
}

func explainSMCUnorderedRAKP3(host string, f engine.Finding) string {
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nRAKP message 3 was answered although message 1 was never sent, with the console\n")
	b.WriteString("session ID echoed back: the BMC located the session slot and computed the\n")
	b.WriteString("message-3 authentication code for an out-of-order message. Message 1 is the only\n")
	b.WriteString("writer of the slot's bound user id, console random, role byte and username\n")
	b.WriteString("length, so on a slot that has not been allocated since boot those fields still\n")
	b.WriteString("hold their boot values and the entire transcript is known to an attacker.\n")
	b.WriteString("\nWhat this finding does and does not establish:\n")
	b.WriteString("  - Established: the ordering defect. No session was obtained; a deliberately wrong key was used.\n")
	b.WriteString("  - Operational effect: the wrong authentication code can increment record 0's failure counter.\n")
	b.WriteString("  - Still required to exploit: user record 0's stored password. It is short and\n")
	b.WriteString("    per-product, not a fleet constant: recovered live as \"0\" on X11DPT-PS, \"admin\"\n")
	b.WriteString("    on X10DSC+ and the EMPTY STRING on H13, or the SMCRAKP firmware constant on a\n")
	b.WriteString("    unit with that mode enabled.\n")
	b.WriteString("  - Still required to exploit: a session slot unallocated since boot - more exactly,\n")
	b.WriteString("    one that no RAKP message 1 has ever landed on. Releasing a slot does not scrub\n")
	b.WriteString("    the residue, so failed attempts do not consume it, but an ordinary login does. A\n")
	b.WriteString("    sweep with no cold reset found nothing on eight lab units, so the exposure is\n")
	b.WriteString("    reachable in the window after a BMC reset or on a lightly used board.\n")
	b.WriteString("  - Searching keys is rate-limited by the firmware itself: a rejected attempt counts\n")
	b.WriteString("    toward a time-limited lock on user record 0 (X11/X12/X13/H13), and past the\n")
	b.WriteString("    threshold a CORRECT key is answered 0x08 exactly like a wrong one.\n")
	b.WriteString("\nImpact when exploited is a session that reaches Serial-over-LAN, an interactive\n")
	b.WriteString("console on the managed host's serial port. It is NOT equivalent to administrative\n")
	b.WriteString("IPMI: record 0's IPMI-messaging bit is clear, so the session is confined to a\n")
	b.WriteString("narrow command lane and raising its privilege to Administrator does not widen it.\n")
	b.WriteString("\nValidate with: oobscan smc-rakp-bypass <host>\n")
	return b.String()
}

func runSMCReservedRole(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	// This probe offers no credential (message 3 is never sent), so it cannot fail
	// a login. It does name accounts to see which resolve, which is an active
	// enumeration, so --disable-logins still suppresses it.
	if t.DisableLogins {
		return nil
	}
	gen, aten := smcATENGeneration(t)
	if !aten {
		return nil
	}
	port := t.IPMIPort()
	probe, err := ipmi.ProbeSMCReservedRole(t.Host, port, t.Cred.User, t.Timeout)
	if probe == nil {
		return nil
	}
	// As above: keep the measurement even when it failed, so a rate-limited board is
	// not silently filed alongside the boards that were measured clean.
	t.SetEvidence("ipmi.smc.rakpReservedRole", probe)
	if err != nil || !probe.Defect {
		// As above: record the measured negative so "conformantly rejected" is
		// distinguishable from "never answered" in the corpus, not just in memory.
		return stampIPMI([]engine.Finding{smcReservedRoleNegativeFinding(port, gen, probe, err)}, port)
	}
	return stampIPMI([]engine.Finding{smcReservedRoleFinding(port, gen, probe)}, port)
}

// smcReservedRoleFinding reports the role-dispatch defect at medium. The escalation
// it enables is serious (low-privilege account to Administrator) but it presupposes
// a valid credential, so this is not unauthenticated access and must not be rated as
// if it were. The confirmed escalation, which needs the
// credential, is reported by `oobscan smc-priv-esc`.
func smcReservedRoleFinding(port int, generation string, p *ipmi.SMCReservedRoleProbe) engine.Finding {
	fields := engine.F(
		"reservedRoleByte", fmt.Sprintf("0x%02x", p.ReservedRole),
		"reservedRoleStatus", fmt.Sprintf("0x%02x", p.ReservedStatus),
		"reservedRoleAccepted", "true",
		// The control is the VALID role byte accepted for the same name (0x12, USER),
		// which every existing account is entitled to. The Administrator lookup (0x14) is
		// recorded separately because it says whether the account can serve as the seed,
		// not whether the role dispatch is broken.
		"controlRoleByte", fmt.Sprintf("0x%02x", p.ConformantRole),
		"controlRoleStatus", fmt.Sprintf("0x%02x", p.ConformantStatus),
		"adminRoleByte", fmt.Sprintf("0x%02x", p.BaselineRole),
		"adminRoleStatus", fmt.Sprintf("0x%02x", p.BaselineStatus),
		"namedAccount", p.Username,
		"credentialOffered", "false",
		"surface", "authenticated",
		// Tokens, not prose -- see the note in smcUnorderedRAKP3Finding.
		// explainSMCReservedRole carries the full wording.
		"prerequisite", "low-priv-credential-plus-admin-account-name",
		"impactIfExploited", "privilege-escalation-not-auth-bypass",
	)
	if generation != "" {
		fields = append(fields, engine.Field{Key: "smcGeneration", Val: generation})
	}
	// namedAccount and adminRoleStatus are in the proof so it varies per host: a proof
	// string that never differs carries no host evidence at all.
	fields = append(fields, engine.Field{Key: "proof", Val: proofKV(
		"namedAccount", p.Username,
		"controlRoleStatus", fmt.Sprintf("0x%02x", p.ConformantStatus),
		"adminRoleStatus", fmt.Sprintf("0x%02x", p.BaselineStatus),
		"reservedRoleByte", fmt.Sprintf("0x%02x", p.ReservedRole),
		"reservedRoleStatus", fmt.Sprintf("0x%02x", p.ReservedStatus),
		"credentialOffered", "false")})
	return engine.Finding{
		Check:    "ipmi.smc.rakpReservedRole",
		Category: "auth",
		Risk:     "medium",
		CVE:      []string{"CVE-2026-65220"},
		Fields:   fields,
	}
}

func explainSMCReservedRole(host string, f engine.Finding) string {
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nRAKP message 1 carrying a role byte with reserved bits set was accepted (message 2\n")
	b.WriteString("status 0x00) where a conformant handler refuses it. The ATEN handler dispatches on\n")
	b.WriteString("the upper nibble of that byte and implements only 0x00 and 0x10 with no default\n")
	b.WriteString("arm; a reserved nibble falls into a path that copies the session slot's existing\n")
	b.WriteString("current-privilege byte into the session maximum instead of consulting the\n")
	b.WriteString("account's channel privilege limit, so the per-user clamp never runs.\n")
	b.WriteString("\nThis is a PRIVILEGE ESCALATION and requires a valid account. Message 1 needs no\n")
	b.WriteString("credential, which is what lets an attacker seed the slot with privilege 4 by\n")
	b.WriteString("naming an Administrator account, but message 3 must still be signed with the\n")
	b.WriteString("attacker's own real password. It is not an authentication bypass.\n")
	b.WriteString("\nThis check offered no password and completed no session: it measured only that the\n")
	b.WriteString("reserved role byte is accepted. Confirm the escalation, with both controls and a\n")
	b.WriteString("privileged read as the proof, with:\n")
	b.WriteString("  oobscan smc-priv-esc <host> --low-user <user> --low-pass <pass> --admin-user ADMIN\n")
	return b.String()
}
