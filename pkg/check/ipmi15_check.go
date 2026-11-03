package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// The IPMI 1.5 session check covers the pre-2.0 LAN login path (Get Session
// Challenge -> Activate Session, pkg/ipmi/session15.go) that the RAKP
// credential check cannot touch. It emits three findings: authNoneSession and
// defaultCreds at critical (a no-auth session established, and a default
// credential accepted by Activate Session -- a real login gated on
// !t.DisableLogins), and usernameOracle at low (accounts distinguished
// pre-auth via the Get Session Challenge completion code). Auth-caps are
// reused from evidence key "ipmi.authCaps" rather than re-probed.
func init() {
	Register(Check{
		Name:        "ipmi.v15.session",
		Description: "IPMI 1.5 session login: auth-None session, default creds (unless --disable-logins), username oracle",
		Category:    "creds",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runIPMI15Session,
	})
}

func runIPMI15Session(ctx context.Context, t *engine.Target) []engine.Finding {
	vendor := ""
	if t.Identity != nil {
		vendor = t.Identity.Vendor
	}

	opts := ipmi.V15Options{
		Vendor:  vendor,
		Online:  !t.DisableLogins, // Activate-Session login is a real login (lockout risk)
		Timeout: t.Timeout,
	}
	// Gate on the already-parsed auth-caps when identify stashed them, so the
	// engine skips paths the BMC's advertised auth modes make pointless (e.g. no
	// auth-None probe when auth-None is not advertised) with no extra probe.
	var caps *ipmi.AuthCaps
	if v, ok := t.Evidenced("ipmi.authCaps"); ok {
		if ac, ok := v.(*ipmi.AuthCaps); ok && ac != nil {
			caps = ac
			opts.Caps = ac
		}
	}
	// Some BMC stacks (e.g. OpenBMC's phosphor-net-ipmid) speak RMCP+/IPMI 2.0
	// over UDP/623 but silently ignore every legacy 1.5 sessionless frame,
	// including the Get Channel Auth Caps probe identify already retried before
	// giving up. If that probe got no answer (caps == nil) but 2.0 cipher-suite
	// enumeration did, the BMC is proven reachable yet proven to ignore 1.5
	// framing, so running the full blind 1.5 suite would just burn a dozen-plus
	// timeouts for a guaranteed-empty result and stall the RAKP/2.0 checks
	// queued behind it in the serial IPMI lane -- skip outright rather than
	// probe blind.
	if caps == nil {
		if _, ok := t.Evidenced("ipmi.ciphers"); ok {
			if t.DebugLog != nil {
				t.DebugLog("ipmi.v15.session: skipping - IPMI 2.0 confirmed (cipher suites) but no 1.5 auth-caps response; BMC does not speak legacy 1.5 framing")
			}
			return nil
		}
	}
	// A supplied credential is worth trying via the online 1.5 login too, so it is
	// not silently confined to the RAKP path. Prefer it as the first candidate by
	// leaving vendor prioritization intact - CredsFor already puts operator-
	// supplied usernames' vendor rows first; the explicit pair still flows through
	// the cred KB, so we do not special-case it here beyond enabling online.

	rep := ipmi.RunSession15(ctx, t.Host, t.IPMIPort(), opts)
	if rep == nil {
		return nil // unreachable / no 1.5 session surface; emit nothing (no none-noise)
	}
	t.SetEvidence("ipmi.v15", rep)

	var findings []engine.Finding

	// (1) auth-None session confirmed: a session was actually established with
	// authType=None and a null user. This is unauthenticated access, the 1.5
	// analog of cipher-0 (ipmi.v20.cipherZero), so critical with matching proof text.
	// The post-login capability probe (Set Session Privilege + a read-only
	// in-session command) upgrades "session established" to "in-session commands
	// executed at <priv>".
	if rep.AuthNoneOK {
		proof := proofKV("authType", "none")
		if c := rep.AuthNoneCaps; c != nil {
			proof += " " + c.Proof()
		}
		findings = append(findings, engine.Finding{
			Check: "ipmi.v15.authNoneSession", Category: "auth", Risk: "critical",
			Fields: engine.F(
				"priv", privName(rep.AuthNonePriv),
				"proof", proof),
		})
	}

	// (2) default credential accepted by Activate Session. Verified by an actual
	// login (not a hash match), so critical. The capability probe reports what the
	// authenticated session could actually do.
	if rep.DefaultCred != nil {
		dc := rep.DefaultCred
		proof := proofKV("activateSession", "ok")
		if dc.Caps != nil {
			proof += " " + dc.Caps.Proof()
		}
		findings = append(findings, engine.Finding{
			Check: "ipmi.v15.defaultCreds", Category: "creds", Risk: "critical",
			Fields: engine.F(
				"username", userLabel(dc.Username),
				"password", dc.Password,
				"via", dc.Via,
				"priv", privName(dc.Priv),
				"proof", proof),
		})
	}

	findings = append(findings, v15UsernameOracleFindings(rep)...)

	// Nothing found: emit no finding rather than a risk=none placeholder, in line
	// with suppressing non-actionable negative results across the scan.
	return stampIPMI(findings, t.IPMIPort())
}

func v15UsernameOracleFindings(rep *ipmi.V15Report) []engine.Finding {
	if rep == nil || len(rep.ValidUsernames) == 0 {
		return nil
	}
	// Some BMCs return CC 0x00 for every non-null username in Get Session
	// Challenge regardless of whether the account exists. When all non-null oracle
	// candidates pass, the oracle cannot discriminate real accounts; report the
	// wildcard behavior, not a long list of supposedly valid usernames.
	nonNullOracleCount := len(ipmi.V15OracleUserList()) - 1 // first entry is null/anonymous
	if len(rep.ValidUsernames) >= nonNullOracleCount {
		return []engine.Finding{{
			Check: "ipmi.v15.oracleBlind", Category: "auth", Risk: "info",
			Fields: engine.F(
				"result", "wildcardUsername",
				"wildcard", "true",
				"probed", fmt.Sprintf("%d", nonNullOracleCount),
				"proof", proofKV("challengeCc", "0x00", "accepted", fmt.Sprintf("%d", nonNullOracleCount))),
		}}
	}
	var names []string
	validCC := byte(0x00)
	for _, e := range rep.ValidUsernames {
		names = append(names, userLabel(e.Username))
		validCC = e.CC
	}
	// Proof is the completion-code differential the oracle keys on: CC 0x00 for
	// the accounts that exist vs the rejection CC for one that does not, e.g.
	// "Get Session Challenge cc=0x00 for ADMIN,root (valid); cc=0x81 for guest (invalid)".
	proof := proofKV("validCc", fmt.Sprintf("0x%02x", validCC), "validUsers", strings.Join(names, ","))
	if rep.OracleInvalidUser != "" {
		proof += " " + proofKV("invalidCc", fmt.Sprintf("0x%02x", rep.OracleInvalidCC), "invalidUser", rep.OracleInvalidUser)
	}
	return []engine.Finding{{
		Check: "ipmi.v15.usernameOracle", Category: "auth", Risk: "low",
		Fields: engine.F(
			"users", strings.Join(names, ","),
			"probed", fmt.Sprintf("%d", len(ipmi.V15OracleUserList())),
			"proof", proof),
	}}
}

// privName renders an IPMI privilege-level number as its spec name for output.
func privName(p byte) string {
	switch p & 0x0f {
	case 0x01:
		return "callback"
	case 0x02:
		return "user"
	case 0x03:
		return "operator"
	case 0x04:
		return "admin"
	case 0x05:
		return "oem"
	default:
		return fmt.Sprintf("0x%02x", p)
	}
}

// ----------------------------------------------------------------------------
// Explainers -- registered next to the check that emits each finding so that
// changing the finding fields and updating the validation guide happen in the
// same diff.
// ----------------------------------------------------------------------------

func init() {
	RegisterExplain("ipmi.v15.authNoneSession", explainIPMI15AuthNone)
	RegisterExplain("ipmi.v15.defaultCreds", explainIPMI15DefaultCreds)
	RegisterExplain("ipmi.v15.usernameOracle", explainIPMI15UsernameOracle)
	RegisterExplain("ipmi.v15.oracleBlind", explainIPMI15OracleBlind)
}

func explainIPMI15AuthNone(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	priv := explainIPMIPriv(explainField(f, "priv"))
	proof := explainField(f, "proof")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe BMC established an IPMI 1.5 session with authType **None** -- no password\n")
	b.WriteString(fmt.Sprintf("or username is required. Any host with network access to UDP/%d can run any\n", port))
	b.WriteString("IPMI command at administrator privilege.\n")
	if proof != "" {
		b.WriteString(fmt.Sprintf("\n**Observed proof:** `%s`\n", proof))
	}
	b.WriteString("\n**Validate:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("ipmitool -I lan -H %s -p %d -A NONE -U '' -P '' -L %s mc info", host, port, priv),
		fmt.Sprintf("ipmitool -I lan -H %s -p %d -A NONE -U '' -P '' chassis status", host, port),
		fmt.Sprintf("ipmitool -I lan -H %s -p %d -A NONE -U '' -P '' lan print", host, port),
		fmt.Sprintf("ipmitool -I lan -H %s -p %d -A NONE -U '' -P '' user list", host, port),
	))
	b.WriteString("\n\n**Impact:** Unauthenticated IPMI 1.5 access -- power control, user management,\n")
	b.WriteString("chassis reboot, SOL access, and firmware interaction.\n")
	return b.String()
}

func explainIPMI15DefaultCreds(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	user := explainField(f, "user")
	pass := explainField(f, "pass")
	via := explainField(f, "via")
	priv := explainIPMIPriv(explainField(f, "priv"))
	proof := explainField(f, "proof")
	du := explainDisplayUser(user)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nThe BMC accepted the default IPMI 1.5 credential **%s / %s**", user, pass))
	if via != "" {
		b.WriteString(fmt.Sprintf(" (verified via %s)", via))
	}
	b.WriteString(".\n")
	if proof != "" {
		b.WriteString(fmt.Sprintf("\n**Proof:** `%s`\n", proof))
	}
	b.WriteString("\n**Validate:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("ipmitool -I lan -H %s -p %d -A MD5 -U '%s' -P '%s' -L %s mc info", host, port, du, pass, priv),
		fmt.Sprintf("ipmitool -I lan -H %s -p %d -A MD5 -U '%s' -P '%s' user list", host, port, du, pass),
		fmt.Sprintf("ipmitool -I lan -H %s -p %d -A MD5 -U '%s' -P '%s' chassis status", host, port, du, pass),
	))
	b.WriteString("\n\n**Impact:** Full authenticated IPMI 1.5 access with a known default credential.\n")
	return b.String()
}

func explainIPMI15OracleBlind(host string, f engine.Finding) string {
	proof := explainField(f, "proof")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe BMC returns CC 0x00 (success + challenge) in response to Get Session\n")
	b.WriteString("Challenge for every non-null username probed. The completion-code differential\n")
	b.WriteString("that the IPMI 1.5 username oracle relies on does not function on this BMC --\n")
	b.WriteString("username enumeration via this method is not possible.\n")
	if proof != "" {
		b.WriteString(fmt.Sprintf("\n**Observed:** `%s`\n", proof))
	}
	b.WriteString("\n**Known affected platforms:** Cisco CIMC.\n")
	return b.String()
}

func explainIPMI15UsernameOracle(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	users := explainField(f, "users")
	proof := explainField(f, "proof")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe BMC returns distinct Get Session Challenge completion codes for valid vs\n")
	b.WriteString("invalid usernames -- pre-auth user enumeration without lockout risk.\n")
	if users != "" {
		b.WriteString(fmt.Sprintf("\n**Confirmed existing accounts:** `%s`\n", users))
	}
	if proof != "" {
		b.WriteString(fmt.Sprintf("**Observed differential:** `%s`\n", proof))
	}
	b.WriteString("\n**Re-run the oracle check:**\n")
	b.WriteString(explainSh(fmt.Sprintf("oobscan scan --checks ipmi.v15.session %s:%d", host, port)))
	b.WriteString("\n\n**Impact:** Confirmed username list enables targeted RAKP hash extraction and brute-force.\n")
	return b.String()
}
