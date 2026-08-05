package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

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
		Online:  !t.DisableLogins,
		Timeout: t.Timeout,
	}

	var caps *ipmi.AuthCaps
	if v, ok := t.Evidenced("ipmi.authCaps"); ok {
		if ac, ok := v.(*ipmi.AuthCaps); ok && ac != nil {
			caps = ac
			opts.Caps = ac
		}
	}

	if caps == nil {
		if _, ok := t.Evidenced("ipmi.ciphers"); ok {
			if t.DebugLog != nil {
				t.DebugLog("ipmi.v15.session: skipping - IPMI 2.0 confirmed (cipher suites) but no 1.5 auth-caps response; BMC does not speak legacy 1.5 framing")
			}
			return nil
		}
	}

	rep := ipmi.RunSession15(ctx, t.Host, t.IPMIPort(), opts)
	if rep == nil {
		return nil
	}
	t.SetEvidence("ipmi.v15", rep)

	var findings []engine.Finding

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

	return stampIPMI(findings, t.IPMIPort())
}

func v15UsernameOracleFindings(rep *ipmi.V15Report) []engine.Finding {
	if rep == nil || len(rep.ValidUsernames) == 0 {
		return nil
	}

	nonNullOracleCount := len(ipmi.V15OracleUserList()) - 1
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
