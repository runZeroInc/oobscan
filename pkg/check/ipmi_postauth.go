package check

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func init() {
	Register(Check{
		Name:        "ipmi.postAuthEnum",
		Description: "Collect post-auth IPMI inventory (mc info, chassis status, user list, lan/lan6, fru) using the identified auth flow",
		Category:    "creds",
		Applies:     Applicability{Classes: []engine.DeviceClass{engine.ClassBMC}},
		Enabled:     true,
		Run:         runIPMIPostAuthEnum,
	})
}

func runIPMIPostAuthEnum(ctx context.Context, t *engine.Target) []engine.Finding {
	debugf := func(string, ...any) {}
	if t != nil && t.DebugLog != nil {
		debugf = func(format string, args ...any) { t.DebugLog(fmt.Sprintf("post-auth ipmi "+format, args...)) }
	}
	var auth *ipmi.AuthReport
	if v, ok := t.Evidenced("ipmi.auth"); ok {
		auth, _ = v.(*ipmi.AuthReport)
	}
	var v15 *ipmi.V15Report
	if v, ok := t.Evidenced("ipmi.v15"); ok {
		v15, _ = v.(*ipmi.V15Report)
	}

	candidates := ipmi.SelectPostAuthFlows(auth, v15)
	if setupFlow, setupOK := selectOpenBMCSetupFlow(t, auth); setupOK {
		candidates = append([]ipmi.AuthFlow{setupFlow}, candidates...)
	}
	var flow ipmi.AuthFlow
	ok := len(candidates) > 0
	if ok {
		flow = candidates[0]
	}
	if !ok {
		debugf("skip inventory: no auth flow selected; attempting smcrakp final password test")
		smcrakpFindings, smcrakpCred := runPostAuthSMCRAKPPasswordEnum(ctx, t, auth, debugf)
		if smcrakpCred != nil && auth != nil {
			dup := false
			for _, cr := range auth.Cracked {
				if cr.Username == smcrakpCred.Username && cr.Password == smcrakpCred.Password && cr.PasswordType == smcrakpCred.PasswordType {
					dup = true
					break
				}
			}
			if !dup {
				auth.Cracked = append(auth.Cracked, *smcrakpCred)
				t.SetEvidence("ipmi.auth", auth)
			}
		}
		if len(smcrakpFindings) == 0 {
			return nil
		}
		return stampIPMI(smcrakpFindings, t.IPMIPort())
	}
	user := flow.Username
	if strings.TrimSpace(user) == "" {
		user = "(null)"
	}
	src := flow.Source
	if strings.TrimSpace(src) == "" {
		src = "unknown"
	}

	budget := postAuthBudgetForFlow(t.Timeout, flow)
	budgetCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	debugf("start host=%s port=%d timeout=%s budget=%s", t.Host, t.IPMIPort(), t.Timeout, budget)
	debugf("selected flow=%s/%s suite=%d user=%s source=%s", flow.Version, flow.Mode, flow.Suite.Suite, user, src)
	t.Progress(fmt.Sprintf("post-auth ipmi start proto=ipmi port=%d flow=%s/%s user=%s source=%s", t.IPMIPort(), flow.Version, flow.Mode, user, src))
	traceCtx := ipmi.WithPostAuthTrace(budgetCtx, debugf)
	inv, err := collectPostAuthWithMatrix(traceCtx, t, flow, debugf)
	if err != nil {
		debugf("primary flow failed err=%v", err)
	}
	collect := func(ctx context.Context, next ipmi.AuthFlow) (*ipmi.PostAuthCollection, error) {
		return ipmi.CollectPostAuthInventory(ctx, t.Host, t.IPMIPort(), next, t.Timeout)
	}
	flow, inv, err = walkPostAuthFallbacks(traceCtx, candidates, flow, inv, err, collect, debugf)

	if !hasPostAuthInventory(inv) && flow.Version == "2.0" && budgetCtx.Err() == nil && !ipmi.SessionResourceExhausted(inv, err) {
		if window, okWindow := postAuthFallbackWindow(budgetCtx); okWindow {
			if v15 == nil && likelyV15Capable(t) {
				debugf("running v1.5 fallback probe")
				v15 = runV15ForPostAuthFallback(budgetCtx, t)
			}
			if fb, fbOK := v15CredFallbackFlow(v15); fbOK {
				debugf("v1.5 fallback selected user=%s authType=0x%02x window=%s", fb.Username, fb.AuthType, window)
				fbCtx, fbCancel := context.WithTimeout(traceCtx, window)
				fbInv, fbErr := collect(fbCtx, fb)
				fbCancel()
				if fbErr == nil {
					flow, inv, err = fb, fbInv, nil
					debugf("v1.5 fallback succeeded")
				} else {
					debugf("v1.5 fallback failed err=%v", fbErr)
				}
			}
		} else {
			debugf("skip v1.5 fallback: budget spent")
		}
	}
	if inv != nil {
		debugf("inventory captured mc=%t chassis=%t users=%d lan=%d lan6=%d fru=%d setpriv=%d", inv.MCInfo != nil, inv.Chassis != nil, len(inv.Users), len(inv.LAN), len(inv.LAN6), len(inv.FRU), len(inv.SetPrivAttempts))
	}
	smcrakpFindings, smcrakpCred := runPostAuthSMCRAKPPasswordEnum(budgetCtx, t, auth, debugf)
	if smcrakpCred != nil && auth != nil {
		dup := false
		for _, cr := range auth.Cracked {
			if cr.Username == smcrakpCred.Username && cr.Password == smcrakpCred.Password && cr.PasswordType == smcrakpCred.PasswordType {
				dup = true
				break
			}
		}
		if !dup {
			auth.Cracked = append(auth.Cracked, *smcrakpCred)
			t.SetEvidence("ipmi.auth", auth)
		}
	}
	limitedAccess := isLimitedPrivilegePostAuthFailure(inv, err)

	if inv != nil {
		t.SetEvidence("ipmi.postAuth", inv)
	}
	issueReported := false
	if err != nil {
		if limitedAccess {
			debugf("limited-access post-auth failure suppressed err=%v", err)
		} else {
			reportPostAuthIssue(t, flow, inv, err)
			issueReported = true
		}
	}

	if inv == nil {
		debugf("no inventory returned")
		return stampIPMI(append(smcrakpFindings,
			postAuthAttemptFailedFinding(flow, inv, err)), t.IPMIPort())
	}

	fields := engine.F("flow", fmt.Sprintf("%s/%s", flow.Version, flow.Mode))
	if flow.Source != "" {
		fields = append(fields, engine.Field{Key: "source", Val: flow.Source})
	}
	if flow.Username != "" {
		fields = append(fields, engine.Field{Key: "user", Val: flow.Username})
	}
	if flow.Version == "2.0" {
		fields = append(fields, engine.Field{Key: "suite", Val: fmt.Sprintf("%d", flow.Suite.Suite)})
	}
	if inv.CommandProtection != "" {
		fields = append(fields, engine.Field{Key: "commandProtection", Val: inv.CommandProtection})
	}
	if inv.Error != "" {
		if !issueReported {
			reportPostAuthIssue(t, flow, inv, errors.New(inv.Error))
		}
		if flow.Mode == "smcrakpFixedKey" && inv.MCInfo == nil && inv.Chassis == nil {
			fields = append(fields,
				engine.Field{Key: "access", Val: "authOnly"},
				engine.Field{Key: "authOnly", Val: "true"},
			)
		}
	}
	if limitedAccess {
		fields = append(fields, engine.Field{Key: "access", Val: "limited"})
	}

	if missing := postAuthMissingSections(inv); len(missing) > 0 {

		coverage := "partial"
		if !hasPostAuthInventory(inv) {
			coverage = "none"
		}
		fields = append(fields,
			engine.Field{Key: "coverage", Val: coverage},
			engine.Field{Key: "missingSections", Val: strings.Join(missing, ",")},
			engine.Field{Key: "collected", Val: postAuthInventorySummary(inv)},
		)

		if inv.Error != "" {
			fields = append(fields, engine.Field{Key: "coverageError", Val: inv.Error})
		} else if err != nil {
			fields = append(fields, engine.Field{Key: "coverageError", Val: err.Error()})
		}
	}
	out := []engine.Finding{{
		Check: "ipmi.postAuthEnum", Category: "creds", Risk: "info", Fields: fields,
	}}
	if finding := smcIntegrityBypassFinding(t, flow, inv); finding != nil {
		out = append(out, *finding)
	}
	out = append(out, ipmiPostAuthDetailFindings(inv)...)
	out = append(out, openBMCRAKPAuthBypassFindings(t, auth, inv, debugf)...)
	out = append(out, smcrakpFindings...)
	debugf("done findings=%d partialError=%t", len(out), inv.Error != "")
	return stampIPMI(out, t.IPMIPort())
}

func postAuthAttemptFailedFinding(flow ipmi.AuthFlow, inv *ipmi.PostAuthCollection, err error) engine.Finding {
	reason := "no inventory returned"
	if err != nil {
		reason = err.Error()
	} else if inv != nil && inv.Error != "" {
		reason = inv.Error
	}
	fields := engine.F(
		"flow", fmt.Sprintf("%s/%s", flow.Version, flow.Mode),
		"access", "failed",
		"error", reason,
	)
	if flow.Source != "" {
		fields = append(fields, engine.Field{Key: "source", Val: flow.Source})
	}
	if flow.Username != "" {
		fields = append(fields, engine.Field{Key: "user", Val: flow.Username})
	}
	if inv != nil {
		fields = append(fields, engine.Field{Key: "collected", Val: postAuthInventorySummary(inv)})
	}
	return engine.Finding{
		Check: "ipmi.postAuthEnum", Category: "creds", Risk: "info", Fields: fields,
	}
}

func smcIntegrityBypassFinding(t *engine.Target, flow ipmi.AuthFlow, inv *ipmi.PostAuthCollection) *engine.Finding {
	if t == nil || inv == nil || flow.Version != "2.0" || inv.CommandProtection != "cleartext" || !strings.EqualFold(identityVendor(t), "supermicro") {
		return nil
	}

	flow = postAuthNegotiatedFlow(flow, inv)

	if flow.Suite.Integrity == ipmi.IntegrityNone && flow.Suite.Conf == ipmi.ConfNone {
		return nil
	}

	if postAuthPinnedCleartextFlow(flow) && !hasPostAuthInventory(inv) {
		return nil
	}
	return &engine.Finding{
		Check: "ipmi.smc.integrityBypass", Category: "auth", Risk: "critical",
		CVE: []string{"CVE-2026-65216"},
		Fields: engine.F(
			"suite", fmt.Sprintf("%d", flow.Suite.Suite),
			"username", userLabel(flow.Username),
			"flow", fmt.Sprintf("%s/%s", flow.Version, flow.Mode),
			"negotiatedIntegrity", fmt.Sprintf("0x%02x", flow.Suite.Integrity),
			"negotiatedConfidentiality", fmt.Sprintf("0x%02x", flow.Suite.Conf),
			"acceptedProtection", "cleartext",
			"proof", proofKV(
				"suite", fmt.Sprintf("%d", flow.Suite.Suite),
				"negotiatedIntegrity", fmt.Sprintf("0x%02x", flow.Suite.Integrity),
				"negotiatedConfidentiality", fmt.Sprintf("0x%02x", flow.Suite.Conf),
				"acceptedProtection", "cleartext")),
	}
}

func postAuthPinnedCleartextFlow(flow ipmi.AuthFlow) bool {
	switch flow.Mode {
	case "smcrakpFixedKey", "openbmcSetup":
		return true
	}
	return false
}

func openBMCRAKPAuthBypassFindings(t *engine.Target, auth *ipmi.AuthReport, inv *ipmi.PostAuthCollection, debugf func(string, ...any)) []engine.Finding {
	if t == nil || inv == nil || inv.Flow.Version != "2.0" {
		return nil
	}
	out := make([]engine.Finding, 0, 1)
	if disabledUser, ok := selectDisabledOpenBMCUser(inv); ok {
		adminUser := selectOpenBMCRelabelAdminUser(t, auth, inv)
		if strings.TrimSpace(adminUser) != "" && auth != nil && auth.Suite != nil && !t.DisableLogins {
			probe, _ := ipmi.ProbeOpenBMCDisabledSetupOverwrite(t.Host, t.IPMIPort(), disabledUser, adminUser, *auth.Suite, t.Timeout)
			if probe != nil {
				t.SetEvidence("ipmi.openBmcSetupIdentity", probe)
				if probe.SetupOverwriteCommandsWork {
					out = append(out, openBMCSetupIdentityFinding(probe))
				}
			} else {
				debugf("openbmc disabled-overwrite probe skipped: no probe result")
			}
		}
	}
	return out
}

func openBMCSetPrivEvidenceFields(attempts []ipmi.SetPrivAttempt) engine.Fields {
	fields := engine.Fields{engine.Field{Key: "setPrivAttempts", Val: fmt.Sprintf("%d", len(attempts))}}
	for i, at := range attempts {
		prefix := fmt.Sprintf("setPriv%d", i+1)
		fields = append(fields,
			engine.Field{Key: prefix + "Requested", Val: fmt.Sprintf("0x%02x", at.Requested)},
			engine.Field{Key: prefix + "Cc", Val: fmt.Sprintf("0x%02x", at.CC)},
			engine.Field{Key: prefix + "Success", Val: ternary(at.Success, "true", "false")},
		)
		if at.Granted != 0 {
			fields = append(fields, engine.Field{Key: prefix + "Granted", Val: fmt.Sprintf("0x%02x", at.Granted)})
		}
	}
	return fields
}

func selectDisabledOpenBMCUser(inv *ipmi.PostAuthCollection) (string, bool) {
	if inv == nil {
		return "", false
	}
	for _, user := range inv.Users {
		if user.Enabled || strings.TrimSpace(user.Name) == "" {
			continue
		}
		return strings.TrimSpace(user.Name), true
	}
	return "", false
}

func selectOpenBMCRelabelAdminUser(t *engine.Target, auth *ipmi.AuthReport, inv *ipmi.PostAuthCollection) string {
	if inv != nil && strings.TrimSpace(inv.Flow.RelabelUser) != "" {
		return strings.TrimSpace(inv.Flow.RelabelUser)
	}
	if v, ok := t.Evidenced("ipmi.openBmcSetupState"); ok {
		setup, _ := v.(*ipmi.OpenBMCSetupProbe)
		if setup != nil && strings.TrimSpace(setup.Username) != "" {
			return strings.TrimSpace(setup.Username)
		}
	}
	if auth != nil {
		for _, cr := range auth.Cracked {
			if cr.Verified && strings.TrimSpace(cr.Username) != "" {
				return strings.TrimSpace(cr.Username)
			}
		}
	}
	return ""
}

func openBMCSetupIdentityFinding(probe *ipmi.OpenBMCDisabledSetupOverwriteProbe) engine.Finding {
	fields := engine.F(
		"disabledUsername", userLabel(probe.DisabledUsername),
		"adminUsername", userLabel(probe.AdminUsername),
		"suite", fmt.Sprintf("%d", probe.Suite),
		"disabledRakpStatus", fmt.Sprintf("0x%02x", probe.DisabledRAKPStatus),
		"disabledCommandsWork", ternary(probe.DisabledCommandsWork, "true", "false"),
		"adminRakpStatus", fmt.Sprintf("0x%02x", probe.AdminRAKPStatus),
		"afterSetPrivAdminCc", fmt.Sprintf("0x%02x", probe.AfterSetPrivAdminCC),
		"proof", proofKV(
			"disabledSetPrivAdminCc", fmt.Sprintf("0x%02x", probe.DisabledSetPrivAdminCC),
			"afterSetPrivAdminCc", fmt.Sprintf("0x%02x", probe.AfterSetPrivAdminCC),
			"disabledCommandsWork", ternary(probe.DisabledCommandsWork, "true", "false")),
	)
	if len(probe.AfterPrivQueryData) > 0 {
		fields = append(fields, engine.Field{Key: "afterPrivQueryData", Val: fmt.Sprintf("%x", probe.AfterPrivQueryData)})
	}
	if len(probe.AfterSetPrivAdminData) > 0 {
		fields = append(fields, engine.Field{Key: "afterSetPrivAdminData", Val: fmt.Sprintf("%x", probe.AfterSetPrivAdminData)})
	}
	if probe.CloseSetupError != "" {
		fields = append(fields, engine.Field{Key: "closeSetupError", Val: probe.CloseSetupError})
	}
	return engine.Finding{Check: "ipmi.rakp.state.setupIdentity", Category: "auth", Risk: "high",
		CVE: []string{"CVE-2026-16140"}, Fields: fields}
}

func runPostAuthSMCRAKPPasswordEnum(ctx context.Context, t *engine.Target, auth *ipmi.AuthReport, debugf func(string, ...any)) ([]engine.Finding, *ipmi.CrackResult) {
	vendor := ""
	if t != nil && t.Identity != nil {
		vendor = t.Identity.Vendor
	}
	opts := ipmi.AuthOptions{
		Vendor:       vendor,
		Online:       !t.DisableLogins,
		OfflineCrack: true,
		Timeout:      t.Timeout,
	}
	if v, ok := t.Evidenced("ipmi.ciphers"); ok {
		if ids, ok := v.([]int); ok {
			opts.Ciphers = ids
		}
	}
	if creds := targetCreds(t); len(creds) > 0 {
		users := make([]string, 0, len(creds))
		passes := make([]string, 0, len(creds))
		seenU := map[string]bool{}
		seenP := map[string]bool{}
		for _, c := range creds {
			if c.User != "" && !seenU[c.User] {
				seenU[c.User] = true
				users = append(users, c.User)
			}
			if c.Pass != "" && !seenP[c.Pass] {
				seenP[c.Pass] = true
				passes = append(passes, c.Pass)
			}
		}
		opts.Usernames = users
		opts.ExtraPasswords = passes
	}

	rep := ipmi.RunSMCRAKPOnlinePasswordEnum(ctx, t.Host, t.IPMIPort(), auth, opts, 100, func(attempts int, sessionAlive bool) {
		debugf("smcrakp password test progress attempts=%d sessionAlive=%t", attempts, sessionAlive)
		t.Progress(fmt.Sprintf("post-auth ipmi smcrakp password test attempts=%d sessionAlive=%t", attempts, sessionAlive))
	})
	if rep == nil || !rep.Attempted {
		return nil, nil
	}
	suites := make([]string, 0, len(rep.Suites))
	for _, sid := range rep.Suites {
		suites = append(suites, fmt.Sprintf("%d", sid))
	}
	fields := engine.F(
		"attempted", "true",
		"candidateCount", fmt.Sprintf("%d", rep.Candidates),
		"attempts", fmt.Sprintf("%d", rep.Attempts),
		"sessionAlive", ternary(rep.SessionOK, "true", "false"),
	)
	if len(rep.Usernames) > 0 {
		fields = append(fields, engine.Field{Key: "usernames", Val: strings.Join(rep.Usernames, ",")})
	}
	if len(suites) > 0 {
		fields = append(fields, engine.Field{Key: "suites", Val: strings.Join(suites, ",")})
	}
	if rep.Credential != nil {
		fields = append(fields,
			engine.Field{Key: "result", Val: "credentialFound"},
			engine.Field{Key: "username", Val: userLabel(rep.Credential.Username)},
			engine.Field{Key: "password", Val: rep.Credential.Password},
			engine.Field{Key: "via", Val: rep.Credential.PasswordType},
			engine.Field{Key: "cracked", Val: crackedLabel(rep.Credential.PasswordType)},
		)
		if strings.TrimSpace(rep.Credential.Proof) != "" {
			fields = append(fields, engine.Field{Key: "proof", Val: rep.Credential.Proof})
		}
		debugf("smcrakp final online password test found user=%s attempts=%d", rep.Credential.Username, rep.Attempts)
		return []engine.Finding{
			{Check: "ipmi.postAuth.smcrakpOnlinePasswordTest", Category: "creds", Risk: "info", Fields: fields},
			{Check: "ipmi.postAuth.smcrakpOnlinePasswordHit", Category: "creds", Risk: "critical", Fields: fields},
			{Check: "ipmi.v20.defaultCreds", Category: "creds", Risk: "critical", Fields: engine.F(
				"username", userLabel(rep.Credential.Username),
				"password", rep.Credential.Password,
				"via", rep.Credential.PasswordType,
				"cracked", crackedLabel(rep.Credential.PasswordType),
				"proof", firstNonEmptySMCRAKP(rep.Credential.Proof, proofKV("rakp34Session", "ok", "verified", "true")),
			)},
		}, rep.Credential
	}
	fields = append(fields, engine.Field{Key: "result", Val: "noCredentialFound"})
	debugf("smcrakp final online password test no-hit attempts=%d", rep.Attempts)
	return []engine.Finding{{Check: "ipmi.postAuth.smcrakpOnlinePasswordTest", Category: "creds", Risk: "info", Fields: fields}}, nil
}

func postAuthBudget(perProbe time.Duration) time.Duration {
	if perProbe <= 0 {
		return 45 * time.Second
	}
	return min(max(perProbe*10, 30*time.Second), 75*time.Second)
}

func postAuthBudgetForFlow(perProbe time.Duration, flow ipmi.AuthFlow) time.Duration {
	b := postAuthBudget(perProbe)

	if flow.Mode == "smcrakpFixedKey" {
		b = min(max(b, 60*time.Second), 90*time.Second)
	}
	return b
}

func ipmiPostAuthDetailFindings(inv *ipmi.PostAuthCollection) []engine.Finding {
	if inv == nil {
		return nil
	}
	flow := fmt.Sprintf("%s/%s", inv.Flow.Version, inv.Flow.Mode)
	out := make([]engine.Finding, 0, 8)

	if inv.MCInfo != nil {
		f := engine.F(
			"flow", flow,
			"firmwareVersion", inv.MCInfo.FirmwareRevision,
			"ipmiVersion", inv.MCInfo.IPMIVersion,
			"manufacturerId", fmt.Sprintf("%d", inv.MCInfo.ManufacturerID),
			"productId", fmt.Sprintf("%d", inv.MCInfo.ProductID),
		)
		if inv.MCInfo.ManufacturerName != "" {
			f = append(f, engine.Field{Key: "manufacturer", Val: inv.MCInfo.ManufacturerName})

			f = append(f, vendorSlugField(inv.MCInfo.ManufacturerName)...)
		}

		if inv.MCInfo.FirmwareRevisionFull != "" {
			f = append(f, engine.Field{Key: "firmwareVersionFull", Val: inv.MCInfo.FirmwareRevisionFull})
		}
		if inv.MCInfo.AuxFirmwareHex != "" {
			f = append(f, engine.Field{Key: "auxFirmwareRev", Val: inv.MCInfo.AuxFirmwareHex})
		}
		out = append(out, engine.Finding{Check: "ipmi.postAuth.mcInfo", Category: "creds", Risk: "info", Fields: f})
	}

	if inv.Chassis != nil {
		out = append(out, engine.Finding{
			Check: "ipmi.postAuth.chassisStatus", Category: "creds", Risk: "info",
			Fields: engine.F(
				"flow", flow,
				"power", ternary(inv.Chassis.PowerOn, "on", "off"),
				"lastPowerEvent", inv.Chassis.LastEvent,
				"powerRestorePolicy", inv.Chassis.PowerRestore,
				"identifyOn", ternary(inv.Chassis.IdentifyOn, "true", "false"),
			),
		})
	}

	if n := len(inv.Users); n > 0 {
		named := make([]string, 0, n)
		enabled := 0
		for _, u := range inv.Users {
			if u.Enabled {
				enabled++
			}
			if strings.TrimSpace(u.Name) != "" {
				named = append(named, u.Name)
			}
		}
		sort.Strings(named)
		f := engine.F(
			"flow", flow,
			"slots", fmt.Sprintf("%d", n),
			"enabledSlots", fmt.Sprintf("%d", enabled),
			"namedUsers", fmt.Sprintf("%d", len(named)),
		)
		if len(named) > 0 {
			f = append(f, engine.Field{Key: "usernames", Val: strings.Join(named, ",")})
		}
		out = append(out, engine.Finding{Check: "ipmi.postAuth.userList", Category: "creds", Risk: "info", Fields: f})
	}

	if len(inv.LAN) > 0 {
		f := engine.F("flow", flow)
		keys := make([]string, 0, len(inv.LAN))
		for k := range inv.LAN {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			f = append(f, engine.Field{Key: k, Val: inv.LAN[k]})
		}
		out = append(out, engine.Finding{Check: "ipmi.postAuth.lanPrint", Category: "creds", Risk: "info", Fields: f})
	}

	if len(inv.LAN6) > 0 {
		f := engine.F("flow", flow)
		keys := make([]string, 0, len(inv.LAN6))
		for k := range inv.LAN6 {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			f = append(f, engine.Field{Key: k, Val: inv.LAN6[k]})
		}
		out = append(out, engine.Finding{Check: "ipmi.postAuth.lan6Print", Category: "creds", Risk: "info", Fields: f})
	}

	if n := len(inv.FRU); n > 0 {
		deviceCount, areaList, preview := summarizeFRU(inv.FRU, 8)
		f := engine.F("flow", flow, "fields", fmt.Sprintf("%d", n))
		f = append(f, engine.Field{Key: "devices", Val: fmt.Sprintf("%d", deviceCount)})
		if len(areaList) > 0 {
			f = append(f, engine.Field{Key: "areas", Val: strings.Join(areaList, ",")})
		}

		if bp := fruFieldValue(inv.FRU, "Board Product"); bp != "" {
			f = append(f, engine.Field{Key: "boardProduct", Val: bp})
		}
		if pn := fruFieldValue(inv.FRU, "Product Name"); pn != "" {
			f = append(f, engine.Field{Key: "productName", Val: pn})
		}
		if bm := fruFieldValue(inv.FRU, "Board Mfg"); bm != "" {
			f = append(f, engine.Field{Key: "boardMfg", Val: bm})
		}
		if pm := fruFieldValue(inv.FRU, "Product Manufacturer"); pm != "" {
			f = append(f, engine.Field{Key: "productMfg", Val: pm})
		}

		if slug := vendorSlugField(fruFieldValue(inv.FRU, "Board Mfg")); len(slug) > 0 {
			f = append(f, slug...)
		} else {
			f = append(f, vendorSlugField(fruFieldValue(inv.FRU, "Product Manufacturer"))...)
		}
		if len(preview) > 0 {
			f = append(f, engine.Field{Key: "preview", Val: strings.Join(preview, " | ")})
		}
		out = append(out, engine.Finding{Check: "ipmi.postAuth.fru", Category: "creds", Risk: "info", Fields: f})
	}

	if n := len(inv.CipherMatrix); n > 0 {
		success := 0
		suites := make([]string, 0, n)
		for _, ca := range inv.CipherMatrix {
			suites = append(suites, fmt.Sprintf("%d", ca.Suite))
			if ca.Success {
				success++
			}
		}
		out = append(out, engine.Finding{
			Check: "ipmi.postAuth.cipherMatrix", Category: "creds", Risk: "info",
			Fields: engine.F(
				"flow", flow,
				"attempts", fmt.Sprintf("%d", n),
				"success", fmt.Sprintf("%d", success),
				"suites", strings.Join(suites, ","),
			),
		})
	}

	if n := len(inv.SetPrivAttempts); n > 0 {
		succeeded := setPrivProbeSuccesses(inv.SetPrivAttempts)
		f := engine.F(
			"flow", flow,
			"attempts", fmt.Sprintf("%d", n),
			"success", fmt.Sprintf("%d", len(succeeded)),
		)
		if len(succeeded) > 0 {
			f = append(f, engine.Field{Key: "successValues", Val: strings.Join(succeeded, ",")})
		}
		out = append(out, engine.Finding{Check: "ipmi.postAuth.setPriv", Category: "creds", Risk: "info", Fields: f})
	}

	if inv.OpenBMCSetup != nil {
		f := engine.F(
			"flow", flow,
			"privilegeQueryCc", fmt.Sprintf("0x%02x", inv.OpenBMCSetup.PrivilegeQueryCC),
			"payloadStatusCc", fmt.Sprintf("0x%02x", inv.OpenBMCSetup.PayloadStatusCC),
			"providerBlocked", ternary(inv.OpenBMCSetup.ProviderBlocked, "true", "false"),
		)
		if inv.OpenBMCSetup.PrivilegeQueryDataHex != "" {
			f = append(f, engine.Field{Key: "privilegeQueryData", Val: inv.OpenBMCSetup.PrivilegeQueryDataHex})
		}
		if inv.OpenBMCSetup.PayloadStatusDataHex != "" {
			f = append(f, engine.Field{Key: "payloadStatusData", Val: inv.OpenBMCSetup.PayloadStatusDataHex})
		}
		if inv.OpenBMCSetup.PayloadInfoDataHex != "" {
			f = append(f, engine.Field{Key: "payloadInfoData", Val: inv.OpenBMCSetup.PayloadInfoDataHex})
		}
		if inv.OpenBMCSetup.ProviderGetDeviceIDHex != "" {
			f = append(f, engine.Field{Key: "providerGetDeviceId", Val: inv.OpenBMCSetup.ProviderGetDeviceIDHex})
		}
		out = append(out, engine.Finding{Check: "ipmi.postAuth.openBmcSetup", Category: "creds", Risk: "info", Fields: f})
	}

	return out
}

func hasPostAuthInventory(inv *ipmi.PostAuthCollection) bool {
	if inv == nil {
		return false
	}
	if len(inv.Completed) > 0 || inv.OpenBMCSetup != nil || inv.MCInfo != nil || inv.Chassis != nil || len(inv.Users) > 0 || len(inv.LAN) > 0 || len(inv.LAN6) > 0 || len(inv.FRU) > 0 {
		return true
	}
	if inv.Flow.Mode == "openbmcSetup" {
		for _, at := range inv.SetPrivAttempts {
			if at.Success {
				return true
			}
		}
	}
	return false
}

func postAuthInventorySummary(inv *ipmi.PostAuthCollection) string {
	completedSet := map[string]bool{}
	if inv != nil {
		for _, section := range inv.Completed {
			completedSet[section] = true
		}
	}
	sections := []struct {
		name string
		has  bool
	}{
		{"mcInfo", completedSet["mcInfo"] || inv != nil && inv.MCInfo != nil},
		{"chassis", completedSet["chassis"] || inv != nil && inv.Chassis != nil},
		{"users", completedSet["users"] || inv != nil && len(inv.Users) > 0},
		{"lan", completedSet["lan"] || inv != nil && len(inv.LAN) > 0},
		{"lan6", completedSet["lan6"] || inv != nil && len(inv.LAN6) > 0},
		{"fru", completedSet["fru"] || inv != nil && len(inv.FRU) > 0},
	}
	completed := make([]string, 0, len(sections))
	missing := make([]string, 0, len(sections))
	for _, section := range sections {
		if section.has {
			completed = append(completed, section.name)
		} else {
			missing = append(missing, section.name)
		}
	}
	summary := fmt.Sprintf("completed=%s missing=%s", strings.Join(completed, ","), strings.Join(missing, ","))

	if inv != nil && len(inv.Empty) > 0 {
		summary += " empty=" + strings.Join(inv.Empty, ",")
	}
	if inv != nil && inv.IncompleteAt != "" {
		summary += " stoppedAt=" + inv.IncompleteAt
	}
	return summary
}

var postAuthSections = []string{"mcInfo", "chassis", "users", "lan", "lan6", "fru"}

func postAuthCoverageScore(inv *ipmi.PostAuthCollection) int {
	if inv == nil {
		return 0
	}
	return len(postAuthSections) - len(postAuthMissingSections(inv))
}

const (
	postAuthMaxFallbackFlows = 2

	postAuthFallbackMinWindow = 8 * time.Second

	postAuthFallbackMaxWindow = 20 * time.Second
)

func postAuthFallbackWindow(ctx context.Context) (time.Duration, bool) {
	dl, ok := ctx.Deadline()
	if !ok {
		return postAuthFallbackMaxWindow, true
	}
	window := time.Until(dl) / 2
	if window < postAuthFallbackMinWindow {
		return 0, false
	}
	return min(window, postAuthFallbackMaxWindow), true
}

const postAuthCandidateMinWindow = 3 * time.Second

func postAuthBudgetSpent(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dl, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	if time.Until(dl) < postAuthCandidateMinWindow {
		return context.DeadlineExceeded
	}
	return nil
}

type postAuthCollectFunc func(ctx context.Context, flow ipmi.AuthFlow) (*ipmi.PostAuthCollection, error)

func walkPostAuthFallbacks(ctx context.Context, candidates []ipmi.AuthFlow, flow ipmi.AuthFlow, inv *ipmi.PostAuthCollection, err error, collect postAuthCollectFunc, debugf func(string, ...any)) (ipmi.AuthFlow, *ipmi.PostAuthCollection, error) {
	if collect == nil || len(candidates) < 2 {
		return flow, inv, err
	}
	if ipmi.SessionResourceExhausted(inv, err) {
		debugf("skip fallback flows: bmc reports no session resources")
		return flow, inv, err
	}
	tried := 0
	for i := 1; i < len(candidates) && ctx.Err() == nil; i++ {
		if postAuthCoverageScore(inv) >= len(postAuthSections) {
			break
		}
		if tried >= postAuthMaxFallbackFlows {
			debugf("stop fallback flows: attempt limit %d reached", postAuthMaxFallbackFlows)
			break
		}
		window, okWindow := postAuthFallbackWindow(ctx)
		if !okWindow {
			debugf("stop fallback flows: budget spent")
			break
		}
		next := candidates[i]
		debugf("trying fallback flow %d/%d %s/%s user=%s source=%s window=%s",
			i+1, len(candidates), next.Version, next.Mode, userOrNull(next.Username), next.Source, window)
		attemptCtx, cancel := context.WithTimeout(ctx, window)
		altInv, altErr := collect(attemptCtx, next)
		cancel()
		tried++
		if postAuthCoverageScore(altInv) > postAuthCoverageScore(inv) {
			debugf("fallback %s/%s improved coverage %d -> %d", next.Version, next.Mode,
				postAuthCoverageScore(inv), postAuthCoverageScore(altInv))
			flow, inv, err = next, altInv, altErr
		} else if altErr != nil {
			debugf("fallback %s/%s failed err=%v", next.Version, next.Mode, altErr)
		}
		if ipmi.SessionResourceExhausted(altInv, altErr) {
			debugf("stop fallback flows: bmc reports no session resources")
			break
		}
	}
	return flow, inv, err
}

func userOrNull(user string) string {
	if strings.TrimSpace(user) == "" {
		return "(null)"
	}
	return user
}

func postAuthMissingSections(inv *ipmi.PostAuthCollection) []string {
	if inv == nil {
		return postAuthSections
	}
	done := map[string]bool{}
	for _, s := range inv.Completed {
		done[s] = true
	}
	has := map[string]bool{
		"mcInfo":  inv.MCInfo != nil,
		"chassis": inv.Chassis != nil,
		"users":   len(inv.Users) > 0,
		"lan":     len(inv.LAN) > 0,
		"lan6":    len(inv.LAN6) > 0,
		"fru":     len(inv.FRU) > 0,
	}
	var missing []string
	for _, s := range postAuthSections {
		if !done[s] && !has[s] {
			missing = append(missing, s)
		}
	}
	return missing
}

func reportPostAuthIssue(t *engine.Target, flow ipmi.AuthFlow, inv *ipmi.PostAuthCollection, err error) {
	if t == nil || t.Progress == nil || err == nil {
		return
	}
	t.Progress(fmt.Sprintf("post-auth ipmi incomplete flow=%s/%s %s error=%v", flow.Version, flow.Mode, postAuthInventorySummary(inv), err))
}

func isLimitedPrivilegePostAuthFailure(inv *ipmi.PostAuthCollection, err error) bool {
	if err == nil {
		return false
	}
	if inv == nil {
		return false
	}
	for _, a := range inv.CipherMatrix {
		if a.Success {
			return false
		}
		if isSetPrivDeniedErr(a.Error) {
			return true
		}
	}
	if isSetPrivDeniedErr(inv.Error) {
		return true
	}
	return isSetPrivDeniedErr(err.Error())
}

func isSetPrivDeniedErr(s string) bool {
	s = strings.ToLower(s)
	if !strings.Contains(s, "set-session-privilege") {
		return false
	}
	return strings.Contains(s, "cc=0x80") || strings.Contains(s, "cc=0x81") || strings.Contains(s, "cc=0x82")
}

func setPrivProbeSuccesses(attempts []ipmi.SetPrivAttempt) []string {
	out := make([]string, 0, len(attempts))
	for _, a := range attempts {
		if !a.Success {
			continue
		}
		label := fmt.Sprintf("0x%02x", a.Requested)
		if a.Name != "" && a.Name != "undefined" {
			label = a.Name
		}
		if a.Granted != 0 {
			label = fmt.Sprintf("%s->0x%02x", label, a.Granted)
		}
		out = append(out, label)
	}
	return out
}

func fruFieldValue(fields []ipmi.FRUField, name string) string {
	for _, ff := range fields {
		if strings.EqualFold(strings.TrimSpace(ff.Name), name) {
			if v := strings.TrimSpace(ff.Value); v != "" {
				return v
			}
		}
	}
	return ""
}

func summarizeFRU(fields []ipmi.FRUField, maxPreview int) (int, []string, []string) {
	devices := map[int]struct{}{}
	areas := map[string]struct{}{}
	preview := make([]string, 0, maxPreview)
	seenPreview := map[string]struct{}{}
	for _, ff := range fields {
		devices[ff.DeviceID] = struct{}{}
		if ff.Area != "" {
			areas[ff.Area] = struct{}{}
		}
		if strings.TrimSpace(ff.Value) == "" || len(preview) >= maxPreview {
			continue
		}
		label := fmt.Sprintf("d%d:%s[%d]=%s", ff.DeviceID, ff.Area, ff.Index, ff.Value)
		if _, ok := seenPreview[label]; ok {
			continue
		}
		seenPreview[label] = struct{}{}
		preview = append(preview, label)
	}
	areaList := make([]string, 0, len(areas))
	for a := range areas {
		areaList = append(areaList, a)
	}
	sort.Strings(areaList)
	return len(devices), areaList, preview
}

func selectOpenBMCSetupFlow(t *engine.Target, auth *ipmi.AuthReport) (ipmi.AuthFlow, bool) {
	if t == nil || auth == nil || auth.Suite == nil || t.DisableLogins {
		return ipmi.AuthFlow{}, false
	}
	v, ok := t.Evidenced("ipmi.openBmcSetupState")
	if !ok {
		return ipmi.AuthFlow{}, false
	}
	setup, _ := v.(*ipmi.OpenBMCSetupProbe)
	if setup == nil || !setup.AdminPrivAccepted || strings.TrimSpace(setup.Username) == "" {
		return ipmi.AuthFlow{}, false
	}
	return ipmi.AuthFlow{
		Version:  "2.0",
		Mode:     "openbmcSetup",
		Username: setup.Username,
		Suite:    *auth.Suite,
		Source:   "ipmi.rakp.state.setupLocalPreRakp3",
	}, true
}

func collectPostAuthWithMatrix(ctx context.Context, t *engine.Target, flow ipmi.AuthFlow, debugf func(string, ...any)) (*ipmi.PostAuthCollection, error) {

	if budgetErr := postAuthBudgetSpent(ctx); budgetErr != nil {
		debugf("skip collect: budget spent before the first session open")
		err := fmt.Errorf("post-auth budget spent before the first session open: %w", budgetErr)
		return &ipmi.PostAuthCollection{Flow: flow, IncompleteAt: "budget", Error: err.Error()}, err
	}
	if flow.Version != "2.0" {
		debugf("single-flow collect version=%s mode=%s", flow.Version, flow.Mode)
		return ipmi.CollectPostAuthInventory(ctx, t.Host, t.IPMIPort(), flow, t.Timeout)
	}
	if flow.Mode == "cipherZero" {

		debugf("single-flow collect mode=cipherZero suite=0")
		return ipmi.CollectPostAuthInventory(ctx, t.Host, t.IPMIPort(), flow, t.Timeout)
	}
	if flow.Mode == "smcrakpFixedKey" {
		cands := smcrakpPostAuthCipherCandidates(t, flow.Suite)
		if len(cands) > 4 {
			cands = cands[:4]
		}
		debugf("smcrakp bounded-suite collect candidates=%d preferred=%d user=%s", len(cands), flow.Suite.Suite, flow.Username)
		attempts := make([]ipmi.CipherAttempt, 0, len(cands))
		var lastErr error
		var bestAuthOnly *ipmi.PostAuthCollection

		var lastFailed *ipmi.PostAuthCollection
		var lastFailedFlow ipmi.AuthFlow
		for _, ca := range cands {

			if budgetErr := postAuthBudgetSpent(ctx); budgetErr != nil {
				debugf("stop smcrakp suites: budget spent before suite=%d", ca.Suite)
				if lastErr == nil {
					lastErr = fmt.Errorf("post-auth budget spent before any smcrakp cipher suite was tried: %w", budgetErr)
				}
				break
			}
			ff := flow
			ff.Suite = ca
			inv, err := ipmi.CollectPostAuthInventory(ctx, t.Host, t.IPMIPort(), ff, t.Timeout)
			a := ipmi.CipherAttempt{Suite: ca.Suite, Auth: ca.Auth, Integrity: ca.Integrity, Conf: ca.Conf}
			if err != nil {
				a.Error = err.Error()
				lastErr = err
				attempts = append(attempts, a)
				if inv != nil {
					lastFailed, lastFailedFlow = inv, ff
				}
				if ipmi.SessionResourceExhausted(inv, err) {
					debugf("stop smcrakp suites: bmc reports no session resources")
					break
				}
				continue
			}
			a.Success = true
			attempts = append(attempts, a)
			if inv == nil {
				continue
			}
			inv.Flow = ff
			inv.CipherMatrix = append([]ipmi.CipherAttempt(nil), attempts...)
			if inv.MCInfo != nil || inv.Chassis != nil || len(inv.Users) > 0 || len(inv.LAN) > 0 || len(inv.LAN6) > 0 || len(inv.FRU) > 0 {
				return inv, nil
			}
			if bestAuthOnly == nil {
				bestAuthOnly = inv
			}
		}
		if bestAuthOnly != nil {
			if len(bestAuthOnly.CipherMatrix) == 0 {
				bestAuthOnly.CipherMatrix = append([]ipmi.CipherAttempt(nil), attempts...)
			}
			return bestAuthOnly, nil
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no smcrakp cipher suite worked")
		}
		if lastFailed != nil {
			lastFailed.Flow = lastFailedFlow
			lastFailed.CipherMatrix = attempts
			if lastFailed.Error == "" {
				lastFailed.Error = lastErr.Error()
			}
			return lastFailed, lastErr
		}
		inv := &ipmi.PostAuthCollection{Flow: flow, CipherMatrix: attempts, Error: lastErr.Error()}
		return inv, lastErr
	}
	cands := v2CipherCandidates(t, flow.Suite)
	debugf("cipher-matrix start candidates=%d preferredSuite=%d", len(cands), flow.Suite.Suite)
	attempts := make([]ipmi.CipherAttempt, 0, len(cands))
	var lastErr error

	var bestOpened *ipmi.PostAuthCollection
	var bestOpenedFlow ipmi.AuthFlow

	var lastFailed *ipmi.PostAuthCollection
	var lastFailedFlow ipmi.AuthFlow
	for _, ca := range cands {

		if budgetErr := postAuthBudgetSpent(ctx); budgetErr != nil {
			debugf("stop cipher candidates: budget spent before suite=%d", ca.Suite)
			if lastErr == nil {
				lastErr = fmt.Errorf("post-auth budget spent before any cipher suite was tried: %w", budgetErr)
			}
			break
		}
		suiteStart := time.Now()
		ff := flow
		ff.Suite = ca
		var (
			inv *ipmi.PostAuthCollection
			err error
		)
		maxAttempts := 2
		if t.Timeout > 0 && t.Timeout <= 10*time.Second {
			maxAttempts = 1
		}
		debugf("cipher suite=%d auth=0x%02x integ=0x%02x conf=0x%02x maxAttempts=%d", ca.Suite, ca.Auth, ca.Integrity, ca.Conf, maxAttempts)
		for attempt := 0; attempt < maxAttempts; attempt++ {
			attemptStart := time.Now()
			inv, err = ipmi.CollectPostAuthInventory(ctx, t.Host, t.IPMIPort(), ff, t.Timeout)
			debugf("cipher suite=%d attempt=%d elapsed=%s err=%v", ca.Suite, attempt+1, time.Since(attemptStart).Round(time.Millisecond), err)
			if err == nil {
				break
			}
			if !isTimeoutLikeErr(err) || ctx.Err() != nil {
				break
			}
		}
		a := ipmi.CipherAttempt{Suite: ca.Suite, Auth: ca.Auth, Integrity: ca.Integrity, Conf: ca.Conf}
		if err != nil {
			a.Error = err.Error()
			if hasPostAuthInventory(inv) {
				a.Success = true
				a.Error = ""
				attempts = append(attempts, a)
				inv.Flow = ff
				inv.CipherMatrix = attempts
				if inv.Error == "" {
					inv.Error = err.Error()
				}
				debugf("cipher suite=%d returned partial inventory totalElapsed=%s", ca.Suite, time.Since(suiteStart).Round(time.Millisecond))
				return inv, err
			}
			attempts = append(attempts, a)
			lastErr = err
			if bestOpened == nil && postAuthSessionOpened(inv) {
				bestOpened, bestOpenedFlow = inv, ff
			}
			if inv != nil {
				lastFailed, lastFailedFlow = inv, ff
			}
			debugf("cipher suite=%d failed totalElapsed=%s", ca.Suite, time.Since(suiteStart).Round(time.Millisecond))

			if ipmi.SessionResourceExhausted(inv, err) {
				debugf("stop cipher candidates: bmc reports no session resources")
				break
			}

			if postAuthPrivilegeCeiling(inv) {
				debugf("stop cipher candidates: session works, account has no command privilege")
				break
			}
			continue
		}
		a.Success = true
		attempts = append(attempts, a)
		debugf("cipher suite=%d succeeded totalElapsed=%s", ca.Suite, time.Since(suiteStart).Round(time.Millisecond))
		if inv != nil {
			inv.Flow = ff
			inv.CipherMatrix = attempts
			debugf("cipher fallback done success suite=%d attempts=%d", ff.Suite.Suite, len(attempts))
			return inv, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no cipher suite candidates worked")
	}
	debugf("cipher-matrix failed attempts=%d err=%v", len(attempts), lastErr)
	if bestOpened != nil {
		bestOpened.Flow = bestOpenedFlow
		bestOpened.CipherMatrix = attempts
		if bestOpened.Error == "" {
			bestOpened.Error = lastErr.Error()
		}
		debugf("cipher-matrix kept opened session suite=%d protection=%s", bestOpenedFlow.Suite.Suite, bestOpened.CommandProtection)
		return bestOpened, lastErr
	}

	if lastFailed != nil {
		lastFailed.Flow = lastFailedFlow
		lastFailed.CipherMatrix = attempts
		if lastFailed.Error == "" {
			lastFailed.Error = lastErr.Error()
		}
		debugf("cipher-matrix kept last failed collection stoppedAt=%s", lastFailed.IncompleteAt)
		return lastFailed, lastErr
	}
	inv := &ipmi.PostAuthCollection{Flow: flow, CipherMatrix: attempts, Error: lastErr.Error()}
	return inv, lastErr
}

func postAuthSessionOpened(inv *ipmi.PostAuthCollection) bool {
	return inv != nil && inv.CommandProtection != ""
}

func postAuthPrivilegeCeiling(inv *ipmi.PostAuthCollection) bool {
	if inv == nil {
		return false
	}
	if inv.CommandProtection != "cleartext" && inv.CommandProtection != "integrity+conf" {
		return false
	}
	return !hasPostAuthInventory(inv)
}

func isTimeoutLikeErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "timeout") || strings.Contains(s, "i/o timeout")
}

func v2CipherCandidates(t *engine.Target, preferred ipmi.CipherAlgos) []ipmi.CipherAlgos {
	ids := []int{}
	if v, ok := t.Evidenced("ipmi.ciphers"); ok {
		if got, ok := v.([]int); ok {
			ids = got
		}
	}
	all := ipmi.CipherTriples(ids)
	out := make([]ipmi.CipherAlgos, 0, len(all)+2)
	seen := map[int]bool{}
	add := func(ca ipmi.CipherAlgos) {
		if ca.Suite == 0 {
			return
		}
		if seen[ca.Suite] {
			return
		}
		seen[ca.Suite] = true
		out = append(out, ca)
	}
	if preferred.Suite != 0 {
		add(preferred)
	}

	add(ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityHMACSHA196, Conf: ipmi.ConfAESCBC})
	for _, ca := range all {
		add(ca)
	}
	if len(out) == 0 {
		out = append(out, ipmi.CipherAlgos{Suite: 3, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityHMACSHA196, Conf: ipmi.ConfAESCBC})
	}
	return out
}

func smcrakpPostAuthCipherCandidates(t *engine.Target, preferred ipmi.CipherAlgos) []ipmi.CipherAlgos {
	ids := []int{}
	if v, ok := t.Evidenced("ipmi.ciphers"); ok {
		if got, ok := v.([]int); ok {
			ids = got
		}
	}
	all := ipmi.CipherTriples(ids)
	byID := map[int]ipmi.CipherAlgos{}
	for _, ca := range all {
		byID[ca.Suite] = ca
	}
	if preferred.Suite != 0 {
		byID[preferred.Suite] = preferred
	}
	prefOrder := []int{1, 6, 15, 16, 3, 17, 2, 7, 8, 11, 12, 4, 5, 9, 10, 13, 14, 18, 19}
	out := make([]ipmi.CipherAlgos, 0, len(prefOrder))
	seen := map[int]bool{}
	add := func(ca ipmi.CipherAlgos) {
		if ca.Suite == 0 || seen[ca.Suite] {
			return
		}
		seen[ca.Suite] = true
		out = append(out, ca)
	}
	for _, sid := range prefOrder {
		if ca, ok := byID[sid]; ok {
			add(ca)
		}
	}
	if len(out) == 0 {
		if ca, ok := ipmi.CipherAlgosFor(1); ok {
			add(ca)
		}
		if ca, ok := ipmi.CipherAlgosFor(6); ok {
			add(ca)
		}
		if ca, ok := ipmi.CipherAlgosFor(15); ok {
			add(ca)
		}
		if ca, ok := ipmi.CipherAlgosFor(16); ok {
			add(ca)
		}
		if ca, ok := ipmi.CipherAlgosFor(3); ok {
			add(ca)
		}
	}
	return out
}

func ternary(ok bool, t, f string) string {
	if ok {
		return t
	}
	return f
}

func runV15ForPostAuthFallback(ctx context.Context, t *engine.Target) *ipmi.V15Report {
	vendor := ""
	if t.Identity != nil {
		vendor = t.Identity.Vendor
	}
	var caps *ipmi.AuthCaps
	if v, ok := t.Evidenced("ipmi.authCaps"); ok {
		caps, _ = v.(*ipmi.AuthCaps)
	}
	rep := ipmi.RunSession15(ctx, t.Host, t.IPMIPort(), ipmi.V15Options{
		Vendor:  vendor,
		Caps:    caps,
		Online:  !t.DisableLogins,
		Timeout: t.Timeout,
	})
	if rep != nil {
		t.SetEvidence("ipmi.v15", rep)
	}
	return rep
}

func v15CredFallbackFlow(v15 *ipmi.V15Report) (ipmi.AuthFlow, bool) {
	if v15 == nil || v15.DefaultCred == nil {
		return ipmi.AuthFlow{}, false
	}
	at := ipmi.IPMI15AuthMD5
	switch v15.DefaultCred.Via {
	case "md2":
		at = ipmi.IPMI15AuthMD2
	case "straight":
		at = ipmi.IPMI15AuthPass
	}
	return ipmi.AuthFlow{
		Version:  "1.5",
		Mode:     "cred",
		Username: v15.DefaultCred.Username,
		Password: v15.DefaultCred.Password,
		AuthType: at,
		Source:   "ipmi.v15.defaultCreds",
	}, true
}

func likelyV15Capable(t *engine.Target) bool {
	if t == nil {
		return false
	}
	if v, ok := t.Evidenced("ipmi.authCaps"); ok {
		if ac, ok := v.(*ipmi.AuthCaps); ok && ac != nil {
			return ac.HasAuthMD5() || ac.HasAuthMD2() || ac.HasAuthStraight() || ac.HasAuthNone()
		}
	}
	return false
}

func init() {
	RegisterExplain("ipmi.postAuthEnum", explainIPMIPostAuthEnum)
}

func explainIPMIPostAuthEnum(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	flow := explainField(f, "flow")
	user := explainField(f, "user")
	pass := explainField(f, "pass")
	if user == "" {
		user = "<user>"
	}
	if pass == "" {
		pass = "<pass>"
	}
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nPost-auth IPMI inventory was collected using the selected auth flow.\n")
	b.WriteString(fmt.Sprintf("\n**Flow:** `%s`\n", flow))
	b.WriteString("\n**Equivalent ipmitool commands:**\n")
	if strings.HasPrefix(flow, "1.5") {
		b.WriteString(explainSh(
			fmt.Sprintf("ipmitool -I lan -H %s -p %d -A MD5 -U '%s' -P '%s' mc info", host, port, user, pass),
			fmt.Sprintf("ipmitool -I lan -H %s -p %d -A MD5 -U '%s' -P '%s' chassis status", host, port, user, pass),
			fmt.Sprintf("ipmitool -I lan -H %s -p %d -A MD5 -U '%s' -P '%s' user list", host, port, user, pass),
			fmt.Sprintf("ipmitool -I lan -H %s -p %d -A MD5 -U '%s' -P '%s' lan print", host, port, user, pass),
			fmt.Sprintf("ipmitool -I lan -H %s -p %d -A MD5 -U '%s' -P '%s' fru", host, port, user, pass),
		))
	} else {
		b.WriteString(explainSh(
			fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -U '%s' -P '%s' mc info", host, port, user, pass),
			fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -U '%s' -P '%s' chassis status", host, port, user, pass),
			fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -U '%s' -P '%s' user list", host, port, user, pass),
			fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -U '%s' -P '%s' lan print", host, port, user, pass),
			fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -U '%s' -P '%s' lan6 print", host, port, user, pass),
			fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -U '%s' -P '%s' fru", host, port, user, pass),
		))
	}
	return b.String()
}

func postAuthNegotiatedFlow(flow ipmi.AuthFlow, inv *ipmi.PostAuthCollection) ipmi.AuthFlow {
	if inv == nil {
		return flow
	}
	got := inv.Flow
	if got.Suite.Suite == 0 && got.Suite.Auth == 0 && got.Suite.Integrity == 0 && got.Suite.Conf == 0 {
		return flow
	}
	return got
}
