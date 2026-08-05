package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/ssh"
)

var sshTryDefaults = ssh.TryDefaults

func sshCredRisk(output string) string {

	if sshAccessLevel(output) == "shell" {
		return "critical"
	}
	return "info"
}

func sshAccessLevel(output string) string {
	o := strings.ToLower(strings.TrimSpace(output))
	if o == "" {
		return "restricted"
	}
	if strings.HasPrefix(o, "authenticated (") {
		return "restricted"
	}
	for _, deny := range []string{
		"no access privilege", "command not supported",
		"access denied", "permission denied", "not permitted",
		"not supported", "invalid command", "unknown command",
	} {
		if strings.Contains(o, deny) {
			return "restricted"
		}
	}
	return "shell"
}

func RunPostChecks(ctx context.Context, t *engine.Target) []engine.Finding {
	var out []engine.Finding
	out = append(out, runIPMICredsFromRecoveredCreds(ctx, t)...)
	out = append(out, runIPMIPostAuthPostCheck(ctx, t)...)
	out = append(out, runSSHWithRecoveredIPMICreds(ctx, t)...)
	out = append(out, runSMCWebWithRecoveredIPMICreds(ctx, t)...)
	return out
}

const smcWebPostCheckMaxPOSTs = 12

func runSMCWebWithRecoveredIPMICreds(ctx context.Context, t *engine.Target) []engine.Finding {
	if ctx.Err() != nil || t == nil || t.DisableLogins {
		return nil
	}
	if identityVendor(t) != "supermicro" {
		return nil
	}
	if targetHasFinding(t, httpCredCheckName("supermicro")) {
		return nil
	}
	seen := map[[2]string]struct{}{}
	var cands []smcCred
	add := func(c smcCred) {
		if c.user == "" {
			return
		}
		k := [2]string{c.user, c.pass}
		if _, dup := seen[k]; dup {
			return
		}
		seen[k] = struct{}{}
		cands = append(cands, c)
	}

	if auth, ok := ipmiAuthEvidence(t); ok {
		for _, p := range ipmiCrackedSSHPairs(auth, 8) {
			add(smcCred{user: p[0], pass: p[1], source: "ipmi.rakpCracked"})
		}
	}
	for _, c := range smcWebCandidates(t) {
		add(c)
	}
	return smcWebLoginWith(ctx, t, cands, smcWebPostCheckMaxPOSTs)
}

func runIPMIPostAuthPostCheck(ctx context.Context, t *engine.Target) []engine.Finding {
	if !shouldRunIPMIPostAuthPostCheck(t) {
		return nil
	}
	return runIPMIPostAuthEnum(ctx, t)
}

func shouldRunIPMIPostAuthPostCheck(t *engine.Target) bool {
	if t == nil || t.Identity == nil || t.Identity.Class != engine.ClassBMC {
		return false
	}
	if targetHasFinding(t, "ipmi.postAuthEnum") {
		return false
	}
	if _, ok := t.Evidenced("ipmi.postAuth"); ok {
		return false
	}
	return true
}

func runSSHWithRecoveredIPMICreds(ctx context.Context, t *engine.Target) []engine.Finding {
	if ctx.Err() != nil || t.DisableLogins || !isOOBDevice(t) || targetHasFinding(t, "ssh.defaultCreds") {
		return nil
	}
	ports := sshPorts(t)
	if len(ports) == 0 {
		return nil
	}
	auth, ok := ipmiAuthEvidence(t)
	if !ok {
		return nil
	}
	pairs := ipmiCrackedSSHPairs(auth, 8)
	if len(pairs) == 0 {
		return nil
	}
	attempted := false
	for _, port := range ports {
		if ctx.Err() != nil {
			return nil
		}
		attempted = true
		if u, p, out, ok := sshTryDefaults(t.Host, port, t.Timeout, pairs, len(pairs)); ok {
			return []engine.Finding{{
				Check: "ssh.defaultCreds", Category: "creds", Risk: sshCredRisk(out),
				Port: port, Transport: "tcp", Protocol: "ssh",
				Fields: engine.F("user", u, "pass", p, "output", out, "access", sshAccessLevel(out), "via", "ipmi.rakpCracked"),
			}}
		}
	}
	if attempted {
		return []engine.Finding{{
			Check: "ssh.defaultCredsAttempted", Category: "creds", Risk: "info",
			Fields: engine.F(
				"via", "ipmi.rakpCracked",
				"ports", intsCSV(ports),
				"pairsTried", fmt.Sprintf("%d", len(pairs)),
				"usersTried", usernamesCSVFromPairs(pairs),
				"sshFromIPMI", "failed",
			),
		}}
	}
	return nil
}

func runIPMICredsFromRecoveredCreds(ctx context.Context, t *engine.Target) []engine.Finding {
	if ctx.Err() != nil || t == nil || targetHasFinding(t, "ipmi.v20.defaultCreds") {
		return nil
	}
	auth, ok := ipmiAuthEvidenceAny(t)
	if !ok {
		return nil
	}

	type cand struct {
		user   string
		pass   string
		source string
	}
	var candidates []cand
	seen := map[[2]string]struct{}{}
	add := func(user, pass, source string) {
		user = strings.TrimSpace(user)
		if user == "" {
			return
		}
		if pass == "(blank)" {
			pass = ""
		}
		k := [2]string{user, pass}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		candidates = append(candidates, cand{user: user, pass: pass, source: source})
	}
	for _, c := range targetCreds(t) {
		add(c.User, c.Pass, "providedCreds")
	}
	for _, f := range t.FindingsSnapshot() {
		u := explainField(f, "username")
		p := explainField(f, "password")
		if u == "" {
			u = explainField(f, "user")
		}
		if p == "" {
			p = explainField(f, "pass")
		}
		if p == "" && f.Check == "ipmi.v20.rakpHash" {
			p = explainField(f, "cracked")
		}
		if u != "" {
			add(u, p, f.Check)
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	var out []engine.Finding
	for i := range auth.Results {
		r := &auth.Results[i]
		if len(r.RAKPHash) == 0 || r.UsesSMCRAKPFixedKey() {
			continue
		}
		for _, c := range candidates {
			if c.user != r.Username {
				continue
			}
			if !r.VerifyRAKPPassword(c.pass) {
				continue
			}
			hit := ipmi.CrackResult{
				Username:     c.user,
				Password:     c.pass,
				PasswordType: "custom",
				Verified:     true,
				Proof:        "rakp2Status=0x00 leakedHashVerified=true recoveredFrom=" + c.source,
			}
			dup := false
			for _, cr := range auth.Cracked {
				if cr.Username == hit.Username && cr.Password == hit.Password {
					dup = true
					break
				}
			}
			if !dup {
				auth.Cracked = append(auth.Cracked, hit)
				t.SetEvidence("ipmi.auth", auth)
			}
			out = append(out, engine.Finding{
				Check: "ipmi.v20.defaultCreds", Category: "creds", Risk: "critical",
				Fields: engine.F(
					"username", hit.Username,
					"password", hit.Password,
					"cracked", crackedLabel(hit.PasswordType),
					"via", "rakpHash+"+c.source,
					"proof", hit.Proof,
				),
			})
			break
		}
	}
	return out
}

func usernamesCSVFromPairs(pairs [][2]string) string {
	if len(pairs) == 0 {
		return ""
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		u := strings.TrimSpace(p[0])
		if u == "" {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return strings.Join(out, ",")
}

func intsCSV(vals []int) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, fmt.Sprintf("%d", v))
	}
	return strings.Join(parts, ",")
}

func ipmiAuthEvidence(t *engine.Target) (*ipmi.AuthReport, bool) {
	v, ok := t.Evidenced("ipmi.auth")
	if !ok {
		return nil, false
	}
	auth, ok := v.(*ipmi.AuthReport)
	return auth, ok && auth != nil && len(auth.Cracked) > 0
}

func ipmiAuthEvidenceAny(t *engine.Target) (*ipmi.AuthReport, bool) {
	v, ok := t.Evidenced("ipmi.auth")
	if !ok {
		return nil, false
	}
	auth, ok := v.(*ipmi.AuthReport)
	if !ok || auth == nil {
		return nil, false
	}
	if len(auth.Cracked) == 0 && len(auth.Results) == 0 {
		return nil, false
	}
	return auth, true
}

func ipmiCrackedSSHPairs(auth *ipmi.AuthReport, limit int) [][2]string {
	if auth == nil || limit <= 0 {
		return nil
	}
	seen := map[[2]string]struct{}{}
	var out [][2]string
	add := func(user, pass string) {
		user = strings.TrimSpace(user)
		pass = strings.TrimSpace(pass)
		if user == "" || pass == "" || len(out) >= limit {
			return
		}
		pair := [2]string{user, pass}
		if _, ok := seen[pair]; ok {
			return
		}
		seen[pair] = struct{}{}
		out = append(out, pair)
	}
	for _, cr := range auth.Cracked {
		if cr.Password == "" || len(out) >= limit {
			continue
		}
		user := strings.TrimSpace(cr.Username)
		if user != "" {
			add(user, cr.Password)
		}

		if cr.AcceptsAny || user == "" {
			for _, candidate := range []string{"admin", "root", "ADMIN", "USERID"} {
				add(candidate, cr.Password)
			}
		}
	}
	return out
}

func targetHasFinding(t *engine.Target, check string) bool {
	for _, f := range t.Findings {
		if f.Check == check && f.Risk != "none" {
			return true
		}
	}
	return false
}
