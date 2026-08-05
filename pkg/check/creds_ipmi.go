package check

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/creds"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func init() {
	Register(Check{
		Name:        "ipmi.defaultCreds",
		Description: "Try default/known BMC credentials via RAKP (offline crack + capped online login)",
		Category:    "creds",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runIPMICreds,
	})
}

func userLabel(u string) string {
	if u == "" {
		return "(null)"
	}
	return u
}

func rakpAuthAlgoName(a byte) string {
	switch a {
	case ipmi.RAKPHMACSHA1:
		return "hmac-sha1"
	case ipmi.RAKPHMACMD5:
		return "hmac-md5"
	case ipmi.RAKPHMACSHA256:
		return "hmac-sha256"
	case ipmi.RAKPNone:
		return "none"
	default:
		return fmt.Sprintf("0x%02x", a)
	}
}

func allZeroBytes(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func runIPMICreds(ctx context.Context, t *engine.Target) []engine.Finding {
	if !t.IsOpen(t.IPMIPort(), "udp") {
		return nil
	}
	vendor := ""
	if t.Identity != nil {
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

	rep, err := ipmi.RunAuth(ctx, t.Host, t.IPMIPort(), opts)
	if err != nil || rep == nil {
		return nil
	}
	t.SetEvidence("ipmi.auth", rep)

	var findings []engine.Finding

	if rep.CipherZero {
		findings = append(findings, engine.Finding{
			Check: "ipmi.v20.cipherZero", Category: "auth", Risk: "critical",
			CVE: []string{"CVE-2013-4782"},
			Fields: engine.F(
				"suite", "0",

				"bmcSessionId", fmt.Sprintf("0x%08x", rep.CipherZeroSID),
				"proof", fmt.Sprintf("openSessionCc=0x00 bmcSessionId=0x%08x", rep.CipherZeroSID),
			),
		})
	}
	if rep.FakeUsername {
		findings = append(findings, engine.Finding{
			Check: "ipmi.v20.usernameOracle", Category: "auth", Risk: "low",
			Fields: engine.F(
				"test", "random_16hex_username",
				"result", "wildcardUsername",
				"wildcard", "true",

				"acceptedUsername", rep.FakeUsernameProbe,
				"proof", fmt.Sprintf("rakp2Cc=0x00 acceptedUsername=%s bmcSessionId=0x%08x",
					rep.FakeUsernameProbe, rep.FakeUsernameSID),
			),
		})
	}
	if p := maybeProbeOpenBMCSetupState(t, rep, vendor); p != nil {
		t.SetEvidence("ipmi.openBmcSetupState", p)
		if p.SetupCommandsWork {
			findings = append(findings, engine.Finding{

				Check: "ipmi.rakp.state.setupLocalPreRakp3", Category: "auth", Risk: "info", Fields: append(engine.F(
					"username", userLabel(p.Username),
					"suite", fmt.Sprintf("%d", p.Suite),
					"rakpStatus", fmt.Sprintf("0x%02x", p.RAKPStatus),
					"setPrivAdminCc", fmt.Sprintf("0x%02x", p.SetPrivAdminCC),
					"payloadStatusCc", fmt.Sprintf("0x%02x", p.PayloadStatusCC),
					"payloadInfoCc", fmt.Sprintf("0x%02x", p.PayloadInfoCC),
					"proof", openBMCSetupProof(p),
				), openBMCSetupStateExtraFields(p)...),
			})
		}
	}

	for i := range rep.Results {
		r := &rep.Results[i]
		if len(r.RAKPHash) == 0 {
			continue
		}

		if (r.Crack != nil && r.Crack.PasswordType == "smcrakp-fixed-key") || r.UsesSMCRAKPFixedKey() {
			continue
		}
		line := r.Hashcat()
		if line == "" {
			line = r.SaltHashLine()
		}
		algName := rakpAuthAlgoName(r.AuthAlgo)
		f := engine.F(
			"username", userLabel(r.Username),
			"hash", line,
			"hashAlgo", algName,
		)

		if len(r.BMCRand) > 0 && allZeroBytes(r.BMCRand) {
			f = append(f, engine.Field{Key: "crackableZeroRand", Val: "true"})
		}
		if r.Crack != nil {
			if r.Crack.PasswordType != "smcrakp-fixed-key" {
				f = append(f, engine.Field{Key: "cracked", Val: r.Crack.Password})
				f = append(f, engine.Field{Key: "crackedFrom", Val: crackedLabel(r.Crack.PasswordType)})
			}
			if r.Crack.PasswordType == "default" {
				f = append(f, engine.Field{Key: "default", Val: "true"})
			}
			if r.Crack.PasswordType == "smcrakp-fixed-key" {
				f = append(f,
					engine.Field{Key: "smcrakpFixedKey", Val: "true"},
					engine.Field{Key: "proof", Val: proofKV("rakp2Hmac", "fixedKeyMatch", "smcrakpFixedKey", "true")},
				)
			}
		}
		findings = append(findings, engine.Finding{
			Check: "ipmi.v20.rakpHash", Category: "rakp", Risk: "critical",
			Fields: f, CVE: []string{"CVE-2013-4786"},
		})
	}

	for _, cr := range rep.Cracked {
		if cr.PasswordType == "smcrakp-fixed-key" {
			username := firstNonEmptySMCRAKP(cr.Username, smcrakpResultUsername(rep), "")
			exploitable := cr.CommandCapable
			risk := "low"
			state := "enabled-not-exploitable"
			if exploitable {
				risk = "critical"
				state = "exploitable"
			}
			proof := cr.Proof
			if proof == "" {
				if exploitable {
					proof = "smcrakpFixedKey=true rakp34Session=ok noIntegrityCmd=ok"
				} else {
					proof = "smcrakpFixedKey=true noIntegrityCmd=rejected(integrity-enforced)"
				}
			}
			fields := engine.F(
				"username", userLabel(username),
				"mode", "smcrakp-fixed-key",
				"smcrakpFixedKey", "true",
				"source", "ipmi.auth.smcrakpBypass",
				"exploitable", ternary(exploitable, "true", "false"),
				"state", state,
				"proof", proof,
			)
			if !exploitable {
				fields = append(fields, engine.Field{Key: "note", Val: "integrity-enforced-no-exec"})
			}
			if cr.Verified {
				fields = append(fields, engine.Field{Key: "sessionForged", Val: "true"})
			}
			if rep.Suite != nil {
				fields = append(fields,
					engine.Field{Key: "cipherSuite", Val: fmt.Sprintf("%d", rep.Suite.Suite)},
					engine.Field{Key: "authAlgo", Val: rakpAuthAlgoName(rep.Suite.Auth)},
					engine.Field{Key: "integrityAlgo", Val: fmt.Sprintf("0x%02x", rep.Suite.Integrity)},
					engine.Field{Key: "confAlgo", Val: fmt.Sprintf("0x%02x", rep.Suite.Conf)},
				)
			}
			findings = append(findings, engine.Finding{
				Check:    "ipmi.v20.smcrakpBypass",
				Category: "auth",
				Risk:     risk,
				CVE:      []string{"CVE-2026-65214"},
				Fields:   fields,
			})
			continue
		}
		via := cr.PasswordType
		if via == "online" && cr.Verified {
			via = "default"
		}
		f := engine.F(
			"username", userLabel(cr.Username),
			"password", cr.Password,
			"via", via,
			"cracked", crackedLabel(cr.PasswordType),
		)
		var risk string
		switch {
		case cr.Verified:

			risk = "critical"
			proof := cr.Proof
			if proof == "" {
				proof = "rakp2Status=0x00 rakp2Hmac=verified"
			}
			f = append(f, engine.Field{Key: "proof", Val: proof})
		case cr.LoginTested:

			risk = "medium"
			f = append(f, engine.Field{Key: "proof", Val: proofKV("state", "candidate", "loginTested", "true", "loginSucceeded", "false")})
		default:

			risk = "medium"
			f = append(f, engine.Field{Key: "proof", Val: proofKV("state", "candidate", "loginTested", "false", "verified", "false")})
		}
		findings = append(findings, engine.Finding{
			Check: "ipmi.v20.defaultCreds", Category: "creds", Risk: risk, Fields: f,
		})
	}
	if findings == nil {
		findings = append(findings, engine.Finding{
			Check: "ipmi.v20.defaultCreds", Category: "creds", Risk: "none",
		})
	}
	return stampIPMI(findings, t.IPMIPort())
}

func openBMCSetupStateExtraFields(p *ipmi.OpenBMCSetupProbe) engine.Fields {
	if p == nil {
		return nil
	}
	fields := engine.Fields{
		{Key: "openSessionOnlyRejected", Val: ternary(p.OpenSessionOnlyRejected, "true", "false")},
		{Key: "adminPrivAccepted", Val: ternary(p.AdminPrivAccepted, "true", "false")},
		{Key: "crossSocket", Val: ternary(p.CrossSocketSetupCommandsWork, "true", "false")},
	}
	if p.OpenSessionOnlyError != "" {
		fields = append(fields, engine.Field{Key: "openSessionOnlyError", Val: p.OpenSessionOnlyError})
	}
	if len(p.PrePrivQueryData) > 0 {
		fields = append(fields, engine.Field{Key: "prePrivQueryData", Val: hex.EncodeToString(p.PrePrivQueryData)})
	}
	if len(p.SetPrivAdminData) > 0 {
		fields = append(fields, engine.Field{Key: "setPrivAdminData", Val: hex.EncodeToString(p.SetPrivAdminData)})
	}
	if len(p.PayloadStatusData) > 0 {
		fields = append(fields, engine.Field{Key: "payloadStatusData", Val: hex.EncodeToString(p.PayloadStatusData)})
	}
	if len(p.PayloadInfoData) > 0 {
		fields = append(fields, engine.Field{Key: "payloadInfoData", Val: hex.EncodeToString(p.PayloadInfoData)})
	}
	if p.CrossSocketSetupCommandsWork {
		fields = append(fields,
			engine.Field{Key: "crossSocketRakpStatus", Val: fmt.Sprintf("0x%02x", p.CrossSocketRAKPStatus)},
			engine.Field{Key: "crossSocketSetPrivAdminCc", Val: fmt.Sprintf("0x%02x", p.CrossSocketSetPrivAdminCC)},
		)
	}
	return fields
}

func maybeProbeOpenBMCSetupState(t *engine.Target, rep *ipmi.AuthReport, vendor string) *ipmi.OpenBMCSetupProbe {
	if t == nil || rep == nil || rep.Suite == nil || t.DisableLogins {
		return nil
	}
	if !isLikelyOpenBMC(t, vendor) {
		return nil
	}
	username := firstValidRAKPUsername(rep)
	if username == "" {
		for _, u := range creds.UsernamesFor("openbmc") {
			if strings.TrimSpace(u) != "" {
				username = u
				break
			}
		}
	}
	if username == "" {
		return nil
	}
	probe, _ := ipmi.ProbeOpenBMCSetupState(t.Host, t.IPMIPort(), username, *rep.Suite, t.Timeout)
	return probe
}

func openBMCSetupProof(p *ipmi.OpenBMCSetupProbe) string {
	if p == nil {
		return ""
	}
	cmds := make([]string, 0, 5)
	if p.PrePrivQueryCC == 0x00 {
		cmds = append(cmds, "privQuery")
	}
	if p.SetPrivAdminCC == 0x00 {
		cmds = append(cmds, "setPriv")
	}
	if p.PayloadStatusCC == 0x00 {
		cmds = append(cmds, "solStatus")
	}
	if p.PayloadInfoCC == 0x00 {
		cmds = append(cmds, "solInfo")
	}
	if len(cmds) == 0 {
		cmds = append(cmds, "none")
	}
	return fmt.Sprintf("rakp1=0x%02x cmds=%s", p.RAKPStatus, strings.Join(cmds, ","))
}

func isLikelyOpenBMC(t *engine.Target, vendor string) bool {
	if strings.EqualFold(vendor, "openbmc") {
		return true
	}

	if strings.EqualFold(vendor, "h3c") {
		return true
	}
	if t == nil || t.Identity == nil {
		return false
	}
	if strings.EqualFold(t.Identity.Vendor, "openbmc") || strings.EqualFold(t.Identity.Vendor, "h3c") {
		return true
	}
	product := strings.ToLower(t.Identity.Product + " " + t.Identity.Generation)
	if strings.Contains(product, "openbmc") || strings.Contains(product, "phosphor") {
		return true
	}
	for _, sig := range t.Identity.Signals {
		blob := strings.ToLower(sig.Vendor + " " + sig.Detail + " " + sig.Source)
		if strings.Contains(blob, "openbmc") || strings.Contains(blob, "phosphor") || strings.Contains(blob, "bmcweb") {
			return true
		}
	}
	return false
}

func firstValidRAKPUsername(rep *ipmi.AuthReport) string {
	if rep == nil {
		return ""
	}
	for _, cr := range rep.Cracked {
		if cr.Verified && strings.TrimSpace(cr.Username) != "" {
			return cr.Username
		}
	}
	for _, r := range rep.Results {
		if r.ErrorCode == 0 && strings.TrimSpace(r.Username) != "" {
			return r.Username
		}
	}
	return ""
}

func crackedLabel(kind string) string {
	switch strings.TrimSpace(kind) {
	case "default", "online":
		return "defaults"
	case "common":
		return "common"
	case "custom", "supplied", "provided":
		return "supplied"
	default:
		return kind
	}
}

func firstNonEmptySMCRAKP(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func smcrakpResultUsername(rep *ipmi.AuthReport) string {
	if rep == nil {
		return ""
	}
	for i := range rep.Results {
		r := &rep.Results[i]
		if (r.Crack != nil && r.Crack.PasswordType == "smcrakp-fixed-key") || r.UsesSMCRAKPFixedKey() {
			if strings.TrimSpace(r.Username) != "" {
				return r.Username
			}
		}
	}
	return ""
}

func targetCreds(t *engine.Target) []engine.Cred {
	if t == nil {
		return nil
	}
	if len(t.Creds) > 0 {
		return t.Creds
	}
	if t.Cred.User == "" && t.Cred.Pass == "" {
		return nil
	}
	return []engine.Cred{t.Cred}
}

func init() {
	RegisterExplain("ipmi.v20.cipherZero", explainIPMI20CipherZero)
	RegisterExplain("ipmi.v20.usernameOracle", explainIPMI20UsernameOracle)
	RegisterExplain("ipmi.v20.rakpHash", explainIPMI20RAKPHash)
	RegisterExplain("ipmi.v20.defaultCreds", explainIPMI20DefaultCreds)
}

func explainIPMI20CipherZero(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nCipher suite 0 disables both authentication and encryption on the RMCP+ path.\n")
	b.WriteString("An attacker opens an administrator session with no credentials (CVE-2013-4782).\n")
	b.WriteString("\n**Validate:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -C 0 -U '' -P '' mc info", host, port),
		fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -C 0 -U '' -P '' chassis status", host, port),
		fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -C 0 -U '' -P '' user list 1", host, port),
	))
	b.WriteString("\n\n**Impact:** Full unauthenticated RMCP+ session -- power control, chassis\n")
	b.WriteString("management, SOL, firmware interaction, and user modification.\n")
	b.WriteString("\n**CVE:** CVE-2013-4782\n")
	return b.String()
}

func explainIPMI20UsernameOracle(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe BMC returns a RAKP-2 HMAC for any username, including non-existent ones.\n")
	b.WriteString("Cracked hashes can't be attributed to a real account without an online login,\n")
	b.WriteString("but any username can still be targeted for offline cracking.\n")
	b.WriteString("\n**Capture hashes and crack:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("oobscan scan --checks ipmi.defaultCreds %s:%d --output /tmp/test.jsonl", host, port),
		"oobscan hashcrack /tmp/test.jsonl",
	))
	return b.String()
}

func explainIPMI20RAKPHash(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	user := explainField(f, "user")
	hash := explainField(f, "hash")
	cracked := explainField(f, "cracked")
	isDefault := explainField(f, "default") == "true"
	du := explainDisplayUser(user)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nThe BMC leaks a crackable RAKP-2 HMAC hash for account `%s` (CVE-2013-4786).\n", user))
	b.WriteString("The hash can be cracked offline -- no lockout risk.\n")
	if cracked != "" {
		label := "Password already cracked"
		if isDefault {
			label = "Password already cracked (default credential)"
		}
		b.WriteString(fmt.Sprintf("\n**%s:** `%s`\n", label, cracked))
		b.WriteString("\n**Validate with cracked credential:**\n")
		b.WriteString(explainSh(
			fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -U '%s' -P '%s' mc info", host, port, du, cracked),
			fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -U '%s' -P '%s' user list", host, port, du, cracked),
		))
	} else {
		b.WriteString("\n**Crack the hash offline:**\n")
		if hash != "" {
			b.WriteString(explainSh(
				"# oobscan native cracker (SHA1+MD5+SHA256, vendor defaults first):",
				"oobscan hashcrack results.jsonl",
				"",
				"# hashcat (HMAC-SHA1 only, mode 7300):",
				fmt.Sprintf("echo '%s' > rakp.hash", hash),
				"hashcat -m 7300 rakp.hash /usr/share/wordlists/rockyou.txt",
			))
		}
		b.WriteString("\n\n**Once cracked, validate:**\n")
		b.WriteString(explainSh(fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -U '%s' -P '<password>' mc info", host, port, du)))
	}
	b.WriteString("\n\n**CVE:** CVE-2013-4786\n")
	return b.String()
}

func explainIPMI20DefaultCreds(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	user := explainField(f, "user")
	pass := explainField(f, "pass")
	via := explainField(f, "via")
	du := explainDisplayUser(user)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nThe BMC accepted the default credential **%s / %s**", user, pass))
	if via != "" {
		b.WriteString(fmt.Sprintf(" (verified via %s)", via))
	}
	b.WriteString(".\n")
	b.WriteString("\n**Validate:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -U '%s' -P '%s' mc info", host, port, du, pass),
		fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -U '%s' -P '%s' user list", host, port, du, pass),
		fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -U '%s' -P '%s' chassis status", host, port, du, pass),
	))
	b.WriteString("\n\n**Impact:** Full authenticated IPMI 2.0 access with a known default credential.\n")
	return b.String()
}
