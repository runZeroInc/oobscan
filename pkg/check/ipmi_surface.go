package check

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/guid"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// The pre-auth surface check reports the IPMI 1.5/2.0 exposures the identify step
// already gathered (auth-caps, cipher suites, GUID, Get Device ID). It reads that
// stashed evidence and does no probing of its own, so it never re-opens sessions
// against a rate-limiting BMC; the re-probing variants are deferred to --ipmi-full.
//
// The one exception is nullUserPrivProbe, which opens a single session under
// --ipmi-null-priv. It lives here because it qualifies the ipmi.authNull /
// ipmi.authAnon findings this check emits.
func init() {
	Register(Check{
		Name:        "ipmi.surface",
		Description: "IPMI 1.5/2.0 pre-auth exposures from the identify fingerprint (auth modes, ciphers, GUID, device ID), plus the measured privilege of an advertised null/anonymous account (--ipmi-null-priv)",
		Category:    "discovery",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runIPMISurface,
	})
}

func runIPMISurface(ctx context.Context, t *engine.Target) []engine.Finding {
	var out []engine.Finding

	// RMCP+ cipher-suite enumeration is a 2.0-only operation, so its presence
	// proves 2.0 support even when the 1.5 auth-caps 2.0 bit is unset (Supermicro
	// leaves it clear yet still speaks RMCP+/RAKP).
	var cipherIDs []int
	if v, ok := t.Evidenced("ipmi.ciphers"); ok {
		if ids, ok := v.([]int); ok {
			cipherIDs = ids
		}
	}
	if v, ok := t.Evidenced("ipmi.authCaps"); ok {
		if ac, ok := v.(*ipmi.AuthCaps); ok && ac != nil {
			// The null/anonymous auth-caps bits are a configuration statement, not
			// an impact statement, so measure the account when the operator opted
			// in (see nullUserPrivProbe) and report the finding against the
			// measurement rather than the bit.
			probe := nullUserPrivProbe(t, ac)
			out = append(out, authCapsFindings(ac, len(cipherIDs) > 0, probe)...)
			out = append(out, nullUserSOLFindings(probe)...)
		}
	}
	if len(cipherIDs) > 0 {
		out = append(out, cipherFindings(cipherIDs)...)
	}
	if v, ok := t.Evidenced("ipmi.deviceId"); ok {
		if dev, ok := v.(*ipmi.DeviceID); ok && dev != nil {
			fields := engine.F("mfr", dev.ManufacturerName(),
				"fw", ipmi.FormatFirmwareRevision(dev.FirmwareMajor, dev.FirmwareMinor),
				"productId", fmt.Sprintf("0x%04x", dev.ProductID))
			// Same reasoning as the post-auth mc-info finding: the auxiliary
			// revision is what makes the version matchable against a vendor
			// advisory, so carry the reconstruction and the raw bytes.
			if full := dev.FirmwareRevisionFull(); full != "" {
				fields = append(fields, engine.Field{Key: "firmwareVersionFull", Val: full})
			}
			if dev.AuxFirmwareVersion != [4]byte{} {
				fields = append(fields, engine.Field{
					Key: "auxFirmwareRev", Val: hex.EncodeToString(dev.AuxFirmwareVersion[:]),
				})
			}
			// The IANA PEN name normalized to a slug, so the identity backfill can
			// attribute a host whose vendor identify left blank.
			fields = append(fields, vendorSlugField(dev.ManufacturerName())...)
			out = append(out, engine.Finding{
				Check: "ipmi.deviceId", Category: "discovery", Risk: "info", Fields: fields,
			})
		}
	}
	if v, ok := t.Evidenced("ipmi.dcmi"); ok {
		if dc, ok := v.(*ipmi.DCMICapabilities); ok && dc != nil {
			fields := engine.F("version", dc.Version(),
				"paramRevision", fmt.Sprintf("%d", dc.ParamRevision))
			if caps := dc.SupportedCapsHex(); caps != "" {
				fields = append(fields, engine.Field{Key: "supportedCaps", Val: caps})
			}
			out = append(out, engine.Finding{
				Check: "ipmi.dcmi", Category: "discovery", Risk: "info",
				Fields: fields,
			})
		}
	}
	if v, ok := t.Evidenced("guid"); ok {
		if g, ok := v.(*guid.Result); ok && g != nil && g.Family != "" {
			fields := engine.F("family", g.Family, "vendor", g.Vendor, "guid", g.Hex)
			// The Supermicro board-code prefix (e.g. "F401MS") is a reliable
			// pre-auth generation signal; surface it so id.final can map it.
			if mp := g.Fields["model_prefix"]; mp != "" {
				fields = append(fields, engine.Field{Key: "modelPrefix", Val: mp})
			}
			out = append(out, engine.Finding{
				Check: "ipmi.guid", Category: "guid", Risk: "info",
				Fields: fields,
			})
		}
	}
	return stampIPMI(out, t.IPMIPort())
}

// stampIPMI pins each finding to the IPMI RMCP location (UDP/623 ipmi) so every
// IPMI result carries where it was observed.
func stampIPMI(fs []engine.Finding, port int) []engine.Finding {
	for i := range fs {
		if fs[i].Port == 0 {
			fs[i].Port, fs[i].Transport, fs[i].Protocol = port, "udp", "ipmi"
		}
	}
	return fs
}

// nullUserPrivProbe measures what an advertised null/anonymous account actually
// holds, since the advertised bit says nothing about impact: the account can still
// be clamped to privilege 0 with IPMI messaging off. Returns nil when the probe does
// not apply.
//
// Opt-in via --ipmi-null-priv because it is the one part of this otherwise probe-free
// check that opens a session, and suppressed by --disable-logins because an
// empty-username RMCP+ handshake is an active login attempt.
func nullUserPrivProbe(t *engine.Target, ac *ipmi.AuthCaps) *ipmi.NullUserPrivProbe {
	if t == nil || ac == nil || !t.IPMINullPriv || t.DisableLogins {
		return nil
	}
	if !ac.NullUser && !ac.AnonLogin {
		return nil
	}
	// Both flags describe the same unnamed slot-1 account, so one session answers
	// for either. The empty username is what makes it the null-user login.
	var cipherIDs []int
	if v, ok := t.Evidenced("ipmi.ciphers"); ok {
		if ids, ok := v.([]int); ok {
			cipherIDs = ids
		}
	}
	probe := ipmi.ProbeNullUserPrivilege(t.Host, t.IPMIPort(), "", cipherIDs, t.Timeout, t.DebugLog)
	if probe != nil {
		t.SetEvidence("ipmi.nullUserPriv", probe)
	}
	return probe
}

// nullUserPrivFields renders the measurement onto the auth-caps finding. An
// unprobed finding gets no fields at all, so the absence of a measurement stays
// visible rather than being reported as a privilege of zero.
func nullUserPrivFields(probe *ipmi.NullUserPrivProbe) []engine.Field {
	if probe == nil {
		return nil
	}
	fields := []engine.Field{{Key: "privilegeProbe", Val: probe.Status()}}
	if !probe.Activated {
		// A session that will not activate is itself the answer: the advertised bit
		// did not translate into access from this vantage point.
		if probe.Error != "" {
			fields = append(fields, engine.Field{Key: "privilegeProbeError", Val: probe.Error})
		}
		return fields
	}
	fields = append(fields,
		engine.Field{Key: "privilegeProbeSuite", Val: fmt.Sprintf("%d", probe.Suite)},
		// The Open Session ceiling is recorded next to the measured level because the
		// gap between them is the trap: the ceiling reads ADMINISTRATOR even on a unit
		// whose null account holds nothing.
		engine.Field{Key: "openSessionMaxPrivilege", Val: ipmi.PrivilegeName(probe.OpenSessionMaxPriv)},
	)
	if probe.Protection != "" {
		fields = append(fields, engine.Field{Key: "sessionProtection", Val: probe.Protection})
	}
	if probe.PrivilegeOK {
		fields = append(fields,
			engine.Field{Key: "measuredPrivilege", Val: ipmi.PrivilegeName(probe.Privilege)},
			engine.Field{Key: "measuredPrivilegeRaw", Val: fmt.Sprintf("0x%02x", probe.Privilege)},
		)
	} else if probe.PrivilegeCC != 0 {
		fields = append(fields, engine.Field{Key: "privilegeQueryCc", Val: fmt.Sprintf("0x%02x", probe.PrivilegeCC)})
	}
	// Get Device ID is the cheapest impact witness -- a clamped account is denied
	// even this, which is the concrete form of "the bit says nothing about impact".
	if probe.DeviceIDSeen {
		fields = append(fields,
			engine.Field{Key: "getDeviceIdCc", Val: fmt.Sprintf("0x%02x", probe.DeviceIDCC)},
			engine.Field{Key: "getDeviceIdReadable", Val: fmt.Sprintf("%t", probe.DeviceIDOK)},
		)
	}
	if probe.SOL.Readable() {
		fields = append(fields, engine.Field{Key: "solConfigReadable", Val: "true"})
	}
	return fields
}

// nullUserAuthRisk is the risk for an advertised null/anonymous account.
//
// Unmeasured (or measured below USER) it stays low, since an enabled null user can
// hold no real access at all. Only a measured privilege of USER (2) or above
// raises it, because that is the level at which the account reads real
// inventory. OPERATOR (3) and above adds chassis power control, so it goes a
// step further.
func nullUserAuthRisk(probe *ipmi.NullUserPrivProbe) string {
	if !probe.UsableAccess() {
		return "low"
	}
	if probe.Privilege >= ipmi.PrivOperator && probe.Privilege != ipmi.PrivNoAccess {
		return "high"
	}
	return "medium"
}

// authCapsFindings reports the Get Channel Auth Caps settings. These are weak
// defaults rather than directly exploitable conditions -- an attacker still needs to
// sniff the wire or brute force -- so they rate low, and confirmed access (default
// creds, cipher-0) is reported by the credential check instead. The exception is a
// null/anonymous account measured at USER or above, which is confirmed
// unauthenticated access; nullUserAuthRisk raises it.
func authCapsFindings(ac *ipmi.AuthCaps, rmcpPlus bool, probe *ipmi.NullUserPrivProbe) []engine.Finding {
	var out []engine.Finding

	// Supported IPMI versions on one informational line. Answering Get Channel Auth Caps at
	// all proves 1.5; the 2.0 bit (or a working RMCP+ cipher enumeration, which is
	// a 2.0-only op) adds 2.0.
	versions := []string{"1.5"}
	if ac.IPMI20 || rmcpPlus {
		versions = append(versions, "2.0")
	}
	out = append(out, engine.Finding{
		Check: "ipmi.versions", Category: "auth", Risk: "info",
		Fields: engine.F("versions", strings.Join(versions, ",")),
	})

	// All accepted IPMI 1.5 authentication types on one low-risk line (they are weak
	// defaults, not directly exploitable), instead of one finding per method.
	var methods []string
	if ac.HasAuthNone() {
		methods = append(methods, "none")
	}
	if ac.HasAuthMD2() {
		methods = append(methods, "md2")
	}
	if ac.HasAuthMD5() {
		methods = append(methods, "md5")
	}
	if ac.HasAuthStraight() {
		methods = append(methods, "plaintext")
	}
	if len(methods) > 0 {
		out = append(out, engine.Finding{
			Check: "ipmi.v15.authMethods", Category: "auth", Risk: "low",
			Fields: engine.F("methods", strings.Join(methods, ",")),
		})
	}

	// Anonymous login and null-user login are distinct account settings, not auth
	// methods, so they stay on their own lines. Each carries the observed auth-
	// methods on the channel so the finding is self-contained and consumers do
	// not have to cross-reference the sibling ipmi.v15.authMethods finding.
	observedAuth := strings.Join(methods, ",")
	channel := fmt.Sprintf("%d", ac.Channel)
	privFields := nullUserPrivFields(probe)
	risk := nullUserAuthRisk(probe)
	if ac.AnonLogin {
		out = append(out, engine.Finding{
			Check: "ipmi.authAnon", Category: "auth", Risk: risk,
			Fields: append(engine.F(
				"channel", channel,
				"observedAuthTypes", observedAuth,
				"anonymousLoginEnabled", "true",
			), privFields...),
		})
	}
	if ac.NullUser {
		out = append(out, engine.Finding{
			Check: "ipmi.authNull", Category: "auth", Risk: risk,
			Fields: append(engine.F(
				"channel", channel,
				"observedAuthTypes", observedAuth,
				"nullUserLoginEnabled", "true",
			), privFields...),
		})
	}
	return out
}

// nullUserSOLFindings reports SOL configuration readable from a null/anonymous
// session holding less than USER privilege. Get SOL Configuration Parameters
// (0x0c/0x22) answering at privilege 0 is a gate failure -- the command is not among
// the documented ATEN Privilege::None set -- but it is disclosure only, since
// activating SOL needs privilege 3, so it rates low and is reported separately
// because the defect is the missing gate rather than the account. At USER or above
// the read is within entitlement and nothing is emitted.
func nullUserSOLFindings(probe *ipmi.NullUserPrivProbe) []engine.Finding {
	if probe == nil || !probe.Activated || !probe.SOL.Readable() {
		return nil
	}
	if probe.UsableAccess() {
		return nil
	}
	// Without a measured privilege there is no evidence the read happened below
	// the gate, which is the entire claim.
	if !probe.PrivilegeOK {
		return nil
	}
	fields := engine.F(
		"measuredPrivilege", ipmi.PrivilegeName(probe.Privilege),
		"measuredPrivilegeRaw", fmt.Sprintf("0x%02x", probe.Privilege),
		"solEnabled", fmt.Sprintf("%t", probe.SOL.Enabled),
	)
	if probe.SOL.RequiredPrivilegeOK {
		fields = append(fields, engine.Field{
			Key: "solRequiredPrivilege", Val: ipmi.PrivilegeName(probe.SOL.RequiredPrivilege),
		})
	}
	if probe.SOL.PayloadChannelOK {
		fields = append(fields, engine.Field{
			Key: "solPayloadChannel", Val: fmt.Sprintf("%d", probe.SOL.PayloadChannel),
		})
	}
	if probe.SOL.PayloadPortOK {
		fields = append(fields, engine.Field{
			Key: "solPayloadPort", Val: fmt.Sprintf("%d", probe.SOL.PayloadPort),
		})
	}
	fields = append(fields, engine.Field{
		Key: "proof",
		Val: fmt.Sprintf("measuredPrivilege=%s(0x%02x) getSolConfigCc=0x00 %s",
			ipmi.PrivilegeName(probe.Privilege), probe.Privilege, probe.SOL.Summary()),
	})
	return []engine.Finding{{
		Check: "ipmi.nullUser.solConfigReadable", Category: "auth", Risk: "low",
		Fields: fields,
	}}
}

// cipherFindings reports the advertised cipher suites as informational and the weak
// ones as low. Cipher suite 0 being advertised is not a vulnerability on its own; it
// is a finding only when it actually works, which the credential check confirms
// separately as ipmi.v20.cipherZero.
func cipherFindings(ids []int) []engine.Finding {
	var list, weak []string
	for _, id := range ids {
		list = append(list, fmt.Sprintf("%d", id))
		if ipmi.CipherSuiteWeak(id) {
			weak = append(weak, fmt.Sprintf("%d", id))
		}
	}
	var out []engine.Finding
	if len(list) > 0 {
		out = append(out, engine.Finding{
			Check: "ipmi.ciphers", Category: "ciphers", Risk: "info",
			Fields: engine.F("suites", strings.Join(list, ",")),
		})
	}
	if len(weak) > 0 {
		out = append(out, engine.Finding{
			Check: "ipmi.weakCiphers", Category: "ciphers", Risk: "low",
			Fields: engine.F("suites", strings.Join(weak, ",")),
		})
	}
	return out
}

func init() {
	RegisterExplain("ipmi.versions", explainIPMIVersions)
	RegisterExplain("ipmi.v15.authMethods", explainIPMI15AuthMethods)
	RegisterExplain("ipmi.authAnon", explainIPMIAuthAnon)
	RegisterExplain("ipmi.authNull", explainIPMIAuthNull)
	RegisterExplain("ipmi.nullUser.solConfigReadable", explainIPMINullUserSOLConfig)
	RegisterExplain("ipmi.deviceId", explainIPMIDeviceID)
	RegisterExplain("ipmi.guid", explainIPMIGUID)
	RegisterExplain("ipmi.ciphers", explainIPMICiphers)
	RegisterExplain("ipmi.weakCiphers", explainIPMIWeakCiphers)
}

func explainIPMIVersions(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	versions := explainField(f, "versions")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nIPMI version(s) **%s** confirmed via Get Channel Auth Caps.\n", versions))
	b.WriteString("\n**Query auth caps and cipher suites:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("ipmitool -I lan -H %s -p %d -A NONE -U '' -P '' channel authcap 1 4", host, port),
		fmt.Sprintf("ipmitool -I lan -H %s -p %d -A NONE -U '' -P '' channel getciphers ipmi", host, port),
	))
	return b.String()
}

func explainIPMI15AuthMethods(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	methods := explainField(f, "methods")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nThe BMC advertises IPMI 1.5 auth methods: **%s**.\n", methods))
	if strings.Contains(methods, "none") {
		b.WriteString("\n> `none` is advertised -- see `ipmi.v15.authNoneSession` to confirm an actual no-auth session.\n")
	}
	if strings.Contains(methods, "plaintext") {
		b.WriteString("\n> `plaintext` means passwords transit the wire in cleartext.\n")
	}
	b.WriteString("\n**Query auth caps:**\n")
	b.WriteString(explainSh(fmt.Sprintf("ipmitool -I lan -H %s -p %d -A NONE -U '' -P '' channel authcap 1 5", host, port)))
	return b.String()
}

func explainIPMIAuthAnon(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe **anonymous login** flag is set in channel auth-caps -- the unnamed (slot-0)\n")
	b.WriteString("account may authenticate with any auth type and a blank password.\n")
	b.WriteString(explainNullUserPrivilege(host, port, f))
	b.WriteString("\n**Validate:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("ipmitool -I lan    -H %s -p %d -A NONE -U '' -P '' mc info", host, port),
		fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -C 0   -U '' -P '' mc info", host, port),
	))
	return b.String()
}

func explainIPMIAuthNull(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe **null-user** flag is set -- the unnamed (slot-0) account is enabled and\n")
	b.WriteString("may accept a blank password.\n")
	b.WriteString(explainNullUserPrivilege(host, port, f))
	b.WriteString("\n**Validate:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("ipmitool -I lanplus -H %s -p %d -U '' -P '' mc info", host, port),
		fmt.Sprintf("ipmitool -I lan    -H %s -p %d -A MD5 -U '' -P '' mc info", host, port),
	))
	return b.String()
}

// explainNullUserPrivilege renders the measured-privilege section, or the note
// explaining that the bit alone is not an impact statement when no measurement
// was taken. Returns the section including its leading blank line.
func explainNullUserPrivilege(host string, port int, f engine.Finding) string {
	var b strings.Builder
	measured := explainField(f, "measuredPrivilege")
	if measured == "" {
		b.WriteString("\n> The advertised bit alone does not establish impact. An enabled null user can\n")
		b.WriteString("> sit at privilege 0 with IPMI messaging disabled, where it cannot read sensors,\n")
		b.WriteString("> FRU, the SEL, or even Get Device ID. Measure it:\n")
		b.WriteString(explainSh(fmt.Sprintf("oobscan scan --ipmi-null-priv %s:%d", host, port)))
		return b.String()
	}
	b.WriteString(fmt.Sprintf("\n**Measured privilege:** `%s` (%s)",
		measured, explainField(f, "measuredPrivilegeRaw")))
	if ceiling := explainField(f, "openSessionMaxPrivilege"); ceiling != "" {
		b.WriteString(fmt.Sprintf("  **Open Session ceiling:** `%s`", ceiling))
	}
	if prot := explainField(f, "sessionProtection"); prot != "" {
		b.WriteString(fmt.Sprintf("  **Session protection:** `%s`", prot))
	}
	b.WriteString("\n")
	if cc := explainField(f, "getDeviceIdCc"); cc != "" {
		b.WriteString(fmt.Sprintf("\nGet Device ID from that session returned `%s` (readable: %s).\n",
			cc, explainField(f, "getDeviceIdReadable")))
	}
	switch measured {
	case "unspecified", "callback", "noAccess":
		b.WriteString("\n> Below USER privilege: the account is enabled but clamped, so it reaches only a\n")
		b.WriteString("> handful of session/GUID commands. The risk stays LOW for that reason -- the\n")
		b.WriteString("> Open Session ceiling above is the channel maximum and routinely reads\n")
		b.WriteString("> ADMINISTRATOR even here, so do not read it as the account's privilege.\n")
	default:
		b.WriteString("\n> **USER privilege or above, measured in-session.** This is unauthenticated\n")
		b.WriteString("> access to real BMC data (sensors, FRU, SEL), not just a weak default.\n")
	}
	return b.String()
}

func explainIPMINullUserSOLConfig(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	priv := explainField(f, "measuredPrivilege")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nA null/anonymous session measured at **%s** privilege (%s) was able to read\n",
		priv, explainField(f, "measuredPrivilegeRaw")))
	b.WriteString("**Get SOL Configuration Parameters** (NetFn 0x0c, cmd 0x22).\n")
	b.WriteString("\nThat command is not in the documented privilege-None command set, so an account\n")
	b.WriteString("intended to grant nothing discloses the SOL exposure:\n\n")
	b.WriteString(fmt.Sprintf("- SOL enabled: `%s`\n", explainField(f, "solEnabled")))
	if rp := explainField(f, "solRequiredPrivilege"); rp != "" {
		b.WriteString(fmt.Sprintf("- Privilege required to activate SOL: `%s`\n", rp))
	}
	if ch := explainField(f, "solPayloadChannel"); ch != "" {
		b.WriteString(fmt.Sprintf("- Payload channel: `%s`\n", ch))
	}
	if pp := explainField(f, "solPayloadPort"); pp != "" {
		b.WriteString(fmt.Sprintf("- Payload port: `%s`\n", pp))
	}
	b.WriteString("\nInformation disclosure only -- the session cannot open SOL, which needs a higher\n")
	b.WriteString("privilege -- but it is a privilege-gate failure on the SOL config read path.\n")
	b.WriteString("\n**Re-measure:**\n")
	b.WriteString(explainSh(fmt.Sprintf("oobscan scan --ipmi-null-priv %s:%d", host, port)))
	b.WriteString("\n**Remediation:** disable the unnamed slot-1 account (`ipmitool user disable 1`)\n")
	b.WriteString("rather than relying on its privilege clamp.\n")
	return b.String()
}

func explainIPMIDeviceID(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	mfr := explainField(f, "mfr")
	fw := explainField(f, "fw")
	pid := explainField(f, "productId")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nIPMI Get Device ID response received pre-auth -- confirms reachability and\n")
	b.WriteString("discloses manufacturer, firmware version, and product ID.\n")
	if mfr != "" {
		b.WriteString(fmt.Sprintf("\n**Manufacturer:** `%s`  **Firmware:** `%s`  **Product ID:** `%s`\n", mfr, fw, pid))
	}
	b.WriteString("\n**Query manually:**\n")
	b.WriteString(explainSh(fmt.Sprintf("ipmitool -I lan -H %s -p %d -A NONE -U '' -P '' mc info", host, port)))
	return b.String()
}

func explainIPMIGUID(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	family := explainField(f, "family")
	vendor := explainField(f, "vendor")
	guid := explainField(f, "guid")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nBMC GUID retrieved pre-auth; the GUID family encodes the vendor origin.\n")
	if family != "" {
		b.WriteString(fmt.Sprintf("\n**Family:** `%s`  **Vendor:** `%s`  **GUID:** `%s`\n", family, vendor, guid))
	}
	b.WriteString("\n**Query the GUID:**\n")
	b.WriteString(explainSh(fmt.Sprintf("ipmitool -I lan -H %s -p %d -A NONE -U '' -P '' mc guid", host, port)))
	return b.String()
}

func explainIPMICiphers(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	suites := explainField(f, "suites")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nAdvertised RMCP+ cipher suites: **%s**.\n", suites))
	b.WriteString("\n**Check which suites are accepted:**\n")
	b.WriteString(explainSh(fmt.Sprintf("ipmitool -I lan -H %s -p %d -A NONE -U '' -P '' channel getciphers ipmi", host, port)))
	return b.String()
}

func explainIPMIWeakCiphers(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 623)
	suites := explainField(f, "suites")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nThe BMC advertises weak/deprecated RMCP+ cipher suites: **%s**.\n", suites))
	b.WriteString("Weak suites (e.g. 0, 1, 2) use MD5/no-auth and should be disabled.\n")
	if strings.Contains(suites, "0") {
		b.WriteString("\n> Cipher suite **0** advertised -- run `oobscan scan --checks ipmi.defaultCreds`\n")
		b.WriteString("> to confirm whether an actual cipher-0 session can be opened.\n")
	}
	b.WriteString("\n**Enumerate cipher support:**\n")
	b.WriteString(explainSh(fmt.Sprintf("ipmitool -I lan -H %s -p %d -A NONE -U '' -P '' channel getciphers ipmi", host, port)))
	return b.String()
}
