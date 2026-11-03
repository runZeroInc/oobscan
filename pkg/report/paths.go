package report

// The compromise model has two axes, not one. A flat "does this host have an
// access path" rollup cannot tell an unauthenticated session apart from a
// privilege escalation that presupposes a credential, so it either overstates a
// low-privilege leg as a full compromise or (worse) drops the escalation leg
// entirely and understates the fleet. Each path therefore declares what it
// needs to start (Entry) and what it lands at (Gain), and the analysis composes
// the two into an administrator-equivalent figure.

// Entry is the precondition a compromise path starts from.
type Entry string

const (
	// EntryNone is a pre-auth path: no credential and no prior session.
	EntryNone Entry = "none"
	// EntryLowPriv presupposes a valid non-administrator credential or an
	// already-open low-privilege session. On its own it is not remote access;
	// it is only a compromise when something else supplies the entry.
	EntryLowPriv Entry = "lowpriv"
)

// Gain is the reach a compromise path establishes. It is a floor, not a
// ceiling: a path that proves a session may in fact be talking to an
// administrator account, but nothing in the evidence says so.
type Gain string

const (
	// GainSession is a management-plane session or a recovered credential whose
	// privilege the evidence does not establish.
	GainSession Gain = "session"
	// GainAdmin is administrator-equivalent on the management plane: a vendor
	// default administrator account, an authentication bypass that grants the
	// requested privilege, a recovered administrator credential, or code
	// execution on the BMC itself.
	GainAdmin Gain = "admin"
	// GainHost reaches the managed host -- serial console (SOL), KVM, virtual
	// media, or host debug -- without proving administrator on the BMC. BMC
	// administrator implies host reach, so the rollup treats GainAdmin as
	// covering this too; GainHost is for the paths that skip the BMC's own
	// authorization instead of defeating it.
	GainHost Gain = "host"
)

// CompromisePath is one observed route to access. Key is the stable rollup key,
// Short a 2-4 char code for dense column headers, and New marks the paths this
// research established (everything else was public before it), which is the
// known-vs-extended split the report headlines.
type CompromisePath struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Short string `json:"short"`
	Entry Entry  `json:"entry"`
	Gain  Gain   `json:"gain"`
	New   bool   `json:"new"`
	// Advisory is the identifier a reader can look the path up under: our own
	// advisory ID for a finding from this research, or the public CVE for one that
	// was already known. Empty where no identifier has been assigned yet, which is
	// itself worth seeing rather than hiding behind a prose label.
	Advisory string `json:"advisory,omitempty"`
}

// CompromisePaths is the ordered compromise taxonomy: findings that establish an
// authentication path, recover a credential, or reach the managed host. Version-
// gated CVE projections and broad protocol weaknesses stay in Taxonomy -- a
// reachable service is not an access path.
//
// Ordering is pre-auth paths first (grouped by what they land at), then the
// escalation legs that need a credential to matter.
var CompromisePaths = []CompromisePath{
	// Pre-auth, administrator-equivalent.
	{"cipher_zero", "Cipher-zero session", "CPH0", EntryNone, GainAdmin, false, "CVE-2013-4784"},
	{"ipmi_default_creds", "IPMI named default credentials", "IDEF", EntryNone, GainAdmin, false, ""},
	{"web_default_creds", "Web default credentials", "WEB", EntryNone, GainAdmin, false, ""},
	{"ssh_default_creds", "SSH default credentials", "SSH", EntryNone, GainAdmin, false, ""},
	{"ilo_http_bypass", "iLO HTTP auth bypass", "ILOH", EntryNone, GainAdmin, false, "CVE-2017-12542"},
	{"amt_auth_bypass", "Intel AMT empty-digest auth bypass", "AMT", EntryNone, GainAdmin, false, "CVE-2017-5689"},
	{"apc_demo_backdoor", "APC/Schneider NMC service credential", "APCB", EntryNone, GainAdmin, false, ""},
	{"smcrakp_bypass", "SMCRAKP fixed-key bypass", "SMCR", EntryNone, GainAdmin, true, "CVE-2026-18449"},
	{"ilo_ipmi_bypass", "iLO passwordless IPMI session", "ILOB", EntryNone, GainAdmin, true, "CVE-2026-65206"},
	{"ami_redfish_bypass", "AMI Redfish auth bypass", "AMIR", EntryNone, GainAdmin, true, "CVE-2024-54085"},
	{"ami_mtls_bypass", "AMI shipped-cert mTLS bypass", "AMIC", EntryNone, GainAdmin, true, "AMI-mTLS"},
	{"ssh_ilo_overflow", "iLO SSH pre-auth overflow (RCE)", "iLOS", EntryNone, GainAdmin, true, "CVE-2026-65204"},
	{"smc_psblock_creds", "Supermicro cleartext credential store", "PSBK", EntryNone, GainAdmin, true, ""},
	{"relabel_admin_unauth", "RAKP relabel to Administrator, no credential", "RLBU", EntryNone, GainAdmin, true, "CVE-2026-16140"},

	// Pre-auth, reaches the managed host without proving BMC administrator.
	{"kvm_no_auth", "Unauthenticated KVM access", "KVM", EntryNone, GainHost, false, ""},
	{"vnc_default_creds", "KVM/VNC default credentials", "VNCD", EntryNone, GainHost, false, ""},
	{"smc_kvm_bypass", "Supermicro KVM auth bypass (wstunnel)", "SMCK", EntryNone, GainHost, true, ""},
	{"smc_rakp_forge", "Supermicro forged RAKP session", "SMCF", EntryNone, GainHost, true, "CVE-2026-65219"},

	// Pre-auth, privilege unproven. These are also the entry legs a credential-
	// gated escalation composes with.
	{"rakp_named", "Named RAKP account cracked", "RAKP", EntryNone, GainSession, false, "CVE-2013-4786"},
	{"ipmi_auth_none", "IPMI auth-none session", "NONE", EntryNone, GainSession, false, ""},
	{"openbmc_userkey", "OpenBMC default-userKey auth bypass", "OBMC", EntryNone, GainSession, true, "CVE-2026-16141"},
	{"ipmi_oem_preauth", "OEM NetFn commands accepted pre-session", "OEMN", EntryNone, GainSession, true, ""},

	// Escalation legs: a valid low-privilege credential becomes Administrator.
	// Alone these are not remote access, which is why they carry EntryLowPriv
	// and only reach the administrator rollup once an entry leg supplies the
	// credential.
	{"relabel_admin", "RAKP relabel: low-privilege to Administrator", "RLBL", EntryLowPriv, GainAdmin, true, "CVE-2026-16140"},
	{"smc_reserved_role", "Supermicro reserved role nibble to Administrator", "SMC15", EntryLowPriv, GainAdmin, true, "CVE-2026-65220"},

	// Escalation leg reaching the host rather than BMC administrator.
	{"smc_ikvm_hijack", "Supermicro iKVM console access with any credential", "IKVM", EntryLowPriv, GainHost, true, ""},
}

// pathByKey indexes CompromisePaths for the per-record rollup.
var pathByKey = func() map[string]CompromisePath {
	m := make(map[string]CompromisePath, len(CompromisePaths))
	for _, p := range CompromisePaths {
		m[p.Key] = p
	}
	return m
}()

// newResearchPaths marks the compromise-path keys this research newly
// established, so a report can separate pre-research (already-known) exposure
// from the extended risk our findings add. Derived from the table so the two
// can never drift.
var newResearchPaths = func() map[string]bool {
	m := make(map[string]bool, len(CompromisePaths))
	for _, p := range CompromisePaths {
		if p.New {
			m[p.Key] = true
		}
	}
	return m
}()

// PotCrack is one password the offline potfile already holds for a record's
// captured RAKP material. The username travels with the plaintext because the
// account shape decides what the recovery proves: a crack on a named account is
// a usable credential, a crack on the empty/callback account is not, and a
// plaintext alone cannot tell them apart.
type PotCrack struct {
	Username string
	Password string
}

// genericExposureKeys are the protocol-presence columns scoreCheck sets from a
// prefix rule alone: they say a plane answered, not that anything is wrong with
// it. A check whose whole contribution is one of these has not really been
// classified, which is the failure mode unclassifiedScore exists to catch --
// every ipmi.* check sets "ipmi" for free, so counting a non-empty score as
// "classified" would hide an unmapped IPMI defect completely.
var genericExposureKeys = map[string]bool{
	"ipmi":            true,
	"ipmi_1_5":        true,
	"ipmi_2_0":        true,
	"kvm_exposed":     true,
	"redfish_exposed": true,
}

// unclassifiedScore reports whether a finding's scored exposure and path sets
// amount to no specific classification.
func unclassifiedScore(exp, paths map[string]bool) bool {
	if len(paths) > 0 {
		return false
	}
	for key := range exp {
		if !genericExposureKeys[key] {
			return false
		}
	}
	return true
}

// access summarizes one host's compromise-path set along both axes.
type access struct {
	any bool // at least one path of any kind
	pre bool // at least one pre-research (already-known) path

	// entry is a pre-auth foothold of any depth: the leg that makes a
	// credential-gated escalation reachable.
	entry bool
	// directAdmin is administrator-equivalent with no precondition.
	directAdmin bool
	// escalation is a credential-gated leg to Administrator.
	escalation bool
	// host is a pre-auth path that reaches the managed host.
	host bool
	// hostEscalation reaches the host but needs a credential first.
	hostEscalation bool
}

// admin reports administrator-equivalent reach: either a pre-auth path that
// lands at Administrator outright, or a pre-auth foothold composed with a
// credential-gated escalation leg observed on the same host.
func (a access) admin() bool {
	return a.directAdmin || (a.entry && a.escalation)
}

// chained reports administrator-equivalent reach that ONLY exists because two
// legs compose. Reported separately so the chain's contribution is auditable
// rather than folded invisibly into the administrator figure.
func (a access) chained() bool {
	return !a.directAdmin && a.entry && a.escalation
}

// hostReach reports reach to the managed host. BMC administrator implies it, and
// a credential-gated host leg counts once an entry leg supplies the credential.
func (a access) hostReach() bool {
	return a.host || a.admin() || (a.entry && a.hostEscalation)
}

// classifyAccess folds a host's compromise-path key set into the two-axis
// summary. An unknown key still counts toward any/pre so a mapping added to
// scoreCompromiseFinding without a CompromisePaths entry cannot silently
// vanish from the headline.
func classifyAccess(keys map[string]bool) access {
	var a access
	for key := range keys {
		a.any = true
		if !newResearchPaths[key] {
			a.pre = true
		}
		p, ok := pathByKey[key]
		if !ok {
			continue
		}
		switch p.Entry {
		case EntryNone:
			a.entry = true
			switch p.Gain {
			case GainAdmin:
				a.directAdmin = true
			case GainHost:
				a.host = true
			}
		case EntryLowPriv:
			switch p.Gain {
			case GainAdmin:
				a.escalation = true
			case GainHost:
				a.hostEscalation = true
			}
		}
	}
	return a
}
