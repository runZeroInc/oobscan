package report

type Entry string

const (
	EntryNone Entry = "none"

	EntryLowPriv Entry = "lowpriv"
)

type Gain string

const (
	GainSession Gain = "session"

	GainAdmin Gain = "admin"

	GainHost Gain = "host"
)

type CompromisePath struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Short string `json:"short"`
	Entry Entry  `json:"entry"`
	Gain  Gain   `json:"gain"`
	New   bool   `json:"new"`

	Advisory string `json:"advisory,omitempty"`
}

var CompromisePaths = []CompromisePath{

	{"cipher_zero", "Cipher-zero session", "CPH0", EntryNone, GainAdmin, false, "CVE-2013-4784"},
	{"ipmi_default_creds", "IPMI named default credentials", "IDEF", EntryNone, GainAdmin, false, ""},
	{"web_default_creds", "Web default credentials", "WEB", EntryNone, GainAdmin, false, ""},
	{"ssh_default_creds", "SSH default credentials", "SSH", EntryNone, GainAdmin, false, ""},
	{"ilo_http_bypass", "iLO HTTP auth bypass", "ILOH", EntryNone, GainAdmin, false, "CVE-2017-12542"},
	{"amt_auth_bypass", "Intel AMT empty-digest auth bypass", "AMT", EntryNone, GainAdmin, false, "CVE-2017-5689"},
	{"apc_demo_backdoor", "APC/Schneider NMC service credential", "APCB", EntryNone, GainAdmin, false, ""},
	{"smcrakp_bypass", "SMCRAKP fixed-key bypass", "SMCR", EntryNone, GainAdmin, true, "SMC-0002"},
	{"ilo_ipmi_bypass", "iLO passwordless IPMI session", "ILOB", EntryNone, GainAdmin, true, "HPE-0005"},
	{"ami_redfish_bypass", "AMI Redfish auth bypass", "AMIR", EntryNone, GainAdmin, true, "CVE-2024-54085"},
	{"ami_mtls_bypass", "AMI shipped-cert mTLS bypass", "AMIC", EntryNone, GainAdmin, true, "AMI-mTLS"},
	{"ssh_ilo_overflow", "iLO SSH pre-auth overflow (RCE)", "iLOS", EntryNone, GainAdmin, true, "HPE-0003"},
	{"smc_psblock_creds", "Supermicro cleartext credential store", "PSBK", EntryNone, GainAdmin, true, ""},
	{"rakp_setup_identity", "RAKP setup-slot identity overwrite", "RSID", EntryNone, GainSession, true, "OBMC-0004"},

	{"kvm_no_auth", "Unauthenticated KVM access", "KVM", EntryNone, GainHost, false, ""},
	{"vnc_default_creds", "KVM/VNC default credentials", "VNCD", EntryNone, GainHost, false, ""},
	{"smc_kvm_bypass", "Supermicro KVM auth bypass (wstunnel)", "SMCK", EntryNone, GainHost, true, ""},

	{"rakp_named", "Named RAKP account cracked", "RAKP", EntryNone, GainSession, false, "CVE-2013-4786"},
	{"ipmi_auth_none", "IPMI auth-none session", "NONE", EntryNone, GainSession, false, ""},
	{"openbmc_rakp_bypass", "OpenBMC RAKP authentication bypass", "OBMC", EntryNone, GainSession, true, "OBMC-0005"},
	{"ipmi_oem_preauth", "OEM NetFn commands accepted pre-session", "OEMN", EntryNone, GainSession, true, ""},

	{"smc_reserved_role", "Supermicro IPMI privilege escalation", "SMCPC", EntryLowPriv, GainAdmin, true, "CVE-2026-65220"},

	{"smc_ikvm_hijack", "Supermicro iKVM console access with any credential", "IKVM", EntryLowPriv, GainHost, true, ""},
}

var pathByKey = func() map[string]CompromisePath {
	m := make(map[string]CompromisePath, len(CompromisePaths))
	for _, p := range CompromisePaths {
		m[p.Key] = p
	}
	return m
}()

var newResearchPaths = func() map[string]bool {
	m := make(map[string]bool, len(CompromisePaths))
	for _, p := range CompromisePaths {
		if p.New {
			m[p.Key] = true
		}
	}
	return m
}()

type PotCrack struct {
	Username string
	Password string
}

var genericExposureKeys = map[string]bool{
	"ipmi":            true,
	"ipmi_1_5":        true,
	"ipmi_2_0":        true,
	"kvm_exposed":     true,
	"redfish_exposed": true,
}

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

type access struct {
	any bool
	pre bool

	entry bool

	directAdmin bool

	escalation bool

	host bool

	hostEscalation bool
}

func (a access) admin() bool {
	return a.directAdmin || (a.entry && a.escalation)
}

func (a access) chained() bool {
	return !a.directAdmin && a.entry && a.escalation
}

func (a access) hostReach() bool {
	return a.host || a.admin() || (a.entry && a.hostEscalation)
}

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
