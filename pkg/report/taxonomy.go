package report

import "strings"

type Exposure struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Short string `json:"short"`
}

var Taxonomy = []Exposure{
	{"ipmi", "IPMI: reachable", "IPMI"},
	{"ipmi_1_5", "IPMI: 1.5 supported", "1.5"},
	{"ipmi_2_0", "IPMI: 2.0 supported", "2.0"},
	{"ipmi_null_auth", "IPMI: null authentication", "NULL"},
	{"ipmi_anon_auth", "IPMI: anonymous authentication", "ANON"},
	{"ipmi_cipher_zero", "IPMI: cipher-zero session", "CPH0"},
	{"ipmi_default_creds", "IPMI: default credentials", "DEF"},
	{"ipmi_rakp_hash", "IPMI: RAKP hash disclosure", "RAKP"},
	{"ipmi_rakp_cracked", "IPMI: RAKP hash cracked", "CRK"},
	{"ipmi_integrity_bypass", "IPMI: integrity / RAKP bypass", "BYP"},
	{"ipmi_smcrakp_bypass", "IPMI: Supermicro SMCRAKP fixed-key bypass", "SMCR"},
	{"ipmi_smc_integrity_bypass", "IPMI: Supermicro unprotected RMCP+ commands", "SMCI"},
	{"ipmi_ilo_auth_bypass", "IPMI: HPE iLO auth bypass (iLO4 and earlier)", "iLOB"},
	{"ipmi_openbmc_bypass", "IPMI: OpenBMC auth bypass", "OBMC"},
	{"ipmi_role_escalation", "IPMI: privilege-role escalation to Administrator", "ROLE"},
	{"ipmi_state_machine", "IPMI: RMCP+ state-machine defect", "STAT"},
	{"ipmi_oem_preauth", "IPMI: OEM commands accepted pre-session", "OEMN"},
	{"ipmi_weak_ciphers", "IPMI: weak or null cipher suites offered", "WCPH"},
	{"ipmi_user_oracle", "IPMI: username enumeration oracle", "UORC"},
	{"ipmi_sid_weak", "IPMI: predictable session ID", "SID"},
	{"ipmi_cleartext_creds", "IPMI: cleartext credential store exposed", "PSBK"},
	{"snmp_default_cred", "SNMP: default community", "COMM"},
	{"snmp_v3", "SNMP: v3 supported", "v3"},
	{"tls_weak", "TLS: weak, expired, or self-signed", "TLS"},
	{"tls_shared_key", "TLS: shared / default private key", "TLSK"},
	{"ami_mtls_bypass", "TLS: AMI shipped-cert mTLS bypass", "AMIC"},
	{"ssh_weak", "SSH: weak crypto", "SSH"},
	{"ssh_shared_key", "SSH: shared / default host key", "SSHK"},
	{"ssh_default_creds", "SSH: default credentials", "SSHC"},
	{"ssh_ilo_overflow", "SSH: HPE iLO pre-auth overflow (iLO5 and earlier)", "iLOS"},
	{"web_default_creds", "HTTP: default web login", "WEB"},
	{"preauth_leak", "HTTP: pre-auth information disclosure", "LEAK"},
	{"ilo_known_cve", "HTTP: HPE iLO firmware CVE (version-gated)", "iLOC"},
	{"redfish_exposed", "Redfish: exposed", "RF"},
	{"ami_redfish_bypass", "Redfish: AMI auth bypass", "AMIR"},
	{"kvm_exposed", "KVM: console / virtual media exposed", "KVM"},
	{"kvm_no_auth", "KVM: unauthenticated or default-credential console", "KVMN"},
	{"smc_kvm_bypass", "KVM: Supermicro auth bypass", "SMCK"},
	{"vnc_exposed", "VNC: exposed", "VNC"},
	{"amt_auth_bypass", "AMT: Intel AMT authentication bypass", "AMT"},
	{"host_debug_exposed", "Host: JTAG / at-scale-debug reachable", "JTAG"},
	{"serial_exposed", "Serial: console exposed", "SER"},
	{"telnet_banner", "Telnet: banner exposed", "TEL"},
}

var exposureOrder = func() map[string]int {
	m := make(map[string]int, len(Taxonomy))
	for i, e := range Taxonomy {
		m[e.Key] = i
	}
	return m
}()

func scoreCheck(check string, set map[string]bool) {
	c := strings.TrimSpace(check)
	if c == "" {
		return
	}
	if strings.HasPrefix(c, "ipmi.") {
		set["ipmi"] = true
	}
	switch {
	case strings.HasPrefix(c, "ipmi.v15."):
		set["ipmi_1_5"] = true
	case strings.HasPrefix(c, "ipmi.v20."), c == "ipmi.ciphers", c == "ipmi.weakCiphers":
		set["ipmi_2_0"] = true
	}
	switch c {
	case "ipmi.authNull", "ipmi.v15.authNoneSession":
		set["ipmi_null_auth"] = true
	case "ipmi.authAnon":
		set["ipmi_anon_auth"] = true
	case "ipmi.v20.cipherZero":
		set["ipmi_cipher_zero"] = true
	case "ipmi.v20.defaultCreds", "ipmi.v15.defaultCreds":
		set["ipmi_default_creds"] = true
	case "ipmi.v20.rakpHash":
		set["ipmi_rakp_hash"] = true
		set["ipmi_2_0"] = true
	case "ipmi.v20.smcrakpBypass",
		"ipmi.ilo.integrityBypass", "ipmi.ilo.authBypass",
		"ipmi.openbmc.rakpAuthBypass":
		set["ipmi_integrity_bypass"] = true

		switch c {
		case "ipmi.v20.smcrakpBypass":
			set["ipmi_smcrakp_bypass"] = true
		case "ipmi.ilo.integrityBypass", "ipmi.ilo.authBypass":
			set["ipmi_ilo_auth_bypass"] = true
		case "ipmi.openbmc.rakpAuthBypass":
			set["ipmi_openbmc_bypass"] = true
		}
	case "ipmi.smc.integrityBypass":

		set["ipmi_integrity_bypass"] = true
		set["ipmi_smc_integrity_bypass"] = true
	case "ipmi.smc.privEsc":

		set["ipmi_role_escalation"] = true
	case "ipmi.smc.authBypass", "ipmi.smc.rakpStateMachine":

		set["ipmi_state_machine"] = true
	case "ipmi.rakp.state.setupIdentity":

		set["ipmi_state_machine"] = true
		set["ipmi_openbmc_bypass"] = true
		set["ipmi_role_escalation"] = true
	case "ipmi.netfnOem":
		set["ipmi_oem_preauth"] = true
	case "ipmi.weakCiphers":

		set["ipmi_weak_ciphers"] = true
		set["ipmi_2_0"] = true
	case "ipmi.v15.usernameOracle", "ipmi.v20.usernameOracle":

		set["ipmi_user_oracle"] = true
	case "http.smc.psBlock":
		set["ipmi_cleartext_creds"] = true
	case "http.jetkvm.metricsUnauth", "http.lantronix.ntcSkipAuth",
		"http.lantronix.ntcRootPassOracle", "http.perle.iolan.cgiUnauthLeak",
		"http.opengear.preAuthLeak", "http.ami.preAuthRouteRead",
		"http.servertech.configBakLeak", "http.eaton.ipmLfi",
		"http.lenovo.xcc.nonauthEdge", "http.ilo.xmlData", "http.ilo.licenseKey",
		"snmp.hostDisclosure":

		set["preauth_leak"] = true
	case "amt.authBypass":
		set["amt_auth_bypass"] = true
	case "xdp.exposed":
		set["host_debug_exposed"] = true
	case "kvm.vnc.unauth", "ipkvm.noAuth", "kvm.vnc.defaultCreds":
		set["kvm_no_auth"] = true
		set["kvm_exposed"] = true
	case "kvm.smc.ikvm.sessionHijack":
		set["smc_kvm_bypass"] = true
		set["kvm_exposed"] = true
	case "ipmi.sidEntropy", "ipmi.sidPredictable", "ipmi.sidClientCorr":

		set["ipmi_sid_weak"] = true
	case "ssh.hpe.iloSSHOverflow":

		set["ssh_ilo_overflow"] = true
	case "http.ilo.authBypass", "http.ilo.knownCVEs":

		set["ilo_known_cve"] = true
	case "http.redfish.amiBypass", "http.redfish.ami.cve202334329",
		"http.redfish.ami.noXffBypass":
		set["ami_redfish_bypass"] = true
		set["redfish_exposed"] = true
	case "tls.mtls.ami.caBypass":
		set["ami_mtls_bypass"] = true
		set["redfish_exposed"] = true
	case "kvm.smc.ws.bypass":
		set["smc_kvm_bypass"] = true
		set["kvm_exposed"] = true
	case "snmp.defaultCreds", "snmp.vendorCommunity":
		set["snmp_default_cred"] = true
	case "snmp.v3", "snmp.v3.defaultCreds":
		set["snmp_v3"] = true
		if c == "snmp.v3.defaultCreds" {
			set["snmp_default_cred"] = true
		}
	case "tls.expired", "tls.selfSigned", "tls.defaultCert", "tls.weakCrypto":
		set["tls_weak"] = true
	case "tls.sharedKey":
		set["tls_shared_key"] = true
		set["tls_weak"] = true
	case "ssh.weakCrypto":
		set["ssh_weak"] = true
	case "ssh.sharedHostKey":
		set["ssh_shared_key"] = true
		set["ssh_weak"] = true
	case "ssh.defaultCreds":
		set["ssh_default_creds"] = true
	case "serialconsole.exposure", "serialconsole.fingerprint",
		"tcp.lantronix.setupBanner", "udp.lantronix.setup",
		"tcp.moxa.serialBanner", "udp.moxa.deviceSearch",
		"tcp.digi.realportBanner":
		set["serial_exposed"] = true
	case "tcp.telnetBanner":
		set["telnet_banner"] = true
	case "ssdp.redfishRest", "http.redfish.exposure":
		set["redfish_exposed"] = true
	}
	if strings.HasPrefix(c, "kvm.") {
		set["kvm_exposed"] = true
		if strings.HasPrefix(c, "kvm.vnc") {
			set["vnc_exposed"] = true
		}
	}
	if strings.HasPrefix(c, "http.redfish.") {
		set["redfish_exposed"] = true
	}

	if strings.HasPrefix(c, "http.") && strings.Contains(strings.ToLower(c), "defaultcreds") {
		set["web_default_creds"] = true
	}
}
