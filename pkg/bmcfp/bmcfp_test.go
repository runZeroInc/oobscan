package bmcfp

import (
	"regexp"
	"testing"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		name        string
		kind        Kind
		value       string
		wantVendor  string
		wantProduct string
		wantOK      bool
	}{
		// -- HTTP Server header --
		{"idrac appweb", HTTPServerHeader, "Mbedthis-Appweb/2.4.2", "dell", "iDRAC", true},
		{"idrac appweb capW", HTTPServerHeader, "Mbedthis-AppWeb/2.4.0", "dell", "iDRAC", true},
		{"idrac embedthis appweb", HTTPServerHeader, "Embedthis-Appweb/3.4.2", "dell", "iDRAC", true},
		{"ilo server", HTTPServerHeader, "HPE-iLO-Server/1.30", "hpe", "iLO", true},
		{"ilo server hp", HTTPServerHeader, "HP-iLO-Server/1.30", "hpe", "iLO", true},
		{"ilo4 fw", HTTPServerHeader, "HP-iLO-4/2.55", "hpe", "iLO", true},
		{"sun ilom", HTTPServerHeader, "Sun-ILOM-Web-Server/1.0", "oracle", "ILOM", true},
		{"oracle ilom", HTTPServerHeader, "Oracle-ILOM-Web-Server/1.0", "oracle", "ILOM", true},
		{"supermicro wpcm450", HTTPServerHeader, "Linux/2.6.17.WB_WPCM450.1.3, UPnP/1.0, Intel SDK for UPnP devices/1.3.1", "supermicro", "IPMI", true},
		{"megarac upnp", HTTPServerHeader, "Linux/3.14.17-ami, UPnP/1.0, Portable SDK for UPnP devices/1.6.19", "ami", "MegaRAC", true},
		{"goahead webs", HTTPServerHeader, "GoAhead-Webs", "", "", false},
		{"goahead ver", HTTPServerHeader, "GoAhead-Webs/2.5.0 PeerSec-MatrixSSL/3.4.2-OPEN", "", "", false},
		{"huawei ibmc", HTTPServerHeader, "UPnP/2.0 iBMC/1.0 ProductName/foo V5 SN/abc", "huawei", "iBMC", true},
		{"huawei older bmc", HTTPServerHeader, "Huawei-BMC", "huawei", "BMC", true},
		{"fujitsu irmc s5 webserver", HTTPServerHeader, "iRMC S5 Webserver", "fujitsu", "iRMC", true},
		{"fujitsu serverview irmc s6", HTTPServerHeader, "FUJITSU ServerView iRMC S6 Webserver", "fujitsu", "iRMC", true},
		{"lenovo imm2", HTTPServerHeader, "Lenovo IMM2 Web Server", "lenovo", "IMM2", true},
		{"lenovo xcc web", HTTPServerHeader, "XCC Web Server", "lenovo", "XCC", true},
		{"lenovo xcc https front", HTTPServerHeader, "Lenovo HTTPS", "lenovo", "XCC", true},
		{"lenovo xcc http front", HTTPServerHeader, "Lenovo HTTP", "lenovo", "XCC", true},
		{"lenovo xcc redfish token", HTTPServerHeader, "Z51/2.22.0", "lenovo", "XCC", true},
		{"unknown server", HTTPServerHeader, "nginx/1.24.0", "", "", false},
		{"generic apache not bmc", HTTPServerHeader, "Apache/2.4.6", "", "", false},

		// -- WWW-Authenticate --
		{"irmc realm", WWWAuthenticate, `Digest realm="iRMC@IRMCA0EC88", qop="auth", nonce="d5"`, "fujitsu", "iRMC", true},
		{"irmc bare realm", WWWAuthenticate, `Basic realm="iRMC"`, "fujitsu", "iRMC", true},
		{"idrac realm", WWWAuthenticate, `Basic realm="iDRAC"`, "dell", "iDRAC", true},
		{"generic realm", WWWAuthenticate, `Basic realm="Restricted"`, "", "", false},

		// -- TLS Subject DN --
		{"supermicro ipmi cert", TLSSubjectDN, "CN=IPMI,OU=Software,O=Super Micro Computer,L=San Jose,ST=California,C=US", "supermicro", "IPMI", true},
		{"idrac default cert", TLSSubjectDN, "CN=iDRAC7 default certificate,OU=Remote Access Group,O=Dell Inc.,L=Round Rock,ST=Texas,C=US", "dell", "iDRAC", true},
		{"idrac servicetag cert", TLSSubjectDN, "CN=idrac-JXJJC02,OU=Remote Access Group,O=Dell Inc.,L=Round Rock,ST=Texas,C=US", "dell", "iDRAC", true},
		{"idrac mac cert", TLSSubjectDN, "CN=iDRACdefault0023AEF89AD1,OU=iDRAC Group,O=Dell Inc.,L=Round Rock,C=US", "dell", "iDRAC", true},
		{"lenovo xcc cert", TLSSubjectDN, "CN=XCC-7X06-J300ABCD,O=Lenovo,L=RTP,ST=NC,C=US", "lenovo", "XCC", true},
		{"hpe ilo iss cert", TLSSubjectDN, "CN=ILOMXQ0000A0A,OU=ISS,O=Hewlett Packard Enterprise,L=Americas,ST=Houston,C=US", "hpe", "iLO", true},
		{"ami megarac cert", TLSSubjectDN, "CN=AMI,OU=Service Processors,O=American Megatrends Inc.,L=Norcross,ST=Georgia,C=US", "ami", "MegaRAC", true},
		{"megarac.com cert", TLSSubjectDN, "CN=megarac.com,OU=Service Processors,O=American Megatrends International LLC (AMI),L=Norcross,ST=Georgia,C=US,emailAddress=support@ami.com", "ami", "MegaRAC", true},
		{"cisco cimc cert", TLSSubjectDN, "CN=C-series CIMC,OU=PID:UCSC-C220-M5SX SERIAL:WAA0000A0AA,O=Cisco Self Signed,L=San Jose,ST=California,C=US", "cisco", "CIMC", true},
		{"oracle ilom cert", TLSSubjectDN, "CN=Oracle Integrated Lights Out Manager,O=Oracle America\\, Inc.,L=Redwood Shores,ST=California,C=US", "oracle", "ILOM", true},
		{"sierra aleos acemanager cert", TLSSubjectDN, "C=CA, ST=British-Columbia, L=Richmond, O=Sierra Wireless, Inc., OU=Airlink, CN=*.sierrawireless.com", "sierra", "AirLink ALEOS", true},
		{"vertiv unity cert cn", TLSSubjectDN, "CN=IS-UNITY Server, O=Vertiv, OU=Liebert Corporation, L=Delaware, ST=Ohio, C=US", "vertiv", "IntelliSlot Unity", true},
		{"vertiv unity cert org", TLSSubjectDN, "CN=something else, O=Vertiv, OU=Liebert Corporation, ST=Ohio, C=US", "vertiv", "IntelliSlot Unity", true},
		{"unknown cert", TLSSubjectDN, "CN=www.example.com,O=Example Inc,C=US", "", "", false},

		// -- HTML title (new) --
		{"tripplite poweralert", HTMLTitle, "PowerAlert Local 12.06.0069", "tripplite", "PowerAlert", true},
		{"tripplite poweralert device mgr", HTMLTitle, "PowerAlert Device Manager", "tripplite", "PowerAlert", true},
		{"digi portserver bare", HTMLTitle, "PortServer TS 1 MEI Configuration and Management", "digi", "PortServer", true},
		{"digi portserver title", HTMLTitle, "PortServer TS 1 Configuration and Management", "digi", "PortServer", true},
		{"digi connect me", HTMLTitle, "Digi Connect ME Configuration and Management", "digi", "PortServer", true},
		{"asus asmb bare board", HTMLTitle, "ASMB9-iKVM", "asus", "ASMB", true},
		{"asrockrack ipmi title", HTMLTitle, "ASRockRack IPMI", "asrockrack", "IPMI", true},
		{"avocent dsview title", HTMLTitle, "Avocent DSView 4", "avocent", "DSView", true},

		// -- TLS Issuer DN --
		{"hpe ilo issuer", TLSIssuerDN, "CN=Default Issuer (Do not trust),OU=ISS,O=Hewlett Packard Enterprise,L=Houston,ST=Texas,C=US", "hpe", "iLO", true},
		{"hpe ilo3 issuer", TLSIssuerDN, "CN=iLO3 Default Issuer (Do not trust),OU=ISS,O=Hewlett-Packard Company,L=Houston,ST=TX,C=US", "hpe", "iLO", true},
		{"quanta issuer", TLSIssuerDN, "CN=Quanta,OU=CCBU,O=Quanta Computer Inc,L=Tao Yuan,ST=Taiwan,C=TW", "quanta", "BMC", true},

		// -- SSH banner --
		{"ilo mpssh", SSHBanner, "mpSSH_0.0.1", "hpe", "iLO", true},
		{"ilom openssh", SSHBanner, "OpenSSH_5.1p1 +ILOM.2015-5600", "oracle", "ILOM", true},
		{"plain openssh", SSHBanner, "OpenSSH_8.9p1 Ubuntu-3", "", "", false},
		{"apc cryptlib ssh", SSHBanner, "cryptlib", "apc", "NMC", true},
		{"apc cryptlib ssh ver", SSHBanner, "cryptlib 3.4.5", "apc", "NMC", true},

		// -- HTML title --
		{"idrac6 title", HTMLTitle, "Integrated Dell Remote Access Controller 6 - Enterprise", "dell", "iDRAC6", true},
		{"idrac6 title no dell", HTMLTitle, "Integrated Remote Access Controller 6 - Express", "dell", "iDRAC6", true},
		{"ilo login title", HTMLTitle, "HP iLO Login", "hpe", "iLO", true},
		{"ilo lom title", HTMLTitle, "HP Integrated Lights-Out", "hpe", "iLO", true},
		{"ilo3 title", HTMLTitle, "iLO 3", "hpe", "iLO", true},
		{"irmc title", HTMLTitle, "ServerView Remote Management iRMC S4 Web Server", "fujitsu", "iRMC", true},
		{"ilom title", HTMLTitle, "Oracle(R) Integrated Lights Out Manager", "oracle", "ILOM", true},
		{"ibmc title", HTMLTitle, "iBMC Login", "huawei", "iBMC", true},
		{"ibmc bare title", HTMLTitle, "iBMC", "huawei", "iBMC", true},
		{"fujitsu irmc s2 title", HTMLTitle, "iRMC S2@irmc0a1b2c", "fujitsu", "iRMC", true},
		{"cisco imc title", HTMLTitle, "Cisco Integrated Management Controller", "cisco", "CIMC", true},
		{"cisco cimc bare title", HTMLTitle, "CIMC", "cisco", "CIMC", true},
		{"megarac sp title", HTMLTitle, "Megarac SP", "ami", "MegaRAC", true},
		{"megarac spx title", HTMLTitle, "MegaRAC SP-X", "ami", "MegaRAC", true},
		{"supermicro title", HTMLTitle, "Supermicro BMC Login", "supermicro", "IPMI", true},
		{"openbmc title", HTMLTitle, "OpenBMC Web UI", "openbmc", "OpenBMC", true},
		{"lenovo xcc title", HTMLTitle, "Lenovo XClarity Controller", "lenovo", "XCC", true},
		// -- IP-KVM appliances (ClassKVM) --
		{"pikvm title", HTMLTitle, "PiKVM - Login", "pikvm", "PiKVM", true},
		{"jetkvm title", HTMLTitle, "JetKVM", "jetkvm", "JetKVM", true},
		{"nanokvm title", HTMLTitle, "Sipeed NanoKVM", "nanokvm", "NanoKVM", true},
		{"tinypilot title", HTMLTitle, "TinyPilot", "tinypilot", "TinyPilot", true},
		{"comet title", HTMLTitle, "GL.iNet Comet", "glinet", "Comet GL-RM1", true},
		{"random title", HTMLTitle, "Welcome to My Site", "", "", false},

		// -- favicon MD5 --
		{"ilom favicon", FaviconMD5, "421e176ae0837bcc6b879ef55adbc897", "oracle", "ILOM", true},
		{"huawei ibmc favicon", FaviconMD5, "e76a1f0f3dfc497ff35e422fcf313655", "huawei", "iBMC", true},
		{"supermicro favicon", FaviconMD5, "06bd07c7437846e2aa5a6f90280b1b56", "supermicro", "IPMI", true},
		{"ilo3 favicon", FaviconMD5, "ec7645edc81cdc336996811ad16f3cc6", "hpe", "iLO 3", true},
		{"ilo favicon a", FaviconMD5, "ad93b3973782b03ea62a43bd6602ba8b", "hpe", "iLO", true},
		{"ilo favicon b", FaviconMD5, "d521487f45fa7657450edfd6c16e4a63", "hpe", "iLO", true},
		{"dell favicon", FaviconMD5, "2c9d5e03f63c39e6336ec491019c4f50", "dell", "iDRAC", true},
		{"unknown favicon", FaviconMD5, "00000000000000000000000000000000", "", "", false},

		// -- serial console servers (ClassSerialConsole) --
		{"moxa server", HTTPServerHeader, "MoxaHttp/1.0", "moxa", "NPort", true},
		{"digi server", HTTPServerHeader, "Digi-PortServer", "digi", "PortServer", true},
		{"perle server", HTTPServerHeader, "IOLAN SCS", "perle", "IOLAN", true},
		{"opengear realm", WWWAuthenticate, `Basic realm="Opengear"`, "opengear", "console server", true},
		{"lantronix realm", WWWAuthenticate, `Basic realm="Lantronix SLC"`, "lantronix", "SLC", true},
		// Advantech EKI serial device server: the Boa Server header is shared (the
		// legacy SMC X10 ATEN stack also serves Boa/0.93.15), so attribution keys on
		// the EKI-<model> Basic realm and the "<model> Web Server" title, not Boa.
		{"advantech eki realm", WWWAuthenticate, `Basic realm="EKI-1524-CE"`, "advantech", "EKI", true},
		{"advantech eki title", HTMLTitle, "EKI-1524-CE Web Server", "advantech", "EKI", true},
		{"advantech eki title 1322", HTMLTitle, "EKI-1322 Web Server", "advantech", "EKI", true},
		{"bare boa not attributed", HTTPServerHeader, "Boa/0.93.15", "", "", false},
		{"moxa title", HTMLTitle, "NPort 6650 Web Console", "moxa", "NPort", true},
		{"opengear title", HTMLTitle, "Opengear Management Console", "opengear", "console server", true},
		{"lantronix spider title", HTMLTitle, "Spider Authentication", "lantronix", "SecureLinx Spider", true},
		{"digi title", HTMLTitle, "Digi PortServer TS", "digi", "PortServer", true},
		{"zpe title", HTMLTitle, "Nodegrid Serial Console", "zpe", "Nodegrid", true},

		// -- managed PDUs (ClassPDU) --
		{"apc rompager", HTTPServerHeader, "Allegro-Software-RomPager/4.34", "apc", "NMC", true},
		{"apc rompager bare", HTTPServerHeader, "RomPager/4.07", "apc", "NMC", true},
		{"raritan server", HTTPServerHeader, "Xerus/3.6.0", "raritan", "PX", true},
		{"apc title", HTMLTitle, "APC | Log On", "apc", "NMC", true},
		{"raritan title", HTMLTitle, "Raritan PX3", "raritan", "PX", true},
		{"eaton title", HTMLTitle, "Eaton Network-M2", "eaton", "Network-M", true},
		{"servertech title", HTMLTitle, "Sentry Switched CDU", "servertech", "Sentry", true},
		{"cyberpower title", HTMLTitle, "CyberPower RMCARD205", "cyberpower", "RMCARD", true},

		// -- empty / wrong-kind isolation --
		{"empty value", HTTPServerHeader, "", "", "", false},
		{"server value wrong kind", HTMLTitle, "Mbedthis-Appweb/2.4.2", "", "", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, p, ok := Match(c.kind, c.value)
			if ok != c.wantOK || v != c.wantVendor || p != c.wantProduct {
				t.Errorf("Match(%s, %q) = (%q, %q, %v), want (%q, %q, %v)",
					c.kind, c.value, v, p, ok, c.wantVendor, c.wantProduct, c.wantOK)
			}
		})
	}
}

func TestMatchAllTrustOrder(t *testing.T) {
	// A strong cert-subject signal must beat a weaker (or absent) title/favicon.
	in := map[Kind]string{
		TLSSubjectDN:     "CN=IPMI,OU=Software,O=Super Micro Computer,ST=California,C=US",
		HTTPServerHeader: "MoxaHttp/1.0",
		HTMLTitle:        "OpenBMC Web UI",
	}
	v, p, ok := MatchAll(in)
	if !ok || v != "supermicro" || p != "IPMI" {
		t.Fatalf("MatchAll trust order = (%q, %q, %v), want (supermicro, IPMI, true)", v, p, ok)
	}
}

func TestMatchAllSpiderNotMegaRAC(t *testing.T) {
	in := map[Kind]string{
		HTTPServerHeader: "GoAhead-Webs",
		HTMLTitle:        "Spider Authentication",
	}
	v, p, ok := MatchAll(in)
	if !ok || v != "lantronix" || p != "SecureLinx Spider" {
		t.Fatalf("MatchAll spider = (%q, %q, %v), want (lantronix, SecureLinx Spider, true)", v, p, ok)
	}
}

func TestMatchAllFallsThrough(t *testing.T) {
	// No cert, but a Server header identifies the box.
	in := map[Kind]string{
		HTTPServerHeader: "Mbedthis-Appweb/2.4.2",
	}
	v, p, ok := MatchAll(in)
	if !ok || v != "dell" || p != "iDRAC" {
		t.Fatalf("MatchAll server fallback = (%q, %q, %v), want (dell, iDRAC, true)", v, p, ok)
	}
}

func TestMatchAllWeightedWeak(t *testing.T) {
	// A generic/shared Server string matches but must be flagged weak so the
	// caller folds it at low confidence (a bare Apache/2.4.57 -- stock Debian 12 --
	// must not become a high-confidence "Vertiv PDU").
	v, p, weak, ok := MatchAllWeighted(map[Kind]string{HTTPServerHeader: "Apache/2.4.57 (Debian)"})
	if !ok || v != "vertiv" || !weak {
		t.Fatalf("Apache/2.4.57 = (%q,%q,weak=%v,ok=%v), want (vertiv,IntelliSlot Unity,weak=true,ok=true)", v, p, weak, ok)
	}
	// A vendor-owned cert tell must be strong (not weak).
	v, _, weak, ok = MatchAllWeighted(map[Kind]string{TLSSubjectDN: "CN=IPMI,OU=Software,O=Super Micro Computer,ST=California,C=US"})
	if !ok || v != "supermicro" || weak {
		t.Fatalf("SMC cert = (%q,weak=%v,ok=%v), want (supermicro,weak=false,ok=true)", v, weak, ok)
	}
}

func TestMatchAllNoMatch(t *testing.T) {
	in := map[Kind]string{
		HTTPServerHeader: "nginx/1.24.0",
		HTMLTitle:        "Home",
	}
	if v, p, ok := MatchAll(in); ok {
		t.Fatalf("MatchAll unknown host = (%q, %q, %v), want no match", v, p, ok)
	}
	if v, p, ok := MatchAll(nil); ok {
		t.Fatalf("MatchAll(nil) = (%q, %q, %v), want no match", v, p, ok)
	}
}

// A vendor typo'd into a rule would silently misclassify hosts. Validate every
// rule is well-formed: compiled regex, non-empty lowercase vendor + product,
// and a recorded recog source file.
func TestRulesWellFormed(t *testing.T) {
	if len(rules) == 0 {
		t.Fatal("rules is empty")
	}
	lower := regexp.MustCompile(`^[a-z0-9]+$`)
	for i := range rules {
		r := &rules[i]
		if r.re == nil {
			t.Errorf("rule %d (%s): nil regexp", i, r.vendor)
		}
		if r.vendor == "" || r.product == "" {
			t.Errorf("rule %d: empty vendor (%q) or product (%q)", i, r.vendor, r.product)
		}
		if !lower.MatchString(r.vendor) {
			t.Errorf("rule %d: vendor %q must be a short lowercase key", i, r.vendor)
		}
		if r.src == "" {
			t.Errorf("rule %d (%s): missing recog source file", i, r.vendor)
		}
	}
}
