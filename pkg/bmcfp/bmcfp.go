package bmcfp

import "regexp"

type Kind string

const (
	HTTPServerHeader Kind = "http.server"

	WWWAuthenticate Kind = "http.wwwauth"

	TLSSubjectCN Kind = "tls.subjectCn"

	TLSIssuerCN Kind = "tls.issuerCn"

	TLSSubjectDN Kind = "tls.subjectDn"

	TLSIssuerDN Kind = "tls.issuer_dn"

	SSHBanner Kind = "ssh.banner"

	HTMLTitle Kind = "html.title"

	FaviconMD5 Kind = "favicon.md5"

	FaviconMMH3 Kind = "favicon.mmh3"

	ContentSecurityPolicy Kind = "http.csp"
)

type rule struct {
	kind    Kind
	re      *regexp.Regexp
	vendor  string
	product string
	src     string

	weak bool
}

var rules = []rule{

	{kind: HTTPServerHeader, vendor: "dell", product: "iDRAC", src: "http_servers", weak: true, re: regexp.MustCompile(`(?i)^(?:M|Em)bedthis-Appweb/`)},

	{kind: HTTPServerHeader, vendor: "hpe", product: "iLO", src: "http_servers", re: regexp.MustCompile(`(?i)^HPE?-iLO-Server/`)},
	{kind: HTTPServerHeader, vendor: "hpe", product: "iLO", src: "http_servers", re: regexp.MustCompile(`(?i)^HP-iLO-\d+/`)},

	{kind: HTTPServerHeader, vendor: "oracle", product: "ILOM", src: "http_servers", re: regexp.MustCompile(`(?i)^(?:Sun|Oracle)-ILOM-Web-Server/`)},

	{kind: HTTPServerHeader, vendor: "supermicro", product: "IPMI", src: "http_servers", re: regexp.MustCompile(`(?i)^Linux/2\.6\.17\.WB_WPCM450`)},

	{kind: HTTPServerHeader, vendor: "ami", product: "MegaRAC", src: "http_servers", re: regexp.MustCompile(`(?i)^Linux/\S+-ami, UPnP/`)},

	{kind: HTTPServerHeader, vendor: "huawei", product: "iBMC", src: "http_servers", re: regexp.MustCompile(`(?i)^UPnP/[\d.]+ iBMC/`)},

	{kind: HTTPServerHeader, vendor: "huawei", product: "BMC", src: "http_servers", re: regexp.MustCompile(`(?i)^Huawei-BMC`)},

	{kind: ContentSecurityPolicy, vendor: "tinypilot", product: "TinyPilot", src: "http_csp", re: regexp.MustCompile(`(?i)connect-src[^;]*https://logs\.tinypilotkvm\.com`)},

	{kind: HTTPServerHeader, vendor: "fujitsu", product: "iRMC", src: "http_servers", re: regexp.MustCompile(`(?i)(?:FUJITSU ServerView )?iRMC S\d+ Webserver`)},

	{kind: HTTPServerHeader, vendor: "lenovo", product: "IMM2", src: "http_servers", re: regexp.MustCompile(`(?i)^Lenovo IMM2 Web Server$`)},

	{kind: HTTPServerHeader, vendor: "lenovo", product: "XCC", src: "xcc-firmware", re: regexp.MustCompile(`(?i)^XCC Web Server$`)},
	{kind: HTTPServerHeader, vendor: "lenovo", product: "XCC", src: "xcc-firmware", re: regexp.MustCompile(`(?i)^Lenovo HTTPS?$`)},
	{kind: HTTPServerHeader, vendor: "lenovo", product: "XCC", src: "xcc-firmware", re: regexp.MustCompile(`(?i)^Z51/[\d.]+`)},

	{kind: HTTPServerHeader, vendor: "asus", product: "ASMB", src: "http_servers", re: regexp.MustCompile(`(?i)ASMB\d`)},

	{kind: HTTPServerHeader, vendor: "moxa", product: "NPort", src: "console_servers", re: regexp.MustCompile(`(?i)^MoxaHttp/`)},

	{kind: HTTPServerHeader, vendor: "digi", product: "PortServer", src: "console_servers", re: regexp.MustCompile(`(?i)^Digi[- ]`)},

	{kind: HTTPServerHeader, vendor: "perle", product: "IOLAN", src: "console_servers", re: regexp.MustCompile(`(?i)^IOLAN`)},
	{kind: HTTPServerHeader, vendor: "perle", product: "IOLAN", src: "console_servers", weak: true, re: regexp.MustCompile(`(?i)^mini_httpd/1\.23 28Dec2015`)},

	{kind: HTTPServerHeader, vendor: "moxa", product: "NPort", src: "console_servers", weak: true, re: regexp.MustCompile(`(?i)MOS.*V3\.4\.13`)},

	{kind: HTTPServerHeader, vendor: "apc", product: "NMC", src: "pdu_servers", re: regexp.MustCompile(`(?i)^(?:Allegro-Software-)?RomPager/`)},
	{kind: HTTPServerHeader, vendor: "apc", product: "NMC", src: "pdu_servers", re: regexp.MustCompile(`(?i)^APC`)},

	{kind: HTTPServerHeader, vendor: "raritan", product: "PX", src: "pdu_servers", re: regexp.MustCompile(`(?i)^(?:Xerus|Raritan)`)},

	{kind: WWWAuthenticate, vendor: "fujitsu", product: "iRMC", src: "http_wwwauth", re: regexp.MustCompile(`(?i)realm="iRMC(?:@IRMC[0-9a-f]{6})?"`)},

	{kind: WWWAuthenticate, vendor: "dell", product: "iDRAC", src: "http_wwwauth", re: regexp.MustCompile(`(?i)realm="i?DRAC`)},

	{kind: WWWAuthenticate, vendor: "opengear", product: "console server", src: "console_servers", re: regexp.MustCompile(`(?i)realm="Opengear`)},

	{kind: WWWAuthenticate, vendor: "lantronix", product: "SLC", src: "console_servers", re: regexp.MustCompile(`(?i)realm="(?:Lantronix|SLC|SLB)`)},

	{kind: WWWAuthenticate, vendor: "advantech", product: "EKI", src: "console_servers", re: regexp.MustCompile(`(?i)realm="EKI-\d{3,4}`)},

	{kind: TLSSubjectDN, vendor: "supermicro", product: "IPMI", src: "x509_subjects", re: regexp.MustCompile(`(?i)O=Super Micro Computer`)},

	{kind: TLSSubjectDN, vendor: "dell", product: "iDRAC", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=i?DRAC[^,]*,OU=(?:Remote Access Group|Server Firmware Group|iDRAC Group),O=Dell Inc`)},
	{kind: TLSSubjectDN, vendor: "dell", product: "iDRAC", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=iDRACdefault[0-9a-f]{12},OU=iDRAC Group,O=Dell Inc`)},

	{kind: TLSSubjectDN, vendor: "lenovo", product: "XCC", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=XCC-[a-z0-9]+-[a-z0-9]+,O=(?:System X|Lenovo)`)},

	{kind: TLSSubjectDN, vendor: "hpe", product: "iLO", src: "x509_subjects", re: regexp.MustCompile(`(?i)OU=ISS,O=Hewlett[ -]Packard (?:Company|Enterprise)`)},
	{kind: TLSSubjectDN, vendor: "hpe", product: "iLO", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=HP Service Processor,OU=UDU Service Tools`)},

	{kind: TLSSubjectDN, vendor: "ami", product: "MegaRAC", src: "x509_subjects", re: regexp.MustCompile(`(?i)O=American Megatrends`)},
	{kind: TLSSubjectDN, vendor: "ami", product: "MegaRAC", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=megarac\.com`)},

	{kind: TLSSubjectDN, vendor: "hpe", product: "iLO", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=OA-[0-9a-f]+,OU=Onboard Administrator`)},

	{kind: TLSSubjectDN, vendor: "oracle", product: "ILOM", src: "x509_subjects", re: regexp.MustCompile(`(?i)(?:CN=Oracle Integrated Lights Out Manager|OU=Oracle Integrated Lights Out Manager)`)},

	{kind: TLSSubjectDN, vendor: "cisco", product: "CIMC", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=[CBS]-series CIMC,OU=PID:`)},

	{kind: TLSSubjectDN, vendor: "lantronix", product: "SLC", src: "console_servers", re: regexp.MustCompile(`(?i)CN=SLC,O=Lantronix`)},

	{kind: TLSSubjectDN, vendor: "cyberpower", product: "RMCARD", src: "pdu_servers", re: regexp.MustCompile(`(?i)OU=RMCARD\d`)},

	{kind: TLSSubjectDN, vendor: "sierra", product: "AirLink ALEOS", src: "cellular_gateways", re: regexp.MustCompile(`(?i)O=Sierra Wireless`)},

	{kind: TLSSubjectDN, vendor: "vertiv", product: "IntelliSlot Unity", src: "pdu_servers", re: regexp.MustCompile(`(?i)CN=IS-UNITY Server`)},
	{kind: TLSSubjectDN, vendor: "vertiv", product: "IntelliSlot Unity", src: "pdu_servers", re: regexp.MustCompile(`(?i)O=Vertiv,\s*OU=Liebert Corporation`)},

	{kind: TLSIssuerDN, vendor: "hpe", product: "iLO", src: "x509_issuers", re: regexp.MustCompile(`(?i)CN=(?:iLO\d )?Default Issuer \(Do not trust\),OU=ISS`)},

	{kind: TLSIssuerDN, vendor: "cisco", product: "CIMC", src: "x509_issuers", re: regexp.MustCompile(`(?i)CN=[CBS]-series CIMC,OU=PID:`)},

	{kind: TLSIssuerDN, vendor: "quanta", product: "BMC", src: "x509_issuers", re: regexp.MustCompile(`(?i)CN=Quanta,OU=CCBU,O=Quanta Computer`)},

	{kind: SSHBanner, vendor: "hpe", product: "iLO", src: "ssh_banners", re: regexp.MustCompile(`^mpSSH_[\d.]+$`)},

	{kind: SSHBanner, vendor: "oracle", product: "ILOM", src: "ssh_banners", re: regexp.MustCompile(`^OpenSSH_[\d.]+p\d \+ILOM\.`)},

	{kind: SSHBanner, vendor: "apc", product: "NMC", src: "pdu_servers", re: regexp.MustCompile(`(?i)^cryptlib`)},

	{kind: SSHBanner, vendor: "servertech", product: "Sentry", src: "pdu_servers", re: regexp.MustCompile(`(?i)ServerTech_SSH`)},

	{kind: HTMLTitle, vendor: "cyberpower", product: "PowerPanel Enterprise", src: "mgmt_software", re: regexp.MustCompile(`(?i)^PDNU$`)},
	{kind: HTMLTitle, vendor: "eaton", product: "Intelligent Power Manager", src: "mgmt_software", re: regexp.MustCompile(`(?i)Intelligent Power (?:Manager|Protector)`)},
	{kind: HTMLTitle, vendor: "hpe", product: "OneView / SIM", src: "mgmt_software", re: regexp.MustCompile(`(?i)HPE? OneView`)},
	{kind: HTMLTitle, vendor: "gude", product: "Expert Net Control", src: "pdu_servers", re: regexp.MustCompile(`(?i)Expert (?:Net|Power) Control|^GUDE`)},

	{kind: HTMLTitle, vendor: "schneiderpm", product: "Link150", src: "pdu_servers", re: regexp.MustCompile(`(?i)Link150|EcoStruxure Link`)},
	{kind: HTMLTitle, vendor: "schneiderpm", product: "PowerLogic PM8000", src: "pdu_servers", re: regexp.MustCompile(`(?i)PowerLogic`)},

	{kind: HTMLTitle, vendor: "dell", product: "iDRAC6", src: "html_title", re: regexp.MustCompile(`(?i)^Integrated (?:Dell )?Remote Access Controller 6 - (?:Enterprise|Express)$`)},

	{kind: HTMLTitle, vendor: "hpe", product: "iLO", src: "html_title", re: regexp.MustCompile(`(?i)^HP iLO (?:Login|Redirection)$`)},
	{kind: HTMLTitle, vendor: "hpe", product: "iLO", src: "html_title", re: regexp.MustCompile(`(?i)^HP Integrated Lights-Out`)},
	{kind: HTMLTitle, vendor: "hpe", product: "iLO", src: "html_title", re: regexp.MustCompile(`(?i)^(?:iLO|Integrated Lights-Out) \d$`)},

	{kind: HTMLTitle, vendor: "fujitsu", product: "iRMC", src: "html_title", re: regexp.MustCompile(`(?i)ServerView.* iRMC S\d+ Web Server`)},

	{kind: HTMLTitle, vendor: "oracle", product: "ILOM", src: "html_title", re: regexp.MustCompile(`(?i)Integrated Lights Out Manager`)},

	{kind: HTMLTitle, vendor: "huawei", product: "iBMC", src: "html_title", re: regexp.MustCompile(`(?i)^iBMC(?: Login)?$`)},

	{kind: HTMLTitle, vendor: "cisco", product: "CIMC", src: "html_title", re: regexp.MustCompile(`(?i)^Cisco (?:IMC Login|Integrated Management Controller)`)},
	{kind: HTMLTitle, vendor: "cisco", product: "CIMC", src: "html_title", re: regexp.MustCompile(`(?i)^CIMC$`)},

	{kind: HTMLTitle, vendor: "ami", product: "MegaRAC", src: "html_title", re: regexp.MustCompile(`(?i)^Megarac SP(?:-X)?$`)},

	{kind: HTMLTitle, vendor: "fujitsu", product: "iRMC", src: "html_title", re: regexp.MustCompile(`(?i)^iRMC S\d+@`)},

	{kind: HTMLTitle, vendor: "lenovo", product: "XCC", src: "html_title", re: regexp.MustCompile(`(?i)(?:Lenovo )?XClarity Controller`)},

	{kind: HTMLTitle, vendor: "asus", product: "ASMB", src: "html_title", re: regexp.MustCompile(`(?i)^ASUS.*(?:ASMB|BMC)|^ASMB\d`)},

	{kind: HTMLTitle, vendor: "asrockrack", product: "IPMI", src: "html_title", re: regexp.MustCompile(`(?i)^ASRockRack`)},

	{kind: HTMLTitle, vendor: "intel", product: "Integrated BMC", src: "html_title", re: regexp.MustCompile(`(?i)^Intel.*(?:BMC|Baseboard Management)`)},

	{kind: HTMLTitle, vendor: "supermicro", product: "IPMI", src: "html_title", re: regexp.MustCompile(`(?i)^Supermicro BMC Login`)},

	{kind: HTMLTitle, vendor: "openbmc", product: "OpenBMC", src: "html_title", re: regexp.MustCompile(`(?i)^(?:OpenBMC Web UI|BMC System Management|OpenBMC)$`)},

	{kind: HTMLTitle, vendor: "pikvm", product: "PiKVM", src: "ipkvm", re: regexp.MustCompile(`(?i)^PiKVM`)},
	{kind: HTMLTitle, vendor: "jetkvm", product: "JetKVM", src: "ipkvm", re: regexp.MustCompile(`(?i)^JetKVM`)},
	{kind: HTMLTitle, vendor: "nanokvm", product: "NanoKVM", src: "ipkvm", re: regexp.MustCompile(`(?i)NanoKVM`)},
	{kind: HTMLTitle, vendor: "tinypilot", product: "TinyPilot", src: "ipkvm", re: regexp.MustCompile(`(?i)TinyPilot`)},
	{kind: HTMLTitle, vendor: "glinet", product: "Comet GL-RM1", src: "ipkvm", re: regexp.MustCompile(`(?i)(?:GL\.iNet|GL-RM1|Comet)`)},

	{kind: HTMLTitle, vendor: "aten", product: "KVM over IP", src: "ipkvm", re: regexp.MustCompile(`(?i)^(?:CS\d{3,4}[a-z]?|KN\d{3,4}[a-z]?|CN\d{4}[a-z]?|KH\d{3,4}[a-z]?)$`)},

	{kind: HTMLTitle, vendor: "moxa", product: "NPort", src: "console_servers", re: regexp.MustCompile(`(?i)NPort`)},
	{kind: HTMLTitle, vendor: "opengear", product: "console server", src: "console_servers", re: regexp.MustCompile(`(?i)Opengear`)},
	{kind: HTMLTitle, vendor: "lantronix", product: "SecureLinx Spider", src: "console_servers", re: regexp.MustCompile(`(?i)^Spider Authentication$`)},
	{kind: HTMLTitle, vendor: "lantronix", product: "SLC", src: "console_servers", re: regexp.MustCompile(`(?i)Lantronix|SecureLinx|SLC Console Manager`)},

	{kind: HTMLTitle, vendor: "digi", product: "PortServer", src: "console_servers", re: regexp.MustCompile(`(?i)Digi (?:PortServer|Connect|International|One)|PortServer TS|ConnectPort`)},
	{kind: HTMLTitle, vendor: "perle", product: "IOLAN", src: "console_servers", re: regexp.MustCompile(`(?i)IOLAN`)},

	{kind: HTMLTitle, vendor: "advantech", product: "EKI", src: "console_servers", re: regexp.MustCompile(`(?i)^EKI-\d{3,4}[\w-]* Web Server`)},
	{kind: HTMLTitle, vendor: "zpe", product: "Nodegrid", src: "console_servers", re: regexp.MustCompile(`(?i)Nodegrid`)},
	{kind: HTMLTitle, vendor: "avocent", product: "DSView", src: "console_servers", re: regexp.MustCompile(`(?i)Avocent(?: DSView| ACS)|DSView \d`)},

	{kind: HTMLTitle, vendor: "apc", product: "NMC", src: "pdu_servers", re: regexp.MustCompile(`(?i)(?:APC|Network Management Card|Schneider Electric)`)},
	{kind: HTMLTitle, vendor: "raritan", product: "PX", src: "pdu_servers", re: regexp.MustCompile(`(?i)Raritan(?: PX)?|Xerus`)},
	{kind: HTMLTitle, vendor: "eaton", product: "Network-M", src: "pdu_servers", re: regexp.MustCompile(`(?i)Eaton|Network-M[23]`)},
	{kind: HTMLTitle, vendor: "servertech", product: "Sentry", src: "pdu_servers", re: regexp.MustCompile(`(?i)Sentry (?:Switched|Power)|Server Technology`)},

	{kind: HTMLTitle, vendor: "vertiv", product: "IntelliSlot", src: "pdu_servers", re: regexp.MustCompile(`(?i)IntelliSlot|Emerson Network Power`)},
	{kind: HTMLTitle, vendor: "cyberpower", product: "RMCARD", src: "pdu_servers", re: regexp.MustCompile(`(?i)CyberPower|RMCARD`)},

	{kind: HTMLTitle, vendor: "tripplite", product: "PowerAlert", src: "pdu_servers", re: regexp.MustCompile(`(?i)^PowerAlert (?:Local|Device Manager)`)},

	{kind: FaviconMD5, vendor: "oracle", product: "ILOM", src: "favicons", re: regexp.MustCompile(`(?i)^421e176ae0837bcc6b879ef55adbc897$`)},

	{kind: FaviconMD5, vendor: "huawei", product: "iBMC", src: "favicons", re: regexp.MustCompile(`(?i)^e76a1f0f3dfc497ff35e422fcf313655$`)},
	{kind: FaviconMD5, vendor: "supermicro", product: "IPMI", src: "favicons", re: regexp.MustCompile(`(?i)^06bd07c7437846e2aa5a6f90280b1b56$`)},
	{kind: FaviconMD5, vendor: "hpe", product: "iLO 3", src: "favicons", re: regexp.MustCompile(`(?i)^ec7645edc81cdc336996811ad16f3cc6$`)},
	{kind: FaviconMD5, vendor: "hpe", product: "iLO", src: "favicons", re: regexp.MustCompile(`(?i)^(?:ad93b3973782b03ea62a43bd6602ba8b|d521487f45fa7657450edfd6c16e4a63)$`)},
	{kind: FaviconMD5, vendor: "dell", product: "iDRAC", src: "favicons", re: regexp.MustCompile(`(?i)^2c9d5e03f63c39e6336ec491019c4f50$`)},

	{kind: FaviconMMH3, vendor: "opengear", product: "console server", src: "shodan-favicons", re: regexp.MustCompile(`^1012948051$`)},
	{kind: FaviconMMH3, vendor: "dell", product: "iDRAC", src: "shodan-favicons", re: regexp.MustCompile(`^1428702434$`)},
	{kind: FaviconMMH3, vendor: "lenovo", product: "XCC", src: "shodan-favicons", re: regexp.MustCompile(`^1958753229$`)},
	{kind: FaviconMMH3, vendor: "fujitsu", product: "iRMC", src: "shodan-favicons", re: regexp.MustCompile(`^354564839$`)},
	{kind: FaviconMMH3, vendor: "huawei", product: "iBMC", src: "shodan-favicons", re: regexp.MustCompile(`^561563906$`)},
	{kind: FaviconMMH3, vendor: "cisco", product: "CIMC", src: "shodan-favicons", re: regexp.MustCompile(`^(?:-646322113|-1750461220)$`)},
	{kind: FaviconMMH3, vendor: "ami", product: "MegaRAC", src: "shodan-favicons", re: regexp.MustCompile(`^-1811518222$`)},
	{kind: FaviconMMH3, vendor: "supermicro", product: "IPMI", src: "shodan-favicons", re: regexp.MustCompile(`^-2016537204$`)},
	{kind: FaviconMMH3, vendor: "raritan", product: "PX / KX", src: "shodan-favicons", re: regexp.MustCompile(`^-1292500717$`)},
	{kind: FaviconMMH3, vendor: "cyberpower", product: "PowerPanel", src: "shodan-favicons", re: regexp.MustCompile(`^-1580435063$`)},
	{kind: FaviconMMH3, vendor: "perle", product: "IOLAN", src: "shodan-favicons", re: regexp.MustCompile(`^-1737557933$`)},

	{kind: FaviconMMH3, vendor: "eaton", product: "Network-M", src: "firmware", re: regexp.MustCompile(`^1897933497$`)},

	{kind: FaviconMMH3, vendor: "perle", product: "IOLAN", src: "firmware", re: regexp.MustCompile(`^783813256$`)},
	{kind: FaviconMMH3, vendor: "nanokvm", product: "NanoKVM", src: "shodan-favicons", re: regexp.MustCompile(`^1323732765$`)},
	{kind: FaviconMMH3, vendor: "jetkvm", product: "JetKVM", src: "shodan-favicons", re: regexp.MustCompile(`^-412815663$`)},
	{kind: FaviconMMH3, vendor: "pikvm", product: "PiKVM", src: "shodan-favicons", re: regexp.MustCompile(`^(?:-1040945478|-692926325)$`)},
	{kind: FaviconMMH3, vendor: "blikvm", product: "BliKVM", src: "shodan-favicons", re: regexp.MustCompile(`^918230991$`)},

	{kind: TLSSubjectCN, vendor: "oracle", product: "ILOM", src: "x509_subjects", re: regexp.MustCompile(`(?i)^ORACLESP-`)},
	{kind: TLSSubjectCN, vendor: "cisco", product: "CIMC", src: "x509_subjects", re: regexp.MustCompile(`(?i)^[CBS]-series CIMC$`)},
	{kind: TLSSubjectCN, vendor: "perle", product: "IOLAN", src: "console_servers", re: regexp.MustCompile(`(?i)^Perle$`)},
	{kind: TLSSubjectCN, vendor: "servertech", product: "Sentry", src: "pdu_servers", re: regexp.MustCompile(`(?i)^Sentry Switched CDU$`)},
	{kind: TLSSubjectCN, vendor: "blikvm", product: "BliKVM", src: "ipkvm", re: regexp.MustCompile(`(?i)^blikvm\.com$`)},

	{kind: TLSIssuerCN, vendor: "huawei", product: "iBMC", src: "x509_issuers", re: regexp.MustCompile(`(?i)^Huawei IT Product CA$`)},

	{kind: HTTPServerHeader, vendor: "huawei", product: "iBMC", src: "http_servers", re: regexp.MustCompile(`(?i)\biBMC/[0-9.]+`)},

	{kind: HTTPServerHeader, vendor: "openbmc", product: "bmcweb", src: "http_servers", re: regexp.MustCompile(`(?i)^bmcweb`)},

	{kind: HTTPServerHeader, vendor: "servertech", product: "Sentry", src: "http_servers", re: regexp.MustCompile(`(?i)\bJAWS/1\.06\b`)},

	{kind: HTTPServerHeader, vendor: "westermo", product: "WeOS", src: "http_servers", weak: true, re: regexp.MustCompile(`(?i)^Civetweb\b`)},

	{kind: HTTPServerHeader, vendor: "vertiv", product: "IntelliSlot Unity", src: "http_servers", weak: true, re: regexp.MustCompile(`(?i)^Apache/2\.4\.57\b`)},

	{kind: HTMLTitle, vendor: "avocent", product: "ACS8000", src: "html_title", re: regexp.MustCompile(`(?i)ACS8000|ACS800`)},

	{kind: TLSSubjectDN, vendor: "asus", product: "ASMB", src: "x509_subjects", re: regexp.MustCompile(`(?i)O=American Megatrends Inc.*OU=Service Processors.*CN=AMI`)},

	{kind: TLSSubjectDN, vendor: "cisco", product: "CIMC legacy Avocent", src: "x509_subjects", re: regexp.MustCompile(`(?i)O=Cisco Systems Inc\.,\s*CN=cisco\.com`)},

	{kind: TLSSubjectDN, vendor: "dell", product: "iDRAC8", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=iDRAC8 default certificate`)},

	{kind: TLSSubjectDN, vendor: "ami", product: "MegaRAC", src: "x509_subjects", weak: true, re: regexp.MustCompile(`(?i)CN=www\.ami\.com`)},

	{kind: TLSSubjectCN, vendor: "aten", product: "KVM over IP", src: "x509_subjects", re: regexp.MustCompile(`(?i)^ATEN INTERNATIONAL`)},

	{kind: TLSSubjectDN, vendor: "h3c", product: "H3C KVM", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=H3C\b`)},

	{kind: TLSSubjectDN, vendor: "intel", product: "Integrated BMC", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=Intel,\s*O=Intel Corporation,\s*OU=BMC Software Team`)},

	{kind: TLSSubjectDN, vendor: "lantronix", product: "IONMM", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=lantronix\.com`)},

	{kind: TLSSubjectDN, vendor: "lantronix", product: "NTC-552", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=DA Magpie Server 1,\s*O=NetComm`)},

	{kind: TLSSubjectDN, vendor: "rittal", product: "CMC III", src: "x509_subjects", re: regexp.MustCompile(`(?i)O=Rittal GmbH`)},

	{kind: TLSSubjectCN, vendor: "fujitsu", product: "iRMC legacy", src: "x509_subjects", re: regexp.MustCompile(`(?i)^iRMC`)},

	{kind: TLSSubjectCN, vendor: "raritan", product: "PX", src: "x509_subjects", re: regexp.MustCompile(`(?i)^Demo Certificate$`)},

	{kind: TLSIssuerCN, vendor: "raritan", product: "PX", src: "x509_issuers", re: regexp.MustCompile(`(?i)^Generic Demo CA$`)},

	{kind: FaviconMD5, vendor: "pikvm", product: "PiKVM", src: "favicons", re: regexp.MustCompile(`(?i)^1a5210ea2fb7cfbabe62c619e8cfdc69$`)},

	{kind: SSHBanner, vendor: "openbmc", product: "dropbear-2025.89", src: "ssh_banners", re: regexp.MustCompile(`(?i)^dropbear_2025\.89\b`)},

	{kind: SSHBanner, vendor: "cyberpower", product: "RMCARD", src: "ssh_banners", re: regexp.MustCompile(`(?i)CPS_SSH_ID`)},

	{kind: SSHBanner, vendor: "servertech", product: "Sentry", src: "ssh_banners", re: regexp.MustCompile(`(?i)^ServerTech`)},
}

func Match(kind Kind, value string) (vendor, product string, ok bool) {
	if r := matchRule(kind, value); r != nil {
		return r.vendor, r.product, true
	}
	return "", "", false
}

func matchRule(kind Kind, value string) *rule {
	if value == "" {
		return nil
	}
	for i := range rules {
		r := &rules[i]
		if r.kind != kind {
			continue
		}
		if r.re.MatchString(value) {
			return r
		}
	}
	return nil
}

func MatchAll(inputs map[Kind]string) (vendor, product string, ok bool) {
	vendor, product, _, ok = MatchAllWeighted(inputs)
	return vendor, product, ok
}

func MatchAllWeighted(inputs map[Kind]string) (vendor, product string, weak, ok bool) {
	order := []Kind{
		TLSSubjectDN, TLSSubjectCN,
		TLSIssuerDN, TLSIssuerCN,
		HTTPServerHeader,
		SSHBanner,
		WWWAuthenticate,
		ContentSecurityPolicy,
		HTMLTitle,
		FaviconMD5,
		FaviconMMH3,
	}
	for _, k := range order {
		v, ok2 := inputs[k]
		if !ok2 {
			continue
		}
		if r := matchRule(k, v); r != nil {
			return r.vendor, r.product, r.weak, true
		}
	}
	return "", "", false, false
}
