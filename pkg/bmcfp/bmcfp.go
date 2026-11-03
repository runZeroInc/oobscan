// Package bmcfp fingerprints BMCs from the low-cost signals every HTTPS/SSH probe
// already collects: the HTTP Server header, the WWW-Authenticate realm, the TLS leaf
// subject/issuer CN, the SSH banner, the HTML title and the favicon MD5.
//
// Many BMCs do not self-identify in the Redfish service root, or gate it behind auth,
// yet still expose vendor identity through these side channels. The rules below are a
// curated set grouped by observed signal; where source material has one fingerprint
// per hardware model but the same vendor-level shape they are collapsed into one
// rule. Vendor keys are the short lowercase slugs used across oobscan.
package bmcfp

import "regexp"

// Kind identifies which observed signal a value came from. Each Match rule is
// scoped to a single Kind so an iLO Server-header regex never fires on, say, a
// certificate subject.
type Kind string

const (
	// HTTPServerHeader is the value of the HTTP "Server:" response header.
	HTTPServerHeader Kind = "http.server"
	// WWWAuthenticate is the value of the "WWW-Authenticate:" response header.
	WWWAuthenticate Kind = "http.wwwauth"
	// TLSSubjectCN is the leaf certificate Subject CommonName.
	TLSSubjectCN Kind = "tls.subjectCn"
	// TLSIssuerCN is the leaf certificate Issuer CommonName.
	TLSIssuerCN Kind = "tls.issuerCn"
	// TLSSubjectDN is the full leaf certificate Subject distinguished name
	// (e.g. "CN=IPMI,OU=Software,O=Super Micro Computer,..."). Several
	// x509_subjects patterns key off O=/OU= rather than the bare CN.
	TLSSubjectDN Kind = "tls.subjectDn"
	// TLSIssuerDN is the full leaf certificate Issuer distinguished name.
	TLSIssuerDN Kind = "tls.issuer_dn"
	// SSHBanner is the SSH server identification string (e.g. "mpSSH_0.0.1").
	SSHBanner Kind = "ssh.banner"
	// HTMLTitle is the text content of the page's <title> element.
	HTMLTitle Kind = "html.title"
	// FaviconMD5 is the hex MD5 of the site's favicon.
	FaviconMD5 Kind = "favicon.md5"
	// FaviconMMH3 is the signed-int32 MurmurHash3 (x86_32) of the MIME-base64
	// favicon -- the same value Shodan exposes as http.favicon.hash. Compute it
	// with FaviconHash()/FaviconHashString(); rules store the decimal string.
	FaviconMMH3 Kind = "favicon.mmh3"
	// ContentSecurityPolicy is the value of the "Content-Security-Policy:"
	// response header. Some appliances ship a fixed CSP whose connect-src
	// allowlist names a vendor telemetry host, which is a strong fingerprint.
	ContentSecurityPolicy Kind = "http.csp"
)

// rule is one compiled fingerprint: a regex over a single Kind that maps to a
// (vendor, product) pair. src records the signal group it belongs to.
type rule struct {
	kind    Kind
	re      *regexp.Regexp
	vendor  string
	product string
	src     string
	// weak marks a rule keyed on a generic signal (a stock/shared web-server
	// version string, a default OEM cert, a widely-reused favicon) rather than a
	// vendor-owned tell. A weak match is real but collision-prone, so callers
	// should fold it at low confidence and require corroboration before it decides
	// a device class. See MatchAllWeighted.
	weak bool
}

// rules is the curated BMC fingerprint set. Ordering within a Kind matters:
// more-specific patterns are listed before broader/weaker ones so the first
// match wins (see Match). All patterns are anchored consistently; case-insensitive rules use "(?i)".
var rules = []rule{
	// ---- HTTP Server header (http_servers) -------------------
	// iDRAC6/iDRAC7 front their web UI with Mbedthis/Embedthis Appweb. The generic
	// fingerprint maps the Server string to the Appweb *software* vendor; the BMC mapping
	// (Appweb on 443 == iDRAC) is oobscan domain knowledge. This is the single
	// highest-value gap-closer: bare iDRACs that don't self-ID in Redfish still
	// serve this header.
	{kind: HTTPServerHeader, vendor: "dell", product: "iDRAC", src: "http_servers", weak: true, re: regexp.MustCompile(`(?i)^(?:M|Em)bedthis-Appweb/`)},
	// HPE iLO: "HP-iLO-Server/...", "HPE-iLO-Server/...", "HP-iLO-4/2.55".
	{kind: HTTPServerHeader, vendor: "hpe", product: "iLO", src: "http_servers", re: regexp.MustCompile(`(?i)^HPE?-iLO-Server/`)},
	{kind: HTTPServerHeader, vendor: "hpe", product: "iLO", src: "http_servers", re: regexp.MustCompile(`(?i)^HP-iLO-\d+/`)},
	// Oracle/Sun ILOM web servers.
	{kind: HTTPServerHeader, vendor: "oracle", product: "ILOM", src: "http_servers", re: regexp.MustCompile(`(?i)^(?:Sun|Oracle)-ILOM-Web-Server/`)},
	// Supermicro WPCM450-era ATEN stack advertises this Linux/UPnP banner.
	{kind: HTTPServerHeader, vendor: "supermicro", product: "IPMI", src: "http_servers", re: regexp.MustCompile(`(?i)^Linux/2\.6\.17\.WB_WPCM450`)},
	// AMI MegaRAC LOM UPnP banner: "Linux/<ver>-ami, UPnP/1.0, ...".
	{kind: HTTPServerHeader, vendor: "ami", product: "MegaRAC", src: "http_servers", re: regexp.MustCompile(`(?i)^Linux/\S+-ami, UPnP/`)},
	// Huawei iBMC UPnP Server header: "UPnP/2.0 iBMC/<ver> ProductName/...".
	{kind: HTTPServerHeader, vendor: "huawei", product: "iBMC", src: "http_servers", re: regexp.MustCompile(`(?i)^UPnP/[\d.]+ iBMC/`)},
	// Older Huawei BMCs that predate the "iBMC" branding advertise "Huawei-BMC"
	// and lack the "iBMC Login" title used by newer builds.
	{kind: HTTPServerHeader, vendor: "huawei", product: "BMC", src: "http_servers", re: regexp.MustCompile(`(?i)^Huawei-BMC`)},

	// TinyPilot ships a fixed CSP whose connect-src allowlists the TinyPilot
	// telemetry host; the tail is the distinctive tell (nginx_response_headers.conf).
	{kind: ContentSecurityPolicy, vendor: "tinypilot", product: "TinyPilot", src: "http_csp", re: regexp.MustCompile(`(?i)connect-src[^;]*https://logs\.tinypilotkvm\.com`)},
	// Fujitsu iRMC embedded web server: "iRMC S<N> Webserver" or the ServerView-
	// branded "FUJITSU ServerView iRMC S<N> Webserver". The Sx token is the iRMC
	// generation.
	{kind: HTTPServerHeader, vendor: "fujitsu", product: "iRMC", src: "http_servers", re: regexp.MustCompile(`(?i)(?:FUJITSU ServerView )?iRMC S\d+ Webserver`)},
	// Lenovo Flex System IMM2 web server.
	{kind: HTTPServerHeader, vendor: "lenovo", product: "IMM2", src: "http_servers", re: regexp.MustCompile(`(?i)^Lenovo IMM2 Web Server$`)},
	// Lenovo XClarity Controller (XCC/XCC2). The nginx web tier sets distinct
	// Server headers for the GUI, HTTP(S) front end, and Redfish tier.
	{kind: HTTPServerHeader, vendor: "lenovo", product: "XCC", src: "xcc-firmware", re: regexp.MustCompile(`(?i)^XCC Web Server$`)},
	{kind: HTTPServerHeader, vendor: "lenovo", product: "XCC", src: "xcc-firmware", re: regexp.MustCompile(`(?i)^Lenovo HTTPS?$`)},
	{kind: HTTPServerHeader, vendor: "lenovo", product: "XCC", src: "xcc-firmware", re: regexp.MustCompile(`(?i)^Z51/[\d.]+`)},
	// ASUS ASMB (AMI MegaRAC SP-X OEM); ASUS-branded UPnP/server banner.
	{kind: HTTPServerHeader, vendor: "asus", product: "ASMB", src: "http_servers", re: regexp.MustCompile(`(?i)ASMB\d`)},
	// ---- Serial console servers (ClassSerialConsole) ---------
	// Moxa NPort embedded web server ("MoxaHttp/<ver>").
	{kind: HTTPServerHeader, vendor: "moxa", product: "NPort", src: "console_servers", re: regexp.MustCompile(`(?i)^MoxaHttp/`)},
	// Opengear appliances front their UI with lighttpd but advertise the product
	// in the realm/title; the Server header alone is generic, so Opengear leans on
	// the WWW-Authenticate realm and HTML title rules below.
	// Digi PortServer/Connect embedded server ("Digi-..." / "Boa" with Digi title).
	{kind: HTTPServerHeader, vendor: "digi", product: "PortServer", src: "console_servers", re: regexp.MustCompile(`(?i)^Digi[- ]`)},
	// Perle IOLAN embedded web server. IOLAN DS/TS/DESK/RACK v5.0 front the
	// admin UI with a pinned mini_httpd build; the exact version string is a
	// strong Perle tell.
	{kind: HTTPServerHeader, vendor: "perle", product: "IOLAN", src: "console_servers", re: regexp.MustCompile(`(?i)^IOLAN`)},
	{kind: HTTPServerHeader, vendor: "perle", product: "IOLAN", src: "console_servers", weak: true, re: regexp.MustCompile(`(?i)^mini_httpd/1\.23 28Dec2015`)},
	// Moxa NPort 6000 (MOS3 RTOS): "MOS ... V3.4.13" is the MOS *kernel* build
	// string. Real-firmware extraction (lab/moxa-nport/) found it only in the
	// kernel segment, not in the HTTP Server header (the header is emitted by the
	// un-extractable moxa.spb RTOS app), so this is unconfirmed as a web banner --
	// weak + version-pinned. The (?i)NPort HTML-title rule below is the real,
	// firmware-grounded Moxa tell.
	{kind: HTTPServerHeader, vendor: "moxa", product: "NPort", src: "console_servers", weak: true, re: regexp.MustCompile(`(?i)MOS.*V3\.4\.13`)},

	// ---- Managed PDUs (ClassPDU) -----------------------------
	// APC Network Management Card: the legacy AOS ships the Allegro "RomPager/<ver>"
	// embedded HTTP server; NMC-branded builds emit "Allegro-Software-RomPager".
	{kind: HTTPServerHeader, vendor: "apc", product: "NMC", src: "pdu_servers", re: regexp.MustCompile(`(?i)^(?:Allegro-Software-)?RomPager/`)},
	{kind: HTTPServerHeader, vendor: "apc", product: "NMC", src: "pdu_servers", re: regexp.MustCompile(`(?i)^APC`)},
	// Raritan PX / Xerus web tier.
	{kind: HTTPServerHeader, vendor: "raritan", product: "PX", src: "pdu_servers", re: regexp.MustCompile(`(?i)^(?:Xerus|Raritan)`)},

	// ---- WWW-Authenticate realm (http_wwwauth) ---------------
	// Fujitsu iRMC: Basic/Digest realm="iRMC" or realm="iRMC@IRMC0A1B2C".
	{kind: WWWAuthenticate, vendor: "fujitsu", product: "iRMC", src: "http_wwwauth", re: regexp.MustCompile(`(?i)realm="iRMC(?:@IRMC[0-9a-f]{6})?"`)},
	// Dell iDRAC occasionally challenges with a DRAC/iDRAC realm.
	{kind: WWWAuthenticate, vendor: "dell", product: "iDRAC", src: "http_wwwauth", re: regexp.MustCompile(`(?i)realm="i?DRAC`)},
	// Opengear console servers challenge with realm="Opengear" (legacy CGI UI).
	{kind: WWWAuthenticate, vendor: "opengear", product: "console server", src: "console_servers", re: regexp.MustCompile(`(?i)realm="Opengear`)},
	// Lantronix SLC/SLB console managers use a Lantronix realm.
	{kind: WWWAuthenticate, vendor: "lantronix", product: "SLC", src: "console_servers", re: regexp.MustCompile(`(?i)realm="(?:Lantronix|SLC|SLB)`)},
	// Advantech EKI serial device servers front a Boa/0.93.15 web tier that
	// challenges HTTP Basic with the model as the realm (e.g. realm="EKI-1524-CE").
	// Boa alone is shared across many embedded vendors (and collides with the old
	// SMC ATEN stack), so we key on the EKI-<model> realm, which is Advantech-specific.
	// Recovered from the real EKI-1524-CE firmware (lab/advantech-eki/).
	{kind: WWWAuthenticate, vendor: "advantech", product: "EKI", src: "console_servers", re: regexp.MustCompile(`(?i)realm="EKI-\d{3,4}`)},

	// ---- TLS certificate Subject (x509_subjects) -------------
	// Match on the full DN because these key off O=/OU= as much as CN.
	// Supermicro: CN=IPMI,OU=Software...,O=Super Micro Computer.
	{kind: TLSSubjectDN, vendor: "supermicro", product: "IPMI", src: "x509_subjects", re: regexp.MustCompile(`(?i)O=Super Micro Computer`)},
	// Dell iDRAC default/service-tag/mac certs, all under O=Dell Inc.,L=Round Rock.
	{kind: TLSSubjectDN, vendor: "dell", product: "iDRAC", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=i?DRAC[^,]*,OU=(?:Remote Access Group|Server Firmware Group|iDRAC Group),O=Dell Inc`)},
	{kind: TLSSubjectDN, vendor: "dell", product: "iDRAC", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=iDRACdefault[0-9a-f]{12},OU=iDRAC Group,O=Dell Inc`)},
	// Lenovo XClarity Controller: CN=XCC-<mtm>-<serial>,O=(System X|Lenovo).
	{kind: TLSSubjectDN, vendor: "lenovo", product: "XCC", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=XCC-[a-z0-9]+-[a-z0-9]+,O=(?:System X|Lenovo)`)},
	// HPE iLO: CN=<host>,OU=ISS,O=Hewlett[ -]Packard (Company|Enterprise).
	{kind: TLSSubjectDN, vendor: "hpe", product: "iLO", src: "x509_subjects", re: regexp.MustCompile(`(?i)OU=ISS,O=Hewlett[ -]Packard (?:Company|Enterprise)`)},
	{kind: TLSSubjectDN, vendor: "hpe", product: "iLO", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=HP Service Processor,OU=UDU Service Tools`)},
	// AMI MegaRAC LOM: CN=AMI or CN=megarac.com under O=American Megatrends.
	{kind: TLSSubjectDN, vendor: "ami", product: "MegaRAC", src: "x509_subjects", re: regexp.MustCompile(`(?i)O=American Megatrends`)},
	{kind: TLSSubjectDN, vendor: "ami", product: "MegaRAC", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=megarac\.com`)},
	// HPE iLO Onboard Administrator: CN=OA-<mac>,OU=Onboard Administrator.
	{kind: TLSSubjectDN, vendor: "hpe", product: "iLO", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=OA-[0-9a-f]+,OU=Onboard Administrator`)},
	// Oracle ILOM: CN=Oracle Integrated Lights Out Manager / OU=... ,O=Oracle America.
	{kind: TLSSubjectDN, vendor: "oracle", product: "ILOM", src: "x509_subjects", re: regexp.MustCompile(`(?i)(?:CN=Oracle Integrated Lights Out Manager|OU=Oracle Integrated Lights Out Manager)`)},
	// Cisco CIMC/UCS certificates share the
	// "CN=<C|B|S>-series CIMC,OU=PID:...SERIAL:..." shape.
	{kind: TLSSubjectDN, vendor: "cisco", product: "CIMC", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=[CBS]-series CIMC,OU=PID:`)},
	// Lantronix SLC console manager factory cert: CN=SLC,O=Lantronix. This is also
	// the shipped shared-key cert catalogued in tlscert.
	{kind: TLSSubjectDN, vendor: "lantronix", product: "SLC", src: "console_servers", re: regexp.MustCompile(`(?i)CN=SLC,O=Lantronix`)},
	// CyberPower RMCARD TLS cert carries the card model in the OU (OU=RMCARD205).
	{kind: TLSSubjectDN, vendor: "cyberpower", product: "RMCARD", src: "pdu_servers", re: regexp.MustCompile(`(?i)OU=RMCARD\d`)},
	// Sierra Wireless AirLink (ALEOS) cellular gateway: the ACEmanager HTTPS tier
	// serves a self-signed fleet cert CN=*.sierrawireless.com,O=Sierra Wireless,
	// Inc.,OU=Airlink -- byte-identical SPKI across RV50/RV55 (and by scheme
	// MP70/LX40/LX60). Also catalogued in tlscert knownSharedKeys (fleet key).
	{kind: TLSSubjectDN, vendor: "sierra", product: "AirLink ALEOS", src: "cellular_gateways", re: regexp.MustCompile(`(?i)O=Sierra Wireless`)},
	// Vertiv/Liebert IntelliSlot Unity monitoring card: first-boot self-signed leaf
	// CN=IS-UNITY Server,O=Vertiv,OU=Liebert Corporation (issuer CN=Liebert
	// Monitoring Group). The web UI ships no static <title> and only a bare Apache
	// Server header, so the TLS DN is the strong passive tell.
	{kind: TLSSubjectDN, vendor: "vertiv", product: "IntelliSlot Unity", src: "pdu_servers", re: regexp.MustCompile(`(?i)CN=IS-UNITY Server`)},
	{kind: TLSSubjectDN, vendor: "vertiv", product: "IntelliSlot Unity", src: "pdu_servers", re: regexp.MustCompile(`(?i)O=Vertiv,\s*OU=Liebert Corporation`)},

	// ---- TLS certificate Issuer (x509_issuers) ---------------
	// HPE iLO self-signed issuer markers ("Default Issuer" and "iLO3 Default
	// Issuer" both under OU=ISS).
	{kind: TLSIssuerDN, vendor: "hpe", product: "iLO", src: "x509_issuers", re: regexp.MustCompile(`(?i)CN=(?:iLO\d )?Default Issuer \(Do not trust\),OU=ISS`)},
	// Cisco CIMC self-signed issuer (same DN family as the subject).
	{kind: TLSIssuerDN, vendor: "cisco", product: "CIMC", src: "x509_issuers", re: regexp.MustCompile(`(?i)CN=[CBS]-series CIMC,OU=PID:`)},
	// Quanta appliance self-signed issuer.
	{kind: TLSIssuerDN, vendor: "quanta", product: "BMC", src: "x509_issuers", re: regexp.MustCompile(`(?i)CN=Quanta,OU=CCBU,O=Quanta Computer`)},

	// ---- SSH banner (ssh_banners) ----------------------------
	// HPE iLO ships its own SSH daemon banner "mpSSH_<ver>".
	{kind: SSHBanner, vendor: "hpe", product: "iLO", src: "ssh_banners", re: regexp.MustCompile(`^mpSSH_[\d.]+$`)},
	// Oracle ILOM patches OpenSSH with a "+ILOM.<date>" comment.
	{kind: SSHBanner, vendor: "oracle", product: "ILOM", src: "ssh_banners", re: regexp.MustCompile(`^OpenSSH_[\d.]+p\d \+ILOM\.`)},
	// APC/Schneider Network Management Card ships cryptlib as its SSH server, so
	// the identification string is "SSH-2.0-cryptlib".
	{kind: SSHBanner, vendor: "apc", product: "NMC", src: "pdu_servers", re: regexp.MustCompile(`(?i)^cryptlib`)},
	// ServerTech (Server Technology / Legrand) Sentry PDU ships Mocana NanoSSH with
	// a product-specific identification string.
	{kind: SSHBanner, vendor: "servertech", product: "Sentry", src: "pdu_servers", re: regexp.MustCompile(`(?i)ServerTech_SSH`)},

	// ---- HTML <title> (html_title) ---------------------------
	// OOB management software (DCIM / UPS-management web apps) - listed first so a
	// specific product title (e.g. "Eaton Intelligent Power Manager") wins over the
	// broad vendor-name PDU rules further down, which would otherwise match on
	// "Eaton" alone. The CVE checks in pkg/check/webapp_cves.go key off these
	// vendor slugs. CyberPower PowerPanel Enterprise titles its SPA "PDNU".
	{kind: HTMLTitle, vendor: "cyberpower", product: "PowerPanel Enterprise", src: "mgmt_software", re: regexp.MustCompile(`(?i)^PDNU$`)},
	{kind: HTMLTitle, vendor: "eaton", product: "Intelligent Power Manager", src: "mgmt_software", re: regexp.MustCompile(`(?i)Intelligent Power (?:Manager|Protector)`)},
	{kind: HTMLTitle, vendor: "hpe", product: "OneView / SIM", src: "mgmt_software", re: regexp.MustCompile(`(?i)HPE? OneView`)},
	{kind: HTMLTitle, vendor: "gude", product: "Expert Net Control", src: "pdu_servers", re: regexp.MustCompile(`(?i)Expert (?:Net|Power) Control|^GUDE`)},
	// Schneider Electric energy gateways / power meters (distinct from the APC NMC).
	{kind: HTMLTitle, vendor: "schneiderpm", product: "Link150", src: "pdu_servers", re: regexp.MustCompile(`(?i)Link150|EcoStruxure Link`)},
	{kind: HTMLTitle, vendor: "schneiderpm", product: "PowerLogic PM8000", src: "pdu_servers", re: regexp.MustCompile(`(?i)PowerLogic`)},
	// Dell iDRAC6 login title.
	{kind: HTMLTitle, vendor: "dell", product: "iDRAC6", src: "html_title", re: regexp.MustCompile(`(?i)^Integrated (?:Dell )?Remote Access Controller 6 - (?:Enterprise|Express)$`)},
	// HPE iLO titles across generations.
	{kind: HTMLTitle, vendor: "hpe", product: "iLO", src: "html_title", re: regexp.MustCompile(`(?i)^HP iLO (?:Login|Redirection)$`)},
	{kind: HTMLTitle, vendor: "hpe", product: "iLO", src: "html_title", re: regexp.MustCompile(`(?i)^HP Integrated Lights-Out`)},
	{kind: HTMLTitle, vendor: "hpe", product: "iLO", src: "html_title", re: regexp.MustCompile(`(?i)^(?:iLO|Integrated Lights-Out) \d$`)},
	// Fujitsu iRMC: "ServerView ... iRMC S4 Web Server".
	{kind: HTMLTitle, vendor: "fujitsu", product: "iRMC", src: "html_title", re: regexp.MustCompile(`(?i)ServerView.* iRMC S\d+ Web Server`)},
	// Oracle ILOM.
	{kind: HTMLTitle, vendor: "oracle", product: "ILOM", src: "html_title", re: regexp.MustCompile(`(?i)Integrated Lights Out Manager`)},
	// Huawei iBMC. The login page titles itself "iBMC Login"; some builds serve
	// a bare "iBMC" title. (Anchored so it never matches "...iBMC..." substrings
	// like an SNMP sysDescr.)
	{kind: HTMLTitle, vendor: "huawei", product: "iBMC", src: "html_title", re: regexp.MustCompile(`(?i)^iBMC(?: Login)?$`)},
	// Cisco Integrated Management Controller. Older UIs title the page "Cisco
	// IMC Login" / "Cisco Integrated Management Controller"; the current single-
	// page UI titles it exactly "CIMC", so match both.
	{kind: HTMLTitle, vendor: "cisco", product: "CIMC", src: "html_title", re: regexp.MustCompile(`(?i)^Cisco (?:IMC Login|Integrated Management Controller)`)},
	{kind: HTMLTitle, vendor: "cisco", product: "CIMC", src: "html_title", re: regexp.MustCompile(`(?i)^CIMC$`)},
	// AMI MegaRAC SP (OEM'd BMC UI). "Megarac SP" (SP-Z) and the SP-X variant
	// ("MegaRAC SP-X") both title the login page.
	{kind: HTMLTitle, vendor: "ami", product: "MegaRAC", src: "html_title", re: regexp.MustCompile(`(?i)^Megarac SP(?:-X)?$`)},
	// Fujitsu iRMC login title: "ServerView ... iRMC S<N> Web Server" and the
	// older "iRMC S2@<host>" form.
	{kind: HTMLTitle, vendor: "fujitsu", product: "iRMC", src: "html_title", re: regexp.MustCompile(`(?i)^iRMC S\d+@`)},
	// Lenovo XClarity Controller login title (XCC/XCC2/XCC3 share the shell).
	{kind: HTMLTitle, vendor: "lenovo", product: "XCC", src: "html_title", re: regexp.MustCompile(`(?i)(?:Lenovo )?XClarity Controller`)},
	// ASUS ASMB (AMI MegaRAC OEM) management login. The login title is sometimes
	// "ASUS ... ASMB..." and sometimes the bare board name "ASMB9-iKVM".
	{kind: HTMLTitle, vendor: "asus", product: "ASMB", src: "html_title", re: regexp.MustCompile(`(?i)^ASUS.*(?:ASMB|BMC)|^ASMB\d`)},
	// ASRockRack IPMI (AMI MegaRAC OEM) management login titles itself "ASRockRack IPMI".
	{kind: HTMLTitle, vendor: "asrockrack", product: "IPMI", src: "html_title", re: regexp.MustCompile(`(?i)^ASRockRack`)},
	// Intel Integrated BMC (AMI-on-ASPEED server boards).
	{kind: HTMLTitle, vendor: "intel", product: "Integrated BMC", src: "html_title", re: regexp.MustCompile(`(?i)^Intel.*(?:BMC|Baseboard Management)`)},
	// Supermicro ATEN BMC login page.
	{kind: HTMLTitle, vendor: "supermicro", product: "IPMI", src: "html_title", re: regexp.MustCompile(`(?i)^Supermicro BMC Login`)},
	// OpenBMC / bmcweb web UI.
	{kind: HTMLTitle, vendor: "openbmc", product: "OpenBMC", src: "html_title", re: regexp.MustCompile(`(?i)^(?:OpenBMC Web UI|BMC System Management|OpenBMC)$`)},
	// ---- Modern IP-KVM appliances (ClassKVM, not BMC) --------
	{kind: HTMLTitle, vendor: "pikvm", product: "PiKVM", src: "ipkvm", re: regexp.MustCompile(`(?i)^PiKVM`)},
	{kind: HTMLTitle, vendor: "jetkvm", product: "JetKVM", src: "ipkvm", re: regexp.MustCompile(`(?i)^JetKVM`)},
	{kind: HTMLTitle, vendor: "nanokvm", product: "NanoKVM", src: "ipkvm", re: regexp.MustCompile(`(?i)NanoKVM`)},
	{kind: HTMLTitle, vendor: "tinypilot", product: "TinyPilot", src: "ipkvm", re: regexp.MustCompile(`(?i)TinyPilot`)},
	{kind: HTMLTitle, vendor: "glinet", product: "Comet GL-RM1", src: "ipkvm", re: regexp.MustCompile(`(?i)(?:GL\.iNet|GL-RM1|Comet)`)},
	// Standalone ATEN/Altusen KVM-over-IP (CN/CS/KN/KH-series). Its login <title>
	// is the bare model number (e.g. "CS1716i", "KN4132", "CN8000"). The whole-
	// title anchor keeps it ATEN-specific and off Supermicro BMCs, which title
	// "Supermicro BMC Login" and share the CN=IPMI cert, not this model title.
	{kind: HTMLTitle, vendor: "aten", product: "KVM over IP", src: "ipkvm", re: regexp.MustCompile(`(?i)^(?:CS\d{3,4}[a-z]?|KN\d{3,4}[a-z]?|CN\d{4}[a-z]?|KH\d{3,4}[a-z]?)$`)},

	// ---- Serial console servers (ClassSerialConsole) ---------
	{kind: HTMLTitle, vendor: "moxa", product: "NPort", src: "console_servers", re: regexp.MustCompile(`(?i)NPort`)},
	{kind: HTMLTitle, vendor: "opengear", product: "console server", src: "console_servers", re: regexp.MustCompile(`(?i)Opengear`)},
	{kind: HTMLTitle, vendor: "lantronix", product: "SecureLinx Spider", src: "console_servers", re: regexp.MustCompile(`(?i)^Spider Authentication$`)},
	{kind: HTMLTitle, vendor: "lantronix", product: "SLC", src: "console_servers", re: regexp.MustCompile(`(?i)Lantronix|SecureLinx|SLC Console Manager`)},
	// Field titles are "PortServer TS <n> Configuration and Management",
	// "Digi Connect ME Configuration...", "Digi One SP...", "ConnectPort..." -- the UI
	// omits the "Digi " prefix on the PortServer line, so match the product names
	// directly (all Digi-specific).
	{kind: HTMLTitle, vendor: "digi", product: "PortServer", src: "console_servers", re: regexp.MustCompile(`(?i)Digi (?:PortServer|Connect|International|One)|PortServer TS|ConnectPort`)},
	{kind: HTMLTitle, vendor: "perle", product: "IOLAN", src: "console_servers", re: regexp.MustCompile(`(?i)IOLAN`)},
	// Advantech EKI serial device server authenticated page: "<model> Web Server"
	// (e.g. "EKI-1524-CE Web Server"). Pre-auth the model is only in the Basic realm
	// (see the WWWAuthenticate rule above). Recovered from lab/advantech-eki/.
	{kind: HTMLTitle, vendor: "advantech", product: "EKI", src: "console_servers", re: regexp.MustCompile(`(?i)^EKI-\d{3,4}[\w-]* Web Server`)},
	{kind: HTMLTitle, vendor: "zpe", product: "Nodegrid", src: "console_servers", re: regexp.MustCompile(`(?i)Nodegrid`)},
	{kind: HTMLTitle, vendor: "avocent", product: "DSView", src: "console_servers", re: regexp.MustCompile(`(?i)Avocent(?: DSView| ACS)|DSView \d`)},

	// ---- Managed PDUs (ClassPDU) -----------------------------
	{kind: HTMLTitle, vendor: "apc", product: "NMC", src: "pdu_servers", re: regexp.MustCompile(`(?i)(?:APC|Network Management Card|Schneider Electric)`)},
	{kind: HTMLTitle, vendor: "raritan", product: "PX", src: "pdu_servers", re: regexp.MustCompile(`(?i)Raritan(?: PX)?|Xerus`)},
	{kind: HTMLTitle, vendor: "eaton", product: "Network-M", src: "pdu_servers", re: regexp.MustCompile(`(?i)Eaton|Network-M[23]`)},
	{kind: HTMLTitle, vendor: "servertech", product: "Sentry", src: "pdu_servers", re: regexp.MustCompile(`(?i)Sentry (?:Switched|Power)|Server Technology`)},
	// Vertiv/Liebert IntelliSlot cards also use the Emerson Network Power name.
	{kind: HTMLTitle, vendor: "vertiv", product: "IntelliSlot", src: "pdu_servers", re: regexp.MustCompile(`(?i)IntelliSlot|Emerson Network Power`)},
	{kind: HTMLTitle, vendor: "cyberpower", product: "RMCARD", src: "pdu_servers", re: regexp.MustCompile(`(?i)CyberPower|RMCARD`)},
	// Tripp Lite PowerAlert (SNMPWEBCARD / WEBCARDLX). The landing/applet-loader
	// page titles itself "PowerAlert Local <ver>" (e.g. "PowerAlert Local 12.06.0069");
	// other pages use "PowerAlert Local: <x>". Pre-auth (login landing).
	{kind: HTMLTitle, vendor: "tripplite", product: "PowerAlert", src: "pdu_servers", re: regexp.MustCompile(`(?i)^PowerAlert (?:Local|Device Manager)`)},

	// ---- favicon MD5 (favicons) ------------------------------
	// Exact 32-hex favicon fingerprints -> BMC vendor/product.
	{kind: FaviconMD5, vendor: "oracle", product: "ILOM", src: "favicons", re: regexp.MustCompile(`(?i)^421e176ae0837bcc6b879ef55adbc897$`)},
	// Huawei iBMC favicon.
	{kind: FaviconMD5, vendor: "huawei", product: "iBMC", src: "favicons", re: regexp.MustCompile(`(?i)^e76a1f0f3dfc497ff35e422fcf313655$`)},
	{kind: FaviconMD5, vendor: "supermicro", product: "IPMI", src: "favicons", re: regexp.MustCompile(`(?i)^06bd07c7437846e2aa5a6f90280b1b56$`)},
	{kind: FaviconMD5, vendor: "hpe", product: "iLO 3", src: "favicons", re: regexp.MustCompile(`(?i)^ec7645edc81cdc336996811ad16f3cc6$`)},
	{kind: FaviconMD5, vendor: "hpe", product: "iLO", src: "favicons", re: regexp.MustCompile(`(?i)^(?:ad93b3973782b03ea62a43bd6602ba8b|d521487f45fa7657450edfd6c16e4a63)$`)},
	{kind: FaviconMD5, vendor: "dell", product: "iDRAC", src: "favicons", re: regexp.MustCompile(`(?i)^2c9d5e03f63c39e6336ec491019c4f50$`)},

	// ---- favicon MurmurHash3 (favicon.mmh3 == Shodan http.favicon.hash) ------
	// Product-specific MMH3 favicon hashes. Signed int32 decimal strings are
	// computed with FaviconHashString(icon). Generic icons shared across multiple
	// vendors are deliberately excluded.
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
	// Eaton Network-M2/M3 brand favicon (computed live from network-m2-3.1.15,
	// assets/images/favicon.ico; MD5 eb9eaff5868f47589f03230773594b34). The M2/M3
	// SPA ships an empty <title>, so this is the only sessionless vendor tell.
	{kind: FaviconMMH3, vendor: "eaton", product: "Network-M", src: "firmware", re: regexp.MustCompile(`^1897933497$`)},
	// DS/TS 5.0G4 firmware favicon (computed from a DS/TS 5.0G4 firmware image);
	// distinct from the shodan-observed hash above (different model/version).
	{kind: FaviconMMH3, vendor: "perle", product: "IOLAN", src: "firmware", re: regexp.MustCompile(`^783813256$`)},
	{kind: FaviconMMH3, vendor: "nanokvm", product: "NanoKVM", src: "shodan-favicons", re: regexp.MustCompile(`^1323732765$`)},
	{kind: FaviconMMH3, vendor: "jetkvm", product: "JetKVM", src: "shodan-favicons", re: regexp.MustCompile(`^-412815663$`)},
	{kind: FaviconMMH3, vendor: "pikvm", product: "PiKVM", src: "shodan-favicons", re: regexp.MustCompile(`^(?:-1040945478|-692926325)$`)},
	{kind: FaviconMMH3, vendor: "blikvm", product: "BliKVM", src: "shodan-favicons", re: regexp.MustCompile(`^918230991$`)},

	// ---- TLS Subject/Issuer CN-only (leaf CN without a keying DN) ----
	// These cover leaves with a bare CN and no O=/OU= fields for the DN rules above.
	{kind: TLSSubjectCN, vendor: "oracle", product: "ILOM", src: "x509_subjects", re: regexp.MustCompile(`(?i)^ORACLESP-`)},
	{kind: TLSSubjectCN, vendor: "cisco", product: "CIMC", src: "x509_subjects", re: regexp.MustCompile(`(?i)^[CBS]-series CIMC$`)},
	{kind: TLSSubjectCN, vendor: "perle", product: "IOLAN", src: "console_servers", re: regexp.MustCompile(`(?i)^Perle$`)},
	{kind: TLSSubjectCN, vendor: "servertech", product: "Sentry", src: "pdu_servers", re: regexp.MustCompile(`(?i)^Sentry Switched CDU$`)},
	{kind: TLSSubjectCN, vendor: "blikvm", product: "BliKVM", src: "ipkvm", re: regexp.MustCompile(`(?i)^blikvm\.com$`)},
	// Huawei iBMC leaf is issued by the Huawei device PKI ("Huawei IT Product CA").
	{kind: TLSIssuerCN, vendor: "huawei", product: "iBMC", src: "x509_issuers", re: regexp.MustCompile(`(?i)^Huawei IT Product CA$`)},

	// --- KB gap additions ---
	// HTTP Server header (http_servers).
	// Huawei iBMC: broad "iBMC/<ver>" token (covers builds where it is not
	// prefixed by the "UPnP/x.y " UPnP banner).
	{kind: HTTPServerHeader, vendor: "huawei", product: "iBMC", src: "http_servers", re: regexp.MustCompile(`(?i)\biBMC/[0-9.]+`)},
	// OpenBMC bmcweb (do not attribute NVIDIA by this header alone).
	{kind: HTTPServerHeader, vendor: "openbmc", product: "bmcweb", src: "http_servers", re: regexp.MustCompile(`(?i)^bmcweb`)},
	// Server Technology Sentry JAWS embedded web server.
	{kind: HTTPServerHeader, vendor: "servertech", product: "Sentry", src: "http_servers", re: regexp.MustCompile(`(?i)\bJAWS/1\.06\b`)},
	// Westermo WeOS Civetweb server.
	{kind: HTTPServerHeader, vendor: "westermo", product: "WeOS", src: "http_servers", weak: true, re: regexp.MustCompile(`(?i)^Civetweb\b`)},
	// Vertiv/Liebert IntelliSlot Unity: version-only Apache banner (also stock
	// Debian 12 httpd) -- weak, needs corroboration before it decides a class.
	{kind: HTTPServerHeader, vendor: "vertiv", product: "IntelliSlot Unity", src: "http_servers", weak: true, re: regexp.MustCompile(`(?i)^Apache/2\.4\.57\b`)},

	// HTML <title> (html_title).
	// Avocent (Vertiv) ACS8000/ACS800 advanced console servers.
	{kind: HTMLTitle, vendor: "avocent", product: "ACS8000", src: "html_title", re: regexp.MustCompile(`(?i)ACS8000|ACS800`)},

	// TLS Subject DN (x509_subjects).
	// ASUS ASMB (AMI MegaRAC): CN=AMI under the ASUS-provisioned service-processor DN.
	{kind: TLSSubjectDN, vendor: "asus", product: "ASMB", src: "x509_subjects", re: regexp.MustCompile(`(?i)O=American Megatrends Inc.*OU=Service Processors.*CN=AMI`)},
	// Cisco CIMC legacy Avocent lineage cert.
	{kind: TLSSubjectDN, vendor: "cisco", product: "CIMC legacy Avocent", src: "x509_subjects", re: regexp.MustCompile(`(?i)O=Cisco Systems Inc\.,\s*CN=cisco\.com`)},
	// Dell iDRAC8 default certificate.
	{kind: TLSSubjectDN, vendor: "dell", product: "iDRAC8", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=iDRAC8 default certificate`)},
	// CN=www.ami.com is the cross-OEM shared AMI default cert (asrock/gigabyte/
	// inspur/h3c/...), so attribute it to the platform vendor "ami", not one OEM,
	// and mark it weak so it never alone decides a class.
	{kind: TLSSubjectDN, vendor: "ami", product: "MegaRAC", src: "x509_subjects", weak: true, re: regexp.MustCompile(`(?i)CN=www\.ami\.com`)},
	// Standalone ATEN/Altusen KVM ships its own vendor cert (CN=ATEN INTERNATIONAL
	// CO.,LTD), distinct from the Supermicro ATEN-stack CN=IPMI cert.
	{kind: TLSSubjectCN, vendor: "aten", product: "KVM over IP", src: "x509_subjects", re: regexp.MustCompile(`(?i)^ATEN INTERNATIONAL`)},
	// H3C KVM discriminator (CN=H3C).
	{kind: TLSSubjectDN, vendor: "h3c", product: "H3C KVM", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=H3C\b`)},
	// Intel Integrated BMC service-processor cert.
	{kind: TLSSubjectDN, vendor: "intel", product: "Integrated BMC", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=Intel,\s*O=Intel Corporation,\s*OU=BMC Software Team`)},
	// Lantronix IONMM.
	{kind: TLSSubjectDN, vendor: "lantronix", product: "IONMM", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=lantronix\.com`)},
	// Lantronix NTC-552 (NetComm-branded).
	{kind: TLSSubjectDN, vendor: "lantronix", product: "NTC-552", src: "x509_subjects", re: regexp.MustCompile(`(?i)CN=DA Magpie Server 1,\s*O=NetComm`)},
	// Rittal CMC III monitoring/PDU.
	{kind: TLSSubjectDN, vendor: "rittal", product: "CMC III", src: "x509_subjects", re: regexp.MustCompile(`(?i)O=Rittal GmbH`)},
	// Note: no BliKVM TLS-subject rule here. BliKVM ships the OpenSSL placeholder
	// subject (O=Internet Widgits Pty Ltd), which is the default for countless
	// unrelated self-signed certs; a rule on it mislabeled honeypots/Citrix/Python
	// servers as blikvm. BliKVM must be keyed on the full cert SHA-256 /
	// SPKI in the tlscert shared-key matcher, not on this subject.

	// TLS Subject CN (x509_subjects).
	// Fujitsu legacy iRMC leaf CN begins with "iRMC".
	{kind: TLSSubjectCN, vendor: "fujitsu", product: "iRMC legacy", src: "x509_subjects", re: regexp.MustCompile(`(?i)^iRMC`)},
	// Raritan demo certificate (shipped demo leaf).
	{kind: TLSSubjectCN, vendor: "raritan", product: "PX", src: "x509_subjects", re: regexp.MustCompile(`(?i)^Demo Certificate$`)},

	// TLS Issuer CN (x509_issuers).
	// Raritan demo CA issuer.
	{kind: TLSIssuerCN, vendor: "raritan", product: "PX", src: "x509_issuers", re: regexp.MustCompile(`(?i)^Generic Demo CA$`)},

	// favicon MD5 (favicons).
	{kind: FaviconMD5, vendor: "pikvm", product: "PiKVM", src: "favicons", re: regexp.MustCompile(`(?i)^1a5210ea2fb7cfbabe62c619e8cfdc69$`)},

	// SSH banner (ssh_banners). Banner values here are the software identifier
	// with the "SSH-2.0-" prefix already stripped (see existing rows + tests).
	// Dropbear 2025.89 N-day (OpenBMC; Westermo shares this build).
	{kind: SSHBanner, vendor: "openbmc", product: "dropbear-2025.89", src: "ssh_banners", re: regexp.MustCompile(`(?i)^dropbear_2025\.89\b`)},
	// CyberPower RMCARD SSH banner.
	// The RMCARD SSH server identifies as "SSH-2.0-CPS_SSH_ID_<ver>"; "CPS-RMCARD"
	// is the default hostname/SYSTEM_NAME, not the banner (verified on rmcard-1.6.0).
	{kind: SSHBanner, vendor: "cyberpower", product: "RMCARD", src: "ssh_banners", re: regexp.MustCompile(`(?i)CPS_SSH_ID`)},
	// Server Technology Sentry SSH banner.
	{kind: SSHBanner, vendor: "servertech", product: "Sentry", src: "ssh_banners", re: regexp.MustCompile(`(?i)^ServerTech`)},
}

// Match tests a single observed value of the given Kind against the curated
// rule set and returns the first (most-specific) BMC vendor/product it matches.
// ok is false when the value is empty or unrecognized. Vendor is a short
// lowercase key (dell, hpe, supermicro, ami, ...) consistent with the rest of
// oobscan; product is a human-facing label (iDRAC, iLO, MegaRAC, ...).
func Match(kind Kind, value string) (vendor, product string, ok bool) {
	if r := matchRule(kind, value); r != nil {
		return r.vendor, r.product, true
	}
	return "", "", false
}

// matchRule returns the first rule matching (kind, value), or nil.
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

// MatchAll evaluates every supplied signal and returns the highest-confidence
// BMC identity. Signals are consulted in descending trust order: a certificate
// subject/issuer or a dedicated Server/banner header is a stronger vendor tell
// than an HTML title or a favicon hash (titles and icons are frequently
// rebranded by OEMs). The first signal that matches wins; product is only kept
// alongside the vendor it was matched with. ok is false when nothing matched.
func MatchAll(inputs map[Kind]string) (vendor, product string, ok bool) {
	vendor, product, _, ok = MatchAllWeighted(inputs)
	return vendor, product, ok
}

// MatchAllWeighted is MatchAll plus the matched rule's weakness. weak is true
// when the winning signal was a generic/shared tell (stock web-server version,
// default OEM cert, reused favicon); callers should fold a weak match at low
// confidence and not let it alone decide a device class (see rule.weak).
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
