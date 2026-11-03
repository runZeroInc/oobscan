// Copyright (c) 2026 runZero, Inc.
// SPDX-License-Identifier: BSD-2-Clause

// Package oob centralises the oobscan inventory of out-of-band management
// and serial-over-IP devices. Every OOB/BMC vendor referenced anywhere in
// oobscan must appear here so that scan coverage is auditable.
//
// Keep entries in lexical order by Vendor. When adding a new entry also add
// a probe or fingerprint in pkg/ (or explicitly mark Coverage=none with
// a reason) so the "completeness" smoke test stays green.
package oob

// Category groups devices by the kind of OOB access they offer.
type Category string

const (
	CatBMC       Category = "bmc"      // full server baseboard management
	CatIPKVM     Category = "ip-kvm"   // keyboard/video/mouse over IP
	CatPDU       Category = "pdu"      // power distribution w/ network mgmt
	CatSerial    Category = "serial"   // serial-over-IP / terminal server
	CatConsole   Category = "console"  // console server
	CatKVMOverIP Category = "kvm"      // rackmount KVM
	CatAMT       Category = "amt"      // Intel AMT / vPro
	CatFirmware  Category = "firmware" // UEFI / BIOS-side mgmt
	CatOther     Category = "other"
)

// Device is an OOB/BMC product entry.
type Device struct {
	Vendor      string // canonical vendor, lowercase slug, e.g. "dell"
	Product     string // product family, e.g. "iDRAC9", "iLO5", "ATEN IPMI"
	Category    Category
	IPMI        bool // speaks IPMI 2.0
	Redfish     bool // Redfish / REST
	WebUI       bool
	SSH         bool
	SNMP        bool
	SSDP        bool
	SLP         bool
	WSMAN       bool
	Telnet      bool     // legacy, but still seen
	Proprietary []string // other proto names (e.g. "vMedia", "Avocent DSView")
	// Fingerprints is a list of short strings oobscan looks for on the wire
	// (HTTP Server header, TLS cert CN, banner, SNMP sysDescr, etc.).
	Fingerprints []string
	// DefaultCreds are vendor-shipped defaults; empty when the vendor uses
	// per-unit printed factory passwords.
	DefaultCreds [][2]string
	// Notes capture implementation context.
	Notes string
}

// Registry is the canonical list. Edits here feed:
//   - cmd/coverage.go       -- `oobscan coverage` subcommand
//   - pkg/creds/*      -- seeded wordlist generation
//   - vendor table (auto-generated)
var Registry = []Device{
	// --- server BMCs (top of the pyramid) ---
	{Vendor: "dell", Product: "iDRAC6", Category: CatBMC, IPMI: true, WebUI: true, SSH: true, SNMP: true, WSMAN: true,
		Fingerprints: []string{"iDRAC6", "IDRAC-Express", "Dell Remote Access"},
		DefaultCreds: [][2]string{{"root", "calvin"}},
		Notes:        "Avocent-derived web stack; pre-RMCP+ on some firmwares."},
	{Vendor: "dell", Product: "iDRAC7", Category: CatBMC, IPMI: true, Redfish: false, WebUI: true, SSH: true, SNMP: true, WSMAN: true,
		Fingerprints: []string{"iDRAC7", "iDRAC-Enterprise"},
		DefaultCreds: [][2]string{{"root", "calvin"}},
		Notes:        "Redfish appears only in 2.60+ firmwares."},
	{Vendor: "dell", Product: "iDRAC8", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true, WSMAN: true,
		Fingerprints: []string{"iDRAC8", "Dell Inc."},
		DefaultCreds: [][2]string{{"root", "calvin"}}},
	{Vendor: "dell", Product: "iDRAC9", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true, WSMAN: true,
		Proprietary:  []string{"RACADM"},
		Fingerprints: []string{"iDRAC9", "/sysmgmt/2012/server"},
		DefaultCreds: [][2]string{{"root", "calvin"}}, // pre-2018 hardware
		Notes:        "Firmware 3.21+ ships per-unit default; service tag printed on bezel."},
	{Vendor: "dell", Product: "iDRAC10", Category: CatBMC, IPMI: false, Redfish: true, WebUI: true, SSH: true,
		Fingerprints: []string{"iDRAC10", "IDRAC.2.14.SWC1908", "HGX_BMC_0"},
		DefaultCreds: [][2]string{{"root", "calvin"}},
		Notes:        "Redfish-only; IPMI disabled by default. 17G Nuvoton NPCM845 OpenBMC; OS root:calvin hash byte-identical to iDRAC9 (FINDINGS_dell_idrac10.md). 17G forces default-password change (IDRAC.2.14.SWC1908) so calvin persists only until first login. NVIDIA HGX routes /redfish/v1/Managers/HGX_BMC_0."},

	{Vendor: "hpe", Product: "iLO2", Category: CatBMC, IPMI: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"HP-iLO-Server", "iLO 2"}, Notes: "EOL 2011; still found in the wild."},
	{Vendor: "hpe", Product: "iLO3", Category: CatBMC, IPMI: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"HP-iLO-Server", "iLO 3"}},
	{Vendor: "hpe", Product: "iLO4", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"HP-iLO-Server", "iLO 4", "HLIN"},
		Notes:        "CVE-2017-12542 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA auth bypass."},
	{Vendor: "hpe", Product: "iLO5", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true, SSDP: true,
		Fingerprints: []string{"HPE-iLO-Server", "iLO 5"},
		Notes:        "Per-unit factory password printed on pull-tab."},
	{Vendor: "hpe", Product: "iLO6", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true, SSDP: true,
		Fingerprints: []string{"HPE-iLO-Server", "iLO 6"}},

	{Vendor: "supermicro", Product: "ATEN IPMI", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true, SSDP: true, SLP: true,
		Proprietary:  []string{"iKVM", "jKVM"},
		Fingerprints: []string{"ATEN International", "Supermicro", "IPMI Firmware Revision"},
		DefaultCreds: [][2]string{{"ADMIN", "ADMIN"}, {"admin", "admin"}},
		Notes:        "Pre-2019 hardware ships ADMIN:ADMIN; post-2019 uses per-unit printed on motherboard."},
	{Vendor: "supermicro", Product: "X13 ASPEED BMC", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true, SLP: true,
		Fingerprints: []string{"Supermicro", "AST2600"}},

	{Vendor: "lenovo", Product: "IMM", Category: CatBMC, IPMI: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"IBM Integrated Management Module", "IMM2"},
		DefaultCreds: [][2]string{{"USERID", "PASSW0RD"}},
		Notes:        "ASCII zero in PASSW0RD."},
	{Vendor: "lenovo", Product: "XClarity Controller (XCC)", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true, SLP: true,
		Fingerprints: []string{"Lenovo XClarity Controller", "XCC"},
		DefaultCreds: [][2]string{{"USERID", "PASSW0RD"}}},

	{Vendor: "cisco", Product: "CIMC", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"Cisco IMC", "UCS-C"},
		DefaultCreds: [][2]string{{"admin", "password"}}},

	{Vendor: "fujitsu", Product: "iRMC S4", Category: CatBMC, IPMI: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"iRMC S4", "Fujitsu"}, DefaultCreds: [][2]string{{"admin", "admin"}}},
	{Vendor: "fujitsu", Product: "iRMC S5", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"iRMC S5", "Fujitsu"}, DefaultCreds: [][2]string{{"admin", "admin"}}},
	{Vendor: "fujitsu", Product: "iRMC S6", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"iRMC S6"}},

	{Vendor: "asrockrack", Product: "BMC (ASPEED+MegaRAC)", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"ASRockRack", "AMI MegaRAC"}, DefaultCreds: [][2]string{{"admin", "admin"}}},
	{Vendor: "asus", Product: "ASMB9-iKVM (MegaRAC SP-X)", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"ASMB9", "ASMB", "QSESSIONID", "R7A41134", "R7A94110", "ast2500evb.PRJ"},
		DefaultCreds: [][2]string{{"admin", "admin"}, {"sysadmin", "superuser"}},
		Notes:        "AMI MegaRAC SP-X on AST2500 (FINDINGS_asus.md); hardcoded sysadmin->priv 0xff special-case; ships default server.pem TLS key until reprovisioned (per-build, catalogued in tlscert); QSESSIONID cookie + X-CSRFTOKEN"},
	{Vendor: "gigabyte", Product: "MergePoint MegaRAC SP-X", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"GIGABYTE", "MegaRAC"}, DefaultCreds: [][2]string{{"admin", "password"}}},
	{Vendor: "ami", Product: "MegaRAC SPx", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"AMI MegaRAC", "Megarac"},
		DefaultCreds: [][2]string{{"admin", "admin"}, {"sysadmin", "superuser"}},
		Notes:        "Base code used by many OEMs; CVE-2024-54085 unauth Redfish bypass."},
	{Vendor: "insyde", Product: "Supervyse BMC", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"Supervyse", "Insyde"}},
	{Vendor: "aspeed", Product: "AST2400/2500/2600 eval", Category: CatBMC, IPMI: true, WebUI: true, SSH: true,
		Fingerprints: []string{"ASPEED"}},
	{Vendor: "nuvoton", Product: "NPCM7xx / NPCM8xx BMC", Category: CatBMC, IPMI: true, Redfish: true,
		Fingerprints: []string{"Nuvoton", "NPCM"}, Notes: "Used by Meta/Google OCP designs."},

	{Vendor: "openbmc", Product: "OpenBMC (phosphor)", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: false,
		Fingerprints: []string{"OpenBMC", "phosphor", "bmcweb"},
		DefaultCreds: [][2]string{{"root", "0penBmc"}},
		Notes:        "Upstream OSS BMC stack used by IBM/Meta/Google."},
	{Vendor: "nvidia", Product: "BlueField DPU BMC", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true,
		Fingerprints: []string{"Moonraker", "RoyB", "Bluefield", "DPU"},
		DefaultCreds: [][2]string{{"root", "0penBmc"}},
		Notes:        "BlueField-3 DPU BMC = OpenBMC BF-26.04; ships root:0penBmc live + fully privileged (SSH/Redfish/IPMI); first-boot expiry is a post-auth forced-change race, not a lockout; stock etc/key_file=OPENBMC= IPMI KEK"},

	{Vendor: "oracle", Product: "ILOM", Category: CatBMC, IPMI: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"Sun Integrated Lights Out", "Oracle ILOM"},
		DefaultCreds: [][2]string{{"root", "changeme"}, {"sysadmin", "superuser"}}},

	{Vendor: "inspur", Product: "M5/M6 BMC", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"Inspur"}, DefaultCreds: [][2]string{{"admin", "admin"}}},
	{Vendor: "huawei", Product: "iBMC", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"HUAWEI", "iBMC"}, DefaultCreds: [][2]string{{"root", "Huawei12#$"}}},
	{Vendor: "quanta", Product: "QCT BMC", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"Quanta"}, DefaultCreds: [][2]string{{"admin", "admin"}}},
	{Vendor: "tyan", Product: "TYAN BMC", Category: CatBMC, IPMI: true, Redfish: true, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"TYAN"}, DefaultCreds: [][2]string{{"sysadmin", "superuser"}},
		Notes: "MiTAC/AMI MegaRAC UID-0 factory default sysadmin:superuser ($6$ shadow byte-identical to ASRock Rack + Fujitsu)."},
	{Vendor: "hitachi", Product: "HA8000 BMC", Category: CatBMC, IPMI: true, WebUI: true, SSH: true,
		Fingerprints: []string{"Hitachi"}},
	{Vendor: "nec", Product: "EXPRESSSCOPE", Category: CatBMC, IPMI: true, WebUI: true, SSH: true,
		Fingerprints: []string{"EXPRESSSCOPE"}, DefaultCreds: [][2]string{{"administrator", "administrator"}}},

	// --- hyperscale ---
	{Vendor: "meta", Product: "OpenBMC (Yosemite)", Category: CatBMC, IPMI: true, Redfish: true,
		Fingerprints: []string{"Yosemite", "Tiogapass"}, Notes: "OCP platforms."},
	{Vendor: "google", Product: "Hoth / OpenBMC", Category: CatBMC, IPMI: false, Redfish: true,
		Fingerprints: []string{"Hoth", "gBMC"}},

	// --- IP-KVM / console servers / serial-over-IP ---
	{Vendor: "avocent", Product: "DSR / ACS console server", Category: CatConsole, SSH: true, Telnet: true, WebUI: true, SNMP: true,
		Fingerprints: []string{"Avocent", "ACS-"},
		DefaultCreds: [][2]string{{"admin", "avocent"}, {"root", "linux"}}},
	{Vendor: "raritan", Product: "Dominion KX/KSX/SX", Category: CatIPKVM, SSH: true, Telnet: true, WebUI: true, SNMP: true,
		Fingerprints: []string{"Raritan", "Dominion"},
		DefaultCreds: [][2]string{{"admin", "raritan"}}},
	// Product must be "PX" to exact-match the token bmcfp emits for PX PDUs
	// (Server/title/demo-cert rules all yield product "PX"); as "PX PDU" it never
	// matched, so classForVendorProduct fell through to the Dominion KX entry above
	// and mis-classed PX3 PDUs as kvm. (The shared PX/KX favicon still yields the
	// genuinely-ambiguous "PX / KX".)
	{Vendor: "raritan", Product: "PX", Category: CatPDU, SSH: true, Telnet: true, WebUI: true, SNMP: true,
		Fingerprints: []string{"Raritan PX"}, DefaultCreds: [][2]string{{"admin", "raritan"}}},
	{Vendor: "vertiv", Product: "Geist / Liebert PDU", Category: CatPDU, SSH: true, WebUI: true, SNMP: true,
		Fingerprints: []string{"Geist", "Liebert", "Vertiv"}},
	{Vendor: "apc", Product: "AP79xx / AP89xx Rack PDU", Category: CatPDU, SSH: true, Telnet: true, WebUI: true, SNMP: true,
		Fingerprints: []string{"APC Web/SNMP Management Card", "Schneider Electric"},
		DefaultCreds: [][2]string{{"apc", "apc"}, {"device", "apc"}},
		Notes:        "NMC1/NMC2 (AP963x); legacy AOS on x86, Allegro RomPager web + Treck TCP/IP."},
	{Vendor: "apc", Product: "NMC3 (AP964x Network Management Card 3)", Category: CatPDU, SSH: true, Telnet: true, WebUI: true, SNMP: true,
		Proprietary:  []string{"PowerChute Network Shutdown (PCNS)", "BACnet/IP", "FTP"},
		Fingerprints: []string{"APC", "Schneider Electric", "Network Management Card", "SSH-2.0-cryptlib", "AP9640", "AP9641", "AP9643", "RomPager"},
		DefaultCreds: [][2]string{{"apc", "apc"}, {"device", "apc"}},
		Notes:        "Renesas RZ/N1 (ARM) / Micrium uC-OS / Treck TCP/IP / Allegro RomPager 4 / cryptlib. One AOS core across Smart-UPS, Rack PDU (RPDU2G), NetBotz 250 (hw21). Hardcoded jmm627 demo/service password gated by uploadable testdrive522.ini; SNMPv3 defaults 'APC ASI User'/'APC ASI auth phrase'/'APC ASI crypt phrase'; default firewall = allow-all. Firmware-static (not lab-validated)."},
	{Vendor: "apc", Product: "NetBotz", Category: CatOther, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"NetBotz"},
		Notes:        "NetBotz 250 (NBRK0250) is an NMC3 (hw21) variant; see the NMC3 entry."},
	{Vendor: "eaton", Product: "ePDU G3", Category: CatPDU, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"Eaton", "ePDU"}, DefaultCreds: [][2]string{{"admin", "admin"}}},
	{Vendor: "eaton", Product: "Network-M2/M3 card", Category: CatPDU, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"Network-M2", "Network-M3", "Eaton Gigabit Network Card"},
		DefaultCreds: [][2]string{{"admin", "admin"}}, Notes: "UPS/PDU network card; firmware on eaton.com"},
	{Vendor: "cyberpower", Product: "RMCARD", Category: CatPDU, WebUI: true, SSH: true, Telnet: true, SNMP: true,
		Fingerprints: []string{"CyberPower", "RMCARD"},
		DefaultCreds: [][2]string{{"cyber", "cyber"}}, Notes: "RMCARD205/305 remote mgmt card; firmware on cyberpower.com"},
	{Vendor: "cyberpower", Product: "PowerPanel Enterprise", Category: CatPDU, WebUI: true,
		Fingerprints: []string{"PDNU", "PowerPanel Enterprise"},
		Notes:        "DCIM/UPS-management web app (default HTTPS 53568). CVE-2024-32735 unauth PDNU REST API leaks device account/passwd; CVE-2024-32736/37/38/39 unauth SQLi. Actively confirmed by cyberpower.ppe."},
	{Vendor: "gude", Product: "Expert Net Control / Expert Power Control", Category: CatPDU, WebUI: true, SNMP: true,
		Fingerprints: []string{"Expert Net Control", "Expert Power Control", "GUDE"},
		DefaultCreds: [][2]string{{"admin", "admin"}},
		Notes:        "networked PDU / power-control; admin:admin default (actively confirmed by gude.default_creds)"},
	{Vendor: "schneiderpm", Product: "EcoStruxure Link150", Category: CatPDU, WebUI: true, SNMP: true,
		Fingerprints: []string{"Link150", "EcoStruxure Link"},
		DefaultCreds: [][2]string{{"Administrator", "Gateway"}},
		Notes:        "Schneider energy gateway (distinct from APC NMC); detection + default-cred posture only"},
	{Vendor: "schneiderpm", Product: "PowerLogic PM8000", Category: CatPDU, WebUI: true, SNMP: true,
		Fingerprints: []string{"PowerLogic"},
		DefaultCreds: [][2]string{{"User1", "0"}},
		Notes:        "Schneider power-quality meter; detection + default-cred posture only"},
	{Vendor: "eaton", Product: "Intelligent Power Manager (IPM)", Category: CatOther, WebUI: true,
		Fingerprints: []string{"Intelligent Power Manager", "Intelligent Power Protector"},
		Notes:        "UPS/PDU-management web app (default 4679/4680). CVE-2018-12031 unauth directory traversal; actively confirmed by eaton.ipm_lfi."},
	{Vendor: "tripplite", Product: "PDUMNV / SRCOOLNET", Category: CatPDU, WebUI: true, SNMP: true,
		Fingerprints: []string{"Tripp Lite"}, DefaultCreds: [][2]string{{"admin", "admin"}}},
	{Vendor: "servertech", Product: "Sentry Switched CDU", Category: CatPDU, SSH: true, Telnet: true, WebUI: true, SNMP: true,
		Fingerprints: []string{"Sentry Switched CDU", "Server Technology", "ServerTech/PRO", "SSH-2.0-ServerTech_SSH", "JAWS"},
		DefaultCreds: [][2]string{{"admn", "admn"}, {"admn", ""}},
		Notes:        "firmware ships admn with a blank / force-set-on-first-login password; SNMPv3 default passphrase 'initial1'/'initial2', communities public/private; privilege taken from RADIUS VSA STI-Access-Level (PEN 1718)"},

	{Vendor: "lantronix", Product: "SLC console manager", Category: CatConsole, SSH: true, Telnet: true, WebUI: true, SNMP: true,
		Fingerprints: []string{"Lantronix", "SLC"},
		DefaultCreds: [][2]string{{"sysadmin", "PASS"}}},
	{Vendor: "lantronix", Product: "SLB/EMG branch office manager", Category: CatConsole, SSH: true, Telnet: true,
		Fingerprints: []string{"Lantronix SLB", "Lantronix EMG"}},
	{Vendor: "lantronix", Product: "UDS / XPort serial server", Category: CatSerial, Telnet: true, WebUI: true,
		Proprietary:  []string{"udp/30718 Setup", "tcp/9999 Setup"},
		Fingerprints: []string{"Lantronix", "xDirect"},
		Notes:        "UDP/30718 broadcast discovery; Setup protocol unauth."},
	{Vendor: "lantronix", Product: "SecureLinx Spider", Category: CatIPKVM, SSH: true, WebUI: true,
		Fingerprints: []string{"Spider", "SecureLinx"},
		DefaultCreds: [][2]string{{"sysadmin", "PASS"}, {"root", "spider24"}},
		Notes:        "Spider 4.x = LARA (shared root:spider24 + shared TLS/Dropbear keys, strong session model); Spider 5.x = rebadged PiKVM kvmd 3.95 with uid-0 sysadmin:PASS + authenticated->root RCE (config layer -> root sruncmd_server:9050) + unsigned-FW-update->root"},
	{Vendor: "lantronix", Product: "SGX5150 / PremierWave / EDS device server", Category: CatSerial, SSH: true, WebUI: true, SNMP: true,
		Proprietary:  []string{"udp/30718 Setup"},
		Fingerprints: []string{"SGX5150", "PremierWave", "Evolution OS"},
		DefaultCreds: [][2]string{{"admin", "PASS"}, {"admin", "admin"}},
		Notes:        "NUEVO Evolution/PremierWave Linux; default admin pw derived from serial (leaked via UDP/30718); fleet-wide lantronix.key TLS"},
	{Vendor: "lantronix", Product: "E22X/G520/X300 cellular gateway", Category: CatSerial, SSH: true, WebUI: true, SNMP: true,
		Fingerprints: []string{"percepxion", "E220", "G520"},
		DefaultCreds: [][2]string{{"admin", "admin"}},
		Notes:        "OpenWrt; byte-identical admin:admin (gid 0) + shared root hash across E22X/G520/X300; G520/X300 post-auth stty root RCE chains with the default"},
	{Vendor: "lantronix", Product: "TNI IONMM media converter", Category: CatOther, SSH: true, WebUI: true, SNMP: true,
		Fingerprints: []string{"IONMM", "Transition Networks"},
		DefaultCreds: [][2]string{{"ION", ""}},
		Notes:        "PRE-AUTH ROOT RCE: /cgi?login=exit base64 SID cookie -> system() (lantronix.ionmm_rce); shipped SSH host + lighttpd TLS keys; SNMP RW private (FINDINGS_lantronix.md)"},

	{Vendor: "opengear", Product: "ACM/IM/CM console server", Category: CatConsole, SSH: true, WebUI: true, SNMP: true,
		Fingerprints: []string{"Opengear", "ACM7000", "IM7200"},
		DefaultCreds: [][2]string{{"root", "default"}}},
	{Vendor: "digi", Product: "PortServer TS / Connect ES", Category: CatSerial, SSH: true, Telnet: true, WebUI: true, SNMP: true,
		Fingerprints: []string{"Digi International", "PortServer", "Connect ES"},
		DefaultCreds: [][2]string{{"root", "dbps"}}},
	{Vendor: "moxa", Product: "NPort 5000/6000 serial server", Category: CatSerial, Telnet: true, WebUI: true, SNMP: true,
		Proprietary:  []string{"4800/udp Moxa Utility Search"},
		Fingerprints: []string{"Moxa", "NPort"},
		DefaultCreds: [][2]string{{"admin", "moxa"}}},
	{Vendor: "moxa", Product: "EDS industrial switch", Category: CatOther, Telnet: true, WebUI: true, SNMP: true,
		Fingerprints: []string{"Moxa EDS"}},
	{Vendor: "perle", Product: "IOLAN SCS console", Category: CatConsole, SSH: true, Telnet: true, WebUI: true, SNMP: true,
		Fingerprints: []string{"IOLAN"}, DefaultCreds: [][2]string{{"admin", "superuser"}}},
	{Vendor: "zpe", Product: "Nodegrid Serial Console", Category: CatConsole, SSH: true, WebUI: true, SNMP: true,
		Fingerprints: []string{"Nodegrid", "ZPE Systems"},
		Notes:        "Linux net services router / console; firmware portal-gated"},
	{Vendor: "advantech", Product: "EKI serial device server", Category: CatSerial, SSH: true, Telnet: true, WebUI: true, SNMP: true,
		Proprietary:  []string{"udp/tcp 5058 EDG config"},
		Fingerprints: []string{"Advantech", "EKI", "ADAM"},
		DefaultCreds: [][2]string{{"admin", ""}},
		Notes:        "EKI-152x/13xx serial device servers; Advantech-documented web/CLI default admin with a blank password. The two SSH daemons reject blank, so the blank default is web/Telnet-reachable only; creds.Table also carries admin/advantech + admin/Admin@9000 for the SSH/IPMI spray. RW SNMP community 'private' shipped; OS root blank is serial-console-only."},
	{Vendor: "redlion", Product: "Sixnet SixTRAK / VersaTRAK industrial gateway", Category: CatSerial, Telnet: true, WebUI: true, SNMP: true,
		Fingerprints: []string{"Red Lion", "Sixnet", "SixTRAK", "VersaTRAK", "R-TRAK"},
		DefaultCreds: [][2]string{{"root", ""}, {"guest", ""}},
		Notes:        "Industrial gateway/RTU (Sixnet lineage); shipped blank-password root/guest reachable over telnet/FTP (pam_unix nullok), an ftp UID-0 account, and PPPLink/PPPLink dial-in. RW SNMP community 'MYCOMMUNITY' + SNMPv3 guest noauth. No default SSH login surface, so this is posture-only."},
	{Vendor: "blackbox", Product: "Emerald KVM over IP", Category: CatIPKVM, WebUI: true, SSH: true,
		Fingerprints: []string{"Emerald KVM", "Black Box"}},
	{Vendor: "adder", Product: "AdderLink ipeps", Category: CatIPKVM, WebUI: true, SSH: true,
		Fingerprints: []string{"AdderLink", "ipeps"}},
	{Vendor: "aten", Product: "ATEN / Altusen KVM over IP", Category: CatIPKVM, WebUI: true,
		Fingerprints: []string{"ATEN", "Altusen", "CN8000", "KN2", "CS17"}},
	{Vendor: "atento", Product: "Avocent MergePoint Unity", Category: CatIPKVM, WebUI: true, SSH: true,
		Fingerprints: []string{"MergePoint Unity"}},

	// --- embedded management controllers ---
	{Vendor: "intel", Product: "AMT / vPro", Category: CatAMT, WebUI: true, WSMAN: true, Redfish: false,
		Proprietary:  []string{"Intel MEI", "SOL over AMT"},
		Fingerprints: []string{"Intel(R) Active Management Technology", "Intel(R) AMT"},
		DefaultCreds: [][2]string{{"admin", "admin"}},
		Notes:        "CVE-2017-5689 auth bypass still detectable; port 16992/16993."},
	{Vendor: "intel", Product: "RMM4 / BMC module", Category: CatBMC, IPMI: true, WebUI: true, SSH: true,
		Fingerprints: []string{"Intel RMM4"}},

	{Vendor: "asmedia", Product: "BMC daughterboard", Category: CatBMC, IPMI: true,
		Fingerprints: []string{"ASMedia"}},

	// --- storage / blade chassis ---
	{Vendor: "hpe", Product: "OneView / SIM", Category: CatOther, WebUI: true, SSH: true,
		Fingerprints: []string{"HPE OneView"}},
	{Vendor: "hpe", Product: "Onboard Administrator (c7000)", Category: CatBMC, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"Onboard Administrator"},
		DefaultCreds: [][2]string{{"Administrator", ""}}},
	{Vendor: "dell", Product: "CMC (M1000e/VRTX/FX2)", Category: CatBMC, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"Chassis Management Controller", "CMC"},
		DefaultCreds: [][2]string{{"root", "calvin"}}},
	{Vendor: "ibm", Product: "BladeCenter AMM", Category: CatBMC, WebUI: true, SSH: true, Telnet: true, SNMP: true,
		Fingerprints: []string{"Advanced Management Module", "AMM"},
		DefaultCreds: [][2]string{{"USERID", "PASSW0RD"}}},
	{Vendor: "lenovo", Product: "Flex System CMM", Category: CatBMC, WebUI: true, SSH: true, SNMP: true,
		Fingerprints: []string{"Flex System CMM"},
		DefaultCreds: [][2]string{{"USERID", "PASSW0RD"}}},

	// --- network gear with OOB ---
	{Vendor: "cisco", Product: "IMC Supervisor / UCS Manager", Category: CatBMC, WebUI: true, SSH: true,
		Fingerprints: []string{"UCS Manager", "IMC Supervisor"}},

	// --- infrastructure / misc ---
	{Vendor: "tplink", Product: "Jetstream OOB", Category: CatOther, WebUI: true, SSH: true, Telnet: true,
		Fingerprints: []string{"JetStream"}},
	{Vendor: "mikrotik", Product: "RouterOS (as OOB jump)", Category: CatOther, SSH: true, WebUI: true,
		Fingerprints: []string{"RouterOS", "MikroTik"}},
	{Vendor: "sierra", Product: "AirLink ALEOS cellular gateway", Category: CatOther, SSH: true, WebUI: true, SNMP: true,
		Fingerprints: []string{"Sierra Wireless", "AirLink", "ALEOS", "ACEmanager"},
		DefaultCreds: [][2]string{{"user", "12345"}},
		Notes:        "ACEmanager documented default user:12345 ($6$ shadow byte-identical RV50/RV55); actively sprayed over SSH by ssh.exposure via creds.Table. Identified by the fleet TLS cert O=Sierra Wireless + /xml/GetPublic.xml."},
	{Vendor: "westermo", Product: "WeOS industrial switch/router", Category: CatOther, SSH: true, WebUI: true,
		Fingerprints: []string{"Westermo", "WeOS", "Lynx", "Civetweb"},
		DefaultCreds: [][2]string{{"admin", "westermo"}},
		Notes:        "WeOS factory default admin:westermo (UID 0, /bin/clish; md5crypt, fleet-wide in factory.cfg, no forced change); actively sprayed over SSH by ssh.exposure via creds.Table. Recovery accounts (password/factory) are serial-console-only."},

	// --- KVM-over-IP appliances frequently mistaken for BMCs ---
	{Vendor: "pikvm", Product: "PiKVM v4", Category: CatIPKVM, WebUI: true, SSH: true,
		Fingerprints: []string{"PiKVM"}, DefaultCreds: [][2]string{{"admin", "admin"}, {"root", "root"}},
		Notes: "Eclypsium 2026 cohort baseline; no assigned CVE, default-cred posture only"},
	{Vendor: "tinypilot", Product: "TinyPilot", Category: CatIPKVM, WebUI: true, SSH: true,
		Fingerprints: []string{"TinyPilot"},
		Notes:        "community edition ships with NO web authentication by default (~26% of exposed units open)"},
	{Vendor: "nanokvm", Product: "Sipeed NanoKVM", Category: CatIPKVM, WebUI: true, SSH: true,
		Fingerprints: []string{"NanoKVM"}, DefaultCreds: [][2]string{{"admin", "admin"}, {"root", "root"}},
		Notes: "CVE-2026-32296 unauth /api/network/wifi; SSH root/root unenforced; shared AES key; 30-day tokens"},
	{Vendor: "jetkvm", Product: "JetKVM", Category: CatIPKVM, WebUI: true, SSH: true,
		Fingerprints: []string{"JetKVM"},
		Notes:        "CVE-2026-32294 unsigned firmware / CVE-2026-32295 no login rate-limit (fixed 0.5.4); /device/status noPassword mode"},
	{Vendor: "glinet", Product: "Comet GL-RM1", Category: CatIPKVM, WebUI: true, SSH: true,
		Fingerprints: []string{"GL.iNet", "GL-RM1", "Comet"},
		Notes:        "PiKVM fork; CVE-2026-32290/32291/32292/32293 (fixed 1.8.2)"},
	{Vendor: "blikvm", Product: "BliKVM (v1-v4)", Category: CatIPKVM, WebUI: true, SSH: true,
		Fingerprints: []string{"BliKVM", "Internet Widgits Pty Ltd", "/api/2fa/", "/api/account/create"},
		DefaultCreds: [][2]string{{"admin", "admin"}},
		Notes:        "PiKVM/kvmd fork; ships a shared TLS cert+key baked into the .deb (SHA256 CA:97:26:7D..., byte-identical v1-v4) = fleet-wide impersonation / non-forward-secret TLS decryption; server_app runs as root; distinguished from upstream kvmd by /api/2fa/* + /api/account/create routes"},
	{Vendor: "angeet", Product: "Angeet/Yeeso ES3", Category: CatIPKVM, WebUI: true,
		Fingerprints: []string{"ES3"},
		Notes:        "CVE-2026-32297 unauth /upload arbitrary file write (9.8, NO FIX) + CVE-2026-32298 os.execute cmd-inj"},

	// --- firmware-side surfaces that often expose BMC too ---
	{Vendor: "insyde", Product: "H2O UEFI", Category: CatFirmware,
		Fingerprints: []string{"Insyde H2O"}},
	{Vendor: "ami", Product: "Aptio V UEFI", Category: CatFirmware,
		Fingerprints: []string{"Aptio", "AMI UEFI"}},
	{Vendor: "phoenix", Product: "SecureCore UEFI", Category: CatFirmware,
		Fingerprints: []string{"Phoenix SecureCore"}},
}

// ByVendor groups the registry.
func ByVendor() map[string][]Device {
	m := map[string][]Device{}
	for _, d := range Registry {
		m[d.Vendor] = append(m[d.Vendor], d)
	}
	return m
}

// Vendors returns a sorted-by-insertion list of unique vendor slugs.
func Vendors() []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range Registry {
		if !seen[d.Vendor] {
			seen[d.Vendor] = true
			out = append(out, d.Vendor)
		}
	}
	return out
}
