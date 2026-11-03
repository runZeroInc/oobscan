package creds

// Table is the canonical default-credential knowledge base. It is the single
// source of truth: the vendor-specific spray order (CredsFor) and the derived
// VendorPairs compatibility slice are both built from it. To teach the scanner
// a new vendor default, add one row here.
//
// Rows are ordered vendor-by-vendor, highest-signal first. Class scopes a row
// to a login surface; most account-level BMC defaults work on both the IPMI and
// the web surface, so they use ClassAny.
var Table = []Credential{
	// Supermicro / ATEN
	{Vendor: "supermicro", Class: ClassAny, Username: "ADMIN", Password: "ADMIN", Source: "vendor-doc", Notes: "ATEN BMCs pre-2020"},
	{Vendor: "supermicro", Class: ClassAny, Username: "ADMIN", Password: "", Source: "vendor-doc", Notes: "older BIOS recovery mode"},
	{Vendor: "supermicro", Class: ClassIPMI, Username: "ADMIN", Password: "4rfv$RFV", Source: "firmware-image", Notes: "some ATEN IPMI builds"},

	// Dell iDRAC
	{Vendor: "dell", Class: ClassAny, Username: "root", Password: "calvin", Source: "vendor-doc", Notes: "iDRAC6/7/8/9 factory default"},
	{Vendor: "dell", Class: ClassAny, Username: "root", Password: "", Source: "vendor-doc", Notes: "some iDRAC7 OEM"},
	{Vendor: "dell", Class: ClassAny, Username: "user1", Password: "user1234", Source: "firmware-image", Notes: "iDRAC firmware-seeded secondary account (cracked from image)"},
	{Vendor: "dell", Class: ClassAny, Username: "root", Password: "computer1", Source: "seclists", Notes: "observed iDRAC default"},
	{Vendor: "dell", Class: ClassAny, Username: "root", Password: "DefaultFactoryPassword", Source: "vendor-doc", Notes: "iDRAC secure-default mode; unit-unique in newer FW"},

	// HPE iLO uses per-unit factory passwords; these are low-yield guesses.
	{Vendor: "hpe", Class: ClassAny, Username: "Administrator", Password: "Administrator", Source: "seclists", Notes: "ancient iLO2 (pre-FW 2.05) only; NOT a modern default"},
	{Vendor: "hpe", Class: ClassAny, Username: "admin", Password: "admin", Source: "seclists", Notes: "iLO4 very old"},

	// IBM / Lenovo IMM/XCC
	{Vendor: "ibm", Class: ClassAny, Username: "USERID", Password: "PASSW0RD", Source: "vendor-doc", Notes: "IMM/IMM2 (zero, not O)"},
	{Vendor: "lenovo", Class: ClassAny, Username: "USERID", Password: "PASSW0RD", Source: "vendor-doc", Notes: "inherited from IBM IMM"},
	{Vendor: "lenovo", Class: ClassAny, Username: "USERID", Password: "Passw0rd", Source: "vendor-doc", Notes: "XCC newer default"},
	{Vendor: "lenovo", Class: ClassAny, Username: "ADMIN", Password: "ADMIN", Source: "seclists", Notes: "XCC some variants"},

	// Fujitsu iRMC
	{Vendor: "fujitsu", Class: ClassAny, Username: "admin", Password: "admin", Source: "vendor-doc", Notes: "iRMC S4"},
	{Vendor: "fujitsu", Class: ClassAny, Username: "sysadmin", Password: "superuser", Source: "firmware-image", Notes: "iRMC built on the shared AMI MegaRAC image"},
	{Vendor: "fujitsu", Class: ClassAny, Username: "anonymous", Password: "superuser", Source: "firmware-image", Notes: "legacy hidden iRMC account (S4 09.21F lineage)"},

	// AMI MegaRAC (cross-OEM monoculture)
	{Vendor: "ami", Class: ClassAny, Username: "root", Password: "superuser", Source: "firmware-image", Notes: "MegaRAC SP-X"},
	{Vendor: "ami", Class: ClassAny, Username: "sysadmin", Password: "superuser", Source: "firmware-image", Notes: "MegaRAC SP-X UID-0; /etc/shadow byte-identical across ASRock+TYAN+Fujitsu (one AMI image) - the cross-OEM monoculture"},
	{Vendor: "ami", Class: ClassAny, Username: "admin", Password: "admin", Source: "seclists", Notes: "MegaRAC generic"},

	// ASRock Rack (MegaRAC-derived)
	{Vendor: "asrockrack", Class: ClassAny, Username: "admin", Password: "admin", Source: "vendor-doc", Notes: "X470 / X570 BMCs"},
	{Vendor: "asrockrack", Class: ClassAny, Username: "sysadmin", Password: "superuser", Source: "firmware-image", Notes: "MegaRAC UID-0 default (firmware-confirmed)"},

	// Tyan / MiTAC (shared AMI image)
	{Vendor: "tyan", Class: ClassAny, Username: "sysadmin", Password: "superuser", Source: "firmware-image", Notes: "MiTAC MegaRAC UID-0 (shared AMI image)"},

	// Gigabyte (MegaRAC-derived; classified AMI-family by the Redfish/mTLS checks)
	{Vendor: "gigabyte", Class: ClassAny, Username: "admin", Password: "admin", Source: "vendor-doc", Notes: "Gigabyte MegaRAC BMC default"},
	{Vendor: "gigabyte", Class: ClassAny, Username: "sysadmin", Password: "superuser", Source: "firmware-image", Notes: "shared AMI MegaRAC UID-0"},

	// Other server OEMs
	{Vendor: "quanta", Class: ClassAny, Username: "admin", Password: "admin", Source: "seclists", Notes: "QSSC / D51"},
	{Vendor: "quanta", Class: ClassAny, Username: "support", Password: "superuser", Source: "seclists", Notes: "QCT support account"},
	{Vendor: "quanta", Class: ClassAny, Username: "admin", Password: "adminadmin", Source: "seclists", Notes: "QCT default"},
	{Vendor: "intel", Class: ClassAny, Username: "admin", Password: "admin", Source: "vendor-doc", Notes: "Intel IMC / server boards"},
	{Vendor: "nec", Class: ClassAny, Username: "administrator", Password: "administrator", Source: "vendor-doc", Notes: "NEC EXPRESSSCOPE"},
	{Vendor: "huawei", Class: ClassAny, Username: "root", Password: "Huawei12#$", Source: "vendor-doc", Notes: "iBMC legacy default"},
	{Vendor: "huawei", Class: ClassAny, Username: "Administrator", Password: "Admin@9000", Source: "vendor-doc", Notes: "iBMC V5/openUBMC documented default"},
	{Vendor: "huawei", Class: ClassAny, Username: "root", Password: "Admin@9000", Source: "firmware-image", Notes: "openUBMC shipped shadow default"},
	{Vendor: "xfusion", Class: ClassAny, Username: "Administrator", Password: "Admin@9000", Source: "vendor-lineage", Notes: "FusionServer iBMC forked from Huawei (PEN 58132); carries the Huawei V5/openUBMC documented default"},
	{Vendor: "xfusion", Class: ClassAny, Username: "root", Password: "Huawei12#$", Source: "vendor-lineage", Notes: "Huawei iBMC legacy default carried into early xFusion FusionServer"},
	{Vendor: "inspur", Class: ClassAny, Username: "admin", Password: "admin", Source: "seclists", Notes: "BMC"},
	{Vendor: "inspur", Class: ClassAny, Username: "sysadmin", Password: "superuser", Source: "firmware-image", Notes: "NF5280M5 SP-X OS/SSH account (uid 0, /etc/shadow cracked); not covered by the web force-change gate = CVE-2022-40242"},
	{Vendor: "h3c", Class: ClassAny, Username: "admin", Password: "Password@_", Source: "firmware-image", Notes: "R4900 G5 HDM documented default (libhdm_user.so); web/Redfish/IPMI, restored on factory reset"},
	{Vendor: "h3c", Class: ClassAny, Username: "sysadmin", Password: "superuser", Source: "firmware-image", Notes: "HDM OS UID-0 account; /conf/shadow (Family-A $1$) and /etc/shadow (HDM2/HDM3 $6$RsGwpA22$) both crack to superuser -> same across all H3C generations; SSH reachability gated on runtime pam.d/sshd binding pam_unix"},
	{Vendor: "cisco", Class: ClassAny, Username: "admin", Password: "password", Source: "vendor-doc", Notes: "CIMC default"},
	{Vendor: "oracle", Class: ClassAny, Username: "root", Password: "changeme", Source: "vendor-doc", Notes: "Oracle ILOM"},
	{Vendor: "advantech", Class: ClassAny, Username: "admin", Password: "advantech", Source: "vendor-doc", Notes: "Advantech BMC"},
	{Vendor: "advantech", Class: ClassAny, Username: "admin", Password: "Admin@9000", Source: "vendor-doc", Notes: "Advantech BMC newer"},
	{Vendor: "avid", Class: ClassAny, Username: "avid", Password: "Avid123", Source: "vendor-doc", Notes: "Avid appliance BMC"},
	{Vendor: "avid", Class: ClassAny, Username: "avid", Password: "Avid123!", Source: "vendor-doc", Notes: "Avid appliance BMC"},

	// OpenBMC (phosphor reference)
	{Vendor: "openbmc", Class: ClassAny, Username: "root", Password: "0penBmc", Source: "vendor-doc", Notes: "phosphor reference default"},
	{Vendor: "openbmc", Class: ClassAny, Username: "root", Password: "root", Source: "firmware-image", Notes: "some meta layers"},

	// NVIDIA BlueField DPU BMC ships root:0penBmc with privileged BMC access;
	// first-boot expiry is a post-auth forced-change flow, not a lockout.
	{Vendor: "nvidia", Class: ClassAny, Username: "root", Password: "0penBmc", Source: "firmware-image", Notes: "BlueField-3 DPU BMC shipped /etc/shadow cracks to 0penBmc; live over SSH/Redfish/IPMI"},
	{Vendor: "nvidia", Class: ClassAny, Username: "root", Password: "Nvidia_12345!", Source: "firmware-image", Notes: "BlueField installer transitional password (install.env/bmc)"},

	// Lantronix console managers / KVM / device servers.
	{Vendor: "lantronix", Class: ClassAny, Username: "sysadmin", Password: "PASS", Source: "firmware-image", Notes: "SLC8000/SLB882 factory default (DES/SHA cracks to PASS); web + SSH/CLI, uid 0"},
	{Vendor: "lantronix", Class: ClassAny, Username: "root", Password: "spider24", Source: "firmware-image", Notes: "Spider KVM 4.x shared root pw (DES-crypt in /etc/passwd), SSH-reachable"},
	{Vendor: "lantronix", Class: ClassAny, Username: "admin", Password: "admin", Source: "firmware-image", Notes: "cellular E22X/G520/X300 shared /etc/shadow (crypt-verified), admin in gid 0; also EDS5000"},
	{Vendor: "lantronix", Class: ClassAny, Username: "admin", Password: "PASS", Source: "firmware-image", Notes: "XPort-Pro-Lx6 default mgmt (/defaults/default.config), admin uid 0"},
	{Vendor: "lantronix", Class: ClassAny, Username: "root", Password: "root", Source: "firmware-image", Notes: "XPort-Pro-Lx6 /etc/shadow root:root (MD5 cracked); telnetd/ftpd as root"},
	{Vendor: "lantronix", Class: ClassAny, Username: "user", Password: "user", Source: "firmware-image", Notes: "Power Xpert Gateway (cross-branded) secondary account"},

	// Eaton UPS/PDU network cards.
	{Vendor: "eaton", Class: ClassAny, Username: "admin", Password: "admin", Source: "firmware-image", Notes: "Network-M2/M3 shipped default (pre-expired one-time change on modern); Power Xpert Gateway admin:admin live (HTTP+SSH, /bin/sh)"},
	{Vendor: "eaton", Class: ClassAny, Username: "user", Password: "user", Source: "firmware-image", Notes: "Power Xpert Gateway secondary default (MD5 cracked)"},

	// Gude Expert Net Control / Expert Power Control networked PDUs.
	{Vendor: "gude", Class: ClassAny, Username: "admin", Password: "admin", Source: "vendor-doc", Notes: "Expert Net Control 2301/2302 shipped default (actively confirmed by gude.defaultCreds)"},

	// Schneider Electric energy gateways / power meters (not the APC NMC PDU line).
	{Vendor: "schneiderpm", Class: ClassAny, Username: "Administrator", Password: "Gateway", Source: "vendor-doc", Notes: "EcoStruxure Link150 energy gateway default"},
	{Vendor: "schneiderpm", Class: ClassAny, Username: "User1", Password: "0", Source: "vendor-doc", Notes: "PowerLogic PM8000 power-quality meter default"},

	// Sierra Wireless AirLink (ALEOS) cellular gateways.
	{Vendor: "sierra", Class: ClassAny, Username: "user", Password: "12345", Source: "firmware-image", Notes: "ACEmanager documented default; byte-identical /etc/shadow across RV50 4.16 + RV55 4.18 (SHA-512 cracked)"},

	// Westermo WeOS industrial switches/routers (Lynx et al.).
	{Vendor: "westermo", Class: ClassAny, Username: "admin", Password: "westermo", Source: "firmware-image", Notes: "WeOS 4.35 factory default (md5crypt cracked), UID 0, /bin/clish; fleet-wide in factory.cfg, no forced change; SSH/HTTP/HTTPS default-on"},

	// Raritan PX/Dominion (Xerus) PDUs and KVMs.
	{Vendor: "raritan", Class: ClassAny, Username: "admin", Password: "raritan", Source: "vendor-doc", Notes: "PX/Dominion factory default (forced-change on modern Xerus; still shipped)"},

	// Avocent (Vertiv) ACS8000/ACS800 advanced console servers.
	{Vendor: "avocent", Class: ClassAny, Username: "admin", Password: "", Source: "firmware-image", Notes: "ACS8000 2.32.4 factory admin ships blank password (sshd PermitEmptyPasswords yes) -> passwordless root-capable login until changed"},
	{Vendor: "avocent", Class: ClassAny, Username: "root", Password: "linux", Source: "vendor-doc", Notes: "legacy Avocent ACS/DSR console-server default"},

	// Tripp Lite PowerAlert / SNMPWEBCARD (WEBCARDLX) UPS/PDU network cards.
	{Vendor: "tripplite", Class: ClassAny, Username: "localadmin", Password: "localadmin", Source: "vendor-doc", Notes: "PowerAlert/SNMPWEBCARD documented default web/CLI account"},
	// Modern PowerAlert rejects admin/admin; localadmin/localadmin is documented.

	// --- KB gap additions --------------------------------------------------
	// Additive default-credential rows drawn from firmware/vendor-doc analysis.
	// Sprayable network defaults only (no serial/console-only, uncracked-hash,
	// or client-certificate "credentials").

	// Advantech EKI serial device servers.
	{Vendor: "advantech", Class: ClassHTTP, Username: "admin", Password: "", Source: "vendor-doc", Notes: "EKI web (Boa Basic auth) blank-password default; confirmed on real EKI-1524-CE firmware (lab/advantech-eki)"},

	// APC / Schneider Network Management Card (NMC).
	{Vendor: "apc", Class: ClassAny, Username: "apc", Password: "apc", Source: "vendor-doc", Notes: "NMC factory Super-User (forced change on first login)"},
	{Vendor: "apc", Class: ClassAny, Username: "device", Password: "apc", Source: "firmware-image", Notes: "NMC alternate documented default"},
	{Vendor: "apc", Class: ClassAny, Username: "apc", Password: "jmm627", Source: "firmware-image", Notes: "hardcoded demo/service pw in NMC3 AOS (gated by uploadable /testdrive522.ini)"},

	// ASRock Rack (MegaRAC-derived) hidden account.
	{Vendor: "asrockrack", Class: ClassAny, Username: "anonymous", Password: "superuser", Source: "firmware-image", Notes: "AMI hidden UID0 (same hash as sysadmin), anonymous-login bit"},

	// ASUS ASMB (AMI MegaRAC SP-X OEM).
	{Vendor: "asus", Class: ClassAny, Username: "sysadmin", Password: "superuser", Source: "firmware-image", Notes: "AMI default (libuserauth special-cases sysadmin->0xff)"},
	{Vendor: "asus", Class: ClassAny, Username: "anonymous", Password: "superuser", Source: "firmware-image", Notes: "hidden UID2, R7A94110 build; same hash as sysadmin"},

	// CyberPower RMCARD.
	{Vendor: "cyberpower", Class: ClassAny, Username: "cyber", Password: "cyber", Source: "vendor-doc", Notes: "RMCARD factory admin"},

	// Digi PortServer / Digi One.
	{Vendor: "digi", Class: ClassAny, Username: "root", Password: "dbps", Source: "vendor-doc", Notes: "PortServer/Digi One factory default"},

	// H3C HDM hidden account.
	{Vendor: "h3c", Class: ClassAny, Username: "anonymous", Password: "superuser", Source: "firmware-image", Notes: "HDM hidden UID0 (same hash as sysadmin)"},

	// Inspur BMC hidden account.
	{Vendor: "inspur", Class: ClassAny, Username: "anonymous", Password: "superuser", Source: "firmware-image", Notes: "hidden shadow (same hash as sysadmin), latent"},

	// Lantronix (additional families).
	{Vendor: "lantronix", Class: ClassAny, Username: "admin", Password: "", Source: "firmware-image", Notes: "SISPM1040 (WebStaX) blank admin"},
	{Vendor: "lantronix", Class: ClassAny, Username: "cifsuser", Password: "CIFSPASS", Source: "firmware-image", Notes: "SLB882 shipped CIFS cred"},

	// Moxa NPort 6000.
	{Vendor: "moxa", Class: ClassAny, Username: "admin", Password: "", Source: "vendor-doc", Notes: "NPort 6000 default (blank)"},
	{Vendor: "moxa", Class: ClassAny, Username: "admin", Password: "moxa", Source: "vendor-doc", Notes: "NPort 6000 default (alternate)"},

	// Sipeed NanoKVM.
	{Vendor: "nanokvm", Class: ClassSSH, Username: "root", Password: "root", Source: "firmware-image", Notes: "NanoKVM 2.4.3 /etc/shadow (PermitRootLogin yes)"},
	{Vendor: "nanokvm", Class: ClassHTTP, Username: "admin", Password: "admin", Source: "firmware-image", Notes: "NanoKVM web getDefaultAccount() bcrypt(admin) when /etc/kvm/pwd absent (github.com/sipeed/NanoKVM server/service/auth)"},

	// Opengear console servers (legacy).
	{Vendor: "opengear", Class: ClassAny, Username: "root", Password: "default", Source: "firmware-image", Notes: "OM2200/legacy ARM factory (PermitRootLogin yes)"},

	// Perle IOLAN.
	{Vendor: "perle", Class: ClassAny, Username: "admin", Password: "superuser", Source: "vendor-doc", Notes: "IOLAN factory default"},

	// PiKVM.
	{Vendor: "pikvm", Class: ClassAny, Username: "admin", Password: "admin", Source: "firmware-image", Notes: "/etc/kvmd/htpasswd, no first-boot rotation"},

	// BliKVM (kvmd fork, same /api/auth login as PiKVM).
	{Vendor: "blikvm", Class: ClassAny, Username: "admin", Password: "admin", Source: "firmware-image", Notes: "kvmd fork; admin/admin answered on all observed BliKVM hosts"},

	// Red Lion / Sixnet industrial gateways.
	{Vendor: "redlion", Class: ClassAny, Username: "root", Password: "", Source: "firmware-image", Notes: "pam_unix nullok; remote if telnet/FTP on"},
	{Vendor: "redlion", Class: ClassAny, Username: "ftp", Password: "", Source: "firmware-image", Notes: "UID0/GID0 anon-equivalent FTP as root"},
	{Vendor: "redlion", Class: ClassAny, Username: "guest", Password: "", Source: "firmware-image", Notes: "remote if telnet on"},
	{Vendor: "redlion", Class: ClassAny, Username: "PPPLink", Password: "PPPLink", Source: "firmware-image", Notes: "DES zR0TPjZBT6P2Q fleet constant, PPP/PAP dial-in"},

	// Server Technology (Legrand) Sentry PDUs.
	{Vendor: "servertech", Class: ClassAny, Username: "admn", Password: "", Source: "firmware-image", Notes: "Sentry PRO single admin (blank/force-set first login)"},
	{Vendor: "servertech", Class: ClassAny, Username: "cdup", Password: "", Source: "firmware-image", Notes: "Switched CDU login (blank/force-set)"},

	// Vertiv / Liebert / Geist (IntelliSlot / iCOM / Geist environmental).
	{Vendor: "vertiv", Class: ClassAny, Username: "Liebert", Password: "Liebert", Source: "vendor-doc", Notes: "Liebert IntelliSlot web card documented default"},
	{Vendor: "vertiv", Class: ClassAny, Username: "admin", Password: "admin", Source: "vendor-doc", Notes: "Geist/Vertiv environmental + newer IntelliSlot Unity default"},

	// OpenBMC-family emulators and IBM meta layers.
	{Vendor: "openbmc", Class: ClassAny, Username: "admin", Password: "password", Source: "firmware-image", Notes: "pyghmi fakebmc/VirtualBMC/ProxmoxBMC IPMI default"},
	{Vendor: "openbmc", Class: ClassSSH, Username: "service", Password: "0penBmc", Source: "firmware-image", Notes: "IBM meta-ibm seeded account (sudo + BMC shell)"},
}
