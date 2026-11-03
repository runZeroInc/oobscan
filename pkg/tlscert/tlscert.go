// Package tlscert inspects a BMC's TLS leaf certificate for shared/default keys.
//
// Many BMC firmwares ship a static TLS certificate together with its private key
// baked into the image, so any unit that never regenerated its cert serves HTTPS
// with a publicly known key. This package captures the served leaf certificate,
// fingerprints it (SHA-256), and matches it against a database of known
// shipped/default BMC certificates, also flagging default-template subjects,
// expired/self-signed certs, and weak keys.
package tlscert

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/excrypto/crypto/tls"
	"github.com/runZeroInc/oobscan/pkg/bmcfp"
)

// KnownDefault is a shipped/default BMC certificate signature.
//
//	SHA256 match  -> the unit serves a certificate whose private key is public in
//	                 firmware: impersonation / non-forward-secret TLS decryption. (critical)
//	Subject match only (fingerprint differs) -> a default-template identity with a
//	                 (likely) per-unit key: weaker signal, worth noting.
type KnownDefault struct {
	Vendor    string
	Product   string
	SHA256    string // uppercase, colon-separated
	SubjectCN string
	SubjectO  string
	Note      string
}

// knownDefaults are the shipped/default BMC certs recovered from firmware.
var knownDefaults = []KnownDefault{
	{
		Vendor: "blikvm", Product: "BliKVM v1/v2/v3/v4",
		SHA256:    "CA:97:26:7D:7A:90:61:A7:21:14:EF:26:54:35:F2:75:FB:B1:6D:73:71:5C:96:D4:97:1C:C6:4F:12:D7:0D:9F",
		SubjectCN: "", SubjectO: "Internet Widgits Pty Ltd",
		Note: "shipped lib/https/cert.pem, byte-identical across all BliKVM versions; served on 443 until reprovisioned (modulus MD5 488991287a26fb09569905611933d43a)",
	},
	{
		Vendor: "rittal", Product: "CMC III (ReOS 10.1.3)",
		SHA256:    "7E:11:92:7D:35:75:69:8B:F1:34:06:DB:D4:7F:F1:D6:10:21:72:6A:7F:D3:84:06:A2:41:D9:EE:F5:DC:E2:CD",
		SubjectCN: "", SubjectO: "Rittal GmbH & Co. KG",
		Note: "fleet-shared etc/reos-defaults server.pem (RSA-4096) restored to 443 at boot; pubkey MD5 7776baba5fb5d94f09e86e2036351777 -> impersonation / non-forward-secret TLS decryption until an operator cert is provisioned",
	},
	{
		Vendor: "supermicro", Product: "X10 ATEN",
		SHA256:    "0E:08:7F:40:E8:DD:3C:F4:54:93:04:5B:70:5B:3C:B9:8F:21:20:B3:17:6B:03:BD:2F:C4:8F:93:DF:07:81:0B",
		SubjectCN: "IPMI", SubjectO: "Super Micro Computer",
		Note: "server.pem shipped with embedded private key (valid 2017-2020)",
	},
	{
		Vendor: "dell", Product: "iDRAC6",
		SHA256:    "A8:76:20:12:DB:EC:E1:1D:78:F4:CC:AD:3A:71:61:B9:33:89:12:E7:09:DA:67:9B:6E:A1:FA:8C:01:15:50:85",
		SubjectCN: "iDRAC6 default certificate", SubjectO: "Dell Inc.",
		Note: "iDRAC6 ships & serves default host.key; no unique-cert generation",
	},
	{
		Vendor: "dell", Product: "iDRAC7/8",
		SHA256:    "B4:63:7E:C6:C3:B7:2D:21:0C:D7:DA:44:1D:42:EE:C1:E9:C5:B3:6C:E0:5F:7F:0D:76:24:3F:12:FE:5B:A2:EB",
		SubjectCN: "iDRAC8 default certificate", SubjectO: "Dell Inc.",
		Note: "default template; D7/8/9 regenerate a unique cert at first boot (fingerprint match = pre-first-boot or cert deleted; the shipped host.key is byte-identical D7->D9)",
	},
	{
		// AMI MegaRAC default server cert, shipped with its matching private key;
		// the fallback/default served by MegaRAC OEM boards that have not regenerated.
		Vendor: "ami", Product: "MegaRAC (default)",
		SHA256:    "53:22:36:0A:61:C2:51:A9:93:4A:9C:32:EF:87:E2:50:BD:3B:6C:95:1E:3C:34:FC:A6:37:FA:8A:7B:41:B1:55",
		SubjectCN: "megarac.com", SubjectO: "American Megatrends International LLC (AMI)",
		Note: "AMI MegaRAC default TLS cert + private key shipped in firmware; shared across MegaRAC OEMs unless regenerated -> impersonation / non-forward-secret TLS decryption",
	},
	{
		Vendor: "ami", Product: "MegaRAC (default alt)",
		SHA256:    "90:97:62:9B:14:F1:AD:21:A5:95:9A:E9:BB:77:52:4E:05:D8:EA:3C:3F:D0:F3:2A:92:A1:39:EE:B9:EE:15:14",
		SubjectCN: "megarac.com", SubjectO: "American Megatrends International LLC (AMI)",
		Note: "AMI MegaRAC default etc/defconfig/server.pem variant",
	},
	{
		// Older AMI MegaRAC default cert + private key. Distinct SDK era from the
		// megarac.com certs (CN=www.ami.com, older "American Megatrends Incorporated").
		Vendor: "ami", Product: "MegaRAC (www.ami.com, older SDK)",
		SHA256:    "ED:4D:A7:C3:E9:E0:43:49:ED:37:6D:AA:81:70:86:FA:26:7D:C1:1F:75:46:6F:9B:85:00:65:34:B2:92:BD:18",
		SubjectCN: "www.ami.com", SubjectO: "American Megatrends Incorporated",
		Note: "older AMI MegaRAC default TLS cert + private key shipped in firmware; shared-key MITM across MegaRAC OEMs",
	},
	{
		// BliKVM ships lib/https/{cert,key}.pem
		// baked into the .deb with the OpenSSL default placeholder subject
		// (C=AU,ST=Some-State,O=Internet Widgits Pty Ltd, no CN). The cert -- and its
		// matching RSA private key -- is byte-identical across versions, so exposed
		// units serve HTTPS with the same public-in-firmware key. Contrast PiKVM,
		// which generates a per-device cert at first boot via kvmd-gencert.
		Vendor: "blikvm", Product: "BliKVM (v1-v4)",
		SHA256:    "CA:97:26:7D:7A:90:61:A7:21:14:EF:26:54:35:F2:75:FB:B1:6D:73:71:5C:96:D4:97:1C:C6:4F:12:D7:0D:9F",
		SubjectCN: "", SubjectO: "Internet Widgits Pty Ltd",
		Note: "shared TLS cert + private key baked into the .deb, byte-identical v1-v4 (SPKI BC:1E:18:70...); fleet-wide impersonation / non-forward-secret TLS decryption",
	},
	{
		// Lantronix SLC8000 (SecureLinx Console Manager) ships www/key.pem +
		// www/cert.pem factory pair in the webroot: 1024-bit RSA, CN=SLC,O=Lantronix,
		// valid 2013-11-25..2018-11-24. Baked into the image => shared across every
		// unit on this firmware => impersonation / non-forward-secret TLS decryption. RSA-1024 is itself weak.
		Vendor: "lantronix", Product: "SLC8000 console manager",
		SHA256:    "83:44:62:75:57:B4:0B:8E:1A:08:28:0D:C0:BA:96:67:02:05:32:AD:BB:BC:E0:36:05:67:8B:24:A7:7D:90:7C",
		SubjectCN: "SLC", SubjectO: "Lantronix",
		Note: "factory www/key.pem shipped with cert (RSA-1024, modulus MD5 3418c967...); shared across all SLC8000 units -> impersonation / non-forward-secret TLS decryption",
	},
	{
		// ASUS ASMB9-iKVM (AMI MegaRAC SP-X) default server.pem: 2048-bit RSA,
		// CN=AMI,O=American Megatrends Inc,
		// OU=Service Processors, valid 2016-06-01..2026-05-30. libsslcertificate
		// regenerates it, so this is the factory-default TLS key presented until an
		// admin reprovisions => predictable/extractable => impersonation / non-forward-secret TLS decryption on
		// un-reprovisioned units. This is a per-build shipped default rather than a
		// cross-OEM shared key.
		Vendor: "asus", Product: "ASMB9-iKVM (SP-X 3.5.0)",
		SHA256:    "6D:EC:FE:56:53:D9:80:0B:55:AB:8F:44:D3:AB:52:AC:8C:0A:B5:AC:92:35:95:66:BA:51:1E:D6:34:36:BC:D0",
		SubjectCN: "AMI", SubjectO: "American Megatrends Inc",
		Note: "ASUS ASMB9 default server.pem shipped with private key (valid 2016-06-01..2026-05-30); default TLS key until reprovisioned -> impersonation / non-forward-secret TLS decryption",
	},
	{
		// ASUS ASMB9-iKVM older build default server.pem:
		// CN=AMI,O=American Megatrends Inc,OU=Service Processors, valid
		// 2014-07-28..2024-07-25. Distinct key material from the build above, so it
		// is a per-build shipped default.
		Vendor: "asus", Product: "ASMB9-iKVM (SP-X 3.2.6)",
		SHA256:    "9D:63:0B:F8:6C:F0:5A:E2:19:D4:9B:3D:5A:6A:1C:39:61:A1:30:4E:47:D3:D9:91:95:1E:EE:06:AA:13:37:0D",
		SubjectCN: "AMI", SubjectO: "American Megatrends Inc",
		Note: "ASUS ASMB9 older-build default server.pem shipped with private key (valid 2014-07-28..2024-07-25); default TLS key until reprovisioned",
	},
	// --- Field-observed default-cert monocultures. These byte-identical
	// self-signed certs recur across many units of one generation, i.e. the shipped
	// default was never regenerated. Matched by exact cert SHA256, with no
	// SubjectCN, to avoid over-matching.
	{
		Vendor: "supermicro", Product: "X10 IPMI (ATEN)",
		SHA256:    "FF:20:93:CD:59:88:93:99:DB:2A:4C:04:A5:8D:93:08:6A:F0:27:D1:C9:4A:25:91:82:89:29:BB:33:2F:58:79",
		SubjectCN: "", SubjectO: "",
		Note: "shipped X10 default HTTPS cert, never regenerated; observed byte-identical on 201 X10 hosts in the 2026-07 scan",
	},
	{
		Vendor: "supermicro", Product: "X10 IPMI (ATEN)",
		SHA256:    "5F:99:65:BC:00:8D:7A:3F:49:57:C3:8C:59:24:8C:21:4F:2A:28:A3:98:19:D9:F6:0C:3B:E2:43:33:7E:39:06",
		SubjectCN: "", SubjectO: "",
		Note: "shipped X10 default HTTPS cert variant, never regenerated; observed on 111 X10 hosts in the 2026-07 scan",
	},
	{
		Vendor: "supermicro", Product: "X10 IPMI (ATEN)",
		SHA256:    "44:5C:B6:AE:C4:57:1D:36:3C:A7:85:12:78:44:E7:A3:F5:5C:8F:5E:DF:08:53:2A:D4:19:E6:2F:3C:BA:2E:ED",
		SubjectCN: "", SubjectO: "",
		Note: "shipped X10 default HTTPS cert variant, never regenerated; observed on 107 X10 hosts in the 2026-07 scan",
	},
	{
		Vendor: "dell", Product: "iDRAC7",
		SHA256:    "57:74:61:36:9D:BD:EB:C7:DA:EA:97:01:EC:DD:03:29:7B:C7:4D:4C:E3:EE:CE:23:EE:3F:EB:63:61:3A:B0:31",
		SubjectCN: "iDRAC7 default certificate", SubjectO: "",
		Note: "iDRAC7 default HTTPS cert (CN=iDRAC7 default certificate) served byte-identical on 187 iDRAC7 hosts in the 2026-07 scan (unit never regenerated its cert)",
	},
	{
		Vendor: "huawei", Product: "iBMC",
		SHA256:    "83:D1:63:A0:F9:FF:E2:05:38:63:2F:79:9B:DC:3B:9F:0D:2F:8F:44:DC:8A:1E:02:EE:D8:CE:A1:66:24:46:55",
		SubjectCN: "", SubjectO: "",
		Note: "iBMC default HTTPS cert served byte-identical on 73 iBMC hosts in the 2026-07 scan (default cert not regenerated)",
	},
}

// SharedPubKey is a public key (SubjectPublicKeyInfo) that ships byte-identical
// across multiple vendors' firmware. Matching a served cert's SPKI is more robust
// than a full-cert fingerprint: it flags a shared private key even when the vendor
// re-wrapped the same key in a fresh certificate (new serial/validity). All values
// verified in firmware analysis (pubkey SHA-256 over
// 98 keys/certs across 14 firmware rootfs).
type SharedPubKey struct {
	SPKI256 string // uppercase hex, no separators (sha256 of RawSubjectPublicKeyInfo)
	Label   string
	Vendors []string
	Note    string
}

// knownSharedKeys are fleet-wide shared public keys: a unit whose served leaf
// SPKI matches one uses a private key that is public in firmware and reused
// across a fleet. Two flavours: cross-OEM (the AMI MegaRAC keys, shared across
// several board vendors) and single-vendor-cross-product (e.g. the Lantronix
// lantronix.key shipped byte-identical across a vendor's whole product line).
// SPKI matching (vs a full-cert fingerprint) catches the key even when a product
// re-wraps it in a fresh certificate.
var knownSharedKeys = []SharedPubKey{
	{
		SPKI256: "DADF500ADB79CA6B807837CC4E6C543F43FF451CD5A7669FBB22557764AF114C",
		Label:   "AMI Redfish CA (CN=www.ami.com)", Vendors: []string{"asrock", "gigabyte", "tyan", "h3c"},
		Note: "shipped CA (ca-key.pem private key byte-identical ASRock/Gigabyte/Tyan + H3C HDM 2432-bit); mint any CN client cert -> passwordless admin (H3C build has no app consumer of client-CN in fs; SUSPECTED there)",
	},
	{
		SPKI256: "59307DA93E1540FC3E5ECC81D7C31B96062A24762FEDEB008BA7B923E80684D4",
		Label:   "AMI TLS server key (CN=megarac.com)", Vendors: []string{"tyan", "gigabyte"},
		Note: "server private key byte-identical Tyan/Gigabyte -> impersonation / non-forward-secret TLS decryption",
	},
	{
		SPKI256: "5D2B4DC1F88BC84DEE6E6D7C976EFE46E115647894D2048EEB26C09EB39083F2",
		Label:   "AMI TLS server key (CN=www.ami.com)", Vendors: []string{"asrock", "gigabyte", "inspur", "h3c"},
		Note: "server private key byte-identical ASRock/Gigabyte + Inspur NF5280M5 SP-X + H3C R4900 HDM (served on :443, no genrsa on first boot) -> impersonation / non-forward-secret TLS decryption",
	},
	{
		// Lantronix fleet-wide /etc/ssl/misc/lantronix.key (RSA-2048, CN=Lantronix,
		// valid 2015-2038). Byte-identical (sha256 87e02dba..., modulus-MD5 05b25e59...)
		// across multiple products: SGX5150, PremierWave 2050, EDS3000/EDS5000/EDS-MD, and
		// the cellular OpenWrt E22X/G520/X300. It is both the HTTPS server key and the
		// key ltrx_evo uses to unwrap the PKCS7 .xcr config-export -> a captured config
		// backup (admin pw, SNMP, VPN/WPA/RADIUS secrets) is decryptable offline.
		SPKI256: "48FDA915BA97D644B511BA9A1505C7396055B175E16D877FCCD0E98CF795B1E0",
		Label:   "Lantronix fleet key (CN=Lantronix, lantronix.key)",
		Vendors: []string{"lantronix"},
		Note:    "fleet-wide RSA-2048 shipped across SGX5150/PremierWave2050/EDS/EDS-MD + cellular E22X/G520/X300; HTTPS server key AND decrypts the .xcr config-export -> impersonation / non-forward-secret TLS decryption + offline config-backup secret recovery",
	},
	{
		// Spider KVM 4.x /etc/e-RIC/ssl/erickey_default.pem (RSA-1024, CN=SLS,
		// O=Lantronix). Shipped default TLS key served by the KVM web/HTTPS.
		SPKI256: "11C5FCC52A313626F7BCCEFA8C9A7EF155A44F69F30FF3C089FD37B04636810E",
		Label:   "Lantronix Spider KVM default key (CN=SLS)",
		Vendors: []string{"lantronix"},
		Note:    "Spider KVM 4.x shipped default TLS private key (RSA-1024, CN=SLS) -> impersonate/MITM any factory-cert unit",
	},
	{
		// SLB882 (SLC branch console) www/key.pem (RSA-3072, CN=SLC, 2024-2034).
		// Same shared-key class as the SLC8000 www/key.pem but distinct material.
		SPKI256: "7A602321977A264183A0D2BFCAD60385135CDDA256C6B27AD960F7FD7B91CFF5",
		Label:   "Lantronix SLB882 default key (CN=SLC, RSA-3072)",
		Vendors: []string{"lantronix"},
		Note:    "SLB882 factory www/key.pem shipped with cert (RSA-3072, CN=SLC) -> impersonation / non-forward-secret TLS decryption",
	},
	{
		// IONMM 1.5.23 media converter /etc/lighttpd/server.pem (CN=lantronix.com,
		// O=Lantronix, 2024-2034) shipped with its private key.
		SPKI256: "8FE92AB0E4D2F43149F8DD4C2B99DDCBE400F6F790B141AAA0D33AB16DEECF74",
		Label:   "Lantronix/TNI IONMM lighttpd key (CN=lantronix.com)",
		Vendors: []string{"lantronix"},
		Note:    "IONMM media converter shipped lighttpd TLS private key (CN=lantronix.com) -> impersonation / non-forward-secret TLS decryption",
	},
	{
		// NTC-552 (NetComm/CASA 5G router, Lantronix-branded) DA authenticate daemon
		// /etc/authenticate/server.key (RSA-2048, CN=DA Magpie Server 1, O=NetComm) on
		// the LAN-exposed listener 0.0.0.0:27068.
		SPKI256: "FB9A05562F717B89085B7334482F82E43A7F1C4799047440CD8C40FF3F777DE3",
		Label:   "Lantronix/NetComm DA daemon key (CN=DA Magpie Server 1)",
		Vendors: []string{"lantronix", "netcomm"},
		Note:    "NTC-552 hardcoded DA-authenticate TLS server key (O=NetComm) on 0.0.0.0:27068 -> impersonate/MITM the auth daemon",
	},

	// --- shipped/default HTTPS server keys from the firmware key sweep. SPKI = sha256
	// of the served leaf SubjectPublicKeyInfo; matches even when a product re-wraps the
	// same private key in a fresh cert. Several are also in knownDefaults by cert-SHA256;
	// the SPKI entry makes the match robust across firmware revisions. ---
	{
		SPKI256: "EEB13ED2B4F5022AA68CC57993F2A2C9E59BB9A43DD368829B36D06B39091948",
		Label:   "Fujitsu iRMC S1 default SSL key (CN=iRMC 1024bit RSA SSL Cert)",
		Vendors: []string{"fujitsu"},
		Note:    "Fujitsu iRMC (RX330-era) shipped default HTTPS server key (RSA-1024, O=Fujitsu Siemens Computers) -> impersonation / non-forward-secret TLS decryption until reprovisioned",
	},
	{
		SPKI256: "E7BF64EFE499475FF891889DA50C1A7A62F088065FA875FD7CACF22B88BABB1D",
		Label:   "Fujitsu iRMC S2 default SSL key (CN=iRMC)",
		Vendors: []string{"fujitsu"},
		Note:    "Fujitsu iRMC S2 shipped default HTTPS server key (O=Fujitsu Technology Solutions) -> impersonation / non-forward-secret TLS decryption until reprovisioned",
	},
	{
		SPKI256: "87C1A08FA6E4680317A7F6DFA83B341CBD68CD852844E257E30EDCC359169C27",
		Label:   "Fujitsu iRMC S3 default SSL key (CN=iRMC)",
		Vendors: []string{"fujitsu"},
		Note:    "Fujitsu iRMC S3 shipped default HTTPS server key (O=Fujitsu Technology Solutions GmbH) -> impersonation / non-forward-secret TLS decryption until reprovisioned",
	},
	{
		SPKI256: "03FBE0E33160C1FCE953A90BA2C4621D703C55E88CADA9C8C1249E2ABA9DA490",
		Label:   "Supermicro X10 ATEN httpd default key (CN=IPMI)",
		Vendors: []string{"supermicro"},
		Note:    "SMC X10 usr/local/httpd/server.pem shipped default HTTPS key (O=Super Micro Computer) -> impersonation / non-forward-secret TLS decryption until reprovisioned",
	},
	{
		SPKI256: "0FBC69D4963E115826BC017297E08B186C1E1974F3F1A9BF5D002A6B145D6C62",
		Label:   "Supermicro X10 ATEN openwsman default key",
		Vendors: []string{"supermicro"},
		Note:    "SMC X10 etc/openwsman/serverkey.pem shipped default WS-Management TLS key -> impersonation / non-forward-secret TLS decryption",
	},
	{
		SPKI256: "F720501EA6DA6956F1BED90A0F81357D378ED5ED35D9755E03343C7EAD541BBD",
		Label:   "Dell iDRAC7/8/9 default host.key (CN=iDRAC8 default certificate)",
		Vendors: []string{"dell"},
		Note:    "iDRAC7/8 (and shipped D9) default host.key baked in firmware; served until first-boot cert regen -> impersonation / non-forward-secret TLS decryption (match = pre-first-boot or cert deleted)",
	},
	{
		SPKI256: "1890E78D9FA225B307D2085C100C012797105BA3D38FE6D00E0F1A71000BD7ED",
		Label:   "Dell iDRAC6 default host.key (CN=iDRAC6 default certificate)",
		Vendors: []string{"dell"},
		Note:    "iDRAC6 ships & serves default host.key (O=Dell Inc.); no unique-cert generation -> impersonation / non-forward-secret TLS decryption",
	},
	{
		SPKI256: "50AF97660AF65FC223E9FC3500B812BECDA32377DEECB543CFCC09347705B49C",
		Label:   "AMI MegaRAC default server key (CN=AMI, SP-X)",
		Vendors: []string{"asrockrack", "asus", "ami"},
		Note:    "AMI MegaRAC SP-X default server.pem/privkey.pem (CN=AMI) byte-identical across ASRock Rack + ASUS ASMB9 builds -> impersonation / non-forward-secret TLS decryption until reprovisioned",
	},
	{
		SPKI256: "3CA8654A4BEFF3084B1CF83439E0AC266B484B2610CDA25C07C8055F63C84CF8",
		Label:   "AMI MegaRAC default server key (CN=AMI, ASUS SP-X 3.2.6)",
		Vendors: []string{"asus", "ami"},
		Note:    "AMI MegaRAC SP-X older-build default server key (CN=AMI) shipped with private key -> impersonation / non-forward-secret TLS decryption",
	},

	{
		// Cisco CIMC legacy (Avocent/AMI-MergePoint) lineage: default host.key
		// shipped byte-identical across S3260 4.3(6.250053) and C220 M4 4.1(2m), copied
		// live onto any default/reset unit by security_manager_setup (SSH host key derived
		// via makeCert). RSA-2048, self-signed CN=cisco.com. New vs the modern jolt C245 M8
		// stack (per-unit, no shipped key). Same class as lantronix.key.
		SPKI256: "8962BC2DF11A9AC6E9CAF651C904B670D2558C85689D03263E9CE462BD3B78FD",
		Label:   "Cisco CIMC legacy default host.key (CN=cisco.com)",
		Vendors: []string{"cisco"},
		Note:    "shipped default TLS/SSH private key byte-identical S3260/C220M4 (legacy Avocent CIMC); live on default/reset -> non-forward-secret TLS decryption + SSH host-key impersonation",
	},

	{
		// Raritan PX3 (Xerus) 3.6.1 shipped demo TLS key:
		// /etc/pki/tls/private/server_key_default.pem (+ server_cert_default.pem,
		// CN=Demo Certificate, issuer CN=Generic Demo CA, RSA-2048, exp 2022-10-20).
		// Served by the PDU HTTPS tier until the operator uploads a real cert; the
		// private key is public in firmware -> fleet-wide impersonation / non-forward-secret TLS decryption.
		SPKI256: "65B1C6E5FE6D2FD91B2D2F2B756B432C28A6FA3AF2740A21EAB19DD7F66C11FF",
		Label:   "Raritan PX3 Xerus demo TLS key (CN=Demo Certificate)",
		Vendors: []string{"raritan"},
		Note:    "Raritan PX3 (Xerus) shipped server_key_default.pem (RSA-2048, CN=Demo Certificate); served until operator replaces cert -> fleet-wide impersonation / non-forward-secret TLS decryption",
	},
	{
		// H3C R4900 G5 HDM KVM/vMedia stunnel key: /usr/local/www/certs/{server,privkey}.pem,
		// self-signed CN=H3C, O=New H3C Technologies (2021-2036), RSA-2048. stunnel.conf
		// binds it for the KVM/virtual-media TLS wrap. Distinct from the generic AMI
		// CN=www.ami.com 443 key (5D2B4DC1...) that H3C also ships.
		SPKI256: "F342C3FFB8A6AD7C2CDBAE34CE0FE5E54F70C30F89773C3D5B7340662C4A1AA6",
		Label:   "H3C HDM KVM/vMedia stunnel key (CN=H3C)",
		Vendors: []string{"h3c"},
		Note:    "H3C R4900 HDM shipped stunnel server key (CN=H3C) for KVM/virtual-media -> impersonation / non-forward-secret TLS decryption of the KVM+vMedia TLS tunnel until reprovisioned",
	},
	{
		// Sierra Wireless AirLink ALEOS ACEmanager fleet TLS key:
		// etc/ACEmanager/certs/server.key + server.crt (self-signed, CN=*.sierrawireless.com,
		// O=Sierra Wireless Inc., OU=Airlink, RSA-2048, 2019-2029). SPKI byte-identical
		// across RV50 4.16 and RV55 4.18 (and by scheme MP70/LX40/LX60) -> fleet-wide.
		SPKI256: "C104651ED8B02BBF777406E8545AA677731A1A6D1AB8D5F6FBA6CB88AA45C58E",
		Label:   "Sierra AirLink ALEOS ACEmanager fleet key (CN=*.sierrawireless.com)",
		Vendors: []string{"sierra"},
		Note:    "ACEmanager shipped server.key byte-identical RV50/RV55 (documented default until reprovisioned) -> impersonation / non-forward-secret TLS decryption of the cellular gateway mgmt UI",
	},

	{
		// BliKVM IP-KVM appliance: lib/https/cert.pem + key.pem, shipped in the
		// public .deb and byte-identical across v1/v2/v3 (Raspberry Pi) and v4
		// (Allwinner H616). Self-signed RSA-2048 with the OpenSSL placeholder
		// subject "Internet Widgits Pty Ltd" -> fleet-wide non-forward-secret TLS decryption
		// / TLS MITM of the management web session.
		SPKI256: "BC1E1870D435B88E4719CFDF610EF2FEA32055F0EB8B5E2B5F3ED081621544B9",
		Label:   "BliKVM shared TLS key (O=Internet Widgits Pty Ltd)",
		Vendors: []string{"blikvm"},
		Note:    "lib/https/{cert,key}.pem shipped in the public .deb, byte-identical across v1/v2/v3 and v4 -> fleet-wide impersonation / non-forward-secret TLS decryption until reprovisioned",
	},

	{
		// Rittal CMC III (ReOS 10.1.3) shared default HTTPS key, shipped as
		// etc/reos-defaults/lighttpd/ssl/server.pem. Boot init re-asserts it whenever
		// the live cert matches a known default, so any unit without a manually
		// installed certificate serves this private key. SPKI matching also catches a
		// re-wrapped cert around the same key; the full-cert SHA-256 is in
		// knownDefaults.
		SPKI256: "582F3ED9741ADEE172AE83648B33CB3793B25666929F20AF1F81B08222582551",
		Label:   "Rittal CMC III default server.pem (O=Rittal GmbH & Co. KG)",
		Vendors: []string{"rittal"},
		Note:    "fleet-shared etc/reos-defaults/lighttpd/ssl/server.pem (RSA-4096) restored to :443 at boot by S03filesystem; private key is public in firmware -> impersonation / non-forward-secret TLS decryption until an operator cert is provisioned",
	},

	{
		// Eaton NetworkMS / MGE-Pulsar (HE/LD/LE) shared device RSA-1024 key:
		// the full private key was recovered from firmware (DES-EDE3-CBC PEM,
		// passphrase "password") and is byte-identical across the NetworkMS
		// HE/LD/LE builds (modulus aa0905cc...e1d38b19). SPKI matching flags a
		// unit that serves this leaf even when it is re-wrapped in a fresh cert.
		// Also catalogued in badkeys.go by bkhash (bNmvE5s+CXOu0OeuqaiW) for the
		// bkhash-only probe path.
		SPKI256: "A6338A902DD61745A79CF44611D81AC404B778DF35C3DD5233EC33B5F0528871",
		Label:   "Eaton NetworkMS/MGE-Pulsar shared device key (RSA-1024)",
		Vendors: []string{"eaton"},
		Note:    "NetworkMS shared RSA-1024 device key (full private key recovered from firmware, byte-identical across HE/LD/LE); firmware-embedded management/device key -> treat a served match as vendor+product-line-indicative shared-key exposure",
	},

	// Eaton ConnectUPS 512-bit RSA moduli are matched via the badkeys.go bkhash
	// mechanism, not duplicated here.
}

// CertInfo is the result of inspecting a served leaf certificate.
type CertInfo struct {
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	SHA256     string    `json:"sha256"`
	SPKI256    string    `json:"spkiSha256,omitempty"`
	SubjectCN  string    `json:"subjectCn,omitempty"`
	SubjectO   string    `json:"subjectO,omitempty"`
	IssuerCN   string    `json:"issuerCn,omitempty"`
	NotBefore  time.Time `json:"notBefore"`
	NotAfter   time.Time `json:"notAfter"`
	SelfSigned bool      `json:"selfSigned"`
	KeyBits    int       `json:"keyBits,omitempty"`
	Expired    bool      `json:"expired"`

	// SharedKeyMatch is set when the fingerprint matches a known shipped cert
	// whose private key is public (critical shared-key exposure).
	SharedKeyMatch *KnownDefault `json:"sharedKeyMatch,omitempty"`
	// DefaultSubject is set when only the subject matches a default template.
	DefaultSubject *KnownDefault `json:"defaultSubject,omitempty"`
	// SharedKeyBySPKI is set when the served leaf's public key (SPKI) matches a
	// known cross-OEM shared AMI key - a shared private key even if the cert wrapper
	// differs from any catalogued full-cert fingerprint.
	SharedKeyBySPKI *SharedPubKey `json:"sharedKeyBySpki,omitempty"`
	// BadKeyMatch is set when the served leaf's public key matches a known-bad /
	// default key imported from the runZero recog badkeys.xml database (matched by
	// the badkeys "bkhash" of the raw key primitive; see badkeys.go). This
	// attributes vendor/product for OOB devices whose default key we recognise
	// from badkeys.xml even when we hold no local firmware key material.
	BadKeyMatch *BadKey `json:"badKeyMatch,omitempty"`
	// BadKeyHash is the badkeys.xml bkhash of the served leaf's public key (the
	// same value stored in a badkeys.xml <fingerprint pattern="...">). Always set,
	// so a downstream consumer can cross-reference the platform recog set.
	BadKeyHash string `json:"badKeyHash,omitempty"`

	// Vendor/Product are the BMC identity inferred from the certificate's
	// subject/issuer DN via the built-in bmcfp fingerprints, when the cert
	// is not one of the known shipped defaults above. Vendor is a short
	// lowercase key (dell, hpe, supermicro, ...); Product is a label (iDRAC).
	Vendor  string `json:"vendor,omitempty"`
	Product string `json:"product,omitempty"`

	// ClientCertRequested is true when the server sent a TLS CertificateRequest
	// (mutual-TLS client-cert auth is enabled on this listener). On AMI MegaRAC
	// this is the precondition for the shipped-CA passwordless-admin bypass
	// (ssl.verifyclient + ssl.verifyclient.username=SSL_CLIENT_S_DN_CN, verified
	// against the firmware-shipped CN=www.ami.com CA whose private key is public).
	ClientCertRequested bool `json:"clientCertRequested,omitempty"`

	// AcceptableCAs holds the distinguished names the server advertises in its TLS
	// CertificateRequest as acceptable client-certificate issuers; populated only
	// when ClientCertRequested is true. It distinguishes CA-chain validation from
	// certificate pinning: an advertised CA DN means anything that CA signed is
	// accepted, so a DN matching a CA whose private key ships in public firmware
	// implies the shipped key can mint an accepted client cert. An empty list on a
	// listener that does request a cert points at pinning instead.
	AcceptableCAs []string `json:"acceptableCas,omitempty"`

	// TLSVersion / CipherSuite record what was actually negotiated, as Go's
	// constant names (for example "TLS 1.2", "TLS_RSA_WITH_AES_128_CBC_SHA").
	// A ceiling of TLS 1.0 with a CBC/RC4/3DES suite is the wire signature of a
	// frozen embedded crypto stack - the OpenSSL 0.9.8-era libraries observed in
	// firmware on Tripp Lite SNMPWEBCARD (0.9.8g) and Red Lion Sixnet IPm (0.9.8k),
	// which predate TLS 1.2 entirely. This is a bundled-component age signal, not
	// a CVE assertion: patch status is not observable from a handshake.
	TLSVersion  string `json:"tlsVersion,omitempty"`
	CipherSuite string `json:"cipherSuite,omitempty"`

	// ALPN is the protocol negotiated when the client offers h2 then http/1.1.
	// "h2" means the listener speaks HTTP/2, which is the applicability gate for
	// the Apache mod_http2 memory-exhaustion DoS (CVE-2026-49975, fixed in httpd
	// 2.4.68): a server that only offers http/1.1 does not expose that code path
	// regardless of its httpd version. Empty means no ALPN was negotiated.
	ALPN string `json:"alpn,omitempty"`

	Findings []string `json:"findings,omitempty"`
}

// Inspect connects to host:port over TLS (verification disabled), captures the
// leaf certificate, and classifies it. Analyze CertInfo.Findings / SharedKeyMatch.
func Inspect(host string, port int, timeout time.Duration) (*CertInfo, error) {
	dialer := &net.Dialer{Timeout: timeout}
	reqClientCert := false
	var acceptableCAs []string
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		// Offer HTTP/2 then HTTP/1.1 so the negotiated protocol tells us whether
		// the listener speaks h2 (the mod_http2 applicability gate). Offering ALPN
		// is a normal browser-shaped ClientHello; a server that does not support it
		// simply returns an empty NegotiatedProtocol.
		NextProtos: []string{"h2", "http/1.1"},
		// Detect mutual-TLS: this hook fires only if the server sends a
		// CertificateRequest. Returning no client cert still completes the handshake
		// where client-cert auth is optional, so the server leaf cert is captured too.
		// The request also carries the issuer DNs the server accepts - see
		// CertInfo.AcceptableCAs.
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			reqClientCert = true
			if cri != nil {
				for _, raw := range cri.AcceptableCAs {
					if dn := parseCADN(raw); dn != "" {
						acceptableCAs = append(acceptableCAs, dn)
					}
				}
			}
			return &tls.Certificate{}, nil
		},
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificate presented")
	}
	leaf := st.PeerCertificates[0]

	sum := sha256.Sum256(leaf.Raw)
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	ci := &CertInfo{
		Host:       host,
		Port:       port,
		SHA256:     colonHexUpper(sum[:]),
		SPKI256:    strings.ToUpper(hex.EncodeToString(spki[:])),
		SubjectCN:  leaf.Subject.CommonName,
		SubjectO:   strings.Join(leaf.Subject.Organization, ","),
		IssuerCN:   leaf.Issuer.CommonName,
		NotBefore:  leaf.NotBefore,
		NotAfter:   leaf.NotAfter,
		SelfSigned: leaf.Subject.String() == leaf.Issuer.String(),
	}
	now := time.Now()
	ci.Expired = now.After(leaf.NotAfter) || now.Before(leaf.NotBefore)
	if k, ok := leaf.PublicKey.(*rsa.PublicKey); ok {
		ci.KeyBits = k.N.BitLen()
	}
	ci.TLSVersion = tls.VersionName(st.Version)
	ci.CipherSuite = tls.CipherSuiteName(st.CipherSuite)
	ci.ALPN = st.NegotiatedProtocol

	for i := range knownDefaults {
		kd := &knownDefaults[i]
		if strings.EqualFold(ci.SHA256, kd.SHA256) {
			ci.SharedKeyMatch = kd
			ci.Findings = append(ci.Findings, fmt.Sprintf(
				"SHARED DEFAULT KEY: %s %s - private key is public in firmware (%s); impersonation / non-forward-secret TLS decryption",
				kd.Vendor, kd.Product, kd.Note))
		} else if ci.SubjectCN != "" && strings.EqualFold(ci.SubjectCN, kd.SubjectCN) {
			ci.DefaultSubject = kd
			ci.Findings = append(ci.Findings, fmt.Sprintf(
				"default-template certificate subject %q (%s %s) - default identity retained (per-unit key likely)",
				kd.SubjectCN, kd.Vendor, kd.Product))
		}
	}
	// SPKI (public-key) match: catches a shared private key even when the served
	// cert wrapper differs from any catalogued full-cert fingerprint (re-issued cert,
	// same key). Only report separately when the full-cert match above didn't fire.
	for i := range knownSharedKeys {
		sk := &knownSharedKeys[i]
		if strings.EqualFold(ci.SPKI256, sk.SPKI256) {
			ci.SharedKeyBySPKI = sk
			if ci.SharedKeyMatch == nil {
				ci.Findings = append(ci.Findings, fmt.Sprintf(
					"SHARED PUBLIC KEY: served TLS key is byte-identical to the %s, shipped across %s - the private key is public in firmware (%s)",
					sk.Label, strings.Join(sk.Vendors, "+"), sk.Note))
			}
			break
		}
	}
	// badkeys.xml cross-reference: compute the served leaf's badkeys "bkhash"
	// (hash of the raw key primitive, not the DER SPKI) and match it against the
	// OOB entries imported from recog badkeys.xml. Catches default/shared keys for
	// vendors we have no local firmware key material for (Huawei iBMC, Oracle ILOM,
	// Inspur, H3C HDM, Quanta, Nokia, Raritan, ...). Reported only when the richer
	// SPKI/cert matches above did not already fire.
	if bkh, ok := BadKeyHash(leaf.PublicKey); ok {
		ci.BadKeyHash = bkh
		if bk, matched := MatchBadKey(bkh); matched {
			ci.BadKeyMatch = &bk
			if ci.Vendor == "" {
				ci.Vendor = bk.Vendor
				ci.Product = bk.Product
			}
			if ci.SharedKeyMatch == nil && ci.SharedKeyBySPKI == nil {
				ci.Findings = append(ci.Findings, fmt.Sprintf(
					"KNOWN-BAD/DEFAULT KEY (badkeys.xml): served TLS key is a known %s %s default/shared key (%s) - %s",
					bk.Vendor, bk.Product, bk.Device, bk.Note))
			}
		}
	}
	// When the cert is not a known shipped default, still try to attribute the
	// BMC vendor from the subject/issuer DN using the built-in rules. Many
	// BMCs regenerate a per-unit cert (so the fingerprint won't match a shipped
	// default) but keep a vendor-identifying DN (O=Super Micro Computer,
	// O=Dell Inc.,L=Round Rock, CN=<C-series> CIMC, OU=ISS/O=Hewlett Packard...).
	if v, p, ok := bmcfp.MatchAll(map[bmcfp.Kind]string{
		bmcfp.TLSSubjectDN: leaf.Subject.String(),
		bmcfp.TLSIssuerDN:  leaf.Issuer.String(),
	}); ok {
		ci.Vendor = v
		ci.Product = p
	}
	// Mutual-TLS detection: a server that requests a client cert and presents an
	// AMI MegaRAC default identity is the precondition for the shipped-CA
	// passwordless-admin bypass (the firmware CA private key, CN=www.ami.com, is
	// public and byte-identical across OEMs). We report the precondition; active
	// confirmation = present a CA-signed CN=<admin> cert (PoC in the finding doc).
	ci.ClientCertRequested = reqClientCert
	ci.AcceptableCAs = acceptableCAs
	if reqClientCert {
		// A CertificateRequest that names acceptable issuer DNs validates by CA
		// chain, so any cert that CA signed is accepted. That is the difference
		// between a shipped CA private key being a forgeable trust anchor and being
		// inert: a listener that pins one certificate advertises no CA DN.
		if len(acceptableCAs) > 0 {
			ci.Findings = append(ci.Findings, fmt.Sprintf(
				"mutual-TLS validates by CA chain -- server advertises %d acceptable client-CA DN(s): %s. Any certificate signed by one of these is accepted, so a CA whose private key ships in public firmware is a forgeable trust anchor here.",
				len(acceptableCAs), strings.Join(acceptableCAs, "; ")))
		} else {
			ci.Findings = append(ci.Findings, "mutual-TLS requested with no acceptable-CA DN advertised -- consistent with certificate pinning rather than CA-chain validation (a shipped CA key may be inert on this listener)")
		}
		isAMI := (ci.SharedKeyMatch != nil && ci.SharedKeyMatch.Vendor == "ami") ||
			(ci.DefaultSubject != nil && ci.DefaultSubject.Vendor == "ami") ||
			ci.Vendor == "ami"
		if isAMI {
			ci.Findings = append(ci.Findings, "AMI MegaRAC mTLS client-cert auth ENABLED -- shipped-CA passwordless-admin bypass LIKELY. The firmware CA (CN=www.ami.com) private key is public and its CN=Administrator client cert is byte-identical across AMI OEMs, so a client cert signed by that CA authenticates with no password (server maps user = SSL_CLIENT_S_DN_CN).")
		} else {
			ci.Findings = append(ci.Findings, "server requests a client certificate (mutual-TLS auth enabled) -- review the trusted client CA")
		}
	}
	if ci.Expired {
		ci.Findings = append(ci.Findings, "certificate is expired or not-yet-valid")
	}
	if ci.SelfSigned {
		ci.Findings = append(ci.Findings, "self-signed certificate")
	}
	if ci.KeyBits > 0 && ci.KeyBits < 2048 {
		ci.Findings = append(ci.Findings, fmt.Sprintf("weak RSA key (%d bits)", ci.KeyBits))
	}
	return ci, nil
}

// parseCADN renders one DER-encoded RDNSequence from a TLS CertificateRequest's
// certificate_authorities list as a readable DN string. The wire form is a bare
// RDNSequence, not a full Name, so it cannot go through x509.ParseCertificate;
// crypto/x509/pkix unmarshals it directly. A DN that fails to parse yields "" and
// is skipped rather than surfaced as garbage, since this value decides whether a
// shipped CA key is a live trust anchor.
func parseCADN(raw []byte) string {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &rdns); err != nil {
		return ""
	}
	var name pkix.Name
	name.FillFromRDNSequence(&rdns)
	dn := name.String()
	if dn == "" {
		return ""
	}
	return sanitizeDN(dn)
}

// sanitizeDN strips control characters and collapses whitespace so a hostile DN
// cannot inject newlines or ANSI escapes into finding output or the explain pane.
func sanitizeDN(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			// drop other control bytes
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(strings.Join(strings.Fields(b.String()), " "))
}

func colonHexUpper(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}
