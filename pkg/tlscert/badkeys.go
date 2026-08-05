package tlscert

import (
	"bytes"
	"crypto/dsa" //nolint:staticcheck // SA1019: DSA host keys still ship on legacy BMC/OOB devices
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"

	exdsa "github.com/runZeroInc/excrypto/crypto/dsa" //nolint:staticcheck // Required to fingerprint shipped DSA keys.
	execdsa "github.com/runZeroInc/excrypto/crypto/ecdsa"
	exed25519 "github.com/runZeroInc/excrypto/crypto/ed25519"
	exrsa "github.com/runZeroInc/excrypto/crypto/rsa"
	xssh "github.com/runZeroInc/excrypto/x/crypto/ssh"
)

type BadKey struct {
	BKHash  string
	Vendor  string
	Product string
	Device  string
	Kind    string
	Note    string
}

var knownBadKeys = []BadKey{
	{BKHash: "rttrbveGuwdJQ1SYau8+", Vendor: "ami", Product: "MegaRAC", Device: "Lights Out Management", Kind: "FW/TLS", Note: "AMI MegaRAC default/shared TLS key (badkeys.xml variant 1)"},
	{BKHash: "KCIhnHihKCS7mBAgMLSt", Vendor: "ami", Product: "MegaRAC", Device: "Lights Out Management", Kind: "FW/TLS", Note: "AMI MegaRAC default/shared TLS key (badkeys.xml variant 2)"},
	{BKHash: "Eu5t3NrTDRLtKwpLLQVM", Vendor: "ami", Product: "MegaRAC", Device: "Lights Out Management", Kind: "FW/TLS", Note: "AMI MegaRAC default/shared TLS key (badkeys.xml variant 3)"},
	{BKHash: "nZi4Qrm/4oC/LFucGu47", Vendor: "aten", Product: "BMC", Device: "Lights Out Management", Kind: "FW/TLS", Note: "ATEN BMC default/shared TLS key"},
	{BKHash: "cp6xENLjreef8s5DbYfx", Vendor: "supermicro", Product: "IPMI", Device: "Lights Out Management", Kind: "FW/TLS", Note: "Supermicro IPMI default/shared TLS key"},
	{BKHash: "2gr/LCgigKgwE9zxZbNF", Vendor: "dell", Product: "Secure Connect Gateway", Device: "Remote Access Server", Kind: "FW/SSH", Note: "Dell Secure Connect Gateway default SSH host key"},
	{BKHash: "VJbv7jKrbezF76M0BdyT", Vendor: "dell", Product: "Secure Connect Gateway", Device: "Remote Access Server", Kind: "FW/SSH", Note: "Dell Secure Connect Gateway default SSH host key"},
	{BKHash: "pXSxqF0nmJqZ/wnO4xS6", Vendor: "dell", Product: "Secure Connect Gateway", Device: "Remote Access Server", Kind: "FW/SSH", Note: "Dell Secure Connect Gateway default SSH host key"},
	{BKHash: "tiqmLdX6UiLcg6EYpyPh", Vendor: "dell", Product: "Secure Connect Gateway", Device: "Remote Access Server", Kind: "FW/TLS", Note: "Dell Secure Connect Gateway default TLS key (9443)"},
	{BKHash: "R2dGlJAfldI9xtVMKQPJ", Vendor: "dell", Product: "Secure Connect Gateway", Device: "Remote Access Server", Kind: "FW/TLS", Note: "Dell Secure Connect Gateway default TLS key (443)"},
	{BKHash: "Km7mVdzkyGBo2/XUQj7m", Vendor: "h3c", Product: "HDM", Device: "Lights Out Management", Kind: "FW/TLS", Note: "H3C HDM BMC default/shared TLS key"},
	{BKHash: "nV0uP9zNZS3dnPy11hHD", Vendor: "huawei", Product: "iBMC", Device: "Management Console", Kind: "FW/TLS", Note: "Huawei iBMC default/shared TLS key"},
	{BKHash: "S7YmTb6gK0DHhzmlbqT2", Vendor: "inspur", Product: "BMC", Device: "Lights Out Management", Kind: "FW/TLS", Note: "Inspur BMC default/shared TLS key"},
	{BKHash: "HALDw7UycV32bzkG6Buf", Vendor: "lantronix", Product: "SLC", Device: "Management Console", Kind: "FW/TLS", Note: "Lantronix SLC console-manager default/shared TLS key"},
	{BKHash: "qSCmXZqB0GgIuRCXwSoz", Vendor: "lsp", Product: "Powercom", Device: "Power Device", Kind: "FW/TLS", Note: "LSP Powercom UPS network card default/shared TLS key"},
	{BKHash: "FKE+vLAuco3e/zm11YMT", Vendor: "microchip", Product: "MaxView", Device: "Management Console", Kind: "FW/TLS", Note: "Microchip MaxView storage-controller manager default/shared TLS key"},
	{BKHash: "eD7FldnmZAPyWac5v1v0", Vendor: "nokia", Product: "AirFrame BMC", Device: "Lights Out Management", Kind: "FW/TLS", Note: "Nokia AirFrame BMC default/shared TLS key"},
	{BKHash: "TS7N+VyfEOL1QR+ubIv/", Vendor: "opengear", Product: "Management Console", Device: "Device Server", Kind: "FW/SSH", Note: "Opengear console server default SSH host key"},
	{BKHash: "EjLXygBPF/Ts1oByPd7n", Vendor: "oracle", Product: "ILOM", Device: "Lights Out Management", Kind: "FW/TLS", Note: "Oracle ILOM default/shared TLS key (variant 1)"},
	{BKHash: "xA73aMFQ/mPQLjZA4ijg", Vendor: "oracle", Product: "ILOM", Device: "Lights Out Management", Kind: "FW/TLS", Note: "Oracle ILOM default/shared TLS key (variant 2)"},
	{BKHash: "IM+lAPVkEI/4EApQUNcf", Vendor: "quanta", Product: "BMC", Device: "Lights Out Management", Kind: "FW/TLS", Note: "Quanta BMC default/shared TLS key (variant 1)"},
	{BKHash: "Fn6VVePcncjaTP6JzH/N", Vendor: "quanta", Product: "BMC", Device: "Lights Out Management", Kind: "FW/TLS", Note: "Quanta BMC default/shared TLS key (variant 2)"},
	{BKHash: "gB2ZgNO9UXofmozWl/7G", Vendor: "raritan", Product: "Raritan", Device: "Power Device", Kind: "FW/TLS", Note: "Raritan default/shared TLS key (variant 1)"},
	{BKHash: "53weFZMBouunhtJ9rSvJ", Vendor: "raritan", Product: "Raritan", Device: "Power Device", Kind: "FW/TLS", Note: "Raritan default/shared TLS key (variant 2)"},
	{BKHash: "8XHZPUL9F5UmJ/vtSFrY", Vendor: "raritan", Product: "Raritan", Device: "Power Device", Kind: "FW/TLS", Note: "Raritan default/shared TLS key (variant 3)"},
	{BKHash: "hWRgN4kaSUyQ7BfEv8hj", Vendor: "roline", Product: "UPS", Device: "Power Device", Kind: "FW/TLS", Note: "Roline UPS network card default/shared TLS key"},
	{BKHash: "slgK3VAZt89tKKxKJpvP", Vendor: "cyberpower", Product: "UPS", Device: "Power Device", Kind: "FW/TLS", Note: "CyberPower UPS network card default/shared TLS key"},
	{BKHash: "D8nfUeoSHBOLO3H/JX33", Vendor: "toshiba", Product: "RemotEye", Device: "Power Device", Kind: "FW/TLS", Note: "Toshiba RemotEye 4 UPS manager default/shared TLS key"},
	{BKHash: "y1LAl7GkQ4GTLsrjZs/L", Vendor: "cyberpower", Product: "RMCARD205/305", Device: "Power Device", Kind: "FW/SSH", Note: "CyberPower RMCARD fleet-wide ed25519 SSH host key (comment default_hostkey); private key public in firmware -> host-key MITM"},
	{BKHash: "wlayBehyPNDSrvh5Gw9O", Vendor: "eaton", Product: "Power Xpert Gateway (PXGX/PXGMS)", Device: "Power Device", Kind: "FW/SSH", Note: "Eaton PXG fleet-wide RSA-2048 SSH host key (comment mlcreech@localhost), shared PXGX-UPS/PXGMS -> host-key MITM"},
	{BKHash: "VT8o68FObk0hSc3rWWm2", Vendor: "eaton", Product: "Power Xpert Gateway (PXGX/PXGMS)", Device: "Power Device", Kind: "FW/SSH", Note: "Eaton PXG fleet-wide DSA SSH host key, shared PXGX-UPS/PXGMS -> host-key MITM"},
	{BKHash: "wZB8T0k1CU/W7AbBiv1b", Vendor: "h3c", Product: "HDM2/HDM3 BMC", Device: "Lights Out Management", Kind: "FW/SSH", Note: "H3C HDM2/HDM3 fleet-wide RSA-3072 SSH host key (comment sysadmin@HDM), shipped in firmware with no first-boot regen -> host-key MITM"},
	{BKHash: "JDP7rsplKIC6pzE8DNTw", Vendor: "h3c", Product: "HDM2/HDM3 BMC", Device: "Lights Out Management", Kind: "FW/SSH", Note: "H3C HDM2/HDM3 fleet-wide ed25519 SSH host key (comment sysadmin@HDM), shipped in firmware with no first-boot regen -> host-key MITM"},
	{BKHash: "DKIUdcS9cVuel/WPENV5", Vendor: "eaton", Product: "ConnectUPS Web/SNMP", Device: "Power Device", Kind: "FW/TLS", Note: "Eaton ConnectUPS shipped 512-bit RSA key #1 (full private key recovered from firmware); 512-bit modulus is factorable + shared fleet-wide -> passive HTTPS decrypt/MITM/impersonation"},
	{BKHash: "I1XObVXQOJHKiihuxNxq", Vendor: "eaton", Product: "ConnectUPS Web/SNMP", Device: "Power Device", Kind: "FW/TLS", Note: "Eaton ConnectUPS shipped 512-bit RSA key #2 (modulus recovered; private half factorable at 512-bit) -> passive HTTPS decrypt/MITM/impersonation"},
	{BKHash: "8ptY7lq+1M6SlzTKaE13", Vendor: "eaton", Product: "ConnectUPS Web/SNMP", Device: "Power Device", Kind: "FW/TLS", Note: "Eaton ConnectUPS shipped 512-bit RSA key #3 (modulus recovered; private half factorable at 512-bit) -> passive HTTPS decrypt/MITM/impersonation"},
	{BKHash: "bNmvE5s+CXOu0OeuqaiW", Vendor: "eaton", Product: "NetworkMS/MGE-Pulsar (HE/LD/LE)", Device: "Power Device", Kind: "FW/TLS", Note: "Eaton NetworkMS shared RSA-1024 device key (full private key recovered from firmware, DES-EDE3-CBC PEM, passphrase 'password'); byte-identical across NetworkMS HE/LD/LE builds; SPKI a6338a90...0528871. Firmware-embedded management/device key: no live NetworkMS hardware, so it is unproven whether a unit serves it as its live TLS leaf on 443 -> treat a match as vendor+product-line-indicative (same caveat as the ConnectUPS moduli)"},
	{BKHash: "Co4KFzGZvaEfpIwlUx2f", Vendor: "lantronix", Product: "SGX5150/PremierWave/EDS", Device: "Management Console", Kind: "FW/TLS", Note: "Lantronix fleet-wide lantronix.key (RSA-2048, CN=Lantronix); HTTPS server key + .xcr config decrypt -> passive decrypt/MITM"},
	{BKHash: "WXgZ5sAHcAy4KOzKbRaP", Vendor: "blikvm", Product: "BliKVM (v1-v4)", Device: "Lights Out Management", Kind: "FW/TLS", Note: "BliKVM shared TLS cert+key baked in firmware, byte-identical v1-v4 -> fleet-wide passive decrypt/MITM"},
	{BKHash: "//jJvoICu3MHEJctzNhc", Vendor: "supermicro", Product: "X10 ATEN", Device: "Lights Out Management", Kind: "FW/TLS", Note: "Supermicro X10 usr/local/httpd/server.pem shipped default HTTPS key (CN=IPMI) -> passive decrypt/MITM"},
	{BKHash: "2ID0466nmJNeb8GY48q3", Vendor: "dell", Product: "iDRAC6", Device: "Lights Out Management", Kind: "FW/TLS", Note: "Dell iDRAC6 default host.key (CN=iDRAC6 default certificate); served with no unique-cert generation -> passive decrypt/MITM"},
	{BKHash: "/nsEBHr5PFUax8mcUewp", Vendor: "dell", Product: "iDRAC7/8/9", Device: "Lights Out Management", Kind: "FW/TLS", Note: "Dell iDRAC7/8 (and shipped iDRAC9) default host.key (CN=iDRAC8 default certificate), byte-identical D7->D9; served pre-first-boot -> passive decrypt/MITM"},
	{BKHash: "+rkriG8+XfOuy8xG7E2r", Vendor: "ami", Product: "MegaRAC Redfish CA", Device: "Lights Out Management", Kind: "FW/TLS", Note: "AMI MegaRAC Redfish CA (CN=www.ami.com, ca-key.pem) byte-identical ASRock/Gigabyte/Tyan; mint any CN client cert -> passwordless admin"},
	{BKHash: "4ocxYhci1mAjfSj88/Z8", Vendor: "ami", Product: "MegaRAC (CN=megarac.com)", Device: "Lights Out Management", Kind: "FW/TLS", Note: "AMI MegaRAC default server key (CN=megarac.com) byte-identical Tyan/Gigabyte -> passive HTTPS decrypt/MITM"},
	{BKHash: "5wFygZzCTu+aa4vl4GeH", Vendor: "ami", Product: "MegaRAC (CN=www.ami.com)", Device: "Lights Out Management", Kind: "FW/TLS", Note: "AMI MegaRAC default server key (CN=www.ami.com) byte-identical ASRock/Gigabyte -> passive HTTPS decrypt/MITM"},
	{BKHash: "7ybxpQOH+/SSTso0rdKC", Vendor: "ami", Product: "MegaRAC SP-X (CN=AMI)", Device: "Lights Out Management", Kind: "FW/TLS", Note: "AMI MegaRAC SP-X default server key (CN=AMI) shared ASRock Rack/ASUS -> passive HTTPS decrypt/MITM"},
	{BKHash: "Hi0pKJP/tW9J/pMMkbN6", Vendor: "ami", Product: "MegaRAC user.pem (CN=Administrator)", Device: "Lights Out Management", Kind: "FW/TLS", Note: "AMI MegaRAC pre-minted CN=Administrator client cert (user.pem, RSA-3072) shared ASRock/Gigabyte; presenting it authenticates as admin via mTLS"},
	{BKHash: "0W8iKD0cT1uafFFFq5Ii", Vendor: "raritan", Product: "PX3 Xerus (CN=Demo Certificate)", Device: "Power Device", Kind: "FW/TLS", Note: "Raritan PX3 (Xerus) shipped server_key_default.pem (RSA-2048, CN=Demo Certificate); served until operator replaces cert -> fleet-wide passive HTTPS decrypt / MITM"},
	{BKHash: "3gOnPlFxsZCsr6Ztgr67", Vendor: "sierra", Product: "AirLink ALEOS ACEmanager (CN=*.sierrawireless.com)", Device: "Remote Access Server", Kind: "FW/TLS", Note: "Sierra AirLink ALEOS ACEmanager fleet server.key (RSA-2048) byte-identical RV50/RV55 -> passive HTTPS decrypt / MITM"},
	{BKHash: "8at6LLitmmTMZcTRx0m6", Vendor: "h3c", Product: "HDM KVM/vMedia + HDM2/HDM3 HTTPS (CN=H3C)", Device: "Lights Out Management", Kind: "FW/TLS", Note: "H3C single RSA-2048 key (CN=H3C, O=New H3C Technologies) reused across ALL generations: Family-A (G3/G5 HDM) stunnel KVM/vMedia server key AND the HDM2/HDM3 lighttpd HTTPS server key -> passive decrypt / MITM of the web UI and KVM+vMedia tunnel fleet-wide"},
	{BKHash: "UnT0h3IQ3H3GmYIUBjTU", Vendor: "rittal", Product: "CMC III (ReOS 10.1.3)", Device: "Management Console", Kind: "FW/TLS", Note: "Rittal CMC III fleet-shared etc/reos-defaults/lighttpd/ssl/server.pem (RSA-4096, O=Rittal GmbH & Co. KG); restored to :443 at boot by S03filesystem, private key public in firmware -> passive HTTPS decrypt / MITM"},
	{BKHash: "Hlj/L0gDKtOqkBNlXvhg", Vendor: "sierra", Product: "AirLink ALEOS (RV50/RV55)", Device: "Remote Access Server", Kind: "FW/SSH", Note: "Sierra AirLink ALEOS fleet-wide Dropbear RSA-2048 SSH host key (etc/dropbear_rsa_host_key) byte-identical RV50/RV55, baked in read-only SquashFS, no per-unit regen by default -> SSH host-key impersonation / MITM"},
	{BKHash: "8y1de1e89X4lv2thEgHp", Vendor: "sierra", Product: "AirLink ALEOS (RV50/RV55)", Device: "Remote Access Server", Kind: "FW/SSH", Note: "Sierra AirLink ALEOS fleet-wide Dropbear ECDSA nistp521 SSH host key (etc/dropbear_ecdsa_host_key) byte-identical RV50/RV55, baked in read-only SquashFS -> SSH host-key impersonation / MITM"},
}

func BadKeyHash(pub any) (bkhash string, ok bool) {
	var rawb []byte
	switch p := pub.(type) {
	case xssh.PublicKey:
		if cpk, isCrypto := p.(xssh.CryptoPublicKey); isCrypto {
			return BadKeyHash(cpk.CryptoPublicKey())
		}
		return "", false
	case *rsa.PublicKey:
		rawb = p.N.Bytes()
	case *exrsa.PublicKey:
		rawb = p.N.Bytes()
	case *ecdsa.PublicKey:
		encoded, err := p.Bytes()
		if err != nil {
			return "", false
		}
		coordinateLen := (len(encoded) - 1) / 2
		if coordinateLen < 1 {
			return "", false
		}
		rawb = bytes.TrimLeft(encoded[1:1+coordinateLen], "\x00")
	case *execdsa.PublicKey:
		//nolint:staticcheck // excrypto lacks PublicKey.Bytes
		rawb = p.X.Bytes()
	case ed25519.PublicKey:
		rawb = p
	case exed25519.PublicKey:
		rawb = p
	case *dsa.PublicKey:
		rawb = p.Y.Bytes()
	case *exdsa.PublicKey:
		rawb = p.Y.Bytes()
	default:
		return "", false
	}
	sum := sha256.Sum256(rawb)
	return base64.RawStdEncoding.EncodeToString(sum[:15]), true
}

func MatchBadKey(bkhash string) (bk BadKey, ok bool) {
	if bkhash == "" {
		return BadKey{}, false
	}
	for i := range knownBadKeys {
		if knownBadKeys[i].BKHash == bkhash {
			return knownBadKeys[i], true
		}
	}
	return BadKey{}, false
}
