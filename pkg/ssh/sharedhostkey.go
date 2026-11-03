package ssh

import (
	"crypto/sha256"
	"encoding/base64"
	"net"
	"strconv"
	"time"

	xssh "github.com/runZeroInc/excrypto/x/crypto/ssh"

	"github.com/runZeroInc/oobscan/pkg/tlscert"
)

// SharedHostKey is an SSH host key that ships byte-identical across every unit
// of a product family. Like a shipped TLS private key (see pkg/tlscert),
// a fleet-wide host key means the matching private key is public in firmware:
// an attacker who extracts it can impersonate any unit (MITM the SSH session,
// defeating the host-key trust that SSH exists to provide).
//
// Match is by the OpenSSH SHA-256 fingerprint of the public key blob
// ("SHA256:<base64>", the same string `ssh-keygen -lf` prints), which is stable
// regardless of the key type/comment.
type SharedHostKey struct {
	Vendor      string
	Product     string
	Fingerprint string // "SHA256:..." (base64, no trailing '=', OpenSSH style)
	KeyType     string // e.g. "ssh-ed25519"
	Note        string
}

// HostKeyCapture carries the captured SSH server host-key metadata.
type HostKeyCapture struct {
	KeyType     string
	Fingerprint string
	BKHash      string
	BadKey      tlscert.BadKey
	BadKeyMatch bool
	SharedKey   SharedHostKey
	SharedMatch bool
}

// knownSharedHostKeys are shipped/fleet-wide SSH host keys recovered from
// firmware. Fingerprints were computed with ssh-keygen over the extracted key.
var knownSharedHostKeys = []SharedHostKey{
	{
		// CyberPower RMCARD205/305 v1.6.0 bakes a valid openssh-key-v1 ed25519
		// private host key (comment "default_hostkey") into the firmware at flash
		// 0x08193B48, loaded by the SSH init routine. It is the same key on every
		// unit -> extract it once, impersonate any RMCARD's SSH endpoint (MITM).
		// Verified by extracting the OpenSSH private-key block and reproducing this
		// fingerprint with ssh-keygen.
		Vendor: "cyberpower", Product: "RMCARD205/305",
		Fingerprint: "SHA256:PG6ZKj40PRyaRboZNT+dkNq7Nc/MUDvvHvKsPpy0O/E",
		KeyType:     "ssh-ed25519",
		Note:        "fleet-wide ed25519 SSH host key baked into firmware (comment 'default_hostkey'); private key is public -> SSH host-key impersonation / MITM",
	},
	{
		// Eaton Power Xpert Gateway ships /ro/etc/ssh/ssh_host_rsa_key
		// byte-identical across both products.
		Vendor: "eaton", Product: "Power Xpert Gateway (PXGX/PXGMS)",
		Fingerprint: "SHA256:oeY2TPdubQnAxUhXloV65tmB8v2gDMg1lDxLpaghe+4",
		KeyType:     "ssh-rsa",
		Note:        "fleet-wide RSA-2048 SSH host key shipped in firmware (comment mlcreech@localhost), shared PXGX-UPS/PXGMS -> SSH host-key impersonation / MITM",
	},
	{
		// Lantronix Spider KVM 4.x /etc/dropbear/dropbear_rsa_host_key is baked into
		// the rootfs and seeded to flash, so it survives factory reset.
		Vendor: "lantronix", Product: "Spider KVM 4.x",
		Fingerprint: "SHA256:hhD1uocTDde09K+J9Exp5BE/TRTg79Nqg0kLyzzBXzY",
		KeyType:     "ssh-rsa",
		Note:        "fleet-wide Dropbear RSA host key baked in Spider 4.x rootfs (survives factory reset) -> SSH host-key impersonation / MITM",
	},
	{
		Vendor: "lantronix", Product: "Spider KVM 4.x",
		Fingerprint: "SHA256:JFZt8harSNzynsjjvMKS4+sQzw8FD2ZcvVYkJXsKc7o",
		KeyType:     "ssh-dss",
		Note:        "fleet-wide Dropbear DSS host key baked in Spider 4.x rootfs -> SSH host-key impersonation / MITM",
	},
	{
		// Lantronix / Transition Networks IONMM media converter ships a shared
		// /etc/dropbear/dropbear_rsa_host_key in the rootfs.
		Vendor: "lantronix", Product: "TNI IONMM media converter",
		Fingerprint: "SHA256:UnbeVjwZmp1/OgbfxKsnSbIXKQrxQpk6wmhwuOOb1PQ",
		KeyType:     "ssh-rsa",
		Note:        "fleet-wide Dropbear RSA host key shipped in IONMM firmware -> SSH host-key impersonation / MITM",
	},
	{
		Vendor: "lantronix", Product: "TNI IONMM media converter",
		Fingerprint: "SHA256:Jw/KFuSjQuxSLgttakhipYNk3gzww8Ct3wxEHV3CyUw",
		KeyType:     "ssh-dss",
		Note:        "fleet-wide Dropbear DSS host key shipped in IONMM firmware -> SSH host-key impersonation / MITM",
	},
	{
		// H3C HDM2 (Debian) and HDM3 (OpenBMC) ship /etc/ssh/ssh_host_rsa_key
		// byte-identical in every firmware image (comment "sysadmin@HDM"), and
		// /etc/init.d/sshd.sh only chmods it -- there is no ssh-keygen -A first-boot
		// regeneration, so the same private key is on every HDM2/HDM3 unit.
		// Verified across hdm2-1.22/2.30/2.31 and hdm3-2.06.02; bkhash wZB8T0k1CU/W7AbBiv1b.
		Vendor: "h3c", Product: "HDM2/HDM3 BMC",
		Fingerprint: "SHA256:wC3o1vT7LNMZcDOT4YBR+PlTH1nzNeb+atUorjCjXTw",
		KeyType:     "ssh-rsa",
		Note:        "fleet-wide RSA-3072 SSH host key shipped in HDM2/HDM3 firmware (comment sysadmin@HDM), no first-boot regen -> SSH host-key impersonation / MITM",
	},
	{
		Vendor: "h3c", Product: "HDM2/HDM3 BMC",
		Fingerprint: "SHA256:1v4RYLO9AAf3P3u1XwpMnXUUFrWB5eYsADAeVIp2yfs",
		KeyType:     "ssh-ed25519",
		Note:        "fleet-wide ed25519 SSH host key shipped in HDM2/HDM3 firmware (comment sysadmin@HDM), no first-boot regen -> SSH host-key impersonation / MITM",
	},
	{
		// Sierra Wireless AirLink ALEOS ships etc/dropbear_{rsa,ecdsa}_host_key
		// baked into the read-only SquashFS, byte-identical across RV50 4.16 and
		// RV55 4.18 (and by scheme MP70/LX40/LX60). dropbear.i only regenerates a
		// key that is missing/empty or when MSCIID_CFG_MAKE_SSH_KEYS=1, so the
		// shipped posture is a shared host key. Fingerprints computed with
		// ssh-keygen over the extracted keys; file SHA-256 83a4d168.../c4d7be9e...;
		// bkhashes Hlj/L0gDKtOqkBNlXvhg / 8y1de1e89X4lv2thEgHp.
		Vendor: "sierra", Product: "AirLink ALEOS (RV50/RV55)",
		Fingerprint: "SHA256:iuxeW3h71pKpYK+PwWG/7ztNAIUom1sdrEu9DbCXwec",
		KeyType:     "ssh-rsa",
		Note:        "fleet-wide Dropbear RSA-2048 SSH host key baked in the read-only SquashFS, byte-identical RV50/RV55, no per-unit regen by default -> SSH host-key impersonation / MITM",
	},
	{
		Vendor: "sierra", Product: "AirLink ALEOS (RV50/RV55)",
		Fingerprint: "SHA256:c6bKq+FIyClFG5TdLztGDKMb5LzCkzl8JzfoDo90sKY",
		KeyType:     "ecdsa-sha2-nistp521",
		Note:        "fleet-wide Dropbear ECDSA nistp521 SSH host key baked in the read-only SquashFS, byte-identical RV50/RV55 -> SSH host-key impersonation / MITM",
	},
}

// HostKeyFingerprint returns the OpenSSH SHA-256 fingerprint of a public key
// blob ("SHA256:<base64>"), matching `ssh-keygen -lf`.
func HostKeyFingerprint(pub xssh.PublicKey) string {
	sum := sha256.Sum256(pub.Marshal())
	return "SHA256:" + base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(sum[:])
}

// HostKeyBadKey computes the badkeys.xml "bkhash" of an SSH host public key and
// cross-references it against the OOB entries imported from recog badkeys.xml
// (Dell Secure Connect Gateway, Opengear, Eaton PXG, CyberPower RMCARD, ...).
// The bkhash hashes the raw key primitive (RSA modulus / ECDSA X / ed25519
// bytes / DSA Y), so it matches badkeys.xml regardless of the SSH wrapper. It
// is a different hash space from the OpenSSH SHA-256 host-key fingerprint used
// by MatchSharedHostKey. ok is false when the bkhash is not a known bad key.
func HostKeyBadKey(pub xssh.PublicKey) (bkhash string, bk tlscert.BadKey, ok bool) {
	h, hok := tlscert.BadKeyHash(pub)
	if !hok {
		return "", tlscert.BadKey{}, false
	}
	bk, ok = tlscert.MatchBadKey(h)
	return h, bk, ok
}

// MatchSharedHostKey reports whether an OpenSSH SHA-256 host-key fingerprint is
// a known shipped/fleet-wide key. ok is false when the fingerprint is unknown.
func MatchSharedHostKey(fingerprint string) (shk SharedHostKey, ok bool) {
	for i := range knownSharedHostKeys {
		if knownSharedHostKeys[i].Fingerprint == fingerprint {
			return knownSharedHostKeys[i], true
		}
	}
	return SharedHostKey{}, false
}

// CaptureHostKeyEx opens a TCP+SSH transport to host:port purely to record the
// server's host key (no authentication is attempted). It returns the key type,
// the OpenSSH SHA-256 fingerprint, and any shared-host-key match. The handshake
// intentionally fails at the auth stage (no credentials), which is expected and
// not treated as an error once the host key has been captured.
func CaptureHostKeyEx(host string, port int, timeout time.Duration) (cap HostKeyCapture, err error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	cfg := &xssh.ClientConfig{
		User: "oobscan",
		Auth: []xssh.AuthMethod{},
		HostKeyCallback: func(_ string, _ net.Addr, key xssh.PublicKey) error {
			cap.KeyType = key.Type()
			cap.Fingerprint = HostKeyFingerprint(key)
			if bkhash, bk, ok := HostKeyBadKey(key); ok {
				cap.BKHash = bkhash
				cap.BadKey = bk
				cap.BadKeyMatch = true
			} else if bkhash, hok := tlscert.BadKeyHash(key); hok {
				cap.BKHash = bkhash
			}
			return nil
		},
		Timeout: timeout,
	}
	// Preserve default KEX support (modern + compatible) and broaden ciphers /
	// host-key algorithms for older BMC daemons.
	cfg.Ciphers = append(cfg.Ciphers, "aes128-cbc", "3des-cbc", "aes128-ctr")
	//nolint:staticcheck // Detection must negotiate DSA host keys still shipped by BMCs.
	cfg.HostKeyAlgorithms = append(cfg.HostKeyAlgorithms,
		xssh.KeyAlgoED25519, xssh.KeyAlgoRSA, xssh.KeyAlgoRSASHA256, xssh.KeyAlgoRSASHA512,
		xssh.KeyAlgoECDSA256, xssh.KeyAlgoECDSA384, xssh.KeyAlgoECDSA521, xssh.KeyAlgoDSA)

	conn, dialErr := net.DialTimeout("tcp", addr, timeout)
	if dialErr != nil {
		return HostKeyCapture{}, dialErr
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	c, _, _, hsErr := xssh.NewClientConn(conn, addr, cfg)
	if c != nil {
		_ = c.Close()
	}
	// The host-key callback fires during the handshake, before auth. If we got a
	// key, the (expected) auth failure is irrelevant.
	if cap.Fingerprint == "" {
		if hsErr != nil {
			return HostKeyCapture{}, hsErr
		}
		return HostKeyCapture{}, errNoHostKey
	}
	cap.SharedKey, cap.SharedMatch = MatchSharedHostKey(cap.Fingerprint)
	return cap, nil
}

func CaptureHostKey(host string, port int, timeout time.Duration) (keyType, fingerprint string, shk SharedHostKey, shared bool, err error) {
	cap, err := CaptureHostKeyEx(host, port, timeout)
	if err != nil {
		return "", "", SharedHostKey{}, false, err
	}
	return cap.KeyType, cap.Fingerprint, cap.SharedKey, cap.SharedMatch, nil
}

// errNoHostKey is returned when a handshake completed without exposing a key.
var errNoHostKey = errNoKey("ssh: no host key captured")

type errNoKey string

func (e errNoKey) Error() string { return string(e) }
