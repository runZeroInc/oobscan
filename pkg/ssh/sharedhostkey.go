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

type SharedHostKey struct {
	Vendor      string
	Product     string
	Fingerprint string
	KeyType     string
	Note        string
}

type HostKeyCapture struct {
	KeyType     string
	Fingerprint string
	BKHash      string
	BadKey      tlscert.BadKey
	BadKeyMatch bool
	SharedKey   SharedHostKey
	SharedMatch bool
}

var knownSharedHostKeys = []SharedHostKey{
	{

		Vendor: "cyberpower", Product: "RMCARD205/305",
		Fingerprint: "SHA256:PG6ZKj40PRyaRboZNT+dkNq7Nc/MUDvvHvKsPpy0O/E",
		KeyType:     "ssh-ed25519",
		Note:        "fleet-wide ed25519 SSH host key baked into firmware (comment 'default_hostkey'); private key is public -> SSH host-key impersonation / MITM",
	},
	{

		Vendor: "eaton", Product: "Power Xpert Gateway (PXGX/PXGMS)",
		Fingerprint: "SHA256:oeY2TPdubQnAxUhXloV65tmB8v2gDMg1lDxLpaghe+4",
		KeyType:     "ssh-rsa",
		Note:        "fleet-wide RSA-2048 SSH host key shipped in firmware (comment mlcreech@localhost), shared PXGX-UPS/PXGMS -> SSH host-key impersonation / MITM",
	},
	{

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

func HostKeyFingerprint(pub xssh.PublicKey) string {
	sum := sha256.Sum256(pub.Marshal())
	return "SHA256:" + base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(sum[:])
}

func HostKeyBadKey(pub xssh.PublicKey) (bkhash string, bk tlscert.BadKey, ok bool) {
	h, hok := tlscert.BadKeyHash(pub)
	if !hok {
		return "", tlscert.BadKey{}, false
	}
	bk, ok = tlscert.MatchBadKey(h)
	return h, bk, ok
}

func MatchSharedHostKey(fingerprint string) (shk SharedHostKey, ok bool) {
	for i := range knownSharedHostKeys {
		if knownSharedHostKeys[i].Fingerprint == fingerprint {
			return knownSharedHostKeys[i], true
		}
	}
	return SharedHostKey{}, false
}

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

var errNoHostKey = errNoKey("ssh: no host key captured")

type errNoKey string

func (e errNoKey) Error() string { return string(e) }
