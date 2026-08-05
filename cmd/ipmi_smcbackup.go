package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func applySMCChunk(x *ipmi.SMCConfigXfer) {
	if ipmiSMCChunk > 0 {
		x.UploadChunk = ipmiSMCChunk
		x.DownloadChunk = ipmiSMCChunk
	}
}

func resolveSMCCrypto(ctx context.Context, sess *ipmi.CmdSess) (key, iv []byte, cipher ipmi.SMCConfigCipher, gen string, err error) {

	if ipmiSMCConfigKey != "" || ipmiSMCConfigCipher != "" || ipmiSMCConfigIV != "" {
		cipher = ipmi.SMCConfigCipher(strings.ToLower(strings.TrimSpace(ipmiSMCConfigCipher)))
		if cipher == "" {
			cipher = ipmi.SMCCipherAES128CBC
		}
		if ipmiSMCConfigKey == "" {
			return nil, nil, cipher, "", fmt.Errorf("--config-cipher/--config-iv require --config-key")
		}
		key, err = hex.DecodeString(strings.TrimPrefix(ipmiSMCConfigKey, "0x"))
		if err != nil {
			return nil, nil, cipher, "", fmt.Errorf("invalid --config-key: %w", err)
		}

		switch {
		case ipmiSMCConfigIV != "":
			iv, err = hex.DecodeString(strings.TrimPrefix(ipmiSMCConfigIV, "0x"))
			if err != nil {
				return nil, nil, cipher, "", fmt.Errorf("invalid --config-iv: %w", err)
			}
		case cipher == ipmi.SMCCipher3DESCBC:
			iv = make([]byte, 8)
		default:
			iv = ipmi.SMCObfuscationIV
		}
		return key, iv, cipher, "", nil
	}

	g, gerr := sess.SMCGeneration(ctx)
	if gerr != nil {
		return nil, nil, "", "", fmt.Errorf("could not detect generation (pass --config-key/--config-cipher): %w", gerr)
	}
	gen = g.Generation
	prof, ok := ipmi.SMCCryptoProfileForGeneration(gen)
	if !ok {
		return nil, nil, "", gen, fmt.Errorf("no built-in config profile for generation %q (model %q); pass --config-key and --config-cipher", gen, g.ModelPrefix)
	}
	return prof.Key, prof.IV, prof.Cipher, gen, nil
}

func resolveSMCInnerPassword() []byte {
	if ipmiSMCConfigInnerPass != "" {
		return []byte(ipmiSMCConfigInnerPass)
	}
	return ipmi.SMCConfigInnerPassword
}

func peelSMCInnerLayer(salted []byte) (tgz []byte, ok bool, err error) {
	pass := resolveSMCInnerPassword()
	pt, gz, ierr := ipmi.SMCOpenSSLSaltedUnwrap(salted, pass)
	if ierr != nil {
		return nil, false, fmt.Errorf("inner openssl-enc unwrap failed: %w", ierr)
	}
	if !gz {
		return nil, false, fmt.Errorf("inner openssl-enc unwrapped, but result is not gzip (wrong inner password; override with --config-inner-pass)")
	}
	return pt, true, nil
}

func sanitizeHostForFile(host string) string {
	r := strings.NewReplacer("/", "_", ":", "_", "%", "_", "[", "", "]", "", " ", "_")
	s := r.Replace(host)
	if s == "" {
		s = "target"
	}
	return s
}

func runIPMISMCBackup(ctx context.Context, sess *ipmi.CmdSess, _ []string) (any, error) {
	host := sanitizeHostForFile(sess.Host())
	key, iv, cipher, gen, keyErr := resolveSMCCrypto(ctx, sess)

	xfer := ipmi.NewSMCConfigXfer(sess)
	applySMCChunk(xfer)
	blob, err := xfer.Export(ctx, ipmi.SMCFileTypeConfig)
	if err != nil {
		return nil, err
	}

	outPath := ipmiSMCOut
	if outPath == "" {
		outPath = fmt.Sprintf("smc-backup-%s.bin", host)
	}
	if err := os.WriteFile(outPath, blob, 0o600); err != nil {
		return nil, fmt.Errorf("writing %s: %w", outPath, err)
	}

	res := map[string]any{
		"action":        "smcbackup",
		"generation":    gen,
		"cipher":        string(cipher),
		"encryptedFile": outPath,
		"encryptedSize": len(blob),
	}
	if ipmi.SMCLooksGzip(blob) {
		res["note"] = "exported blob is already gzip: this generation did not encrypt it"
	}

	if ipmiSMCNoDecrypt {
		return res, nil
	}
	if key == nil {
		res["decrypt"] = fmt.Sprintf("skipped: %v", keyErr)
		return res, nil
	}
	pt, crcOK, derr := ipmi.SMCContainerUnwrap(blob, key, iv, cipher)
	if derr != nil {
		res["decrypt"] = fmt.Sprintf("failed: %v", derr)
		return res, nil
	}
	res["crcOK"] = crcOK
	res["plaintextIsGzip"] = ipmi.SMCLooksGzip(pt)

	if crcOK && ipmi.SMCLooksOpenSSLSalted(pt) {

		res["innerFormat"] = "openssl-enc-salted"
		inner, ok, ierr := peelSMCInnerLayer(pt)
		if ierr != nil {
			res["decrypt"] = ierr.Error()
			saltedOut := strings.TrimSuffix(outPath, ".bin") + ".openssl-salted.bin"
			if werr := os.WriteFile(saltedOut, pt, 0o600); werr == nil {
				res["innerBlobFile"] = saltedOut
			}
			return res, nil
		}
		_ = ok
		res["innerDecrypted"] = true
		pt = inner
	}
	if !crcOK && !ipmi.SMCLooksGzip(pt) {
		res["decrypt"] = "wrong key: CRC mismatch and output is not gzip"
		return res, nil
	}
	tgz := strings.TrimSuffix(outPath, ".bin") + ".tar.gz"
	if err := os.WriteFile(tgz, pt, 0o600); err != nil {
		return nil, fmt.Errorf("writing %s: %w", tgz, err)
	}
	res["decryptedFile"] = tgz
	res["decryptedSize"] = len(pt)
	if names, nerr := ipmi.SMCArchiveMemberNames(pt); nerr == nil {
		res["members"] = len(names)
	}
	return res, nil
}
