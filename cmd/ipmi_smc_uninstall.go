package cmd

// smc-uninstall removes the stunnel shell or a legacy oobtsnet chain from an
// SMC ATEN BMC by rebuilding the config archive with its members stripped,
// re-encrypting, and restoring it.
// Applying the rebuilt archive cold-resets the BMC. Separate runtime artifacts
// and configuration changes require operator verification.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// runIPMISMCUninstall rebuilds the config archive without our payload and
// restores it. Without --apply it only stages the upload.
func runIPMISMCUninstall(ctx context.Context, sess *ipmi.CmdSess, _ []string) (any, error) {
	host := sanitizeHostForFile(sess.Host())
	key, iv, cipher, gen, keyErr := resolveSMCCrypto(ctx, sess)
	if key == nil {
		return nil, keyErr
	}

	// 1. Base decrypted archive, peeling the inner openssl-salted layer when
	// present (X9/X10 FW 3.5x).
	var baseTGZ []byte
	var innerPass []byte
	if smcFrom != "" {
		b, err := os.ReadFile(smcFrom)
		if err != nil {
			return nil, fmt.Errorf("reading --from %s: %w", smcFrom, err)
		}
		if !ipmi.SMCLooksGzip(b) {
			pt, crcOK, derr := ipmi.SMCContainerUnwrap(b, key, iv, cipher)
			if derr != nil || (!crcOK && !ipmi.SMCLooksGzip(pt)) {
				return nil, fmt.Errorf("--from is neither a gzip tar nor a decryptable backup for this key")
			}
			b = pt
		}
		if ipmi.SMCLooksOpenSSLSalted(b) {
			pt, ok, ierr := peelSMCInnerLayer(b)
			if ierr != nil {
				return nil, fmt.Errorf("--from: %w", ierr)
			}
			b, innerPass = pt, resolveSMCInnerPassword()
			_ = ok
		}
		baseTGZ = b
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

	// 2. Strip our launchers and remove/neutralize our added members.
	//
	// The launcher strip (removing the appended block from the sourced member) is
	// the reliable kill switch on every generation: it stops phase-2 (and the
	// stunnel shell) from being launched at boot. The added members are handled
	// two ways for cross-generation cleanliness:
	//   - Remove drops them from the archive (X10/X13/H13SSF no-guard copy loops
	//     then delete the /nv files).
	//   - Overwrite replaces them with inert content on generations whose copy
	//     loop has an existence guard (H13 F401MS): those boards do not delete
	//     absent members, so we replace the file in place to clear the binary.
	inert := []byte("# oobscan: removed\n")
	edit := ipmi.SMCArchiveEdit{
		Replace: map[string][]byte{
			// Neutralize (not just drop) so guard-loops replace the orphaned files.
			ipmi.SMCTailnetBinName:       inert,
			ipmi.SMCTailnetConfName:      inert,
			ipmi.SMCX9CarrierName:        inert,
			ipmi.SMCShellServiceConfName: inert,
		},
		Remove: []string{},
	}

	// Strip the phase-2 launcher block from syslog.conf (or netconfig0), and the
	// stunnel shell launcher block too. service.conf is included because X9
	// 3.5x/3.62 sources it outright, so it can host a launcher (see
	// BuildSMCShellServiceConf).
	for _, hostName := range []string{ipmi.SMCShellSyslogConfName, ipmi.SMCShellNetconfigName, ipmi.SMCShellServiceName} {
		cur, ok, err := ipmi.SMCArchiveMember(baseTGZ, hostName)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", hostName, err)
		}
		if !ok {
			continue
		}
		stripped, tOK := ipmi.StripSMCTailnetLauncher(cur)
		stripped, sOK := ipmi.StripSMCDebugShellLauncher(stripped)
		if tOK || sOK {
			edit.Replace[hostName] = stripped
		}
	}

	// hostname_for_dhcp is interpolated RAW into udhcpc --hostname on X9/X10, so
	// the telnetd/TLS/phase-2 injection always starts with "x;". Reset it to the
	// X9 factory hostname so a purged board does not resurrect a shell on boot.
	// A hostname the operator set (no leading "x;") is left alone.
	if hd, ok, err := ipmi.SMCArchiveMember(baseTGZ, ipmi.SMCShellHostnameDHCPName); err == nil && ok {
		if bytes.HasPrefix(hd, []byte("x;")) {
			edit.Replace[ipmi.SMCShellHostnameDHCPName] = []byte("smash-bmc")
		}
	}

	rebuilt, report, err := ipmi.SMCRebuildArchive(baseTGZ, edit)
	if err != nil {
		return nil, fmt.Errorf("rebuilding archive: %w", err)
	}

	// 3. Encrypt and self-check (re-apply inner layer when present).
	inner := rebuilt
	if innerPass != nil {
		inner, err = ipmi.SMCOpenSSLSaltedWrap(rebuilt, innerPass)
		if err != nil {
			return nil, fmt.Errorf("re-encrypting inner layer: %w", err)
		}
	}
	ct, err := ipmi.SMCContainerWrap(inner, key, iv, cipher)
	if err != nil {
		return nil, fmt.Errorf("encrypting archive: %w", err)
	}
	pt, crcOK, uerr := ipmi.SMCContainerUnwrap(ct, key, iv, cipher)
	if uerr != nil || !crcOK {
		return nil, fmt.Errorf("internal: re-encrypted archive failed self-check (crcOK=%v err=%v)", crcOK, uerr)
	}
	if innerPass != nil {
		if p2, gz, e2 := ipmi.SMCOpenSSLSaltedUnwrap(pt, innerPass); e2 != nil || !gz {
			return nil, fmt.Errorf("internal: inner-layer self-check failed (gzip=%v err=%v)", gz, e2)
		} else {
			pt = p2
		}
	}
	if !ipmi.SMCLooksGzip(pt) {
		return nil, fmt.Errorf("internal: re-encrypted archive self-check: recovered payload is not gzip")
	}

	// 4. Local artifact.
	outDir := smcOut
	if outDir == "" {
		outDir = fmt.Sprintf("smc-uninstall-%s", host)
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", outDir, err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "config.uninstall.bin"), ct, 0o600); err != nil {
		return nil, fmt.Errorf("writing artifact: %w", err)
	}

	res := map[string]any{
		"action":          "smc-uninstall",
		"generation":      gen,
		"cipher":          string(cipher),
		"innerLayer":      innerPass != nil,
		"archiveReplaced": report.Replaced,
		"archiveRemoved":  report.Removed,
		"artifactDir":     outDir,
		"encryptedSize":   len(ct),
	}

	// 5. Stage + optional apply.
	xfer := ipmi.NewSMCConfigXfer(sess)
	applySMCChunk(xfer)
	rid, err := xfer.Upload(ctx, ct)
	if err != nil {
		return nil, fmt.Errorf("uploading archive: %w", err)
	}
	res["reservationID"] = fmt.Sprintf("0x%04x", rid)

	if !smcApply {
		res["applied"] = false
		res["note"] = "staged only; pass --apply to commit the cleaned archive and reboot the BMC"
		return res, nil
	}

	cc, aerr := xfer.Apply(ctx, rid, ipmi.SMCFileTypeConfig)
	res["applied"] = true
	if aerr != nil {
		res["applyReply"] = fmt.Sprintf("no reply (expected: BMC is rebooting): %v", aerr)
	} else {
		res["applyReply"] = fmt.Sprintf("cc=0x%02x", cc)
	}
	res["note"] = "uninstall committed; verify service removal after the BMC reboots"
	return res, nil
}
