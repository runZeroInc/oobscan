package cmd

// Central flag registration for the IPMI and Supermicro/ATEN command families.
//
// `oobscan ipmi` and the top-level `smc-*` commands talk to the same BMC over
// the same stack, so their options are declared once here and bound onto each
// command that needs them. A command's init() names the groups it uses; nothing
// re-declares a flag it shares with a sibling.

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// IPMI transport and session options. Shared by `ipmi` and every smc-* command
// that reaches the BMC over IPMI.
var (
	ipmiPort           int
	ipmiUser           string
	ipmiPassword       string
	ipmiTimeout        time.Duration
	ipmiMaxRetries     int
	ipmiDisableSMCRAKP bool
	ipmiForceSMCRAKP   bool
	ipmiCipher         int
	ipmiVersion        string
	ipmiAuth           string
	ipmiProto          string
	ipmiOpenBMCRelabel string
	ipmiOpenBMCBMCRand string
	ipmiOpenBMCBypass  bool
	ipmiOpenBMCRounds  int
	ipmiILORAKPNone    bool
	ipmiOutputFormat   string
	ipmiMaxFRUField    int
)

// Supermicro/ATEN config-archive options, shared by smc-backup, smc-restore-shell
// and smc-uninstall.
var (
	smcConfigKey       string
	smcConfigCipher    string
	smcConfigIV        string
	smcConfigInnerPass string
	smcChunk           int
	smcOut             string
	smcFrom            string
	smcApply           bool
	smcUploadOnly      bool
	smcNoDecrypt       bool
)

// stunnel root-shell service options, shared by smc-restore-shell, smc-shell and
// `ipmi mem ... via=shell`.
var (
	smcShellPort   int
	smcShellDelay  int
	smcCertPath    string
	smcRawInner    bool
	smcPayloadHost string
)

// RMCP+ RAKP bypass options for smc-rakp-bypass (record 0 forge) and smc-priv-esc
// (reserved-role privilege escalation).
var (
	smcRecord0Keys     string
	smcRecord0MaxTries int
	smcRecord0Rest     time.Duration
	smcActivateSOL     bool

	smcLowUser      string
	smcLowPass      string
	smcAdminUser    string
	smcReservedRole string
	smcOpUser       string
	smcOpPass       string
	smcAdminPass    string

	smcProbeOnly bool
	smcNotes     bool
)

// Command-injection confirmation options, shared by smc-x14-cmdinj and smc-alert-cmdinj. Both
// findings are blind, so every run needs at least one channel that reports the
// injected command actually ran.
var (
	smcCmdInjCallbackHost string
	smcCmdInjCallbackPort int
	smcCmdInjCallbackAddr string
	smcCmdInjCallbackWait time.Duration
	smcCmdInjMarker       string

	smcX14MAC       string
	smcX14Marker    string
	smcX14ProbeOnly bool

	smc0022Sink        string
	smc0022Fields      string
	smc0022Channel     int
	smc0022Destination int
	smc0022WebUser     string
	smc0022WebPass     string
	smc0022WebPort     int
	smc0022WebScheme   string
	smc0022AlertWait   time.Duration
)

// registerIPMITransportFlags binds the options needed to put a packet on the
// wire. The sessionless RAKP bypasses take these without the credential group.
func registerIPMITransportFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.IntVarP(&ipmiPort, "port", "p", ipmi.DefaultPort, "UDP port for IPMI")
	f.DurationVarP(&ipmiTimeout, "timeout", "t", time.Second, "per-attempt IPMI request timeout")
	f.IntVarP(&ipmiMaxRetries, "max-retries", "r", 2, "maximum retry attempts for timed-out IPMI requests")
}

// registerIPMISessionFlags binds the credential and session-negotiation options
// for commands that open an authenticated session.
func registerIPMISessionFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&ipmiUser, "user", "u", "", "IPMI username")
	f.StringVarP(&ipmiPassword, "password", "P", "", "IPMI password")
	f.BoolVar(&ipmiDisableSMCRAKP, "disable-smcrakp", false, "disable automatic SMCRAKP fixed-key detection/handling")
	f.BoolVar(&ipmiForceSMCRAKP, "force-smcrakp", false, "force SMCRAKP fixed-key mode without detection (for boards locked in RAKP4 0x08 where the detection probe cannot run)")
	f.IntVarP(&ipmiCipher, "cipher", "c", -1, "RMCP+ cipher suite id (-1 auto, 0 none/none/none bypass)")
	f.StringVarP(&ipmiVersion, "ipmi-version", "i", "2.0", "IPMI session version: 2.0 or 1.5")
	f.StringVar(&ipmiAuth, "auth", "", "IPMI 1.5 auth mode: none|md2|md5|password")
	f.StringVar(&ipmiProto, "proto", "auto", "IPMI 2.0 in-session command protection: auto|cleartext|negotiated")
}

// registerIPMIBypassFlags binds the vendor authentication-bypass options. They
// change how the session is opened, so they ride with the session group on every
// command that opens one.
func registerIPMIBypassFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&ipmiOpenBMCRelabel, "openbmc-relabel", "", "Target username to write into the active session for OpenBMC relabeling (also works with --openbmc-bmcrand)")
	f.StringVar(&ipmiOpenBMCBMCRand, "openbmc-bmcrand", "", "Bypass authentication using the OpenBMC default userKey and a stale random field (full 16-byte hex, or a 4-byte heap pointer like 0x0066e020)")
	f.BoolVar(&ipmiOpenBMCBypass, "openbmc-bypass", false, "Bypass authentication using the OpenBMC default userKey with no seed: open sessions and re-roll the known constant-string residues (grooming to manufacture them), retrying until one activates. Like the scan fast path; needs only an enabled --user (default root)")
	f.IntVar(&ipmiOpenBMCRounds, "openbmc-rounds", 0, "OpenBMC --openbmc-bypass: how many times to re-roll the residue set before giving up (0 = default 96)")
	f.BoolVar(&ipmiILORAKPNone, "ilo-rakp-none", false, "Bypass authentication on iLO4 via RAKP-none payload-type confusion (no password; --user defaults to Administrator)")
}

// registerIPMIFormatFlag binds --format for every command that renders a result
// through printIPMIResult.
func registerIPMIFormatFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&ipmiOutputFormat, "format", "table", "output format: table|json|jsonl|ndjson")
}

// registerIPMIAllSessionFlags is the whole set a command needs to open an
// authenticated session and print a result.
func registerIPMIAllSessionFlags(cmd *cobra.Command) {
	registerIPMITransportFlags(cmd)
	registerIPMISessionFlags(cmd)
	registerIPMIBypassFlags(cmd)
	registerIPMIFormatFlag(cmd)
}

// registerSMCConfigCryptoFlags binds the config-obfuscation overrides and the
// transfer chunk size. The key is normally auto-selected from the generation
// detected via the System GUID; these pin it.
func registerSMCConfigCryptoFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&smcConfigKey, "config-key", "", "config-obfuscation key as hex (16 bytes for AES, 24 for 3DES). Default: auto by detected generation")
	f.StringVar(&smcConfigCipher, "config-cipher", "", "config cipher for --config-key: aes-128-cbc or 3des-ede3-cbc (default aes-128-cbc)")
	f.StringVar(&smcConfigIV, "config-iv", "", "config IV as hex (default: AES fixed IV, or zero IV for 3des-ede3-cbc)")
	f.StringVar(&smcConfigInnerPass, "config-inner-pass", "", "openssl -pass password for the older X10 (FW ~3.5x) openssl-enc-salted INNER config layer. Only needed on units whose config is double-encrypted (smc-backup reports innerFormat=openssl-enc-salted)")
	f.IntVar(&smcChunk, "chunk", 0, "transfer chunk size in bytes (0 = safer 500-byte default; raise it only on known-good paths)")
}

// registerSMCOutFlag binds --out. The destination is a file for smc-backup and a
// directory for the restore commands, so each names its own.
func registerSMCOutFlag(cmd *cobra.Command, usage string) {
	cmd.Flags().StringVar(&smcOut, "out", "", usage)
}

// registerSMCFromFlag binds --from, the decrypted archive to build from instead
// of exporting the target live.
func registerSMCFromFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&smcFrom, "from", "", "decrypted backup tar.gz to build from (default: export the target live first)")
}

// registerSMCApplyFlags binds the staged/commit pair. What --apply commits
// differs per command, so each supplies its own consequence.
func registerSMCApplyFlags(cmd *cobra.Command, usage string) {
	f := cmd.Flags()
	f.BoolVar(&smcApply, "apply", false, usage)
	f.BoolVar(&smcUploadOnly, "stage-only", false, "stage the archive and stop, even if --apply is also present; explicit for scripts that must never commit")
}

// registerSMCCertPathFlag binds the pinned client-certificate identity used to
// reach a deployed root shell. Shared by smc-restore-shell (which generates it),
// smc-shell and `ipmi mem ... via=shell` (which reuse it).
func registerSMCCertPathFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&smcCertPath, "cert-path", "",
		"combined client cert+key PEM pinning the root-shell identity (default: ~/.cache/oobscan/smcrestore-shell.pem; smc-restore-shell reuses it if present and generates it otherwise, so a redeploy never strands an already-pinned cert)")
}

// registerSMCShellServiceFlags binds where the deployed stunnel root shell
// listens. `ipmi mem ... via=shell` takes only the port, since it connects to a
// service someone else deployed.
func registerSMCShellPortFlag(cmd *cobra.Command) {
	cmd.Flags().IntVar(&smcShellPort, "shell-port", 4444, "TCP port of the stunnel root shell service")
}

func registerSMCShellServiceFlags(cmd *cobra.Command) {
	registerSMCShellPortFlag(cmd)
	f := cmd.Flags()
	f.IntVar(&smcShellDelay, "shell-delay", 20, "seconds the service waits after boot before starting")
	f.BoolVar(&smcRawInner, "raw-inner", false, "diagnostic for older X10 FW ~3.5x - skip the inner openssl-enc layer and upload a raw gzip tar under obfuscation, exercising restore_file.sh's raw-tar fallback")
	f.StringVar(&smcPayloadHost, "payload-host", "", "force the launcher into this config member (e.g. syslog.conf, service.conf, network/netconfig0) instead of auto-selecting; ADDED if not already present (diagnostic - only persists if the name is in the firmware's restore copy list)")
}

// registerSMCProbeFlags binds the options both RAKP bypasses share.
func registerSMCProbeFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVar(&smcProbeOnly, "probe-only", false, "run only the detection probe without obtaining a session; the unordered-RAKP probe can still increment an authentication-failure counter")
	f.BoolVar(&smcNotes, "notes", false, "print the full interpretation notes that follow the result - the per-generation keys, the record-0 lockout and how to read an ambiguous rejection. The scope precondition is always shown beside the impact; this flag adds the rest, which are off by default so a run ends on its own verdict")
}

// registerSMC0014Flags binds the record-0 forge options.
func registerSMC0014Flags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&smcRecord0Keys, "record0-keys", "",
		"comma-separated candidate keys for user record 0 (default: ordered by the generation detected from the System GUID; an empty element means the empty key, \"smcrakp\" the CVE-2026-18449 firmware constant, \"hex:<hex>\" raw bytes)")
	f.IntVar(&smcRecord0MaxTries, "record0-max-attempts", 1,
		"how many record-0 candidates to actually send in one run. DEFAULT 1: on X11/X12/X13/H13 a rejected RAKP3 counts toward a lock on user record 0, and once the threshold is reached a locked record 0 answers the CORRECT key with the same 0x08. Raise it together with --record0-rest, or on X10 (no lockout in its RAKP3 path)")
	f.DurationVar(&smcRecord0Rest, "record0-rest", 0,
		"rest between record-0 candidates so each starts outside record 0's lock window. At or above 60s a multi-candidate run is interpretable; the lock measured live on H13 FW 01.03 cleared in under 32s at a threshold of 3 rejections")
	f.BoolVar(&smcActivateSOL, "activate-sol", false,
		"OPT-IN. After a successful forge, activate the SOL payload to prove the host serial console is reachable, then deactivate it. Off by default; the default path issues read-only commands only")
	registerSMCProbeFlags(cmd)
}

// registerSMC0015Flags binds the reserved-role escalation options.
func registerSMC0015Flags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&smcLowUser, "low-user", "", "the low-privilege account whose real credential signs RAKP message 3 (required)")
	f.StringVar(&smcLowPass, "low-pass", "", "the low-privilege account's real password (required)")
	f.StringVar(&smcAdminUser, "admin-user", "ADMIN", "name of an Administrator account to seed the slot privilege with (no password needed; the factory default on these units is ADMIN)")
	f.StringVar(&smcReservedRole, "reserved-role", "0x24", "RAKP1 reserved role byte. Every upper nibble from 0x2 to 0xF falls into the same unimplemented residual-privilege arm; 0x24 is the value the live evidence used")
	f.StringVar(&smcOpUser, "op-user", "", "an OPERATOR-privilege control account. Without it the Administrator/Operator boundary cannot be established: a witness command only counts as Administrator-gated if an Operator session is refused it, and on H13 FW 01.03 a real ADMIN session is refused Get Device SDR Info too")
	f.StringVar(&smcOpPass, "op-pass", "", "the operator control account's password")
	f.StringVar(&smcAdminPass, "admin-pass", "", "password for --admin-user, used ONLY to measure the upper reference for witness selection. The seed itself needs no password. Without it a command refused to an Operator cannot be told apart from one this firmware refuses to everyone (H13 FW 01.03 refuses Get Device SDR Info to a real ADMIN too)")
	registerSMCProbeFlags(cmd)
}

// registerSMCCmdInjCallbackFlags binds the callback listener every
// command-injection validator needs to confirm execution out of band.
func registerSMCCmdInjCallbackFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&smcCmdInjCallbackHost, "callback-host", "",
		"interface address or hostname the target should reach the callback listener on. Default: the local end of the route to the target, which is right for a target on a directly attached network. On a routed or NATed target set this explicitly.")
	f.IntVar(&smcCmdInjCallbackPort, "callback-port", 0,
		"TCP port for the callback listener (0 = an ephemeral port). The payload carries whatever port is bound.")
	f.StringVar(&smcCmdInjCallbackAddr, "callback-listen", "0.0.0.0",
		"local address the callback listener binds (default 0.0.0.0 so the target can reach it)")
	f.DurationVar(&smcCmdInjCallbackWait, "callback-wait", 20*time.Second,
		"how long to wait for the injected command's callback before reporting the run as unconfirmed")
	f.StringVar(&smcCmdInjMarker, "marker", "",
		"BMC path the injected command writes with its id(1) output (default: a /tmp path specific to each finding). The marker is a secondary channel: nothing in this run reads it back, so the callback is what confirms execution; the marker is there for an operator who has a separate way to read it, such as smc-read or a deployed shell.")
}

// registerSMC0021Flags binds the X14 RestorePSOOBBFile injection options.
func registerSMC0021Flags(cmd *cobra.Command) {
	registerSMCCmdInjCallbackFlags(cmd)
	registerSMCApplyFlags(cmd, "COMMIT: apply action 0x05, which dispatches the handler and runs the injected command. Without it the document is only uploaded")
	f := cmd.Flags()
	f.StringVar(&smcX14MAC, "mac", "",
		"the current MAC to echo back to fw_setenv (xx:xx:xx:xx:xx:xx). If empty, the target's MAC is resolved over IPMI: LAN config param 5, then the PS OOB backup export. The injection fails hard when no valid MAC can be resolved, because fw_setenv does not validate the value and a wrong one stops the BMC from booting.")
	f.BoolVar(&smcX14ProbeOnly, "probe-only", false,
		"exercise and report the upload chain only: reserve a slot, start an upload, send one chunk, read the result, and stop. Nothing is applied, so no command is injected.")
}

// registerSMC0022Flags binds the ATEN alert-delivery injection options.
func registerSMC0022Flags(cmd *cobra.Command) {
	registerSMCCmdInjCallbackFlags(cmd)
	registerSMCApplyFlags(cmd, "COMMIT: store the injected value, fire the alert trigger, and wait for the callback. Without it the run reads the current state and prints the requests it would send, but transmits no setter, POST or trigger")
	f := cmd.Flags()
	f.StringVar(&smc0022Sink, "sink", "both",
		"which alert-delivery sink to exercise: smtp (IPMI OEM 0x30/0x68, plus the 0x04/0x16 Alert Immediate trigger) | snmp (web SNMPv3 trap credentials) | both")
	f.StringVar(&smc0022Fields, "smtp-fields", "server",
		"comma-separated SMTP fields to inject: server,user,password,sender. Only the server field is injectable on X13/H13SSF; the other three are X10-only, so the default is the field that is injectable somewhere on every affected generation")
	f.IntVar(&smc0022Channel, "pef-channel", 0x01, "PEF Alert Immediate channel byte (0x0e = current channel)")
	f.IntVar(&smc0022Destination, "pef-destination", 0x01, "PEF Alert Immediate destination byte")
	f.StringVar(&smc0022WebUser, "web-user", "ADMIN", "ATEN web UI username for the SNMPv3 sink")
	f.StringVar(&smc0022WebPass, "web-pass", "", "ATEN web UI password for the SNMPv3 sink (falls back to -P when empty)")
	f.IntVar(&smc0022WebPort, "web-port", 0, "ATEN web UI port (0 = 443)")
	f.StringVar(&smc0022WebScheme, "web-scheme", "https", "ATEN web UI scheme: https or http")
	f.DurationVar(&smc0022AlertWait, "alert-wait", 30*time.Second,
		"how long to wait for the callback after firing the alert trigger. The alert path is asynchronous and its delivery is timer-driven, so this allows for a lap of the PEF timer.")
}
