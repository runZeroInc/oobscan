package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/runZeroInc/oobscan/pkg/discover"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

var (
	ipmiPort           int
	ipmiUser           string
	ipmiPassword       string
	ipmiTimeout        time.Duration
	ipmiMaxRetries     int
	ipmiDisableSMCRAKP bool
	ipmiCipher         int
	ipmiVersion        string
	ipmiAuth           string
	ipmiProto          string
	ipmiOutputJSON     bool
	ipmiOutputFormat   string
	ipmiMaxFRUField    int

	ipmiSMCConfigKey       string
	ipmiSMCConfigCipher    string
	ipmiSMCConfigIV        string
	ipmiSMCConfigInnerPass string
	ipmiSMCOut             string
	ipmiSMCNoDecrypt       bool
	ipmiSMCChunk           int

	ansiSeqRE         = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	ipmiKnownCommands = []string{"isol", "mc", "chassis", "lan", "lan6", "fru", "user", "raw", "sol", "i2c", "spd", "channel", "xdp", "smcbackup"}
)

var ipmiCmd = &cobra.Command{
	Use:   "ipmi [flags] <host[,host|cidr|range...]|targets...> <command> [args...]",
	Short: "Run authenticated IPMI commands across one or more targets.",
	Long: `ipmi runs practical, ipmitool-like command workflows directly through oobscan's
IPMI stack so responders can quickly validate exposures and perform common
triage/remediation tasks (user inventory/disable/reset, mc/chassis/lan/fru,
raw requests, SOL config, and i2c/spd checks).

Targets can be comma-separated and/or space-separated and may be IPs, hostnames,
CIDRs, and hyphen ranges. The first recognized subcommand token marks where
target input ends. An IPv6 multicast target is a link-local sweep instead of a
host: ff02::1%en0 probes the all-nodes group on en0 and runs the command against
every link-local address that answers.

Command sections and syntax:

	Core inventory
		mc info
		mc
		mc reset cold|warm
		chassis status
		chassis
		lan print
		lan
		lan6 print
		lan6
		fru
		fru print

	User management
		user list
		user
		user enable <id>
		user disable <id>
		user clear <id>
		user set name <id> <name>
		user set priv <id> <priv>
		user set pass <id> <password>
		user set password <id> <password>

		<priv> supports names and numeric values:
			callback|user|operator|admin|oem|none|off|0..15

	Raw IPMI
		raw <netfn> <cmd> [data ...]

		Byte values accept decimal or hex, e.g. 6 or 0x06.

	SOL / ISOL
		sol info
		sol set <key> <value>
		sol activate
		sol deactivate
		sol console
		isol console

		SOL set keys:
			enabled
			force-encryption
			force-authentication
			character-accumulate-level | accumulate
			character-send-threshold   | threshold
			retry-count
			retry-interval
			non-volatile-bit-rate
			volatile-bit-rate
			payload-channel
			payload-port

		For interactive console use:
			- sol console  : IPMI 2.0 (lanplus)
			- isol console : IPMI 1.5 (lan)

	I2C / SPD
		i2c read <slave_addr> <read_len> [write_byte ...]
		spd read <slave_addr> [offset] [length]

	Channel access
		channel info [channel]
		channel getaccess <channel> [id]
		channel setaccess <channel> <id> callin=<on|off> ipmi=<on|off> link=<on|off> privilege=<level>

	RemoteXDP (Intel At-Scale-Debug / JTAG) OEM service
		xdp status [key=value ...]
		xdp enable [port] [key=value ...]
		xdp disable [key=value ...]

		Toggles H3C's OEM RemoteXDP service via GetServiceConf/SetServiceConf
		(netfn 0x36). Discovers the handler route by default; pin it with
		key=value overrides (netfn, cmd, control=aa,bb, mfr=a2,63,00, subcmd,
		sid, maxprobes) plus the flag token "nodiscover". Default port 6868.

		Service config: port (nonsecure), secureport (TLS), timeout
		(session idle seconds), and editmask=aa,bb (which fields the handler
		applies; default 80,80).

	Supermicro/ATEN OEM config export
		smcbackup

		smcbackup exports the BMC configuration (the SaveConfig download path)
		and, when the config-obfuscation key is known, decrypts it to a gzip tar
		of the /nv preserve_config tree. Read-only against the BMC. The key is
		auto-selected from the generation detected via the System GUID; pass
		--config-key for generations without a built-in profile. Files: --out
		(default smc-backup-<host>.bin) plus <out>.tar.gz when decrypted;
		--no-decrypt keeps only the ciphertext.

Examples:

	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 user list
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 user set name 2 responder
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 user set priv 2 admin
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 user set pass 2 NewPass123
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 user clear 7
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mc info
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 chassis status
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 lan print
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 lan6 print
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 fru
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 raw 0x06 0x01
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 sol console
	oobscan ipmi --ipmi-version=1.5 --auth=md5 -u ADMIN -P ADMIN 10.0.0.10 isol console
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 i2c read 0xa0 16 0x00
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 spd read 0xa0 0x00 64
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 channel info
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 xdp enable 6868
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 smcbackup --out backup.bin

Two legacy weak-authentication modes can be selected explicitly:
	--ipmi-version=1.5 --auth=none
	--ipmi-version=2   --cipher=0

SMCRAKP mode is automatically detected and handled, but can be disabled with:
	--disable-smcrakp
`,
	Args: cobra.ArbitraryArgs,
	RunE: runIPMI,
}

func init() {
	f := ipmiCmd.Flags()
	f.IntVarP(&ipmiPort, "port", "p", ipmi.DefaultPort, "UDP port for IPMI (default 623)")
	f.StringVarP(&ipmiUser, "user", "u", "", "IPMI username")
	f.StringVarP(&ipmiPassword, "password", "P", "", "IPMI password")
	f.DurationVarP(&ipmiTimeout, "timeout", "t", time.Second, "per-attempt IPMI request timeout")
	f.IntVarP(&ipmiMaxRetries, "max-retries", "r", 2, "maximum retry attempts for timed-out IPMI requests")
	f.BoolVar(&ipmiDisableSMCRAKP, "disable-smcrakp", false, "disable automatic SMCRAKP fixed-key detection/handling")
	f.IntVarP(&ipmiCipher, "cipher", "c", -1, "RMCP+ cipher suite id (-1 auto, 0 none/none/none bypass)")
	f.StringVarP(&ipmiVersion, "ipmi-version", "i", "2.0", "IPMI session version: 2.0 or 1.5")
	f.StringVar(&ipmiAuth, "auth", "", "IPMI 1.5 auth mode: none|md2|md5|password")
	f.StringVar(&ipmiProto, "proto", "auto", "IPMI 2.0 in-session command protection: auto|cleartext|negotiated")
	f.StringVar(&ipmiOutputFormat, "format", "table", "output format: table|json|jsonl|ndjson")
	f.IntVar(&ipmiMaxFRUField, "fru-max-fields", 64, "maximum FRU string fields to decode")
	f.StringVar(&ipmiSMCConfigKey, "config-key", "", "smcbackup: config-obfuscation key as hex (16 bytes for AES, 24 for 3DES). Default: auto by detected generation")
	f.StringVar(&ipmiSMCConfigCipher, "config-cipher", "", "smcbackup: config cipher for --config-key: aes-128-cbc or 3des-ede3-cbc (default aes-128-cbc)")
	f.StringVar(&ipmiSMCConfigIV, "config-iv", "", "smcbackup: config IV as hex (default: AES fixed IV, or zero IV for 3des-ede3-cbc)")
	f.StringVar(&ipmiSMCConfigInnerPass, "config-inner-pass", "", "smcbackup: openssl -pass password for the older X10 (FW ~3.5x) openssl-enc-salted INNER config layer. Only needed on units whose config is double-encrypted (smcbackup reports innerFormat=openssl-enc-salted)")
	f.StringVar(&ipmiSMCOut, "out", "", "smcbackup: output path for the exported blob (default smc-backup-<host>.bin)")
	f.BoolVar(&ipmiSMCNoDecrypt, "no-decrypt", false, "smcbackup: save only the encrypted blob, do not decrypt")
	f.IntVar(&ipmiSMCChunk, "chunk", 0, "smcbackup: transfer chunk size in bytes (0 = default ~1400; lower it if a board throttles/times out mid-transfer)")
	rootCmd.AddCommand(ipmiCmd)
}

func runIPMI(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()
	if ipmiOutputJSON {
		ipmiOutputFormat = "json"
	}
	if !isSupportedIPMIFormat(ipmiOutputFormat) {
		fmt.Fprintf(out, "ipmi: unsupported --format %q (use table, json, jsonl, or ndjson)\n", ipmiOutputFormat)
		printIPMIShortUsage(cmd)
		return nil
	}
	if ipmiMaxRetries < 1 {
		fmt.Fprintf(out, "ipmi: invalid --max-retries %d (use 1 or greater)\n", ipmiMaxRetries)
		printIPMIShortUsage(cmd)
		return nil
	}
	idx := findIPMICommandIndex(args)
	if idx <= 0 {
		fmt.Fprintln(out, "ipmi: missing or unsupported command")
		printIPMIShortUsage(cmd)
		return nil
	}
	targets, err := expandIPMITargets(args[:idx])
	if err != nil {
		fmt.Fprintf(out, "ipmi: target parse error: %v\n", err)
		printIPMIShortUsage(cmd)
		return nil
	}
	if len(targets) == 0 {
		fmt.Fprintln(out, "ipmi: no targets expanded from input")
		printIPMIShortUsage(cmd)
		return nil
	}
	commandArgs := args[idx:]

	ctx := context.Background()
	failures := 0
	validationErrs := 0
	interactiveSOL := isSOLConsoleCommand(commandArgs)
	status := newIPMIStatusSpinner(errOut, len(targets), summarizeIPMICommand(commandArgs))
	status.Start()
	defer status.Stop("")
	if interactiveSOL && len(targets) != 1 {
		fmt.Fprintln(out, "ipmi: sol/isol console supports exactly one target")
		printIPMIShortUsage(cmd)
		return nil
	}
	for i, host := range targets {
		status.Set(i+1, host, "opening session")
		if interactiveSOL {
			status.Set(i+1, host, "starting interactive console")
			if err := runIPMISOLConsole(host, commandArgs); err != nil {
				failures++
				status.WithPaused(func() {
					fmt.Fprintf(out, "[%s] sol console error: %v\n", host, err)
				})
			}
			status.Set(i+1, host, "interactive console finished")
			continue
		}
		opts := ipmi.CmdSessOptions{
			Host:              host,
			Port:              ipmiPort,
			Username:          ipmiUser,
			Password:          ipmiPassword,
			Timeout:           ipmiTimeout,
			MaxRetries:        ipmiMaxRetries,
			IPMIVersion:       ipmiVersion,
			Auth:              ipmiAuth,
			Cipher:            ipmiCipher,
			DisableSMCRAKP:    ipmiDisableSMCRAKP,
			CommandProtection: ipmiProto,
		}
		sess, err := ipmi.OpenCmdSess(opts)
		if err != nil {
			status.Set(i+1, host, "session failed")
			failures++
			msg := err.Error()
			if strings.Contains(msg, "required") || strings.Contains(msg, "unsupported --") {
				validationErrs++
			}
			status.WithPaused(func() {
				fmt.Fprintf(out, "[%s] session error: %v\n", host, err)
			})
			continue
		}
		if sess.SMCRAKPDetected() {
			status.WithPaused(func() {
				log().Warnf("[%s] Hardcoded SMCRAKP RAKP key detected, passwords may be optional...", host)
			})
		}

		status.Set(i+1, host, "running command")
		commandCtx := ipmi.WithCommandProgress(ctx, func(update string) {
			status.Set(i+1, host, update)
		})
		res, err := runIPMITargetCommand(commandCtx, sess, commandArgs)
		sess.Close()
		if err != nil {
			status.Set(i+1, host, "command failed")
			failures++
			msg := err.Error()
			if strings.Contains(msg, "usage:") || strings.Contains(msg, "unsupported") || strings.Contains(msg, "invalid") {
				validationErrs++
			}
			status.WithPaused(func() {
				fmt.Fprintf(out, "[%s] command error: %v\n", host, err)
			})
			continue
		}
		status.Set(i+1, host, "rendering output")
		var printErr error
		status.WithPaused(func() {
			printErr = printIPMIResult(cmd, host, sess, res)
		})
		if printErr != nil {
			status.Set(i+1, host, "output failed")
			failures++
			status.WithPaused(func() {
				fmt.Fprintf(out, "[%s] output error: %v\n", host, printErr)
			})
			continue
		}
		status.Set(i+1, host, "done")
	}
	if failures > 0 {
		status.Stop(fmt.Sprintf("ipmi finished: %d/%d target(s) failed", failures, len(targets)))
		if validationErrs > 0 {
			status.WithPaused(func() {
				printIPMIShortUsage(cmd)
			})
		}
		status.WithPaused(func() {
			fmt.Fprintf(out, "ipmi: %d target(s) failed\n", failures)
		})
		return nil
	}
	status.Stop(fmt.Sprintf("ipmi finished: %d target(s) ok", len(targets)))
	return nil
}

type ipmiStatusSpinner struct {
	enabled bool
	w       io.Writer
	total   int
	cmd     string

	mu      sync.RWMutex
	current string
	paused  bool

	stopCh chan struct{}
	doneCh chan struct{}
}

type ipmiChannelAccessSettings struct {
	Alerting       bool
	PerMessageAuth bool
	UserLevelAuth  bool
	AccessMode     string
}

type ipmiChannelInfoResult struct {
	Channel            int
	MediumType         string
	ProtocolType       string
	SessionSupport     string
	ActiveSessionCount int
	ProtocolVendorID   uint32
	Volatile           ipmiChannelAccessSettings
	NonVolatile        ipmiChannelAccessSettings
}

type ipmiChannelAccessUser struct {
	ID          int
	Name        string
	FixedName   bool
	Callin      bool
	LinkAuth    bool
	IPMIAuth    bool
	Privilege   byte
	EnableState bool
}

type ipmiChannelAccessResult struct {
	Channel        int
	MaxUserIDs     int
	EnabledUserIDs int
	Users          []ipmiChannelAccessUser
}

const ipmiChannelUsage = "Channel Commands: info [channel] | getaccess <channel> [user id] | setaccess <channel> <user id> [callin=on|off] [ipmi=on|off] [link=on|off] [privilege=level]"

func newIPMIStatusSpinner(w io.Writer, total int, cmd string) *ipmiStatusSpinner {
	enabled := term.IsTerminal(int(os.Stderr.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	if _, ok := w.(*os.File); !ok {
		enabled = false
	}
	return &ipmiStatusSpinner{
		enabled: enabled,
		w:       w,
		total:   total,
		cmd:     cmd,
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

func (s *ipmiStatusSpinner) Start() {
	if s == nil || !s.enabled {
		return
	}
	go func() {
		defer close(s.doneCh)
		frames := []string{"|", "/", "-", "\\"}
		t := time.NewTicker(120 * time.Millisecond)
		defer t.Stop()
		i := 0
		for {
			select {
			case <-s.stopCh:
				return
			case <-t.C:
				line, ok := s.line(frames[i%len(frames)])
				if !ok {
					continue
				}
				i++
				_, _ = fmt.Fprintf(s.w, "\r%s", padStatusLine(line, 120))
			}
		}
	}()
}

func (s *ipmiStatusSpinner) Set(index int, host, phase string) {
	if s == nil || !s.enabled {
		return
	}
	if index < 1 {
		index = 1
	}
	phase = strings.TrimSpace(phase)
	host = strings.TrimSpace(host)
	msg := fmt.Sprintf("[%d/%d] %s %s: %s", index, s.total, s.cmd, host, phase)
	s.mu.Lock()
	s.current = msg
	s.mu.Unlock()
}

func (s *ipmiStatusSpinner) Stop(finalMsg string) {
	if s == nil || !s.enabled {
		return
	}
	select {
	case <-s.stopCh:
		return
	default:
		close(s.stopCh)
	}
	<-s.doneCh
	_, _ = fmt.Fprintf(s.w, "\r%s\r", strings.Repeat(" ", 120))
	if strings.TrimSpace(finalMsg) != "" {
		_, _ = fmt.Fprintln(s.w, finalMsg)
	}
}

func (s *ipmiStatusSpinner) line(frame string) (string, bool) {
	s.mu.RLock()
	cur := s.current
	paused := s.paused
	s.mu.RUnlock()
	if paused {
		return "", false
	}
	if cur == "" {
		cur = fmt.Sprintf("[%d/%d] %s waiting", 0, s.total, s.cmd)
	}
	return fmt.Sprintf("%s %s", frame, cur), true
}

func (s *ipmiStatusSpinner) WithPaused(fn func()) {
	if s == nil || fn == nil {
		return
	}
	if !s.enabled {
		fn()
		return
	}
	s.mu.Lock()
	s.paused = true
	s.mu.Unlock()
	_, _ = fmt.Fprintf(s.w, "\r%s\r", strings.Repeat(" ", 120))
	fn()
	s.mu.Lock()
	s.paused = false
	s.mu.Unlock()
}

func padStatusLine(line string, width int) string {
	line = sanitizeASCII(line)
	if len(line) >= width {
		return line
	}
	return line + strings.Repeat(" ", width-len(line))
}

func summarizeIPMICommand(args []string) string {
	if len(args) == 0 {
		return "ipmi"
	}
	if len(args) == 1 {
		return strings.ToLower(strings.TrimSpace(args[0]))
	}
	return strings.ToLower(strings.TrimSpace(args[0])) + " " + strings.ToLower(strings.TrimSpace(args[1]))
}

func printIPMIShortUsage(cmd *cobra.Command) {
	fmt.Fprintln(cmd.OutOrStdout(), "Usage:")
	fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", cmd.UseLine())
	fmt.Fprintln(cmd.OutOrStdout(), "")
	fmt.Fprintln(cmd.OutOrStdout(), "Supported commands:")
	fmt.Fprintln(cmd.OutOrStdout(), "  mc [info]")
	fmt.Fprintln(cmd.OutOrStdout(), "  chassis [status]")
	fmt.Fprintln(cmd.OutOrStdout(), "  lan [print]")
	fmt.Fprintln(cmd.OutOrStdout(), "  lan6 [print]")
	fmt.Fprintln(cmd.OutOrStdout(), "  fru [print]")
	fmt.Fprintln(cmd.OutOrStdout(), "  user <list|enable|disable|clear|set ...>")
	fmt.Fprintln(cmd.OutOrStdout(), "  raw <netfn> <cmd> [data ...]")
	fmt.Fprintln(cmd.OutOrStdout(), "  sol <info|set|activate|deactivate|console>")
	fmt.Fprintln(cmd.OutOrStdout(), "  isol <console>")
	fmt.Fprintln(cmd.OutOrStdout(), "  channel info [channel]")
	fmt.Fprintln(cmd.OutOrStdout(), "  channel getaccess <channel> [id]")
	fmt.Fprintln(cmd.OutOrStdout(), "  channel setaccess <channel> <id> callin=<on|off> ipmi=<on|off> link=<on|off> privilege=<level>")
	fmt.Fprintln(cmd.OutOrStdout(), "  i2c read <slave_addr> <read_len> [write_byte ...]")
	fmt.Fprintln(cmd.OutOrStdout(), "  spd read <slave_addr> [offset] [length]")
	fmt.Fprintln(cmd.OutOrStdout(), "  mem info | probe | read <addr|region> <len> [key=value ...]")
	fmt.Fprintln(cmd.OutOrStdout(), "  mem write <addr|region> <hexbytes|in=FILE> [key=value ...] apply")
}

func printIPMIResult(cmd *cobra.Command, host string, sess *ipmi.CmdSess, result any) error {
	out := cmd.OutOrStdout()
	flow := sess.Flow()
	header := map[string]any{
		"host":              host,
		"version":           flow.Version,
		"mode":              flow.Mode,
		"cipherSuite":       flow.Suite.Suite,
		"advertisedCiphers": sess.AdvertisedCiphers(),
		"commandProtection": sess.CommandProtection(),
		"result":            result,
	}
	format := normalizeIPMIFormat(ipmiOutputFormat)
	if format == "json" {
		b, err := json.Marshal(header)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(b))
		return err
	}
	if format == "jsonl" {
		b, err := json.Marshal(header)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(b))
		return err
	}
	return printIPMIResultTable(out, host, flow, sess.AdvertisedCiphers(), sess.CommandProtection(), result)
}

func normalizeIPMIFormat(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "ndjson" {
		return "jsonl"
	}
	if v == "" {
		return "table"
	}
	return v
}

func isSupportedIPMIFormat(v string) bool {
	switch normalizeIPMIFormat(v) {
	case "table", "json", "jsonl":
		return true
	default:
		return false
	}
}

func printIPMIResultTable(out any, host string, flow ipmi.AuthFlow, ciphers []int, protection string, result any) error {
	w, ok := out.(interface{ Write([]byte) (int, error) })
	if !ok {
		return fmt.Errorf("output writer unavailable")
	}
	header := fmt.Sprintf("HOST=%s VERSION=%s MODE=%s CIPHER=%d", host, flow.Version, flow.Mode, flow.Suite.Suite)
	if len(ciphers) > 0 {
		header += fmt.Sprintf(" ADVERTISED=%v", ciphers)
	}
	if protection != "" {
		header += fmt.Sprintf(" PROTO=%s", protection)
	}
	if _, err := fmt.Fprintln(w, header); err != nil {
		return err
	}

	switch v := result.(type) {
	case []ipmi.UserEntry:
		rows := make([][]string, 0, len(v))
		for _, u := range v {
			rows = append(rows, []string{
				strconv.Itoa(u.ID),
				u.Name,
				formatUserPrivilege(u.Priv),
				boolWord(u.Enabled),
				boolWord(u.Callin),
				boolWord(u.LinkAuth),
				boolWord(u.IPMIAuth),
			})
		}
		return writeASCIITable(w, []string{"ID", "Name", "Privilege", "Enabled", "Call In", "Link Auth", "IPMI Auth"}, rows)
	case []ipmi.FRUField:
		rows := make([][]string, 0, len(v))
		for _, f := range v {
			name := f.Name
			if name == "" {
				name = fmt.Sprintf("%s %d", formatTitleCase(f.Area), f.Index)
			}
			rows = append(rows, []string{strconv.Itoa(f.DeviceID), sanitizeASCII(name), sanitizeASCII(f.Value)})
		}
		return writeASCIITable(w, []string{"Device", "Field", "Value"}, rows)
	case map[string]string:
		if isSOLInfoMap(v) {
			return writeSOLInfoTable(w, v)
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		rows := make([][]string, 0, len(keys))
		for _, k := range keys {
			rows = append(rows, []string{prettyKey(k), formatTypedValue(k, v[k])})
		}
		return writeASCIITable(w, []string{"Setting", "Value"}, rows)
	case *ipmi.MCInfo:
		if v == nil {
			_, err := fmt.Fprintln(w, "(no data)")
			return err
		}
		return writeKVFromJSON(w, v)
	case *ipmi.ChassisStatus:
		if v == nil {
			_, err := fmt.Fprintln(w, "(no data)")
			return err
		}
		return writeKVFromJSON(w, v)
	case map[string]any:
		return writeKVMapAny(w, v)
	case *ipmiChannelInfoResult:
		if v == nil {
			_, err := fmt.Fprintln(w, "(no data)")
			return err
		}
		if _, err := fmt.Fprintf(w, "Channel 0x%x info:\n", v.Channel); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  Channel Medium Type   : %s\n", v.MediumType); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  Channel Protocol Type : %s\n", v.ProtocolType); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  Session Support       : %s\n", v.SessionSupport); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  Active Session Count  : %d\n", v.ActiveSessionCount); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  Protocol Vendor ID    : %d\n", v.ProtocolVendorID); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "  Volatile(active) Settings"); err != nil {
			return err
		}
		if err := writeChannelAccessSettings(w, "    ", v.Volatile); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "  Non-Volatile Settings"); err != nil {
			return err
		}
		return writeChannelAccessSettings(w, "    ", v.NonVolatile)
	case *ipmiChannelAccessResult:
		if v == nil {
			_, err := fmt.Fprintln(w, "(no data)")
			return err
		}
		if _, err := fmt.Fprintf(w, "Maximum User IDs     : %d\n", v.MaxUserIDs); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "Enabled User IDs     : %d\n", v.EnabledUserIDs); err != nil {
			return err
		}
		for _, u := range v.Users {
			if _, err := fmt.Fprintln(w, ""); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "User ID              : %d\n", u.ID); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "User Name            : %s\n", u.Name); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "Fixed Name           : %s\n", yesNoWord(u.FixedName)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "Access Available     : %s\n", channelAccessAvailable(u.Callin)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "Link Authentication  : %s\n", enabledDisabledWord(u.LinkAuth)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "IPMI Messaging       : %s\n", enabledDisabledWord(u.IPMIAuth)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "Privilege Level      : %s\n", channelPrivilegeLabel(u.Privilege)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "Enable Status        : %s\n", enabledDisabledWord(u.EnableState)); err != nil {
				return err
			}
		}
		return nil
	default:
		rv := reflect.ValueOf(result)
		if rv.IsValid() && rv.Kind() == reflect.Slice {
			return writeSliceGeneric(w, result)
		}
		return writeKVFromJSON(w, result)
	}
}

func writeChannelAccessSettings(w io.Writer, indent string, s ipmiChannelAccessSettings) error {
	if _, err := fmt.Fprintf(w, "%sAlerting            : %s\n", indent, enabledDisabledWord(s.Alerting)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%sPer-message Auth    : %s\n", indent, enabledDisabledWord(s.PerMessageAuth)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%sUser Level Auth     : %s\n", indent, enabledDisabledWord(s.UserLevelAuth)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "%sAccess Mode         : %s\n", indent, s.AccessMode)
	return err
}

func runIPMITargetCommand(ctx context.Context, sess *ipmi.CmdSess, args []string) (any, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("missing command")
	}
	switch strings.ToLower(args[0]) {
	case "isol":
		return runIPMISOL(ctx, sess, append([]string{"sol"}, args[1:]...))
	case "mc":
		if len(args) == 1 || strings.EqualFold(args[1], "info") {
			return sess.MCInfo(ctx)
		}
		if len(args) == 3 && strings.EqualFold(args[1], "reset") {
			switch strings.ToLower(args[2]) {
			case "cold":
				if err := sess.MCReset(true); err != nil {
					return nil, err
				}
				return map[string]any{"ok": true, "action": "mc reset", "mode": "cold"}, nil
			case "warm":
				if err := sess.MCReset(false); err != nil {
					return nil, err
				}
				return map[string]any{"ok": true, "action": "mc reset", "mode": "warm"}, nil
			default:
				return nil, fmt.Errorf("usage: mc reset <cold|warm>")
			}
		}
	case "chassis":
		if len(args) == 1 || strings.EqualFold(args[1], "status") {
			return sess.ChassisStatus(ctx)
		}
	case "lan":
		if len(args) == 1 || strings.EqualFold(args[1], "print") {
			lan, _, err := sess.LANPrint(ctx)
			return lan, err
		}
	case "lan6":
		if len(args) == 1 || strings.EqualFold(args[1], "print") {
			_, lan6, err := sess.LANPrint(ctx)
			return lan6, err
		}
	case "fru":
		if len(args) == 1 || strings.EqualFold(args[1], "print") {
			return sess.FRUPrint(ctx, ipmiMaxFRUField)
		}
	case "raw":
		return runIPMIRaw(sess, args[1:])
	case "user":
		return runIPMIUser(ctx, sess, args[1:])
	case "sol":
		return runIPMISOL(ctx, sess, args[1:])
	case "channel":
		return runIPMIChannel(sess, args[1:])
	case "i2c":
		return runIPMII2C(sess, args[1:])
	case "spd":
		return runIPMISPD(sess, args[1:])
	case "smcbackup":
		return runIPMISMCBackup(ctx, sess, args[1:])
	}
	return nil, fmt.Errorf("unsupported command %q", strings.Join(args, " "))
}

func runIPMIRaw(sess *ipmi.CmdSess, args []string) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("usage: raw <netfn> <cmd> [data...]")
	}
	netfn, err := parseByteArg(args[0])
	if err != nil {
		return nil, fmt.Errorf("invalid netfn: %w", err)
	}
	cmd, err := parseByteArg(args[1])
	if err != nil {
		return nil, fmt.Errorf("invalid cmd: %w", err)
	}
	data, err := parseByteArgs(args[2:])
	if err != nil {
		return nil, err
	}
	cc, resp, err := sess.ExecRaw(netfn, cmd, data)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"completionCode": fmt.Sprintf("0x%02x", cc),
		"responseHex":    hex.EncodeToString(resp),
		"responseBytes":  bytesToHex(resp),
	}, nil
}

func runIPMIUser(ctx context.Context, sess *ipmi.CmdSess, args []string) (any, error) {
	if len(args) == 0 || strings.EqualFold(args[0], "list") {
		users, err := sess.UserList(ctx)
		if err != nil {
			return nil, err
		}
		sort.Slice(users, func(i, j int) bool { return users[i].ID < users[j].ID })
		return users, nil
	}
	switch strings.ToLower(args[0]) {
	case "enable":
		if len(args) != 2 {
			return nil, fmt.Errorf("usage: user enable <id>")
		}
		id, err := strconv.Atoi(args[1])
		if err != nil {
			return nil, fmt.Errorf("invalid id %q", args[1])
		}
		if err := sess.UserEnable(id); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "action": "user enable", "id": id}, nil
	case "disable":
		if len(args) != 2 {
			return nil, fmt.Errorf("usage: user disable <id>")
		}
		id, err := strconv.Atoi(args[1])
		if err != nil {
			return nil, fmt.Errorf("invalid id %q", args[1])
		}
		if err := sess.UserDisable(id); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "action": "user disable", "id": id}, nil
	case "clear":
		if len(args) != 2 {
			return nil, fmt.Errorf("usage: user clear <id>")
		}
		id, err := strconv.Atoi(args[1])
		if err != nil {
			return nil, fmt.Errorf("invalid id %q", args[1])
		}
		if err := sess.UserClear(ctx, id); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "action": "user clear", "id": id}, nil
	case "set":
		if len(args) < 4 {
			return nil, fmt.Errorf("usage: user set <name|priv|pass> <id> <value>")
		}
		sub := strings.ToLower(args[1])
		id, err := strconv.Atoi(args[2])
		if err != nil {
			return nil, fmt.Errorf("invalid id %q", args[2])
		}
		switch sub {
		case "name":
			name := args[3]
			if err := sess.UserSetName(id, name); err != nil {
				return nil, err
			}
			return map[string]any{"ok": true, "action": "user set name", "id": id, "name": name}, nil
		case "priv":
			priv, err := ipmi.ParsePrivilege(args[3])
			if err != nil {
				return nil, err
			}
			if err := sess.UserSetPrivilege(ctx, id, priv); err != nil {
				return nil, err
			}
			return map[string]any{"ok": true, "action": "user set priv", "id": id, "priv": priv}, nil
		case "pass", "password":
			pass := args[3]
			if err := sess.UserSetPassword(id, pass); err != nil {
				return nil, err
			}
			return map[string]any{"ok": true, "action": "user set pass", "id": id}, nil
		default:
			return nil, fmt.Errorf("unsupported user set field %q", args[1])
		}
	}
	return nil, fmt.Errorf("unsupported user command %q", strings.Join(args, " "))
}

func runIPMISOL(ctx context.Context, sess *ipmi.CmdSess, args []string) (any, error) {
	if len(args) > 0 && strings.EqualFold(args[0], "sol") {
		args = args[1:]
	}
	if len(args) == 0 || strings.EqualFold(args[0], "info") {
		params := map[string]byte{
			"set_in_progress":            0,
			"enabled":                    1,
			"authentication":             2,
			"character_accumulate_level": 3,
			"character_send_threshold":   4,
			"retry_count":                5,
			"retry_interval":             6,
			"non_volatile_bit_rate":      7,
			"volatile_bit_rate":          8,
			"payload_channel":            9,
			"payload_port":               10,
		}
		out := map[string]string{}
		for k, p := range params {
			d, err := sess.SOLGetConfigParam(ctx, p)
			if err != nil {
				continue
			}
			out[k] = hex.EncodeToString(d)
		}
		return out, nil
	}
	if strings.EqualFold(args[0], "activate") {
		d, err := sess.SOLActivate()
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "response": bytesToHex(d)}, nil
	}
	if strings.EqualFold(args[0], "deactivate") {
		if err := sess.SOLDeactivate(); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, nil
	}
	if strings.EqualFold(args[0], "set") {
		if len(args) < 3 {
			return nil, fmt.Errorf("usage: sol set <key> <value>")
		}
		param, val, err := parseSOLSet(args[1], args[2])
		if err != nil {
			return nil, err
		}
		if err := sess.SOLSetConfigParam(ctx, param, val); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "key": args[1], "value": args[2]}, nil
	}
	return nil, fmt.Errorf("unsupported sol command %q", strings.Join(args, " "))
}

func parseOnOff(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "1", "yes", "enable", "enabled":
		return true, nil
	case "off", "false", "0", "no", "disable", "disabled":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q", v)
	}
}

func sanitizeIPMIUserName(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	end := len(raw)
	for i, b := range raw {
		if b == 0x00 || b == 0xff {
			end = i
			break
		}
	}
	name := strings.TrimSpace(string(raw[:end]))
	return sanitizeASCII(name)
}

func parseSOLSet(key, value string) (byte, []byte, error) {
	key = strings.ToLower(strings.TrimSpace(key))
	value = strings.ToLower(strings.TrimSpace(value))
	boolByte := func(v string) (byte, error) {
		switch v {
		case "on", "true", "1", "yes", "enable", "enabled":
			return 1, nil
		case "off", "false", "0", "no", "disable", "disabled":
			return 0, nil
		default:
			return 0, fmt.Errorf("invalid boolean value %q", v)
		}
	}
	parseNum := func(v string, min, max int) (byte, error) {
		n, err := strconv.Atoi(v)
		if err != nil || n < min || n > max {
			return 0, fmt.Errorf("value %q out of range %d-%d", v, min, max)
		}
		return byte(n), nil
	}
	switch key {
	case "enabled":
		b, err := boolByte(value)
		return 1, []byte{b}, err
	case "force-encryption":
		b, err := boolByte(value)
		return 2, []byte{b << 1}, err
	case "force-authentication":
		b, err := boolByte(value)
		return 2, []byte{b}, err
	case "character-accumulate-level", "accumulate":
		b, err := parseNum(value, 0, 255)
		return 3, []byte{b}, err
	case "character-send-threshold", "threshold":
		b, err := parseNum(value, 1, 255)
		return 4, []byte{b}, err
	case "retry-count":
		b, err := parseNum(value, 0, 255)
		return 5, []byte{b}, err
	case "retry-interval":
		b, err := parseNum(value, 0, 255)
		return 6, []byte{b}, err
	case "non-volatile-bit-rate":
		b, err := parseSOLBitrate(value)
		return 7, []byte{b}, err
	case "volatile-bit-rate":
		b, err := parseSOLBitrate(value)
		return 8, []byte{b}, err
	case "payload-channel":
		b, err := parseNum(value, 0, 0x0f)
		return 9, []byte{b}, err
	case "payload-port":
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 65535 {
			return 0, nil, fmt.Errorf("invalid payload-port %q", value)
		}
		return 10, []byte{byte(n & 0xff), byte((n >> 8) & 0xff)}, nil
	default:
		return 0, nil, fmt.Errorf("unsupported SOL setting %q", key)
	}
}

func parseSOLBitrate(v string) (byte, error) {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "serial", "0":
		return 0, nil
	case "9.6", "9600", "1":
		return 6, nil
	case "19.2", "19200", "2":
		return 7, nil
	case "38.4", "38400", "3":
		return 8, nil
	case "57.6", "57600", "4":
		return 9, nil
	case "115.2", "115200", "5":
		return 10, nil
	default:
		return 0, fmt.Errorf("unsupported bitrate %q", v)
	}
}

func runIPMII2C(sess *ipmi.CmdSess, args []string) (any, error) {
	if len(args) < 3 {
		return nil, fmt.Errorf("usage: i2c read <slave_addr> <read_len> [write_byte ...]")
	}
	if !strings.EqualFold(args[0], "read") {
		return nil, fmt.Errorf("unsupported i2c command %q", args[0])
	}
	slave, err := parseByteArg(args[1])
	if err != nil {
		return nil, fmt.Errorf("invalid slave_addr: %w", err)
	}
	readLen, err := parseByteArg(args[2])
	if err != nil {
		return nil, fmt.Errorf("invalid read_len: %w", err)
	}
	writeData, err := parseByteArgs(args[3:])
	if err != nil {
		return nil, err
	}
	resp, err := sess.I2CMasterWriteRead(0x0e, slave, readLen, writeData)
	if err != nil {
		return nil, err
	}
	return map[string]any{"responseHex": hex.EncodeToString(resp), "responseBytes": bytesToHex(resp)}, nil
}

func runIPMISPD(sess *ipmi.CmdSess, args []string) (any, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("usage: spd read <slave_addr> [offset] [length]")
	}
	if !strings.EqualFold(args[0], "read") {
		return nil, fmt.Errorf("unsupported spd command %q", args[0])
	}
	if len(args) < 2 {
		return nil, fmt.Errorf("usage: spd read <slave_addr> [offset] [length]")
	}
	slave, err := parseByteArg(args[1])
	if err != nil {
		return nil, fmt.Errorf("invalid slave_addr: %w", err)
	}
	offset := byte(0)
	length := byte(64)
	if len(args) >= 3 {
		offset, err = parseByteArg(args[2])
		if err != nil {
			return nil, fmt.Errorf("invalid offset: %w", err)
		}
	}
	if len(args) >= 4 {
		length, err = parseByteArg(args[3])
		if err != nil {
			return nil, fmt.Errorf("invalid length: %w", err)
		}
	}
	resp, err := sess.SPDRead(slave, offset, length)
	if err != nil {
		return nil, err
	}
	return map[string]any{"responseHex": hex.EncodeToString(resp), "responseBytes": bytesToHex(resp)}, nil
}

func findIPMICommandIndex(args []string) int {
	known := make(map[string]struct{}, len(ipmiKnownCommands))
	for _, name := range ipmiKnownCommands {
		known[name] = struct{}{}
	}
	for i, a := range args {
		if _, ok := known[strings.ToLower(a)]; ok {
			return i
		}
	}
	return -1
}

func isSOLConsoleCommand(args []string) bool {
	if len(args) < 2 {
		return false
	}
	cmd := strings.ToLower(strings.TrimSpace(args[0]))
	if cmd != "sol" && cmd != "isol" {
		return false
	}
	return strings.EqualFold(args[1], "console")
}

func runIPMISOLConsole(host string, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: sol|isol console")
	}
	cmdName := strings.ToLower(strings.TrimSpace(args[0]))
	forceLegacy := cmdName == "isol"
	version := normalizeIPMIVersionCLI(ipmiVersion)
	useV15 := forceLegacy || version == "1.5"

	bin, err := exec.LookPath("ipmitool")
	if err != nil {
		return fmt.Errorf("interactive SOL requires ipmitool in PATH")
	}

	ipmiArgs := []string{"-H", host, "-p", strconv.Itoa(ipmiPort)}
	if useV15 {
		ipmiArgs = append(ipmiArgs, "-I", "lan")
	} else {
		ipmiArgs = append(ipmiArgs, "-I", "lanplus")
	}
	if ipmiUser != "" {
		ipmiArgs = append(ipmiArgs, "-U", ipmiUser)
	}
	if ipmiPassword != "" {
		ipmiArgs = append(ipmiArgs, "-P", ipmiPassword)
	}
	if ipmiTimeout > 0 {
		secs := int(ipmiTimeout.Round(time.Second) / time.Second)
		if secs <= 0 {
			secs = 1
		}
		ipmiArgs = append(ipmiArgs, "-N", strconv.Itoa(secs))
	}
	if useV15 {
		if a := strings.TrimSpace(strings.ToLower(ipmiAuth)); a != "" {
			switch a {
			case "none":
				ipmiArgs = append(ipmiArgs, "-A", "NONE")
			case "md2":
				ipmiArgs = append(ipmiArgs, "-A", "MD2")
			case "md5":
				ipmiArgs = append(ipmiArgs, "-A", "MD5")
			case "password", "straight":
				ipmiArgs = append(ipmiArgs, "-A", "PASSWORD")
			default:
				return fmt.Errorf("unsupported --auth %q for legacy SOL console", ipmiAuth)
			}
		}
		ipmiArgs = append(ipmiArgs, "isol", "activate")
	} else {
		if ipmiCipher >= 0 {
			ipmiArgs = append(ipmiArgs, "-C", strconv.Itoa(ipmiCipher))
		}
		ipmiArgs = append(ipmiArgs, "sol", "activate")
	}

	proc := exec.Command(bin, ipmiArgs...)
	return runInteractivePTY(proc)
}

func runInteractivePTY(proc *exec.Cmd) error {
	if proc == nil {
		return fmt.Errorf("missing process")
	}

	stdinFD := int(os.Stdin.Fd())
	stdoutFD := int(os.Stdout.Fd())
	if !term.IsTerminal(stdinFD) || !term.IsTerminal(stdoutFD) {
		proc.Stdin = os.Stdin
		proc.Stdout = os.Stdout
		proc.Stderr = os.Stderr
		return proc.Run()
	}

	ptmx, err := pty.Start(proc)
	if err != nil {
		proc.Stdin = os.Stdin
		proc.Stdout = os.Stdout
		proc.Stderr = os.Stderr
		return proc.Run()
	}
	defer ptmx.Close()

	_ = pty.InheritSize(os.Stdin, ptmx)
	oldState, err := term.MakeRaw(stdinFD)
	if err == nil {
		defer func() { _ = term.Restore(stdinFD, oldState) }()
	}

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(ptmx, os.Stdin)
		close(done)
	}()

	_, _ = io.Copy(os.Stdout, ptmx)
	<-done
	return proc.Wait()
}

func normalizeIPMIVersionCLI(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" || v == "2" || v == "2.0" {
		return "2.0"
	}
	if v == "1" || v == "1.5" {
		return "1.5"
	}
	return "2.0"
}

func expandIPMITargets(parts []string) ([]string, error) {
	specs := make([]string, 0, len(parts))
	for _, p := range parts {
		specs = append(specs, csvFields(p)...)
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("at least one target is required")
	}
	out := make([]string, 0, len(specs))
	seen := make(map[string]struct{}, len(specs))
	for _, spec := range specs {

		if discover.IsSpec(spec) {
			found, err := expandLinkLocalIPMITargets(spec)
			if err != nil {
				return nil, err
			}
			for _, h := range found {
				if _, ok := seen[h]; ok {
					continue
				}
				seen[h] = struct{}{}
				out = append(out, h)
			}
			continue
		}
		hosts, err := engine.ExpandTargets([]string{spec})
		if err != nil {
			return nil, err
		}
		for _, raw := range hosts {

			h, _ := engine.SplitHostPortHint(raw)
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}
	return out, nil
}

func expandLinkLocalIPMITargets(spec string) ([]string, error) {
	lg := log()
	ctx, cancel := context.WithTimeout(context.Background(), discover.DefaultWait+15*time.Second)
	defer cancel()
	found, err := discover.LinkLocal(ctx, spec, discover.Options{
		Log: func(s string) { lg.Infof("IPMI: %s", s) },
	})
	if err != nil {
		return nil, fmt.Errorf("link-local discovery %s: %w", spec, err)
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("link-local discovery %s: no hosts answered", spec)
	}
	out := make([]string, 0, len(found))
	for _, r := range found {
		lg.Infof("IPMI: link-local %s (%s)", r.Host(), strings.Join(r.Via, "+"))
		out = append(out, r.Host())
	}
	return out, nil
}

func parseByteArg(v string) (byte, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(v), 0, 8)
	if err != nil {
		return 0, err
	}
	return byte(n), nil
}

func parseByteArgs(args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}
	out := make([]byte, 0, len(args))
	for _, a := range args {
		b, err := parseByteArg(a)
		if err != nil {
			return nil, fmt.Errorf("invalid byte %q: %w", a, err)
		}
		out = append(out, b)
	}
	return out, nil
}

func bytesToHex(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	out := make([]string, 0, len(b))
	for _, x := range b {
		out = append(out, fmt.Sprintf("0x%02x", x))
	}
	return out
}
