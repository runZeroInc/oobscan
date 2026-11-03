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
	ansiSeqRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

	// ipmiKnownCommands marks where target input ends and the command begins.
	// The Supermicro OEM workflows are top-level `smc-*` commands, not tokens here.
	ipmiKnownCommands = []string{"isol", "mc", "chassis", "lan", "lan6", "fru", "user", "raw", "sol", "i2c", "spd", "mem", "channel", "xdp"}
)

var ipmiCmd = &cobra.Command{
	Use:   "ipmi [flags] <host[,host|cidr|range...]|targets...> <command> [args...]",
	Short: "Run authenticated IPMI commands across one or more targets.",
	Long: `ipmi runs practical, ipmitool-like command workflows directly through oobscan's
IPMI stack so responders can quickly validate exposures and perform common
triage/remediation tasks (user inventory/disable/reset, mc/chassis/lan/fru,
raw requests, SOL config, and i2c/spd checks).

Run only operations authorized for the specified targets. Raw requests, account
changes, resets, and some service settings execute immediately; there is no
global dry-run mode. A register read or diagnostic request can have hardware
side effects. Review command-specific apply requirements and maintenance needs.

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

	Remote memory and hardware-register access
		mem info
		mem probe [<addr|region> ...]
		mem read  <addr|region> <length> [key=value ...]
		mem write <addr|region> <hexbytes...|in=FILE> [key=value ...] apply

		Reads and writes the BMC's own address space, and the buses hanging
		off it, through whichever OEM primitive the target's firmware
		exposes. Options are key=value tokens rather than flags, so they do
		not collide with the shared "oobscan ipmi" flag namespace.

		The vendor profile is detected from the IPMI System GUID board code
		(the same lookup smc-backup uses), refined by the firmware revision
		where one build differs from its family; pin it with profile=<id>.
		"mem info" prints the resolved profile, which address spaces it
		supports, its page allowlist, its named regions and its hazards.

		Address spaces (space=):
			physical  the BMC's own physical space, via the vendor
			          /dev/mem primitive (Supermicro: 0x30/0x70 subfn 0xC0)
			virtual   a kernel virtual address, translated through the
			          profile's PAGE_OFFSET and DRAM base. Valid only inside
			          the 1:1 lowmem window
			flash     an offset into the BMC SPI flash, translated through
			          the memory-mapped window (Supermicro FMC CS0 at
			          0x20000000). via=wst instead streams the ATEN
			          whole-flash staging chain (NetFn 0x3E), 56 B/request
			scu       an offset into the SoC system-control registers
			gpio      an offset into the GPIO register block, or a single
			          pin with pin=<n> where the firmware has a pin-level
			          command (X14 subfn 0x4B)
			i2c       a byte offset inside a device on an I2C/SMBus segment,
			          via App/0x52 Master Write-Read; oem switches to the
			          vendor transport, which on Supermicro reaches bus 0 on
			          the generations where App/0x52 answers CC 0xd6
			spd       i2c with the SPD conventions. Above 256 bytes it does
			          the DDR4 SPA page select, which is the JEDEC
			          convention rather than something measured on these
			          boards, so treat a long read as unverified. DDR5 pages
			          through SPD5118 MR11 instead and is not handled: stay
			          under 256 bytes, or drive the part with space=i2c
			fru       raw bytes inside a FRU inventory device (0x0a/0x11,
			          0x0a/0x12) - no field decoding, unlike "fru print"
			sdr       raw bytes inside one SDR repository record
			mii       an MDIO/PHY register on the BMC NIC
			peci      a raw PECI transaction to the host CPU, 32 B each way
			cpu       the host CPU's own register planes over AMD APML on
			          the Supermicro AMD boards (0x30/0x80): the SMU mailbox
			          (apml=mailbox), SB-TSI (apml=sbtsi) and the 16-bit
			          SB-RMI space (apml=sbrmi), socket=0|1
			nvram     the vendor manufacturing-data store, one indexed byte
			          at a time

		BYTE ORDER IS THE TRAP. On X10 and X11 the read reply serialises the
		loaded word MSB-first even though the BMC is a little-endian ARM, so
		each group is reversed to reconstruct a faithful image. X13 01.07.01
		and X14 answer in ascending-address order and must not be reversed.
		The profile carries the right default; order=ascending|msb-first
		overrides it, and unit=1 sidesteps the question entirely at four
		times the request cost.

		THROUGHPUT. The physical primitive moves 1-4 bytes per request. A
		64 KB sector is ~16k requests and takes minutes; megabytes are not
		realistic. Point it at something small and specific.

		WRITES ARE STAGED BY DEFAULT. "mem write" prints the exact request
		bytes it would send and transmits nothing until the bare token
		"apply" is present. Add verify to read each unit back. An
		unrestricted physical write is BMC code execution and can wedge the
		board; the profile's hazards are printed before every write.

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

	Supermicro/ATEN OEM workflows
		The Supermicro config backup, restore-shell, file/CDB and
		RAKP-bypass workflows are top-level commands, not tokens here:
		smc-backup, smc-restore-shell, smc-uninstall,
		smc-read, smc-cdb, smc-rakp-bypass, smc-priv-esc, smc-shell, smc-kvm.
		Run "oobscan smc-<tool> --help" for each.

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

	# Read the Supermicro U-Boot environment. The SPI flash is memory-mapped at
	# FMC CS0 0x20000000 and the uboot_env sector is at flash offset 0x1FC0000,
	# i.e. physical 0x21FC0000, 64 KB. Word 0 is the environment's CRC32; the
	# NUL-separated name=value pairs start at +4 and end at a double NUL, and a
	# provisioned unit's whole environment is realistically under 1 KB - so read
	# 2 KB, not the full sector.
	# Live on X11. On X10 the FMC CE0 window is left in command mode, so reads
	# there return ZEROS rather than flash content; "mem read" says so, and
	# changing it would need a write to the flash controller.
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem read 0x21FC0000 2k
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem read uboot-env 2k out=uboot-env.bin
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem read space=flash 0x1FC0000 2k

	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem info
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem probe
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem read scu 64
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem read 0x1e6e2078 4 unit=4
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem read space=virtual 0xc0008000 256
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem read space=i2c bus=1 slave=0x50 0 256
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem read space=spd bus=1 slave=0x50 0 512
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem read space=fru fru=0 0 256 out=fru.bin
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem read space=gpio pin=42
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem read space=cpu apml=sbtsi socket=0 0x01
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem read space=cpu apml=mailbox 0x11 apply
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem write 0x1e6e2000 deadbeef
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem write 0x1e6e2000 deadbeef verify apply
	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 mem write space=fru fru=0 0x10 in=patch.bin apply

	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 xdp enable 6868

Two protocol-level authentication bypass methods include:
	--ipmi-version=1.5 --auth=none
	--ipmi-version=2   --cipher=0

SMCRAKP mode is automatically detected and handled, but can be disabled with:
	--disable-smcrakp

OpenBMC targets support two unique features:
	--openbmc-relabel=<admin-user>

	This replaces the credentials of the active session after authentication and
	is useful for privilege escalation and when chained to --openbmc-bmcrand.

	--openbmc-bmcrand=<16-byte hex or 4-byte heap pointer>

	This opens the session with no password using the OpenBMC default-userKey
	bypass, given a stale bmcRandomNum you already know (e.g. sampled with shell
	access). On a miss it retries nearby heap pages and the constant strings.

	--openbmc-bypass

	This opens the session with no password and NO seed value, the same way the
	scanner's fast path does: it opens sessions and re-rolls the known
	constant-string residues (the freed phosphor-logging / D-Bus buffers), grooming
	the target to manufacture the log-template residue, and retries until one
	activates. Only an enabled --user is needed (default root). Example:
		oobscan ipmi --openbmc-bypass -u root 10.0.0.10 user list

HPE iLO4 targets support a RAKP-none authentication bypass:
	--ilo-rakp-none

	This opens a session with no password by declaring the RMCP+ Open Session
	authentication-algorithm record as payload-type 0x02 (confidentiality) with
	algorithm 0, which evades iLO4's auth-algo-0 reject guard while the parser
	positionally assigns it as the authentication algorithm (NONE). Only an enabled
	username is required (--user, default Administrator); the session is
	Administrator-capable. Example:
	oobscan ipmi --ilo-rakp-none -u Administrator 10.0.0.10 user list
`,
	Args: cobra.ArbitraryArgs,
	RunE: runIPMI,
}

func init() {
	registerIPMIAllSessionFlags(ipmiCmd)
	ipmiCmd.Flags().IntVar(&ipmiMaxFRUField, "fru-max-fields", 64, "maximum FRU string fields to decode")
	// "mem ... via=shell" reaches the BMC through a root shell a prior
	// smc-restore-shell deploy left behind, so it needs that service's address
	// and the pinned client identity.
	registerSMCShellPortFlag(ipmiCmd)
	registerSMCCertPathFlag(ipmiCmd)
	rootCmd.AddCommand(ipmiCmd)
}

func runIPMI(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	if err := validateIPMIOutputFlags(); err != nil {
		fmt.Fprintf(out, "ipmi: %v\n", err)
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

	if isSOLConsoleCommand(commandArgs) && len(targets) != 1 {
		fmt.Fprintln(out, "ipmi: sol/isol console supports exactly one target")
		printIPMIShortUsage(cmd)
		return nil
	}

	usage := func() { printIPMIShortUsage(cmd) }
	return runIPMITargets(cmd, targets, summarizeIPMICommand(commandArgs), usage,
		func(ctx context.Context, idx int, host string, status *ipmiStatusSpinner) error {
			// sol/isol console hands the terminal to ipmitool, and
			// "mem ... via=shell" reaches the BMC through a deployed root shell.
			// Both replace the session rather than running inside one, so they
			// come before OpenCmdSess. via=shell is what keeps the memory
			// primitive usable when IPMI is wedged, unauthenticated, or has none
			// (e.g. X10 fw 3.53, where the IPMI /dev/mem open fails).
			switch {
			case isSOLConsoleCommand(commandArgs):
				status.Set(idx, host, "starting interactive console")
				return stepErrorf("sol console", runIPMISOLConsole(host, commandArgs))
			case memViaShell(commandArgs):
				status.Set(idx, host, "via=shell (no IPMI session)")
				res, merr := runIPMIMemViaShell(host, commandArgs)
				if merr != nil {
					status.Set(idx, host, "command failed")
					return stepErrorf("command", merr)
				}
				status.WithPaused(func() {
					_ = printViaShellResult(cmd, host, res)
				})
				return nil
			}
			return runIPMISessionStep(cmd, commandArgs, runIPMITargetCommand)(ctx, idx, host, status)
		})
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
	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintf(out, "  %s\n", cmd.UseLine())
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Supported commands:")
	for _, line := range ipmiShortUsageLines {
		fmt.Fprintf(out, "  %s\n", line)
	}
	fmt.Fprintln(out, "")
	fmt.Fprintf(out, "Supermicro OEM workflows are separate commands: %s\n", strings.Join(smcCommandNames(), ", "))
}

// ipmiShortUsageLines is the one-line-per-command summary printed on a usage
// error. Every entry in ipmiKnownCommands is represented here; the
// TestIPMIShortUsageCoversKnownCommands test keeps the two in step.
var ipmiShortUsageLines = []string{
	"mc [info] | mc reset <cold|warm>",
	"chassis [status]",
	"lan [print]",
	"lan6 [print]",
	"fru [print]",
	"user <list|enable|disable|clear|set ...>",
	"raw <netfn> <cmd> [data ...]",
	"sol <info|set|activate|deactivate|console>",
	"isol <console>",
	"channel info [channel]",
	"channel getaccess <channel> [id]",
	"channel setaccess <channel> <id> callin=<on|off> ipmi=<on|off> link=<on|off> privilege=<level>",
	"i2c read <slave_addr> <read_len> [write_byte ...]",
	"spd read <slave_addr> [offset] [length]",
	"mem info | probe | read <addr|region> <len> [key=value ...]",
	"mem write <addr|region> <hexbytes|in=FILE> [key=value ...] apply",
	"xdp <status|enable|disable> [port] [key=value ...]",
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
	case *ipmiMemReadResult:
		if v == nil {
			_, err := fmt.Fprintln(w, "(no data)")
			return err
		}
		return writeMemReadResult(w, v)
	case *ipmiMemGlobalVarResult:
		if v == nil {
			_, err := fmt.Fprintln(w, "(no data)")
			return err
		}
		return writeMemGlobalVarResult(w, v)
	case *ipmi.FlashCredResult:
		if v == nil {
			_, err := fmt.Fprintln(w, "(no data)")
			return err
		}
		return writeFlashCredResult(w, v)
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
		// A workflow result that renders its own table wins over the generic
		// key/value rendering, so the command-injection validators can lay out a
		// verdict, a safety contract and a per-field store/readback table.
		if tr, ok := result.(ipmi.TableReporter); ok {
			return tr.SMCPrintTable(w)
		}
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
	case "mem":
		return runIPMIMem(ctx, sess, args[1:])
	case "xdp":
		return runIPMIXDP(sess, args[1:])
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
		// An IPv6 multicast spec (ff02::1%en0) is a link-local sweep: probe the
		// group and take the BMCs that answer as the target list.
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
			// IPMI runs over UDP/623 (or the ipmi subcommand's own port flag), so a
			// host:port target's web-port hint is not meaningful here - drop it.
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

// expandLinkLocalIPMITargets sweeps an IPv6 multicast group for link-local hosts
// and returns them as IPMI targets. The RMCP vector alone would be the tighter
// filter here, but a BMC that answers ICMPv6 while its IPMI listener is slow to
// come up is still worth handing to the caller's command, so both vectors run.
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
