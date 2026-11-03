// Package cmd is the cobra entrypoint for the oobscan CLI.
//
// The CLI structure mirrors sshamble (runZeroInc/sshamble) so that existing
// muscle memory carries over: `oobscan scan` probes, `oobscan coverage` shows
// the device/check inventory.
package cmd

import (
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/runZeroInc/oobscan/pkg/output"
)

// rootNoColor and rootVerbose are the persistent flag targets. Every
// subcommand shares the same --no-color and --verbose semantics so the shared
// output.Logger (see pkg/output) produces consistent severity-tagged,
// colorized lines across the whole CLI.
var (
	rootNoColor bool
	rootVerbose bool
	rootPprof   int
)

// pprofOnce guards the loopback pprof server so PersistentPreRun (which fires
// for every command in the chain) starts it at most once.
var pprofOnce sync.Once

var rootCmd = &cobra.Command{
	Use:   "oobscan [scan|ipmi|smc-*|explain|coverage|version]",
	Short: "A security assessment and diagnostic tool for out-of-band management.",
	Long: `oobscan enumerates BMCs, serial-port servers, IP-KVMs, PDUs, and other
out-of-band management services to identify exposures, validate remediation,
and support authorized investigation and reproducible security research.

Use only on systems you own or have explicit permission to assess. Scans send
active probes and enable login checks by default. To suppress login checks, use
"oobscan scan --disable-logins"; this does not make scanning passive.
Manual operations can change device state, interrupt management access, or
reboot a controller. Review each
command's help and agree on scope and maintenance windows before production use.

Start a scan (scan is the default command):

	oobscan -o results.jsonl 10.0.0.0/24

Captured RAKP hashes are written into each result's "rakp" records: the
"hashcat" field holds the hashcat -m 7300 audit input when one applies
(HMAC-SHA1); HMAC-MD5/SHA256 records omit it but keep the full reconstruction
material (sids, nonces, guid, hmac) for offline password auditing. Scan records,
backups, potfiles, and reports can contain secrets; restrict access and review
redacted copies before sharing.

Show the device + security-check coverage:

  oobscan coverage

Run direct IPMI validation/remediation commands:

	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 user list

The Supermicro/ATEN OEM workflows are separate smc-<tool> commands. Break-glass
deployment is opt-in. Committing with
"oobscan smc-restore-shell --apply" changes configuration and reboots the BMC:

	oobscan smc-backup -u ADMIN -P ADMIN 10.0.0.10
	oobscan smc-restore-shell -u ADMIN -P ADMIN 10.0.0.10 --apply
	oobscan smc-shell 10.0.0.10 4444
`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		initDefaultLogger()
		startPprof()
	},
}

// startPprof launches the net/http/pprof server bound to loopback on the port
// given by --pprof, so a stuck or slow scan can be inspected live with
// `go tool pprof http://127.0.0.1:<port>/debug/pprof/{goroutine,heap,profile}`.
// It binds only to 127.0.0.1 (never a routable interface) so the profiling
// surface is not exposed to the network, and runs at most once regardless of
// how many commands share the persistent pre-run.
func startPprof() {
	if rootPprof <= 0 {
		return
	}
	pprofOnce.Do(func() {
		addr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", rootPprof))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log().Warnf("pprof: cannot listen on %s: %v", addr, err)
			return
		}
		srv := newPprofServer()
		go func() {
			if serr := srv.Serve(ln); serr != nil && serr != http.ErrServerClosed {
				log().Warnf("pprof: server stopped: %v", serr)
			}
		}()
		log().Infof("pprof: serving on http://%s/debug/pprof/", addr)
	})
}

func newPprofServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// initDefaultLogger builds the process-wide output.Default() from the
// persistent --no-color / --verbose flags plus stdout TTY detection so every
// subcommand routes stdout/stderr through the same colorized, severity-tagged
// formatter.
func initDefaultLogger() {
	noColor := rootNoColor
	if !noColor && !isatty.IsTerminal(os.Stdout.Fd()) {
		noColor = true
	}
	if os.Getenv("NO_COLOR") != "" {
		noColor = true
	}
	output.SetDefault(output.NewLogger(os.Stdout, os.Stderr, noColor, rootVerbose))
}

// log returns the process-wide default logger. Kept as a short helper so
// subcommands can call log().Info(...), log().Warnf(...), etc. without the
// output package prefix.
func log() *output.Logger { return output.Default() }

// Execute runs the root command.
func Execute() {
	rootCmd.SetArgs(defaultScanArgs(os.Args[1:]))
	if err := rootCmd.Execute(); err != nil {
		log().Warnf("%v", err)
		os.Exit(1)
	}
}

func defaultScanArgs(args []string) []string {
	if !shouldDefaultToScan(args) {
		return args
	}
	withScan := make([]string, 0, len(args)+1)
	withScan = append(withScan, "scan")
	withScan = append(withScan, args...)
	return withScan
}

func shouldDefaultToScan(args []string) bool {
	commands := rootCommandNames()
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "" {
			continue
		}
		if isHelpFlag(arg) {
			return false
		}
		if arg == "--" {
			return true
		}
		if _, ok := commands[arg]; ok {
			return false
		}
		if strings.HasPrefix(arg, "-") {
			consumesNext, ok := rootPersistentFlag(arg)
			if !ok {
				return true
			}
			if consumesNext {
				i++
			}
			continue
		}
		return true
	}
	return false
}

func rootCommandNames() map[string]struct{} {
	commands := map[string]struct{}{"help": {}}
	for _, cmd := range rootCmd.Commands() {
		commands[cmd.Name()] = struct{}{}
		for _, alias := range cmd.Aliases {
			commands[alias] = struct{}{}
		}
	}
	return commands
}

func isHelpFlag(arg string) bool {
	return arg == "-h" || arg == "--help" || strings.HasPrefix(arg, "--help=")
}

func rootPersistentFlag(arg string) (consumesNext bool, ok bool) {
	if after, ok0 := strings.CutPrefix(arg, "--"); ok0 {
		name, _, hasValue := strings.Cut(after, "=")
		flag := rootCmd.PersistentFlags().Lookup(name)
		if flag == nil {
			return false, false
		}
		return flag.NoOptDefVal == "" && !hasValue, true
	}

	if !strings.HasPrefix(arg, "-") || len(arg) != 2 {
		return false, false
	}
	flag := rootCmd.PersistentFlags().ShorthandLookup(arg[1:])
	if flag == nil {
		return false, false
	}
	return flag.NoOptDefVal == "", true
}

func init() {
	rootCmd.CompletionOptions = cobra.CompletionOptions{DisableDefaultCmd: true}
	pf := rootCmd.PersistentFlags()
	pf.BoolVar(&rootNoColor, "no-color", false, "disable ANSI colors in all output (also honored via NO_COLOR)")
	pf.BoolVarP(&rootVerbose, "verbose", "v", false, "log detailed diagnostics (DEBUG lines) to stderr")
	pf.IntVar(&rootPprof, "pprof", 0, "start a loopback-bound pprof server on this port (127.0.0.1) for goroutine/heap/CPU profiling of a running scan")
}
