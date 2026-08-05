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

var (
	rootNoColor bool
	rootVerbose bool
	rootPprof   int
)

var pprofOnce sync.Once

var rootCmd = &cobra.Command{
	Use:   "oobscan [scan|ipmi|explain|coverage|version]",
	Short: "An exploration tool for (in)secure out-of-band management services.",
	Long: `oobscan enumerates BMCs, serial-port servers, IP-KVMs, PDUs, and other
out-of-band management surfaces for protocol exposures, pre-auth information
leakage, default credentials, and known-vulnerable firmware.

Start a scan (scan is the default command):

	oobscan -o results.jsonl 10.0.0.0/24

Captured RAKP hashes are written into each result's "rakp" records: the
"hashcat" field holds the ready-to-crack hashcat -m 7300 line when one applies
(HMAC-SHA1); HMAC-MD5/SHA256 records omit it but keep the full reconstruction
material (sids, nonces, guid, hmac) for offline cracking.

Show the device + security-check coverage:

  oobscan coverage

Run direct IPMI validation/remediation commands:

	oobscan ipmi -u ADMIN -P ADMIN 10.0.0.10 user list
`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		initDefaultLogger()
		startPprof()
	},
}

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

func log() *output.Logger { return output.Default() }

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
