package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/runZeroInc/oobscan/pkg/check"
	"github.com/runZeroInc/oobscan/pkg/discover"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/httpscan"
	"github.com/runZeroInc/oobscan/pkg/identify"
	"github.com/runZeroInc/oobscan/pkg/output"
)

const checkConcurrency = 8

var (
	scanInput                string
	scanPorts                string
	scanTimeout              time.Duration
	scanTargetTimeout        time.Duration
	scanWorkers              int
	scanHTTPSweepConcurrency int
	scanCategories           string
	scanChecks               string
	scanOutput               string
	scanNoOutput             bool
	scanNoCorrelate          bool
	scanIPMIFull             bool
	scanIPMINullPriv         bool
	scanCreds                []string
	scanDisableLogins        bool
	scanSNMPV3LocalizedKey   string
	scanAssumeVendor         string
	scanAssumeClass          string
	scanAssumeScheme         string
	scanWebPort              int
	scanLinkLocalWait        time.Duration
)

var scanCmd = &cobra.Command{
	Use:   "scan [flags] [targets...]",
	Short: "Comprehensively scan targets for out-of-band management exposures.",
	Long: `Scan runs the full BMC/KVM/serial exposure pipeline against each target: it
identifies the device (vendor, product, class), runs the device-specific and
cross-vendor security checks, tries default credentials, and - with --ipmi-full
- walks the entire IPMI NetFn/IPMB surface.

Targets may be single IPs, hostnames, CIDRs (10.0.0.0/24), hyphen ranges
(10.0.0.1-20), or host:port pairs, given as arguments or via -i (a file, or '-'
for stdin). The fancy human results always render to stdout (diagnostics to
stderr); machine NDJSON always writes to an output file (set with --output,
or auto-created under ~/.cache/oobscan when omitted; disable auto-creation
with --disable-output).

An IPv6 multicast target is a link-local sweep rather than a host: ff02::1%en0
probes the all-nodes group on en0 (ICMPv6 echo + RMCP presence ping) and scans
every link-local address that answers. Use it to reach a BMC that has no
routable address at all - freshly racked, DHCP-less, or on a management VLAN
with no addressing. Drop the zone (ff02::1) to sweep every eligible interface.

  oobscan scan 10.0.0.0/24
  oobscan scan --output results.jsonl 10.0.0.0/16
  oobscan scan --ipmi-full 10.0.0.22
  oobscan scan ff02::1%en0`,
	Run: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	f := scanCmd.Flags()
	f.StringVarP(&scanOutput, "output", "o", "", "write NDJSON records to this file (default: auto-create in user cache dir as YYYYmmdd-<timestamp>.jsonl)")
	f.BoolVar(&scanNoOutput, "disable-output", false, "disable automatic NDJSON output file creation when --output is not set")
	f.BoolVar(&scanNoCorrelate, "disable-correlate", false,
		"skip the post-scan correlation pass. By default a finished scan is re-read once and each "+
			"out-of-band device is matched to the server it manages (name/address/MAC/serial as the BMC "+
			"itself discloses them), written to a sibling .managed.jsonl. The pass is read-only, adds no "+
			"network traffic, and never rewrites the scan output")
	f.StringVarP(&scanInput, "input-targets", "i", "", "read targets (one per line) from a file ('-' = stdin)")

	f.SetNormalizeFunc(func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
		if name == "input" {
			name = "input-targets"
		}
		return pflag.NormalizedName(name)
	})
	f.StringVarP(&scanPorts, "ports", "p", "623/udp,623/tcp,161/udp,443/tcp,444/tcp,8443/tcp,9443/tcp,4443/tcp,4433/tcp,10443/tcp,7443/tcp,6443/tcp,4444/tcp,8083/tcp,7548/tcp,9898/tcp,4434/tcp,8081/tcp,80/tcp,8080/tcp,8000/tcp,81/tcp,82/tcp,805/tcp,3052/tcp,5000/tcp,8090/tcp,8888/tcp,55000/tcp,23/tcp,5986/tcp,5985/tcp,16993/tcp,16992/tcp,1900/udp,427/udp,5900/tcp,5901/tcp,3900/tcp,2068/tcp,7578/tcp,5120/tcp,5122/tcp,5123/tcp,17988/tcp,17990/tcp,49152/tcp,4001/tcp,10001/tcp,10002/tcp,10003/tcp,10064/tcp,30718/udp,4800/udp,2362/udp,771/tcp,1027/tcp,9999/tcp,5988/tcp,5989/tcp,5353/udp,3702/udp,6868/tcp,5123/tcp",
		"ports to probe (port[/proto]); includes IPMI+SNMP, ranked OOB HTTPS management ports (TLS-first, incl. 444 iDRAC/XCC/ATEN alt-HTTPS), key BMC KVM/virtual-media channels (3900/2068/7578/5120-5123/17988-17990/5900-5901/49152/623-tcp), HTTP-native fallbacks incl. HTTP-only OOB web ports observed in the Shodan census (Tripp Lite PowerAlert 805, CyberPower RMCARD 3052, Advantech EKI 8090, Moxa 55000/81/82, NanoKVM 5000/8888), serialConsole discovery (Lantronix/Moxa/Digi/Perle), SLP service discovery (427/udp), CIM/WBEM (5988/5989), mDNS DNS-SD (5353/udp), WS-Discovery (3702/udp), Lantronix raw serial passthrough (10001/10002/10003), Intel ASD / H3C RemoteXDP JTAG-over-network (6868 H3C remap, 5123 Intel default), and generic telnet banner capture on 23/tcp (alt-SSH 2222 is probed by the ssh.exposure check, not via this list)")
	f.DurationVar(&scanTimeout, "timeout", 4*time.Second, "per-probe timeout")
	f.DurationVar(&scanTargetTimeout, "target-timeout", 0, "overall budget per target across all checks (default 4m; negative disables the deadline)")
	f.IntVarP(&scanWorkers, "workers", "w", engine.DefaultWorkers, "concurrent target workers")
	f.IntVar(&scanHTTPSweepConcurrency, "http-sweep-concurrency", httpscan.DefaultGlobalSweepConcurrency,
		"process-wide ceiling on in-flight HTTP endpoint-sweep requests. This is a bound on OUTBOUND SOCKETS, not workers: "+
			"the sweep runs 16-wide per target, so it would otherwise scale with --workers and exhaust the ~28k ephemeral ports "+
			"a single source address has (at -w 3500 it asks for ~56k). Past that ceiling connects fail locally and hosts are "+
			"silently not measured. Raise it only with a widened ephemeral-port range or multiple source addresses")
	f.StringVar(&scanCategories, "categories", "", "only run these check categories (comma-separated)")
	f.StringVar(&scanChecks, "checks", "", "only run these checks (name, category, or dotted prefix)")
	f.BoolVar(&scanIPMIFull, "ipmi-full", false, "walk the full IPMI NetFn/Cmd/IPMB surface (deep, slow). Implies --ipmi-null-priv")
	f.BoolVar(&scanIPMINullPriv, "ipmi-null-priv", false, "when Get Channel Auth Caps advertises an enabled null or anonymous account, open an RMCP+ session as it and measure the privilege it actually holds (Set Session Privilege Level request 0). The advertised bit alone says nothing about impact: an account can be enabled yet clamped to privilege 0 with IPMI messaging off, unable to read sensors, FRU, the SEL or even Get Device ID. Without this the ipmi.authNull/ipmi.authAnon findings stay at the unmeasured LOW risk. Costs one session per affected host and is an active login, so --disable-logins suppresses it")
	f.StringArrayVar(&scanCreds, "creds", nil, "additional credential to try, as user:pass (repeatable; also accepts comma-separated pairs)")
	f.BoolVar(&scanDisableLogins, "disable-logins", false, "disable active login attempts (default and user-specified credentials) while keeping passive checks like RAKP hash enumeration")
	f.StringVar(&scanSNMPV3LocalizedKey, "snmp-v3-localized-key", "", "operator-supplied raw localized SNMPv3 USM key to try, as user:authHex[:privHex] (SHA-256 auth / AES privacy assumed). Use to test a firmware-recovered shared USM key that is a localized key, not a passphrase")
	f.StringVar(&scanAssumeVendor, "assume-vendor", "", "override the identified vendor slug (e.g. 'raritan'); use to exercise vendor-gated checks against a known/simulated target that would not self-fingerprint")
	f.StringVar(&scanAssumeClass, "assume-class", "", "override the identified device class (bmc|kvm|serialConsole|pdu|amt|firmware); pair with --assume-vendor for simulator/lab testing")
	f.StringVar(&scanAssumeScheme, "assume-scheme", "", "force the web scheme (http|https) for web checks; overrides the port heuristic (lab simulators serve plain http on non-standard ports)")
	f.IntVar(&scanWebPort, "web-port", 0, "web port for the identify/web-check stage when a target does not carry its own host:port (a host:port target overrides this); use for targets served on a non-standard web port")
	f.DurationVar(&scanLinkLocalWait, "link-local-wait", discover.DefaultWait, "how long to listen for replies when an IPv6 multicast target (ff02::1%en0) is swept for link-local hosts; raise it on a busy segment where stacks stagger their multicast replies")
}

func applyIdentityOverride(t *engine.Target) {
	if scanAssumeVendor == "" && scanAssumeClass == "" && scanAssumeScheme == "" {
		return
	}
	if t.Identity == nil {
		t.Identity = &engine.Identity{}
	}
	if scanAssumeVendor != "" {
		t.Identity.Vendor = strings.ToLower(strings.TrimSpace(scanAssumeVendor))
		if t.Identity.Confidence == "" || t.Identity.Confidence == engine.ConfLow {
			t.Identity.Confidence = engine.ConfHigh
		}
	}
	if scanAssumeClass != "" {
		if c, ok := parseDeviceClass(scanAssumeClass); ok {
			t.Identity.Class = c
		}
	}
	if t.Identity.Attributes == nil {
		t.Identity.Attributes = map[string]string{}
	}

	if t.Identity.Attributes["web.port"] == "" {
		for _, p := range t.Ports {
			if p.Proto == engine.ProtoTCP {
				t.Identity.Attributes["web.port"] = strconv.Itoa(p.Num)
				if t.Identity.Attributes["web.scheme"] == "" {
					t.Identity.Attributes["web.scheme"] = assumeWebScheme(p.Num)
				}
				break
			}
		}
	}

	if scanAssumeScheme == "http" || scanAssumeScheme == "https" {
		t.Identity.Attributes["web.scheme"] = scanAssumeScheme
	}
}

func parseDeviceClass(s string) (engine.DeviceClass, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "bmc":
		return engine.ClassBMC, true
	case "kvm":
		return engine.ClassKVM, true
	case "serialconsole", "serial", "console":
		return engine.ClassSerialConsole, true
	case "pdu":
		return engine.ClassPDU, true
	case "amt":
		return engine.ClassAMT, true
	case "firmware":
		return engine.ClassFirmware, true
	default:
		return engine.ClassUnknown, false
	}
}

func assumeWebScheme(port int) string {
	switch port {
	case 80, 8080, 8000, 8888, 8081:
		return "http"
	default:
		return "https"
	}
}

func resolveLinkLocalTargets(lg *output.Logger, hosts []string) []string {
	if !slices.ContainsFunc(hosts, discover.IsSpec) {
		return hosts
	}

	ctx, cancel := context.WithTimeout(context.Background(), scanLinkLocalWait+15*time.Second)
	defer cancel()
	resolved, err := discover.ResolveSpecs(ctx, hosts, discover.Options{
		Wait: scanLinkLocalWait,
		Log:  func(s string) { lg.Infof("Scan: %s", s) },
	})
	if err != nil {
		lg.Warnf("Scan: link-local discovery: %v", err)
	}
	return resolved
}

func runScan(cmd *cobra.Command, args []string) {
	lg := log()

	specs := append([]string{}, args...)
	hosts, err := engine.ExpandTargets(specs)
	if err != nil {
		lg.Warnf("Scan: %v", err)
		os.Exit(2)
	}
	if scanInput != "" {
		fh, ferr := openInput(scanInput)
		if ferr != nil {
			lg.Warnf("Scan: %v", ferr)
			os.Exit(2)
		}
		fileHosts, rerr := engine.ReadTargetLines(fh)
		fh.Close()
		if rerr != nil {
			lg.Warnf("Scan: %v", rerr)
			os.Exit(2)
		}
		hosts = append(hosts, fileHosts...)
	}

	hosts = resolveLinkLocalTargets(lg, hosts)
	if len(hosts) == 0 {
		lg.Warn("Scan: no targets (pass IPs/CIDRs as arguments or via -i)")
		os.Exit(2)
	}

	ports, err := engine.ParsePorts(scanPorts)
	if err != nil {
		lg.Warnf("Scan: %v", err)
		os.Exit(2)
	}

	var records io.Writer
	var outputFile *os.File
	var scanOutputPath string
	var outputPathOnce sync.Once
	printOutputPath := func(prefix string) {
		if scanOutputPath == "" {
			return
		}
		outputPathOnce.Do(func() {
			lg.Infof("%s %s", prefix, scanOutputPath)
		})
	}

	if strings.TrimSpace(scanOutput) != "" || !scanNoOutput {

		generated := false
		if strings.TrimSpace(scanOutput) != "" {
			scanOutputPath = scanOutput
		} else {
			generated = true
			path, _, rerr := resolveScanOutputPath("", time.Now())
			if rerr != nil {
				lg.Warnf("Scan: %v", rerr)
				os.Exit(2)
			}
			scanOutputPath = path
		}
		if err := ensureParentDir(scanOutputPath); err != nil {
			lg.Warnf("Scan: %v", err)
			os.Exit(1)
		}

		openOutput := func(path string, unique bool) (*os.File, error) {
			if unique {
				return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
			}
			return os.Create(path)
		}

		fh, cerr := openOutput(scanOutputPath, generated)
		if cerr != nil {
			lg.Warnf("Scan: %v", cerr)
			os.Exit(1)
		}
		outputFile = fh
		records = fh
	}

	noColor := rootNoColor || !isatty.IsTerminal(os.Stdout.Fd())
	verbose := rootVerbose

	creds := parseCreds(scanCreds)
	cred := engine.Cred{}
	if len(creds) > 0 {
		cred = creds[0]
	}
	emit := output.New(output.Options{
		Fancy:   os.Stdout,
		Errors:  os.Stderr,
		Records: records,
		Total:   len(hosts),
		NoColor: noColor,
		Verbose: verbose,
	})

	httpscan.SetGlobalSweepConcurrency(scanHTTPSweepConcurrency)
	if scanHTTPSweepConcurrency != httpscan.DefaultGlobalSweepConcurrency {
		lg.Infof("Scan: HTTP endpoint-sweep concurrency set to %d (default %d)",
			scanHTTPSweepConcurrency, httpscan.DefaultGlobalSweepConcurrency)
	}
	targetTimeout := scanTargetTimeout

	ipmiNullPriv := scanIPMINullPriv || scanIPMIFull
	eng := engine.New(engine.Config{
		Workers:            scanWorkers,
		Timeout:            scanTimeout,
		TargetTimeout:      targetTimeout,
		Ports:              ports,
		WebPort:            scanWebPort,
		Cred:               cred,
		Creds:              creds,
		DisableLogins:      scanDisableLogins,
		SNMPV3LocalizedKey: scanSNMPV3LocalizedKey,
		IPMIFull:           scanIPMIFull,
		IPMINullPriv:       ipmiNullPriv,
		Verbose:            verbose,
	}, emit)
	var closeOnce sync.Once
	closeOutput := func() {
		closeOnce.Do(func() {
			if err := emit.Close(); err != nil {
				lg.Warnf("Scan: %v", err)
			}
			if outputFile != nil {
				if err := outputFile.Close(); err != nil {
					lg.Warnf("Scan output: %v", err)
				}
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	forceQuit := func() {
		cancel()
		closeOutput()
		printOutputPath("Scan output written to")
		lg.Warn("Aborted")
		os.Exit(130)
	}
	go func() {
		<-sigCh
		forceQuit()
	}()
	if isatty.IsTerminal(os.Stdin.Fd()) {
		go scanStatusOnEnter(ctx, eng, emit)
	}
	go scanStatusTicker(ctx, eng, emit)

	eng.Run(ctx, hosts, makePipeline(emit, verbose))
	cancel()
	closeOutput()
	printOutputPath("Scan output written to")

	if !scanNoCorrelate && scanOutputPath != "" {
		sum, path, err := runCorrelateStage(scanOutputPath)
		switch {
		case err != nil:
			lg.Warnf("Correlation: %v", err)
		case sum.Described == 0:
			lg.Infof("Correlation: no out-of-band device disclosed anything about a managed server")
		default:
			lg.Infof("%s", correlateSummaryLine(sum, path))
		}
	}
}

func scanStatusOnEnter(ctx context.Context, eng *engine.Engine, emit engine.Emitter) {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		done, total := eng.Stats()
		emit.Status(done, total, true)
		if d, ok := emit.(interface{ StatusDetailed(done, total uint64) }); ok {
			d.StatusDetailed(done, total)
		}
	}
	_ = sc.Err()
}

func scanStatusTicker(ctx context.Context, eng *engine.Engine, emit engine.Emitter) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			done, total := eng.Stats()
			emit.Status(done, total, false)
		}
	}
}

func resolveScanOutputPath(explicit string, now time.Time) (path string, generated bool, err error) {
	if strings.TrimSpace(explicit) != "" {
		return explicit, false, nil
	}
	name := fmt.Sprintf("%s-%d.jsonl", now.Format("20060102"), now.UnixNano())
	return filepath.Join(userCacheDir(), "oobscan", name), true, nil
}

func makePipeline(emit engine.Emitter, verbose bool) engine.RunFunc {
	return func(ctx context.Context, t *engine.Target) {
		t.Progress = func(msg string) { emit.Activity(t.Host, msg) }
		if verbose {
			t.DebugLog = func(msg string) { emit.Log("    " + t.Host + " " + msg) }
		}
		emit.Activity(t.Host, "identify")
		var logf func(string)
		if verbose {
			logf = func(msg string) { emit.Log("    " + t.Host + " identify: " + msg) }
		}
		t.Identity = identify.Identify(ctx, t, logf)
		applyIdentityOverride(t)
		if verbose {
			classLabel := string(t.Identity.Class)
			if strings.EqualFold(classLabel, "bmc") {
				classLabel = "BMC"
			}
			emit.Log(fmt.Sprintf("  %s -> %s / %s %s (%s)",
				t.Host, classLabel, orDash(t.Identity.Vendor), orDash(t.Identity.Product), t.Identity.Confidence))
		}
		sel := check.Selector{
			Checks:      csvFields(scanChecks),
			Categories:  csvFields(scanCategories),
			Destructive: t.Destructive,
			HasCreds:    t.Cred.User != "" || len(t.Creds) > 0,
		}
		checks := check.ForIdentity(t.Identity, sel)
		emit.Checks(t.Host, 0, len(checks))
		emit.Activity(t.Host, fmt.Sprintf("running %d checks", len(checks)))

		plan := planCheckLanes(checks)

		var checksDone atomic.Int64
		runOne := func(c check.Check) {
			if lc, ok := emit.(interface {
				CheckStart(host, check string)
				CheckDone(host, check string)
			}); ok {
				lc.CheckStart(t.Host, c.Name)
				defer lc.CheckDone(t.Host, c.Name)
			}
			if verbose {
				emit.Log("    " + t.Host + " check " + c.Name)
			}
			start := time.Now()
			fs := runCheck(ctx, t, c)
			if pe, ok := emit.(interface {
				EmitFindings(host string, fs []engine.Finding)
			}); ok && len(fs) > 0 {
				pe.EmitFindings(t.Host, fs)
			}
			done := int(checksDone.Add(1))
			emit.Checks(t.Host, done, len(checks))
			if verbose {
				emit.Log(fmt.Sprintf("    %s check %s done %.1fs", t.Host, c.Name, time.Since(start).Seconds()))
			}
		}

		runCheckLanes(ctx, plan, runOne)

		emit.Activity(t.Host, "post-checks")
		if fs := check.RunPostChecks(ctx, t); len(fs) > 0 {
			t.AddFindings(fs...)
			if pe, ok := emit.(interface {
				EmitFindings(host string, fs []engine.Finding)
			}); ok {
				pe.EmitFindings(t.Host, fs)
			}
			for _, f := range fs {
				if f.Port != 0 && f.Protocol != "" && f.Risk != "none" {
					t.MarkOpen(f.Port, f.Transport, f.Protocol)
				}
			}
		}

		reclassifyHoneypotByBreadth(ctx, t)

		emit.Activity(t.Host, "finalize")
		t.Final = engine.Finalize(t)
		if verbose {
			emit.Log(fmt.Sprintf("  %s => id.final %s / %s %s (%s) %s",
				t.Host, t.Final.Class, orDash(t.Final.Vendor), orDash(t.Final.Product),
				t.Final.Confidence, t.Final.FlagsString()))
		}
	}
}

func runCheck(ctx context.Context, t *engine.Target, c check.Check) (out []engine.Finding) {
	defer func() {
		if r := recover(); r != nil {

			panicFinding := engine.Finding{
				Check: "check.panic", Category: "diagnostic", Risk: "info",
				Fields: engine.F(
					"check", c.Name,
					"category", c.Category,
					"panic", fmt.Sprint(r)),
			}
			t.AddFindings(panicFinding)
			out = append(out, panicFinding)
		}
	}()
	fs := c.Run(ctx, t)
	t.AddFindings(fs...)
	out = append(out, fs...)

	for _, f := range fs {
		if f.Port != 0 && f.Protocol != "" && f.Risk != "none" {
			t.MarkOpen(f.Port, f.Transport, f.Protocol)
		}
	}
	return out
}

func reclassifyHoneypotByBreadth(ctx context.Context, t *engine.Target) {
	if identify.ReclassifyHoneypotByBreadth(t) {
		t.ReplaceFindings("id", check.RunIdentityReport(ctx, t)...)
	}
}

type checkPlan struct {
	ipmi []check.Check

	concurrent []check.Check

	afterIPMI []check.Check
}

func planCheckLanes(checks []check.Check) checkPlan {
	var p checkPlan
	for _, c := range checks {
		switch {
		case needsIPMIEvidence(c.Name):
			p.afterIPMI = append(p.afterIPMI, c)
		case strings.HasPrefix(c.Name, "ipmi."):
			p.ipmi = append(p.ipmi, c)
		default:
			p.concurrent = append(p.concurrent, c)
		}
	}

	sort.SliceStable(p.ipmi, func(i, j int) bool {
		return ipmiLaneStage(p.ipmi[i].Name) < ipmiLaneStage(p.ipmi[j].Name)
	})
	return p
}

const (
	ipmiStageProduce = iota

	ipmiStageConsume

	ipmiStageSampleSessions
)

var ipmiEvidenceConsumers = map[string]struct{}{
	"ipmi.postAuthEnum": {},
}

func ipmiLaneStage(name string) int {
	switch {
	case ipmiOpensSessionsLast(name):
		return ipmiStageSampleSessions
	default:
		if _, ok := ipmiEvidenceConsumers[name]; ok {
			return ipmiStageConsume
		}
		return ipmiStageProduce
	}
}

var ipmiEvidenceDependents = map[string]struct{}{
	"http.redfish.postAuthEnum": {},

	"http.megarac.webDefaultCreds": {},

	"http.cim.defaultCreds": {},
}

func needsIPMIEvidence(name string) bool {
	_, ok := ipmiEvidenceDependents[name]
	return ok
}

func ipmiOpensSessionsLast(name string) bool {
	return name == "ipmi.sidEntropy" || name == "ipmi.sidPredictable"
}

func runCheckLanes(ctx context.Context, plan checkPlan, runOne func(check.Check)) {
	var wg sync.WaitGroup

	sem := make(chan struct{}, checkConcurrency)

	launch := func(cs []check.Check) {
		var lane sync.WaitGroup
		for _, c := range cs {
			if ctx.Err() != nil {
				break
			}
			lane.Add(1)
			sem <- struct{}{}
			go func(c check.Check) {
				defer lane.Done()
				defer func() { <-sem }()
				runOne(c)
			}(c)
		}
		lane.Wait()
	}

	ipmiDone := make(chan struct{})
	wg.Go(func() {
		defer close(ipmiDone)
		for _, c := range plan.ipmi {
			if ctx.Err() != nil {
				break
			}
			runOne(c)
		}
	})

	if len(plan.afterIPMI) > 0 {
		wg.Go(func() {
			select {
			case <-ipmiDone:
			case <-ctx.Done():
				return
			}
			launch(plan.afterIPMI)
		})
	}

	launch(plan.concurrent)
	wg.Wait()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func parseCreds(values []string) []engine.Cred {
	if len(values) == 0 {
		return nil
	}
	out := make([]engine.Cred, 0, len(values))
	seen := map[string]bool{}
	for _, v := range values {
		for part := range strings.SplitSeq(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			user, pass, ok := strings.Cut(part, ":")
			if !ok {
				continue
			}
			k := user + "\x00" + pass
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, engine.Cred{User: user, Pass: pass})
		}
	}
	return out
}

func openInput(path string) (io.ReadCloser, error) {
	if path == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	return os.Open(path)
}
