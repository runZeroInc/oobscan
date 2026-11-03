package engine

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultWorkers is the default fan-out. IPMI is UDP and retry-heavy, so this is
// lower than a TCP scanner's; raise it with --workers for large IPv4 sweeps.
const DefaultWorkers = 512

// Config parameterizes a scan run.
type Config struct {
	Workers                  int           // concurrent target goroutines (default DefaultWorkers)
	Timeout                  time.Duration // per-probe I/O timeout
	TargetTimeout            time.Duration // overall budget per target (0 = default 4m, negative = no deadline)
	Ports                    []Port        // ports probed on every target
	WebPort                  int           // explicit web port applied to targets that did not carry their own host:port hint (0 = none)
	Cred                     Cred          // credential offered to authenticated checks
	Creds                    []Cred        // optional credential list offered to authenticated checks
	Destructive              bool          // enable destructive checks
	IPMIFull                 bool          // run the full IPMI NetFn/IPMB walk
	IPMINullPriv             bool          // measure the real privilege of an advertised null/anonymous IPMI account
	OpenBMCDefaultUserKey    bool          // run the slow/aggressive OpenBMC default-userKey heap-grooming auth-bypass check
	OpenBMCUserKeyBMCRand    string        // optional operator-supplied stale bmcRandomNum (hex) to try first in the OpenBMC default-userKey check
	OpenBMCUserKeyHeapStart  string        // optional hex start of the OpenBMC default-userKey heap-pointer sweep range (empty = default)
	OpenBMCUserKeyHeapEnd    string        // optional hex end of the OpenBMC default-userKey heap-pointer sweep range (empty = default)
	OpenBMCUserKeyPageOffset string        // optional in-page offset(s) (hex, comma-separated) to restrict the blind heap sweep to; empty = step all offsets
	OpenBMCUserKeySkipFast   bool          // skip the constant-string/zero residue rounds and go straight to the heap-pointer sweep
	DisableLogins            bool          // disable active online login attempts (default false)
	SNMPV3LocalizedKey       string        // operator-supplied raw localized USM key: "user:authHex[:privHex]"
	Verbose                  bool          // log per-target start/finish via the emitter
}

// RunFunc is the per-target pipeline. It is supplied by the caller (cmd) so the
// engine need not import the identify/check packages, avoiding an import cycle.
// It must be safe to run in many goroutines concurrently.
type RunFunc func(ctx context.Context, t *Target)

// Engine owns the worker pool and progress counters for one scan.
type Engine struct {
	cfg   Config
	emit  Emitter
	done  atomic.Uint64
	total atomic.Uint64
}

// New builds an Engine writing results to emit.
func New(cfg Config, emit Emitter) *Engine {
	if cfg.Workers <= 0 {
		cfg.Workers = DefaultWorkers
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	// Negative means "no per-target deadline" (set by opt-in long-running checks);
	// zero means "unset", which takes the default.
	if cfg.TargetTimeout == 0 {
		cfg.TargetTimeout = 4 * time.Minute
	}
	return &Engine{cfg: cfg, emit: emit}
}

// Stats reports progress (done, total) for status display.
func (e *Engine) Stats() (done, total uint64) { return e.done.Load(), e.total.Load() }

// Run fans hosts out across the worker pool, invoking run for each target in its
// own goroutine. It blocks until every target completes or ctx is cancelled.
func (e *Engine) Run(ctx context.Context, hosts []string, run RunFunc) {
	raiseFileLimit()
	e.total.Store(uint64(len(hosts)))

	workers := e.cfg.Workers
	if workers > len(hosts) && len(hosts) > 0 {
		workers = len(hosts)
	}

	ch := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range ch {
				e.runOne(ctx, host, run)
			}
		}()
	}

	go func() {
		defer close(ch)
		// Top-level guard so an unexpected panic in the feeder can never leave
		// workers blocked on an unclosed channel (close still runs on unwind).
		defer func() { _ = recover() }()
		for _, h := range hosts {
			select {
			case <-ctx.Done():
				return
			case ch <- h:
			}
		}
	}()

	wg.Wait()
}

// runOne processes a single host with a panic guard so one target's crash can
// never abort the scan; on panic it records the stack on the Target and still
// emits a result.
func (e *Engine) runOne(ctx context.Context, spec string, run RunFunc) {
	cred := e.cfg.Cred
	if cred.User == "" && len(e.cfg.Creds) > 0 {
		cred = e.cfg.Creds[0]
	}
	// A target given as host:port names an explicit web port; split it off so the
	// bare host is used for dialing/emit keys and the port becomes a web hint that
	// identify probes and records as web.port. A bare host inherits the global
	// --web-port default (0 = none).
	host, webPort := SplitHostPortHint(spec)
	if webPort == 0 {
		webPort = e.cfg.WebPort
	}
	t := &Target{
		Host:                     host,
		Ports:                    e.cfg.Ports,
		WebPort:                  webPort,
		Timeout:                  e.cfg.Timeout,
		Cred:                     cred,
		Creds:                    append([]Cred(nil), e.cfg.Creds...),
		Destructive:              e.cfg.Destructive,
		IPMIFull:                 e.cfg.IPMIFull,
		IPMINullPriv:             e.cfg.IPMINullPriv,
		OpenBMCDefaultUserKey:    e.cfg.OpenBMCDefaultUserKey,
		OpenBMCUserKeyBMCRand:    e.cfg.OpenBMCUserKeyBMCRand,
		OpenBMCUserKeyHeapStart:  e.cfg.OpenBMCUserKeyHeapStart,
		OpenBMCUserKeyHeapEnd:    e.cfg.OpenBMCUserKeyHeapEnd,
		OpenBMCUserKeyPageOffset: e.cfg.OpenBMCUserKeyPageOffset,
		OpenBMCUserKeySkipFast:   e.cfg.OpenBMCUserKeySkipFast,
		DisableLogins:            e.cfg.DisableLogins,
		SNMPV3LocalizedKey:       e.cfg.SNMPV3LocalizedKey,
		Evidence:                 map[string]any{},
	}
	e.emit.Start(host)
	if e.cfg.Verbose {
		e.emit.Log("-> scanning " + host)
	}
	started := time.Now()
	defer func() {
		if r := recover(); r != nil {
			t.Err = fmt.Sprintf("panic: %v\n%s", r, debug.Stack())
		}
		e.done.Add(1)
		if e.cfg.Verbose {
			e.emit.Log(fmt.Sprintf("[ok] %s  %d finding(s)  %.1fs", host, len(t.FindingsSnapshot()), time.Since(started).Seconds()))
		}
		e.emit.Emit(t)
	}()

	// A negative TargetTimeout means no per-target deadline: opt-in long-running
	// checks (the OpenBMC default-userKey heap sweep) must be able to finish.
	newTargetCtx := context.WithCancel
	if e.cfg.TargetTimeout > 0 {
		newTargetCtx = func(p context.Context) (context.Context, context.CancelFunc) {
			return context.WithTimeout(p, e.cfg.TargetTimeout)
		}
	}
	tctx, cancel := newTargetCtx(ctx)
	defer cancel()
	run(tctx, t)
}
