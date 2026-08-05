package engine

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

const DefaultWorkers = 512

type Config struct {
	Workers            int
	Timeout            time.Duration
	TargetTimeout      time.Duration
	Ports              []Port
	WebPort            int
	Cred               Cred
	Creds              []Cred
	Destructive        bool
	IPMIFull           bool
	IPMINullPriv       bool
	DisableLogins      bool
	SNMPV3LocalizedKey string
	Verbose            bool
}

type RunFunc func(ctx context.Context, t *Target)

type Engine struct {
	cfg   Config
	emit  Emitter
	done  atomic.Uint64
	total atomic.Uint64
}

func New(cfg Config, emit Emitter) *Engine {
	if cfg.Workers <= 0 {
		cfg.Workers = DefaultWorkers
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}

	if cfg.TargetTimeout == 0 {
		cfg.TargetTimeout = 4 * time.Minute
	}
	return &Engine{cfg: cfg, emit: emit}
}

func (e *Engine) Stats() (done, total uint64) { return e.done.Load(), e.total.Load() }

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

func (e *Engine) runOne(ctx context.Context, spec string, run RunFunc) {
	cred := e.cfg.Cred
	if cred.User == "" && len(e.cfg.Creds) > 0 {
		cred = e.cfg.Creds[0]
	}

	host, webPort := SplitHostPortHint(spec)
	if webPort == 0 {
		webPort = e.cfg.WebPort
	}
	t := &Target{
		Host:               host,
		Ports:              e.cfg.Ports,
		WebPort:            webPort,
		Timeout:            e.cfg.Timeout,
		Cred:               cred,
		Creds:              append([]Cred(nil), e.cfg.Creds...),
		Destructive:        e.cfg.Destructive,
		IPMIFull:           e.cfg.IPMIFull,
		IPMINullPriv:       e.cfg.IPMINullPriv,
		DisableLogins:      e.cfg.DisableLogins,
		SNMPV3LocalizedKey: e.cfg.SNMPV3LocalizedKey,
		Evidence:           map[string]any{},
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
