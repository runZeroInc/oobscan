package check

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// fakePostAuthCollector stands in for CollectPostAuthInventory, recording one entry per
// attempt so a test can count the sessions the walk would have opened.
type fakePostAuthCollector struct {
	results []struct {
		inv *ipmi.PostAuthCollection
		err error
	}
	flows     []ipmi.AuthFlow
	remaining []time.Duration
}

func (c *fakePostAuthCollector) collect(ctx context.Context, flow ipmi.AuthFlow) (*ipmi.PostAuthCollection, error) {
	c.flows = append(c.flows, flow)
	left := time.Duration(-1)
	if dl, ok := ctx.Deadline(); ok {
		left = time.Until(dl)
	}
	c.remaining = append(c.remaining, left)
	i := len(c.flows) - 1
	if i < len(c.results) {
		return c.results[i].inv, c.results[i].err
	}
	return &ipmi.PostAuthCollection{}, errors.New("no session")
}

func (c *fakePostAuthCollector) attempts() int { return len(c.flows) }

func candidateFlows(n int) []ipmi.AuthFlow {
	out := make([]ipmi.AuthFlow, 0, n)
	for i := range n {
		out = append(out, ipmi.AuthFlow{
			Version:  "2.0",
			Mode:     "cred",
			Username: string(rune('a' + i)),
			Suite:    ipmi.CipherAlgos{Suite: 3},
		})
	}
	return out
}

// invWith builds a collection that has landed the named sections. The section list is
// copied so a caller can splat postAuthSections without aliasing it.
func invWith(sections ...string) *ipmi.PostAuthCollection {
	return &ipmi.PostAuthCollection{Completed: append([]string(nil), sections...)}
}

func sessionExhaustedErr() error {
	return errors.New("sessionOpen: open-session rejected: status=0x01 (insufficient resources for session)")
}

// A budget long enough that the window gate never fires.
func walkCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// A refused session means the pool is full. Every further candidate takes another slot and
// leaves the host worse off than the single attempt would have, so the walk stops there.
func TestPostAuthWalkStopsOnSessionExhaustion(t *testing.T) {
	c := &fakePostAuthCollector{results: []struct {
		inv *ipmi.PostAuthCollection
		err error
	}{
		{&ipmi.PostAuthCollection{Error: "sessionOpen: open-session rejected: status=0x01 (insufficient resources for session)"}, sessionExhaustedErr()},
	}}
	candidates := candidateFlows(5)

	_, inv, _ := walkPostAuthFallbacks(walkCtx(t), candidates, candidates[0], invWith("lan", "lan6"), nil, c.collect, func(string, ...any) {})

	if c.attempts() != 1 {
		t.Errorf("walk made %d attempts after a session-exhaustion rejection, want 1", c.attempts())
	}
	// The rejection must not cost the coverage the primary flow already had.
	if postAuthCoverageScore(inv) != 2 {
		t.Errorf("coverage = %d, want the primary flow's 2 sections kept", postAuthCoverageScore(inv))
	}
}

// When the primary attempt is itself refused for want of resources, no fallback is worth
// opening: the pool is already full before the walk starts.
func TestPostAuthWalkSkipsWalkWhenPrimaryExhausted(t *testing.T) {
	c := &fakePostAuthCollector{}
	candidates := candidateFlows(4)

	walkPostAuthFallbacks(walkCtx(t), candidates, candidates[0], nil, sessionExhaustedErr(), c.collect, func(string, ...any) {})

	if c.attempts() != 0 {
		t.Errorf("walk made %d attempts, want 0 when the primary flow was refused a session", c.attempts())
	}
}

// A cipher-suite walk records the rejection per suite and returns the last suite's error,
// so the stop signal has to be read from the collection too.
func TestPostAuthWalkStopsOnExhaustionRecordedInCipherMatrix(t *testing.T) {
	c := &fakePostAuthCollector{}
	primary := &ipmi.PostAuthCollection{
		CipherMatrix: []ipmi.CipherAttempt{
			{Suite: 3, Error: "open-session rejected: status=0x01 (insufficient resources for session)"},
			{Suite: 17, Error: "rakp3: i/o timeout"},
		},
		Error: "no cipher suite candidates worked",
	}
	candidates := candidateFlows(4)

	walkPostAuthFallbacks(walkCtx(t), candidates, candidates[0], primary, errors.New("rakp3: i/o timeout"), c.collect, func(string, ...any) {})

	if c.attempts() != 0 {
		t.Errorf("walk made %d attempts, want 0 when a cipher attempt was refused a session", c.attempts())
	}
}

// Even with a long candidate list and a host that keeps answering, the walk opens a bounded
// number of extra sessions.
func TestPostAuthWalkCapsAttempts(t *testing.T) {
	c := &fakePostAuthCollector{}
	candidates := candidateFlows(8)

	walkPostAuthFallbacks(walkCtx(t), candidates, candidates[0], invWith("lan"), nil, c.collect, func(string, ...any) {})

	if c.attempts() != postAuthMaxFallbackFlows {
		t.Errorf("walk made %d attempts over %d candidates, want the cap of %d",
			c.attempts(), len(candidates), postAuthMaxFallbackFlows)
	}
	if postAuthMaxFallbackFlows >= len(candidates)-1 {
		t.Fatalf("cap %d does not bound a %d-candidate list; the test proves nothing",
			postAuthMaxFallbackFlows, len(candidates))
	}
}

// The most complete inventory seen wins, not the last one tried: a fallback that reads less
// than the primary must not replace it.
func TestPostAuthWalkKeepsBestCoverage(t *testing.T) {
	better := invWith("mcInfo", "chassis", "users", "lan")
	c := &fakePostAuthCollector{results: []struct {
		inv *ipmi.PostAuthCollection
		err error
	}{
		{better, nil},
		{invWith("lan"), errors.New("mc_info: cc=0xd4")},
	}}
	candidates := candidateFlows(4)

	flow, inv, err := walkPostAuthFallbacks(walkCtx(t), candidates, candidates[0], invWith("lan", "lan6"), nil, c.collect, func(string, ...any) {})

	if inv != better {
		t.Fatalf("walk kept coverage %d, want the richer fallback's %d",
			postAuthCoverageScore(inv), postAuthCoverageScore(better))
	}
	if flow.Username != candidates[1].Username {
		t.Errorf("flow = %q, want the candidate that produced the kept inventory (%q)", flow.Username, candidates[1].Username)
	}
	if err != nil {
		t.Errorf("err = %v, want the kept attempt's nil error", err)
	}
}

// A complete primary result has nothing to gain from another session.
func TestPostAuthWalkStopsOnFullCoverage(t *testing.T) {
	c := &fakePostAuthCollector{}
	candidates := candidateFlows(4)

	walkPostAuthFallbacks(walkCtx(t), candidates, candidates[0], invWith(postAuthSections...), nil, c.collect, func(string, ...any) {})

	if c.attempts() != 0 {
		t.Errorf("walk made %d attempts on a complete inventory, want 0", c.attempts())
	}
}

// A fallback started on a spent budget cannot reach any inventory: it opens a session and
// reports a deadline it never had room to meet. Skipping it is what keeps the collector's
// "before mcInfo: context deadline exceeded" out of the speculative attempts.
func TestPostAuthWalkSkipsAttemptsWithoutBudget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c := &fakePostAuthCollector{}
	candidates := candidateFlows(4)

	walkPostAuthFallbacks(ctx, candidates, candidates[0], invWith("lan"), nil, c.collect, func(string, ...any) {})

	if c.attempts() != 0 {
		t.Errorf("walk made %d attempts with %s of budget left, want 0", c.attempts(), 2*time.Second)
	}
}

// Each attempt gets its own sub-budget out of what the primary left, so one speculative
// flow cannot spend the window the next attempt and the trailing probes need.
func TestPostAuthWalkGivesEachAttemptItsOwnWindow(t *testing.T) {
	const budget = 60 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	c := &fakePostAuthCollector{}
	candidates := candidateFlows(4)

	walkPostAuthFallbacks(ctx, candidates, candidates[0], invWith("lan"), nil, c.collect, func(string, ...any) {})

	if c.attempts() == 0 {
		t.Fatal("no attempt was made with a full budget")
	}
	for i, left := range c.remaining {
		if left <= 0 {
			t.Errorf("attempt %d ran with no deadline of its own (%s)", i+1, left)
			continue
		}
		if left < postAuthFallbackMinWindow {
			t.Errorf("attempt %d window = %s, below the %s floor an attempt needs", i+1, left, postAuthFallbackMinWindow)
		}
		if left >= budget {
			t.Errorf("attempt %d window = %s, want less than the whole %s budget", i+1, left, budget)
		}
	}
}

func TestPostAuthFallbackWindow(t *testing.T) {
	for _, tc := range []struct {
		name      string
		remaining time.Duration
		wantOK    bool
		wantMax   time.Duration
	}{
		{"spent", 0, false, 0},
		{"nearly spent", 4 * time.Second, false, 0},
		{"below floor", 2*postAuthFallbackMinWindow - time.Second, false, 0},
		{"just above floor", 2*postAuthFallbackMinWindow + time.Second, true, postAuthFallbackMinWindow + time.Second},
		{"generous", 75 * time.Second, true, postAuthFallbackMaxWindow},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), tc.remaining)
		got, ok := postAuthFallbackWindow(ctx)
		cancel()
		if ok != tc.wantOK {
			t.Errorf("%s: ok = %v, want %v (window %s)", tc.name, ok, tc.wantOK, got)
			continue
		}
		if !ok {
			continue
		}
		if got > tc.wantMax {
			t.Errorf("%s: window = %s, want at most %s", tc.name, got, tc.wantMax)
		}
		if got < postAuthFallbackMinWindow {
			t.Errorf("%s: window = %s, below the %s floor", tc.name, got, postAuthFallbackMinWindow)
		}
		if got > tc.remaining/2 {
			t.Errorf("%s: window = %s, want no more than half of the %s remaining", tc.name, got, tc.remaining)
		}
	}
}

// Without a deadline the walk still runs, but each attempt is capped rather than unbounded.
func TestPostAuthFallbackWindowWithoutDeadline(t *testing.T) {
	got, ok := postAuthFallbackWindow(context.Background())
	if !ok {
		t.Fatal("a context with no deadline must not block the walk")
	}
	if got != postAuthFallbackMaxWindow {
		t.Errorf("window = %s, want the %s cap", got, postAuthFallbackMaxWindow)
	}
}

// A single-candidate list has no fallback to walk.
func TestPostAuthWalkNoCandidates(t *testing.T) {
	c := &fakePostAuthCollector{}
	candidates := candidateFlows(1)
	flow, inv, err := walkPostAuthFallbacks(walkCtx(t), candidates, candidates[0], invWith("lan"), nil, c.collect, func(string, ...any) {})
	if c.attempts() != 0 {
		t.Errorf("walk made %d attempts with one candidate, want 0", c.attempts())
	}
	if flow.Username != candidates[0].Username || inv == nil || err != nil {
		t.Errorf("walk altered the primary result: flow=%q inv=%v err=%v", flow.Username, inv, err)
	}
}
