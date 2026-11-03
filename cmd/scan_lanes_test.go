package cmd

import (
	"context"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/check"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// laneTestCheck is a check whose Run just calls run.
func laneTestCheck(name string, run func()) check.Check {
	return check.Check{
		Name: name,
		Run: func(context.Context, *engine.Target) []engine.Finding {
			run()
			return nil
		},
	}
}

func laneNames(cs []check.Check) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

// TestPlanCheckLanesSplitsThreeLanes pins the lane assignment: the shared UDP/623
// checks serial with the session sampler last, the consumers of IPMI-derived
// evidence deferred, and every other probe concurrent.
func TestPlanCheckLanesSplitsThreeLanes(t *testing.T) {
	plan := planCheckLanes([]check.Check{
		{Name: "ipmi.sidEntropy"},
		{Name: "http.redfish.postAuthEnum"},
		{Name: "ipmi.v20.rakpHash"},
		{Name: "http.web.defaultCreds"},
		{Name: "ipmi.defaultCreds"},
		{Name: "tls.cert"},
	})

	wantIPMI := []string{"ipmi.v20.rakpHash", "ipmi.defaultCreds", "ipmi.sidEntropy"}
	if got := laneNames(plan.ipmi); !slices.Equal(got, wantIPMI) {
		t.Errorf("ipmi lane = %v, want %v", got, wantIPMI)
	}
	wantAfter := []string{"http.redfish.postAuthEnum"}
	if got := laneNames(plan.afterIPMI); !slices.Equal(got, wantAfter) {
		t.Errorf("deferred lane = %v, want %v", got, wantAfter)
	}
	wantConcurrent := []string{"http.web.defaultCreds", "tls.cert"}
	if got := laneNames(plan.concurrent); !slices.Equal(got, wantConcurrent) {
		t.Errorf("concurrent lane = %v, want %v", got, wantConcurrent)
	}
}

// TestIPMIEvidenceDependentsAreRegistered guards the marker against drift: a
// renamed or deleted check would leave a stale entry that quietly stops deferring
// anything, which is the failure mode the deferred lane exists to prevent.
func TestIPMIEvidenceDependentsAreRegistered(t *testing.T) {
	registered := map[string]struct{}{}
	for _, c := range check.All() {
		registered[c.Name] = struct{}{}
	}
	for name := range ipmiEvidenceDependents {
		if _, ok := registered[name]; !ok {
			t.Errorf("%q is not a registered check; the deferred lane entry is stale", name)
		}
		// An ipmi.* name belongs in the serial lane, which already orders it after
		// its producer; listing it here would pull it out of that lane instead.
		if strings.HasPrefix(name, "ipmi.") {
			t.Errorf("%q is an IPMI check and must stay in the serial lane", name)
		}
	}
}

// TestRunCheckLanesDeferredLaneSeesIPMIEvidence is the regression test for the
// scheduling bug: the Redfish post-auth check reuses the credentials the IPMI
// lane cracks, so it has to observe ipmi.auth after that lane writes it. The IPMI
// producer here also holds until the concurrent lane has started, which pins the
// other half of the contract -- independent probes stay parallel with IPMI.
func TestRunCheckLanesDeferredLaneSeesIPMIEvidence(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.7"}
	concurrentStarted := make(chan struct{})
	var deferredRan, sawCracked atomic.Bool

	plan := checkPlan{
		ipmi: []check.Check{laneTestCheck("ipmi.v20.rakpHash", func() {
			select {
			case <-concurrentStarted:
			case <-time.After(10 * time.Second):
				t.Error("concurrent lane did not start while the IPMI lane was busy")
			}
			// Publishing late leaves an ungated deferred lane a wide window to read
			// the handle early, which is the defect being pinned; a lane that waits
			// passes regardless of the delay.
			time.Sleep(30 * time.Millisecond)
			tgt.SetEvidence("ipmi.auth", &ipmi.AuthReport{
				Cracked: []ipmi.CrackResult{{Username: "ADMIN", Password: "s3cret", Verified: true}},
			})
		})},
		concurrent: []check.Check{laneTestCheck("http.web.defaultCreds", func() {
			close(concurrentStarted)
		})},
		afterIPMI: []check.Check{laneTestCheck("http.redfish.postAuthEnum", func() {
			deferredRan.Store(true)
			v, ok := tgt.Evidenced("ipmi.auth")
			if !ok {
				return
			}
			auth, _ := v.(*ipmi.AuthReport)
			if auth != nil && len(auth.Cracked) == 1 && auth.Cracked[0].Password == "s3cret" {
				sawCracked.Store(true)
			}
		})},
	}

	ctx := context.Background()
	runCheckLanes(ctx, plan, func(c check.Check) { _ = c.Run(ctx, tgt) })

	if !deferredRan.Load() {
		t.Fatal("deferred lane never ran")
	}
	if !sawCracked.Load() {
		t.Fatal("deferred check read ipmi.auth before the IPMI lane published it")
	}
}

// TestRunCheckLanesSerializesIPMIOnly checks the two scheduling properties the
// lanes exist for: IPMI checks never overlap (one UDP/623 conversation), while
// the other lane really does run its probes at the same time.
func TestRunCheckLanesSerializesIPMIOnly(t *testing.T) {
	var inFlight, peak atomic.Int64
	enter := func() {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
	}

	const concurrentCount = 4
	arrived := make(chan struct{}, concurrentCount)
	release := make(chan struct{})
	var overlapped atomic.Bool

	var plan checkPlan
	for _, name := range []string{"ipmi.v20.rakpHash", "ipmi.defaultCreds", "ipmi.sidEntropy"} {
		plan.ipmi = append(plan.ipmi, laneTestCheck(name, func() {
			enter()
			defer inFlight.Add(-1)
			time.Sleep(2 * time.Millisecond)
		}))
	}
	for range concurrentCount {
		plan.concurrent = append(plan.concurrent, laneTestCheck("tls.cert", func() {
			// Each concurrent check parks until all of them have arrived, so a lane
			// that ran them one at a time would never release.
			arrived <- struct{}{}
			select {
			case <-release:
			case <-time.After(10 * time.Second):
				t.Error("concurrent lane did not run its checks in parallel")
			}
		}))
	}

	go func() {
		for range concurrentCount {
			select {
			case <-arrived:
			case <-time.After(10 * time.Second):
				return
			}
		}
		overlapped.Store(true)
		close(release)
	}()

	ctx := context.Background()
	tgt := &engine.Target{Host: "192.0.2.8"}
	runCheckLanes(ctx, plan, func(c check.Check) { _ = c.Run(ctx, tgt) })

	if got := peak.Load(); got != 1 {
		t.Errorf("peak concurrent IPMI checks = %d, want 1", got)
	}
	if !overlapped.Load() {
		t.Error("concurrent lane checks never overlapped")
	}
}

// TestRunCheckLanesCancelledSkipsDeferredLane confirms a cancelled scan does not
// start the deferred lane.
func TestRunCheckLanesCancelledSkipsDeferredLane(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var ran atomic.Int64
	plan := checkPlan{
		ipmi:       []check.Check{laneTestCheck("ipmi.v20.rakpHash", func() { ran.Add(1) })},
		concurrent: []check.Check{laneTestCheck("tls.cert", func() { ran.Add(1) })},
		afterIPMI:  []check.Check{laneTestCheck("http.redfish.postAuthEnum", func() { ran.Add(1) })},
	}
	tgt := &engine.Target{Host: "192.0.2.9"}
	runCheckLanes(ctx, plan, func(c check.Check) { _ = c.Run(ctx, tgt) })

	if got := ran.Load(); got != 0 {
		t.Errorf("%d checks ran after cancellation, want 0", got)
	}
}
