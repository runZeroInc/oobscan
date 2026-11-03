package hashcrack

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/creds"
)

// bmcDefaultPasswords are OOB/BMC-specific factory passwords that seed the
// always-on "common defaults" pass. They are merged with creds.Passwords() (the
// shared default-credential knowledge base) and creds.CommonPasswordSeeds, then
// expanded with light case/leet/doubling variations via creds.Permute.
var bmcDefaultPasswords = []string{
	// Cross-vendor / AMI MegaRAC.
	"ADMIN", "admin", "administrator", "PASSW0RD", "password", "passw0rd",
	"superuser", "changeme", "unknown", "guest", "sysadmin", "root",
	// Dell iDRAC.
	"calvin", "user1234",
	// IBM / Lenovo IMM / XCC.
	"USERID", "PASSW0RD!", "passw0rd!",
	// HPE iLO.
	"password123", "ilo", "hpinvent",
	// Cisco CIMC / UCS.
	"cisco", "Cisco123", "password1",
	// OpenBMC (incl. NVIDIA BlueField).
	"0penBmc",
	// Huawei iBMC / openUBMC.
	"Huawei12#$", "Admin@9000", "Admin@huawei.com",
	// Supermicro.
	"Supermicro",
	// APC / Schneider NMC.
	"jmm627", "apc",
	// Common weak set frequently seen on BMCs in the wild.
	"admin123", "Admin1234", "P@ssw0rd", "Password1", "welcome1",
	"12345678", "123456789", "000000", "111111", "toor", "public", "private",
}

// DefaultSeeds returns the deduplicated base words for the common-defaults pass,
// in a stable order (BMC-specific first, then the shared KB). Each seed is
// expanded with light variations by the producer.
func DefaultSeeds() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(list []string) {
		for _, s := range list {
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	add(bmcDefaultPasswords)
	add(creds.CommonPasswordSeeds)
	add(creds.Passwords())
	return out
}

// Options configures the candidate producer.
type Options struct {
	Wordlists       []string         // dictionary files, streamed in order
	Patterns        []string         // hashcat/John mask specs, streamed in order
	Custom          map[byte]string  // custom mask charsets ?1..?4
	ExtraSeeds      []string         // cleartext user/pass harvested from the scans (see HarvestSeeds)
	BatchSize       int              // candidates per channel batch (default 64)
	Limit           int              // stop after N candidates (0 = unlimited)
	IncludeDefaults bool             // run the always-on defaults + variations pass first
	Deep            bool             // deep variations: also combine with year/digit/symbol affixes
	Warn            func(msg string) // optional warning sink (defaults to stderr)
	Info            func(msg string) // optional info sink (mask keyspace etc; defaults to stderr)
}

func (o *Options) warn(msg string) {
	if o.Warn != nil {
		o.Warn(msg)
		return
	}
	fmt.Fprintln(os.Stderr, "warn: "+msg)
}

func (o *Options) info(msg string) {
	if o.Info != nil {
		o.Info(msg)
		return
	}
	fmt.Fprintln(os.Stderr, msg)
}

// Produce streams candidates to cands as batched slices, closing cands when done
// (or when stop is closed). Order: (1) common defaults + light variations, then
// (2) each wordlist, then (3) each mask. It is meant to run in its own goroutine.
func Produce(cands chan<- []string, stop <-chan struct{}, o Options) {
	defer close(cands)
	if o.BatchSize < 1 {
		o.BatchSize = 64
	}
	n := 0
	batch := make([]string, 0, o.BatchSize)
	flush := func() bool {
		if len(batch) == 0 {
			return true
		}
		select {
		case cands <- batch:
			batch = make([]string, 0, o.BatchSize)
			return true
		case <-stop:
			return false
		}
	}
	// emit returns false when the producer should stop (batch send interrupted or
	// candidate limit reached).
	emit := func(s string) bool {
		batch = append(batch, s)
		n++
		if len(batch) >= o.BatchSize && !flush() {
			return false
		}
		return !(o.Limit > 0 && n >= o.Limit)
	}

	// Phase 1: common defaults + light variations (always-on).
	if o.IncludeDefaults {
		if !emitDefaults(o.Deep, emit) {
			flush()
			return
		}
	}

	// Phase 1b: cleartext user/pass harvested from the scan results. These are
	// tried like defaults (always-on when present). In --deep mode they are
	// additionally expanded with case/leet/affix variations via creds.Permute,
	// so a recovered/observed credential seeds permutations of related accounts.
	if len(o.ExtraSeeds) > 0 {
		if !emitExtraSeeds(o.ExtraSeeds, o.Deep, emit) {
			flush()
			return
		}
	}

	// Phase 2: wordlists.
	for _, wl := range o.Wordlists {
		f, err := os.Open(wl)
		if err != nil {
			o.warn("wordlist " + wl + ": " + err.Error())
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		done := false
		for sc.Scan() {
			if !emit(strings.TrimRight(sc.Text(), "\r\n")) {
				done = true
				break
			}
		}
		if err := sc.Err(); err != nil {
			o.warn("wordlist " + wl + ": " + err.Error())
		}
		f.Close()
		if done {
			flush()
			return
		}
	}

	// Phase 3: masks.
	for _, ms := range o.Patterns {
		m, err := ParseMask(ms, o.Custom)
		if err != nil {
			o.warn(err.Error())
			continue
		}
		o.info(fmt.Sprintf("pattern %q keyspace=%s", ms, m.Keyspace().String()))
		mc := make(chan string, 8192)
		go m.Stream(mc, stop)
		stopped := false
		for s := range mc {
			if !emit(s) {
				stopped = true
				break
			}
		}
		if stopped {
			flush()
			return
		}
	}

	flush()
}

// EstimateCandidateCap estimates the total number of candidates that Produce
// would emit for the given options, honoring Limit. It returns -1 when the
// space cannot be represented safely as int64.
func EstimateCandidateCap(o Options) int64 {
	limit := int64(o.Limit)
	total := int64(0)
	add := func(n int64) bool {
		if n < 0 {
			return false
		}
		if n > math.MaxInt64-total {
			return false
		}
		total += n
		if limit > 0 && total >= limit {
			total = limit
			return true
		}
		return false
	}

	if o.IncludeDefaults {
		left := int64(0)
		if limit > 0 {
			left = limit - total
			if left <= 0 {
				return limit
			}
		}
		if add(countDefaults(o.Deep, left)) {
			return total
		}
	}

	if len(o.ExtraSeeds) > 0 {
		left := int64(0)
		if limit > 0 {
			left = limit - total
			if left <= 0 {
				return limit
			}
		}
		if add(countExtraSeeds(o.ExtraSeeds, o.Deep, left)) {
			return total
		}
	}

	for _, wl := range o.Wordlists {
		left := int64(0)
		if limit > 0 {
			left = limit - total
			if left <= 0 {
				return limit
			}
		}
		n, err := countWordlistCandidates(wl, left)
		if err != nil {
			o.warn("wordlist " + wl + ": " + err.Error())
			continue
		}
		if add(n) {
			return total
		}
	}

	for _, ms := range o.Patterns {
		m, err := ParseMask(ms, o.Custom)
		if err != nil {
			o.warn(err.Error())
			continue
		}
		k := m.Keyspace()
		if !k.IsInt64() {
			return -1
		}
		if add(k.Int64()) {
			return total
		}
	}

	return total
}

func countDefaults(deep bool, limit int64) int64 {
	n := int64(0)
	emitDefaults(deep, func(string) bool {
		n++
		if limit > 0 && n >= limit {
			return false
		}
		return true
	})
	return n
}

// countExtraSeeds counts how many candidates emitExtraSeeds would emit for the
// given seeds and mode, honoring limit (dedup-aware, mirroring emitExtraSeeds).
func countExtraSeeds(seeds []string, deep bool, limit int64) int64 {
	n := int64(0)
	emitExtraSeeds(seeds, deep, func(string) bool {
		n++
		return !(limit > 0 && n >= limit)
	})
	return n
}

func countWordlistCandidates(path string, limit int64) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	n := int64(0)
	for sc.Scan() {
		n++
		if limit > 0 && n >= limit {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	return n, nil
}

// emitDefaults expands each default seed with case/leet/doubling variations (and,
// when deep, year/digit/symbol affixes) via creds.Permute, deduplicating across
// seeds. It returns false if emit signalled a stop.
func emitDefaults(deep bool, emit func(string) bool) bool {
	seen := map[string]struct{}{}
	cont := true
	for _, s := range DefaultSeeds() {
		// creds.Permute's test callback returns true to stop enumeration; we return
		// true only when emit asks us to stop, and false (keep going) otherwise --
		// including for already-seen candidates, which we simply skip.
		creds.Permute(s, deep, func(cand string) bool {
			if _, dup := seen[cand]; dup {
				return false
			}
			seen[cand] = struct{}{}
			if !emit(cand) {
				cont = false
				return true
			}
			return false
		})
		if !cont {
			return false
		}
	}
	return true
}

// emitExtraSeeds emits cleartext credentials harvested from the scans. In normal
// mode each seed is emitted verbatim (like an inline wordlist). In deep mode
// each seed is additionally expanded with case/leet/affix variations via
// creds.Permute, so an observed credential also seeds permutations. It
// deduplicates across seeds and returns false if emit signalled a stop.
func emitExtraSeeds(seeds []string, deep bool, emit func(string) bool) bool {
	seen := map[string]struct{}{}
	push := func(cand string) bool {
		if cand == "" {
			return true
		}
		if _, dup := seen[cand]; dup {
			return true
		}
		seen[cand] = struct{}{}
		return emit(cand)
	}
	for _, s := range seeds {
		if !deep {
			if !push(s) {
				return false
			}
			continue
		}
		cont := true
		creds.Permute(s, true, func(cand string) bool {
			if !push(cand) {
				cont = false
				return true
			}
			return false
		})
		if !cont {
			return false
		}
	}
	return true
}
