package hashcrack

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/creds"
)

var bmcDefaultPasswords = []string{

	"ADMIN", "admin", "administrator", "PASSW0RD", "password", "passw0rd",
	"superuser", "changeme", "unknown", "guest", "sysadmin", "root",

	"calvin", "user1234",

	"USERID", "PASSW0RD!", "passw0rd!",

	"password123", "ilo", "hpinvent",

	"cisco", "Cisco123", "password1",

	"0penBmc",

	"Huawei12#$", "Admin@9000", "Admin@huawei.com",

	"Supermicro",

	"jmm627", "apc",

	"admin123", "Admin1234", "P@ssw0rd", "Password1", "welcome1",
	"12345678", "123456789", "000000", "111111", "toor", "public", "private",
}

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

type Options struct {
	Wordlists       []string
	Patterns        []string
	Custom          map[byte]string
	ExtraSeeds      []string
	BatchSize       int
	Limit           int
	IncludeDefaults bool
	Deep            bool
	Warn            func(msg string)
	Info            func(msg string)
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

	emit := func(s string) bool {
		batch = append(batch, s)
		n++
		if len(batch) >= o.BatchSize && !flush() {
			return false
		}
		return !(o.Limit > 0 && n >= o.Limit)
	}

	if o.IncludeDefaults {
		if !emitDefaults(o.Deep, emit) {
			flush()
			return
		}
	}

	if len(o.ExtraSeeds) > 0 {
		if !emitExtraSeeds(o.ExtraSeeds, o.Deep, emit) {
			flush()
			return
		}
	}

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

func emitDefaults(deep bool, emit func(string) bool) bool {
	seen := map[string]struct{}{}
	cont := true
	for _, s := range DefaultSeeds() {

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
