package convert

import (
	"fmt"
	"hash/fnv"
	"io"
	"sort"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

// Replay re-runs the detection logic that is a pure function of a stored record
// over an existing corpus, and reports counts that can be diffed between two
// builds. It exists because the quality audit's own report caps its examples and
// carries no totals, so it can say a signature exists but not how far it reaches,
// and because comparing two builds is the only way to tell whether a change to a
// rule moved anything.
//
// Only logic that needs no network is in scope. The findings in a native corpus
// were emitted by whichever binary produced it, so replaying that corpus exercises
// the audit rules, the proof predicates and record migration over those findings;
// it cannot re-derive a finding the scan never made.

// replayDistinctCap bounds the per-slot distinct-value set. Past the cap the count
// is reported as saturated and the slot is never called constant, which is the
// safe direction: a slot that overflowed plainly holds more than one value.
const replayDistinctCap = 1024

// ReplayOptions configures a replay pass.
type ReplayOptions struct {
	Format Format
	Input  string
	// Field selects one check.field slot for exact value frequencies. Empty skips
	// the extra bookkeeping, which is what makes the default pass cheap.
	Field string
	// Hosts selects one counter key whose host list should be reported, so two
	// builds can be compared with comm to see which hosts gained or lost it.
	Hosts    string
	Progress func(int)
}

// FieldSlot is one check-and-field pair's value spread across the corpus.
type FieldSlot struct {
	Key       string
	Findings  int
	Hosts     int
	Distinct  int
	Saturated bool
	Constant  bool
}

// ReplayResult is a replay pass's tally.
type ReplayResult struct {
	Format    Format
	Records   int
	Skipped   int
	Truncated bool
	// Rows is the counter table, keyed by rule key.
	Rows   map[string]*ReplayCounter
	Fields map[string]*FieldSlot
	Values map[string]int
	// Hosts is the host list for the key named by --hosts, sorted.
	Hosts    []string
	Field    string
	HostsKey string
}

// ReplayCounter is one key's event and host tally.
type ReplayCounter struct {
	Events int
	Hosts  int
	hosts  map[string]struct{}
	list   []string
	keep   bool
}

func (c *ReplayCounter) add(host string) {
	c.Events++
	if host == "" {
		return
	}
	if c.hosts == nil {
		c.hosts = map[string]struct{}{}
	}
	if _, dup := c.hosts[host]; dup {
		return
	}
	c.hosts[host] = struct{}{}
	c.Hosts++
	if c.keep {
		c.list = append(c.list, host)
	}
}

type fieldTally struct {
	slot   FieldSlot
	hosts  map[string]struct{}
	digest map[uint64]struct{}
}

// Replay streams the corpus and tallies every rule the harness covers.
func Replay(opts ReplayOptions) (*ReplayResult, error) {
	res := &ReplayResult{
		Format:   opts.Format,
		Rows:     map[string]*ReplayCounter{},
		Fields:   map[string]*FieldSlot{},
		Values:   map[string]int{},
		Field:    opts.Field,
		HostsKey: opts.Hosts,
	}
	counters := map[string]*ReplayCounter{}
	fields := map[string]*fieldTally{}

	bump := func(key, host string) {
		c := counters[key]
		if c == nil {
			c = &ReplayCounter{keep: opts.Hosts != "" && key == opts.Hosts}
			counters[key] = c
		}
		c.add(host)
	}

	n := 0
	stats, err := StreamRecords(opts.Format, opts.Input, func(rec *scanfile.Record) {
		n++
		if opts.Progress != nil {
			opts.Progress(n)
		}
		replayRecord(rec, opts, bump, fields, res.Values)
	})
	if err != nil {
		return nil, err
	}
	res.Records, res.Skipped, res.Truncated = stats.Read, stats.Skipped, stats.Truncated

	for k, c := range counters {
		res.Rows[k] = c
		if c.keep {
			sort.Strings(c.list)
			res.Hosts = c.list
		}
	}
	for k, ft := range fields {
		ft.slot.Key = k
		ft.slot.Hosts = len(ft.hosts)
		ft.slot.Distinct = len(ft.digest)
		ft.slot.Saturated = ft.slot.Distinct >= replayDistinctCap
		ft.slot.Constant = ft.slot.Distinct == 1 && !ft.slot.Saturated
		slot := ft.slot
		res.Fields[k] = &slot
	}
	return res, nil
}

// replayRecord applies every in-scope rule to one record.
func replayRecord(rec *scanfile.Record, opts ReplayOptions, bump func(key, host string), fields map[string]*fieldTally, values map[string]int) {
	host := rec.Host

	for _, p := range contradictionPairs(rec) {
		bump("contradiction", host)
		bump(fmt.Sprintf("contradiction/%s|%d", sanitizeReplayKey(p.Key), p.Port), host)
	}
	for _, k := range silentPartialKeys(rec) {
		bump("silentPartial", host)
		bump("silentPartial/"+sanitizeReplayKey(k), host)
	}
	for sig, count := range duplicateURLClusters(rec) {
		if count > 1 {
			bump("duplicate", host)
			bump("duplicate/"+sanitizeReplayKey(sig), host)
		}
	}

	for i := range rec.Findings {
		f := &rec.Findings[i]
		bump("finding/"+sanitizeReplayKey(f.Check), host)
		if needsProofField(f) {
			if hasProofField(f) {
				bump("proof.present", host)
			} else {
				bump("proof.missing", host)
				bump("proof.missing/"+sanitizeReplayKey(f.Check), host)
			}
		}
		for _, fd := range f.Fields {
			key := f.Check + "." + fd.Key
			tallyField(fields, key, host, fd.Val)
			if looksBinary(fd.Val) {
				bump("binaryText", host)
				bump("binaryText/"+sanitizeReplayKey(key), host)
			}
			if opts.Field != "" && key == opts.Field {
				values[fd.Val]++
			}
		}
	}
	// AttemptedChecks is a sorted comma-separated list, not a slice.
	for _, c := range strings.Split(rec.AttemptedChecks, ",") {
		if c = strings.TrimSpace(c); c != "" {
			bump("attempted/"+sanitizeReplayKey(c), host)
		}
	}
}

func tallyField(fields map[string]*fieldTally, key, host, val string) {
	ft := fields[key]
	if ft == nil {
		ft = &fieldTally{hosts: map[string]struct{}{}, digest: map[uint64]struct{}{}}
		fields[key] = ft
	}
	ft.slot.Findings++
	if host != "" {
		ft.hosts[host] = struct{}{}
	}
	// Hash rather than retain: a corpus holds hundreds of thousands of values and
	// only their cardinality is wanted here.
	if len(ft.digest) < replayDistinctCap {
		h := fnv.New64a()
		_, _ = h.Write([]byte(val))
		ft.digest[h.Sum64()] = struct{}{}
	}
}

// sanitizeReplayKey folds control bytes and tabs so a device-supplied string
// cannot split a row and silently corrupt a diff of two tables.
func sanitizeReplayKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r', r < 0x20, r == 0x7f:
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// WriteReplay renders the tally as one tab-separated, key-sorted table. The
// ordering is stable so two builds' output can be compared with diff.
func WriteReplay(w io.Writer, res *ReplayResult) error {
	if res == nil {
		return nil
	}
	keys := make([]string, 0, len(res.Rows))
	for k := range res.Rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c := res.Rows[k]
		if _, err := fmt.Fprintf(w, "count\t%s\t%d\t%d\n", k, c.Events, c.Hosts); err != nil {
			return err
		}
	}

	fkeys := make([]string, 0, len(res.Fields))
	for k := range res.Fields {
		fkeys = append(fkeys, k)
	}
	sort.Strings(fkeys)
	for _, k := range fkeys {
		s := res.Fields[k]
		distinct := fmt.Sprintf("%d", s.Distinct)
		if s.Saturated {
			distinct += "+"
		}
		if _, err := fmt.Fprintf(w, "field\t%s\t%d\t%d\t%s\t%t\n",
			s.Key, s.Findings, s.Hosts, distinct, s.Constant); err != nil {
			return err
		}
	}

	if res.Field != "" {
		vals := make([]string, 0, len(res.Values))
		for v := range res.Values {
			vals = append(vals, v)
		}
		sort.Slice(vals, func(i, j int) bool {
			if res.Values[vals[i]] != res.Values[vals[j]] {
				return res.Values[vals[i]] > res.Values[vals[j]]
			}
			return vals[i] < vals[j]
		})
		for _, v := range vals {
			if _, err := fmt.Fprintf(w, "value\t%s\t%d\t%s\n",
				res.Field, res.Values[v], sanitizeReplayKey(v)); err != nil {
				return err
			}
		}
	}

	for _, h := range res.Hosts {
		if _, err := fmt.Fprintf(w, "host\t%s\n", h); err != nil {
			return err
		}
	}
	return nil
}
