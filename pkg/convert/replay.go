package convert

import (
	"fmt"
	"hash/fnv"
	"io"
	"sort"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

const replayDistinctCap = 1024

type ReplayOptions struct {
	Format Format
	Input  string

	Field string

	Hosts    string
	Progress func(int)
}

type FieldSlot struct {
	Key       string
	Findings  int
	Hosts     int
	Distinct  int
	Saturated bool
	Constant  bool
}

type ReplayResult struct {
	Format    Format
	Records   int
	Skipped   int
	Truncated bool

	Rows   map[string]*ReplayCounter
	Fields map[string]*FieldSlot
	Values map[string]int

	Hosts    []string
	Field    string
	HostsKey string
}

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

	for c := range strings.SplitSeq(rec.AttemptedChecks, ",") {
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

	if len(ft.digest) < replayDistinctCap {
		h := fnv.New64a()
		_, _ = h.Write([]byte(val))
		ft.digest[h.Sum64()] = struct{}{}
	}
}

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
