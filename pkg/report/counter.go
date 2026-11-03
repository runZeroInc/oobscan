package report

import "sort"

// counter is a frequency table over string values. Ported from bmc-stats.
type counter struct {
	counts map[string]int
	total  int
}

func newCounter() *counter { return &counter{counts: map[string]int{}} }

func (c *counter) add(v string) {
	c.counts[v]++
	c.total++
}

// addN records n occurrences of v at once.
func (c *counter) addN(v string, n int) {
	if n <= 0 {
		return
	}
	c.counts[v] += n
	c.total += n
}

// mergeFrom folds another counter's tallies into c.
func (c *counter) mergeFrom(o *counter) {
	if o == nil {
		return
	}
	for v, n := range o.counts {
		c.addN(v, n)
	}
}

// Pair is one (value, count) row.
type Pair struct {
	Value string `json:"v"`
	Count int    `json:"n"`
}

// top returns the n most frequent entries, count desc then value asc. n <= 0
// returns all.
func (c *counter) top(n int) []Pair {
	out := make([]Pair, 0, len(c.counts))
	for k, v := range c.counts {
		out = append(out, Pair{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}
