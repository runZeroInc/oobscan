package report

import "sort"

type counter struct {
	counts map[string]int
	total  int
}

func newCounter() *counter { return &counter{counts: map[string]int{}} }

func (c *counter) add(v string) {
	c.counts[v]++
	c.total++
}

func (c *counter) addN(v string, n int) {
	if n <= 0 {
		return
	}
	c.counts[v] += n
	c.total += n
}

func (c *counter) mergeFrom(o *counter) {
	if o == nil {
		return
	}
	for v, n := range o.counts {
		c.addN(v, n)
	}
}

type Pair struct {
	Value string `json:"v"`
	Count int    `json:"n"`
}

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
