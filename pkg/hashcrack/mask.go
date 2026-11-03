package hashcrack

import (
	"fmt"
	"math/big"
)

// builtinCharset holds the hashcat/John built-in mask charsets.
var builtinCharset = map[byte]string{
	'l': "abcdefghijklmnopqrstuvwxyz",
	'u': "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	'd': "0123456789",
	's': " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
	'h': "0123456789abcdef",
	'H': "0123456789ABCDEF",
	'a': "", // filled in init (?l?u?d?s)
}

func init() {
	builtinCharset['a'] = builtinCharset['l'] + builtinCharset['u'] + builtinCharset['d'] + builtinCharset['s']
}

// Mask is a parsed hashcat-style mask: one charset per output position.
type Mask struct {
	spec string
	sets [][]byte
}

// ParseMask parses a hashcat/John mask spec: ?l ?u ?d ?s ?a ?h ?H built-ins,
// ?1..?4 custom charsets, literal characters, and ?? for a literal '?'.
func ParseMask(spec string, custom map[byte]string) (*Mask, error) {
	m := &Mask{spec: spec}
	for i := 0; i < len(spec); i++ {
		c := spec[i]
		if c != '?' {
			m.sets = append(m.sets, []byte{c}) // literal
			continue
		}
		i++
		if i >= len(spec) {
			return nil, fmt.Errorf("mask %q: trailing '?'", spec)
		}
		t := spec[i]
		switch {
		case t == '?':
			m.sets = append(m.sets, []byte{'?'})
		case t >= '1' && t <= '4':
			cs, ok := custom[t]
			if !ok {
				return nil, fmt.Errorf("mask %q: custom charset ?%c not defined (use -%c)", spec, t, t)
			}
			m.sets = append(m.sets, []byte(cs))
		default:
			cs, ok := builtinCharset[t]
			if !ok {
				return nil, fmt.Errorf("mask %q: unknown charset ?%c", spec, t)
			}
			m.sets = append(m.sets, []byte(cs))
		}
	}
	if len(m.sets) == 0 {
		return nil, fmt.Errorf("mask %q: empty", spec)
	}
	return m, nil
}

// Keyspace returns the total number of candidates the mask produces (may be huge).
func (m *Mask) Keyspace() *big.Int {
	total := big.NewInt(1)
	for _, s := range m.sets {
		total.Mul(total, big.NewInt(int64(len(s))))
	}
	return total
}

// Stream emits every candidate for the mask (an odometer over positions,
// rightmost fastest) to out, then closes out so consumers ranging over it
// terminate. It stops early if stop is closed.
func (m *Mask) Stream(out chan<- string, stop <-chan struct{}) {
	defer close(out)
	idx := make([]int, len(m.sets))
	buf := make([]byte, len(m.sets))
	for {
		for i, p := range idx {
			buf[i] = m.sets[i][p]
		}
		select {
		case out <- string(buf):
		case <-stop:
			return
		}
		// Increment odometer (rightmost position fastest).
		pos := len(idx) - 1
		for pos >= 0 {
			idx[pos]++
			if idx[pos] < len(m.sets[pos]) {
				break
			}
			idx[pos] = 0
			pos--
		}
		if pos < 0 {
			return // wrapped -> exhausted
		}
	}
}
