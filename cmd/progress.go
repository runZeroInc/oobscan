package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
)

type streamProgress struct {
	verb  string
	label string
	tty   bool
	log   bool
	start time.Time
	last  time.Time
	lastN int
}

const (
	progressPaintInterval = 150 * time.Millisecond
	progressLogInterval   = 5 * time.Second
)

func newStreamProgress(verb, label string) *streamProgress {
	now := time.Now()
	tty := isatty.IsTerminal(os.Stderr.Fd())
	p := &streamProgress{
		verb:  verb,
		label: filepath.Base(label),
		tty:   tty,
		log:   !tty && rootVerbose,
		start: now,
	}

	p.last = now.Add(-p.interval())
	return p
}

func (p *streamProgress) interval() time.Duration {
	if p.tty {
		return progressPaintInterval
	}
	return progressLogInterval
}

func (p *streamProgress) tick(n int) {
	if !p.tty && !p.log {
		return
	}
	now := time.Now()
	if now.Sub(p.last) < p.interval() {
		return
	}
	rate := 0.0
	if d := now.Sub(p.last).Seconds(); d > 0 {
		rate = float64(n-p.lastN) / d
	}
	p.last, p.lastN = now, n
	elapsed := now.Sub(p.start).Round(time.Second)

	if p.tty {

		fmt.Fprintf(os.Stderr, "\r\x1b[K  %s %s  %s records · %s/s · %s",
			p.verb, p.label, withCommas(n), withCommas(int(rate)), elapsed)
		return
	}
	log().Info(p.verb, "input", p.label, "records", withCommas(n),
		"rate", withCommas(int(rate))+"/s", "elapsed", elapsed.String())
}

func (p *streamProgress) finish() {
	if p.tty && p.lastN > 0 {
		fmt.Fprint(os.Stderr, "\r\x1b[K")
	}
}

func withCommas(n int) string {
	s := strconv.Itoa(n)
	neg := ""
	if n < 0 {
		neg, s = "-", s[1:]
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return neg + b.String()
}
