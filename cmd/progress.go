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

// streamProgress renders a live, throttled progress line for a long streaming
// operation (convert, report load). On an interactive stderr it repaints one
// carriage-returned line with the running count and instantaneous rate; when
// stderr is not a terminal (piped or a log file) it stays silent unless
// --verbose, in which case it emits a periodic line so a batch run still shows
// it is alive. Everything goes to stderr, never stdout, so a piped NDJSON
// stream is never corrupted.
type streamProgress struct {
	verb  string // "Converting" / "Reading"
	label string // input basename
	tty   bool
	log   bool // periodic lines when not a tty (verbose only)
	start time.Time
	last  time.Time
	lastN int
}

// Repaint cadence: a terminal line is cheap to overwrite, so repaint it often
// for a smooth counter; a log line is appended forever, so emit it rarely so a
// batch run leaves a handful of breadcrumbs rather than thousands.
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
	// Backdate so the first record repaints immediately.
	p.last = now.Add(-p.interval())
	return p
}

func (p *streamProgress) interval() time.Duration {
	if p.tty {
		return progressPaintInterval
	}
	return progressLogInterval
}

// tick is the per-record progress callback: called once per record, so it
// self-throttles and does no work between repaints beyond a time comparison.
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
		// \r returns to column 0, \x1b[K clears to end of line.
		fmt.Fprintf(os.Stderr, "\r\x1b[K  %s %s  %s records · %s/s · %s",
			p.verb, p.label, withCommas(n), withCommas(int(rate)), elapsed)
		return
	}
	log().Info(p.verb, "input", p.label, "records", withCommas(n),
		"rate", withCommas(int(rate))+"/s", "elapsed", elapsed.String())
}

// finish clears the animated line so the summary that follows starts clean.
func (p *streamProgress) finish() {
	if p.tty && p.lastN > 0 {
		fmt.Fprint(os.Stderr, "\r\x1b[K")
	}
}

// withCommas groups an integer with thousands separators.
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
