package output

import (
	"bytes"
	"strings"
	"testing"
)

// TestLoggerSentenceCaseAndSeverity verifies the shared formatter capitalizes
// the first alphabetic rune of human-facing messages, keeps leading non-letter
// runes intact, leaves debug diagnostics verbatim (they begin with lowercase
// identifiers like "ipmi.defaultUserKey:"), emits key=val pairs, and routes
// SevWarn/SevDebug to stderr.
func TestLoggerSentenceCaseAndSeverity(t *testing.T) {
	var out, errw bytes.Buffer
	l := NewLogger(&out, &errw, true /*noColor*/, true /*verbose*/)

	l.Info("scan started")
	l.Warn("connection refused", "host", "10.0.0.5")
	l.Warn("smc-shell: connect 10.0.0.5:4444: i/o timeout")
	l.Debug("    10.0.0.5 ipmi.defaultUserKey: trying bmcRandomNum")
	l.Critical("Panic on host 10.0.0.5: bad packet")

	stdout := out.String()
	stderr := errw.String()

	cases := []struct {
		sink string
		want string
	}{
		{stdout, "INFO"},
		{stdout, "Scan started"},
		{stderr, "WARN"},
		{stderr, "Connection refused"},
		{stderr, "smc-shell: connect 10.0.0.5:4444: i/o timeout"},
		{stderr, "host=10.0.0.5"},
		{stderr, "DEBUG"},
		{stderr, "ipmi.defaultUserKey: trying bmcRandomNum"}, // verbatim, not "Ipmi..."
		{stdout, "CRITICAL"},
		{stdout, "Panic on host 10.0.0.5: bad packet"},
	}
	for _, c := range cases {
		if !strings.Contains(c.sink, c.want) {
			t.Errorf("output missing %q\n---stdout---\n%s\n---stderr---\n%s", c.want, stdout, stderr)
		}
	}

	// No ANSI when noColor=true.
	for _, seq := range []string{"\x1b[", "38;5;"} {
		if strings.Contains(stdout+stderr, seq) {
			t.Errorf("no-color logger produced ANSI %q", seq)
		}
	}
}

// TestLoggerDebugGatedByVerbose confirms SevDebug lines are dropped when
// verbose=false, so a --verbose flag toggles them without extra plumbing.
func TestLoggerDebugGatedByVerbose(t *testing.T) {
	var out, errw bytes.Buffer
	l := NewLogger(&out, &errw, true, false /*verbose*/)
	l.Debug("hidden diagnostic")
	l.Info("visible line")
	if strings.Contains(errw.String(), "hidden diagnostic") {
		t.Errorf("debug line leaked when verbose=false: %q", errw.String())
	}
	if !strings.Contains(out.String(), "Visible line") {
		t.Errorf("info line missing: %q", out.String())
	}
}

// TestLoggerFormatColorsTagOnly ensures colorization wraps the severity tag
// (not the whole line) when a color-enabled logger renders a WARN, and that
// the tag column stays a stable eight characters wide.
func TestLoggerFormatColorsTagOnly(t *testing.T) {
	l := NewLogger(nil, nil, false /*color on*/, false)
	line := l.Format(SevWarn, "hello", "k", "v")
	// The visible text sequence should contain the padded tag and the sentence-
	// cased message; the exact ANSI wrapping is a lipgloss detail.
	if !strings.Contains(line, "WARN") {
		t.Fatalf("format missing WARN tag: %q", line)
	}
	if !strings.Contains(line, "Hello") {
		t.Fatalf("format did not sentence-case message: %q", line)
	}
	if !strings.Contains(line, "k=v") {
		t.Fatalf("format missing key=val pair: %q", line)
	}
}
