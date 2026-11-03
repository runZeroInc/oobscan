package output

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/mattn/go-isatty"
)

// Severity is the log/output severity used to select colorization and the
// output stream. Values double as risk labels for scan findings so that the
// same formatter can render findings and freeform log/error messages with a
// consistent tag column.
type Severity string

// Severity levels, roughly in urgency order. Levels above SevInfo represent
// scan findings; SevInfo/SevWarn/SevDebug are for freeform log lines.
const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevWarn     Severity = "warn"
	SevInfo     Severity = "info"
	SevDebug    Severity = "debug"
)

// Logger is the single serialization point for all human-readable oobscan
// output (subcommands and the scan pipeline). It renders every line as
// `<SEV_TAG>  <msg>  key=val ...`, colorizes the tag by
// severity (respecting --no-color / NO_COLOR / non-TTY stdout), and serializes
// concurrent writers behind one mutex so lines never interleave.
type Logger struct {
	mu      sync.Mutex
	out     io.Writer // primary sink for INFO and finding-level severities
	errw    io.Writer // sink for WARN / DEBUG diagnostics
	styles  styleSet
	verbose bool // gate SevDebug lines
	noColor bool
}

// NewLogger builds a Logger. Nil writers default to os.Stdout / os.Stderr.
func NewLogger(out, errw io.Writer, noColor, verbose bool) *Logger {
	if out == nil {
		out = os.Stdout
	}
	if errw == nil {
		errw = os.Stderr
	}
	return &Logger{
		out:     out,
		errw:    errw,
		styles:  newStyleSet(noColor),
		verbose: verbose,
		noColor: noColor,
	}
}

// NoColor reports whether the logger renders bare (unstyled) output.
func (l *Logger) NoColor() bool {
	if l == nil {
		return true
	}
	return l.noColor
}

// Verbose reports whether debug-level lines are emitted.
func (l *Logger) Verbose() bool {
	if l == nil {
		return false
	}
	return l.verbose
}

var (
	defaultLoggerMu sync.RWMutex
	defaultLogger   *Logger = NewLogger(os.Stdout, os.Stderr, defaultNoColor(), false)
)

// Default returns the process-wide default Logger. It is safe to call before
// SetDefault: it starts out wired to os.Stdout/os.Stderr with color
// auto-detected from stdout, and is typically replaced from the cobra root's
// PersistentPreRun once --no-color / --verbose have been parsed.
func Default() *Logger {
	defaultLoggerMu.RLock()
	defer defaultLoggerMu.RUnlock()
	return defaultLogger
}

// SetDefault replaces the process-wide default Logger.
func SetDefault(l *Logger) {
	if l == nil {
		return
	}
	defaultLoggerMu.Lock()
	defaultLogger = l
	defaultLoggerMu.Unlock()
}

// defaultNoColor reports whether the initial default logger should skip ANSI
// styling based on NO_COLOR or stdout not being a terminal.
func defaultNoColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return true
	}
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		return true
	}
	return false
}

// Emit prints one line at severity sev. SevWarn and SevDebug go to stderr; all
// other severities go to stdout. kv is a flat list of alternating keys and
// values that render as ` key=val key=val` in the dim style; odd-length input
// prints the trailing key with a blank value.
func (l *Logger) Emit(sev Severity, msg string, kv ...string) {
	if l == nil {
		return
	}
	if sev == SevDebug && !l.verbose {
		return
	}
	line := l.Format(sev, msg, kv...)
	w := l.streamFor(sev)
	l.mu.Lock()
	fmt.Fprintln(w, line)
	l.mu.Unlock()
}

// Emitf is a convenience for Emit with fmt.Sprintf on the message.
func (l *Logger) Emitf(sev Severity, format string, a ...any) {
	l.Emit(sev, fmt.Sprintf(format, a...))
}

// Critical emits a critical-severity message.
func (l *Logger) Critical(msg string, kv ...string) { l.Emit(SevCritical, msg, kv...) }

// High emits a high-severity message.
func (l *Logger) High(msg string, kv ...string) { l.Emit(SevHigh, msg, kv...) }

// Medium emits a medium-severity message.
func (l *Logger) Medium(msg string, kv ...string) { l.Emit(SevMedium, msg, kv...) }

// Low emits a low-severity message.
func (l *Logger) Low(msg string, kv ...string) { l.Emit(SevLow, msg, kv...) }

// Info emits an informational message.
func (l *Logger) Info(msg string, kv ...string) { l.Emit(SevInfo, msg, kv...) }

// Warn emits a warning message.
func (l *Logger) Warn(msg string, kv ...string) { l.Emit(SevWarn, msg, kv...) }

// Debug emits a debug message when verbose logging is enabled.
func (l *Logger) Debug(msg string, kv ...string) { l.Emit(SevDebug, msg, kv...) }

// Criticalf formats and emits a critical-severity message.
func (l *Logger) Criticalf(format string, a ...any) { l.Emitf(SevCritical, format, a...) }

// Highf formats and emits a high-severity message.
func (l *Logger) Highf(format string, a ...any) { l.Emitf(SevHigh, format, a...) }

// Mediumf formats and emits a medium-severity message.
func (l *Logger) Mediumf(format string, a ...any) { l.Emitf(SevMedium, format, a...) }

// Lowf formats and emits a low-severity message.
func (l *Logger) Lowf(format string, a ...any) { l.Emitf(SevLow, format, a...) }

// Infof formats and emits an informational message.
func (l *Logger) Infof(format string, a ...any) { l.Emitf(SevInfo, format, a...) }

// Warnf formats and emits a warning message.
func (l *Logger) Warnf(format string, a ...any) { l.Emitf(SevWarn, format, a...) }

// Debugf formats and emits a debug message when verbose logging is enabled.
func (l *Logger) Debugf(format string, a ...any) { l.Emitf(SevDebug, format, a...) }

// Format returns the formatted line without emitting it. Callers that must
// splice into an existing writer (e.g. the ttyEmitter's findings render) use
// this to keep exact tag width and colorization.
func (l *Logger) Format(sev Severity, msg string, kv ...string) string {
	if l == nil {
		return ""
	}
	tag := severityTag(sev)
	styled := l.styles.style(sev).Render(tag)
	msg = strings.TrimRight(msg, " \t\r\n")
	if sev != SevDebug {
		// Human-facing lines read as sentences; debug diagnostics (e.g.
		// "ipmi.defaultUserKey: ...") keep their verbatim identifier casing.
		msg = sentenceCase(msg)
	}
	fields := formatKV(kv)
	var sb strings.Builder
	sb.WriteString(styled)
	if msg != "" {
		sb.WriteByte(' ')
		sb.WriteString(msg)
	}
	if fields != "" {
		if msg == "" {
			sb.WriteByte(' ')
		} else {
			sb.WriteByte(' ')
		}
		sb.WriteString(l.styles.dim.Render(fields))
	}
	return sb.String()
}

func (l *Logger) streamFor(sev Severity) io.Writer {
	switch sev {
	case SevWarn, SevDebug:
		return l.errw
	}
	return l.out
}

// severityTag returns the display tag for a severity, padded to a consistent
// eight-character column so the message column aligns across levels.
func severityTag(sev Severity) string {
	name := strings.ToUpper(strings.TrimSpace(string(sev)))
	if name == "" {
		name = "INFO"
	}
	return fmt.Sprintf("%-8s", name)
}

// sentenceCase uppercases the first alphabetic rune of msg, leaving any leading
// non-letter runes (indentation, digits, punctuation) intact. Already-capitalized
// and empty messages are returned unchanged.
func sentenceCase(msg string) string {
	if colon := strings.IndexByte(msg, ':'); colon > 0 && lowercaseIdentifier(msg[:colon]) {
		return msg
	}
	for i, r := range msg {
		if !unicode.IsLetter(r) {
			continue
		}
		if unicode.IsUpper(r) {
			return msg
		}
		return msg[:i] + string(unicode.ToUpper(r)) + msg[i+utf8.RuneLen(r):]
	}
	return msg
}

// lowercaseIdentifier reports whether s is a lowercase command or subsystem
// identifier, such as "smc-shell", rather than sentence text.
func lowercaseIdentifier(s string) bool {
	hasLetter := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			hasLetter = true
		case r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return hasLetter
}

// formatKV joins pairs from a flat slice as "key=val key=val". Values that
// contain whitespace or quotes are strconv.Quote'd.
func formatKV(kv []string) string {
	if len(kv) == 0 {
		return ""
	}
	parts := make([]string, 0, len(kv)/2+1)
	for i := 0; i < len(kv); i += 2 {
		k := kv[i]
		v := ""
		if i+1 < len(kv) {
			v = kv[i+1]
		}
		if strings.ContainsAny(v, " \t\"") {
			v = strconv.Quote(v)
		}
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " ")
}
