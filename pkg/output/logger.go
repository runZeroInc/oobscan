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

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevWarn     Severity = "warn"
	SevInfo     Severity = "info"
	SevDebug    Severity = "debug"
)

type Logger struct {
	mu      sync.Mutex
	out     io.Writer
	errw    io.Writer
	styles  styleSet
	verbose bool
	noColor bool
}

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

func (l *Logger) NoColor() bool {
	if l == nil {
		return true
	}
	return l.noColor
}

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

func Default() *Logger {
	defaultLoggerMu.RLock()
	defer defaultLoggerMu.RUnlock()
	return defaultLogger
}

func SetDefault(l *Logger) {
	if l == nil {
		return
	}
	defaultLoggerMu.Lock()
	defaultLogger = l
	defaultLoggerMu.Unlock()
}

func defaultNoColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return true
	}
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		return true
	}
	return false
}

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

func (l *Logger) Emitf(sev Severity, format string, a ...any) {
	l.Emit(sev, fmt.Sprintf(format, a...))
}

func (l *Logger) Critical(msg string, kv ...string) { l.Emit(SevCritical, msg, kv...) }

func (l *Logger) High(msg string, kv ...string) { l.Emit(SevHigh, msg, kv...) }

func (l *Logger) Medium(msg string, kv ...string) { l.Emit(SevMedium, msg, kv...) }

func (l *Logger) Low(msg string, kv ...string) { l.Emit(SevLow, msg, kv...) }

func (l *Logger) Info(msg string, kv ...string) { l.Emit(SevInfo, msg, kv...) }

func (l *Logger) Warn(msg string, kv ...string) { l.Emit(SevWarn, msg, kv...) }

func (l *Logger) Debug(msg string, kv ...string) { l.Emit(SevDebug, msg, kv...) }

func (l *Logger) Criticalf(format string, a ...any) { l.Emitf(SevCritical, format, a...) }

func (l *Logger) Highf(format string, a ...any) { l.Emitf(SevHigh, format, a...) }

func (l *Logger) Mediumf(format string, a ...any) { l.Emitf(SevMedium, format, a...) }

func (l *Logger) Lowf(format string, a ...any) { l.Emitf(SevLow, format, a...) }

func (l *Logger) Infof(format string, a ...any) { l.Emitf(SevInfo, format, a...) }

func (l *Logger) Warnf(format string, a ...any) { l.Emitf(SevWarn, format, a...) }

func (l *Logger) Debugf(format string, a ...any) { l.Emitf(SevDebug, format, a...) }

func (l *Logger) Format(sev Severity, msg string, kv ...string) string {
	if l == nil {
		return ""
	}
	tag := severityTag(sev)
	styled := l.styles.style(sev).Render(tag)
	msg = strings.TrimRight(msg, " \t\r\n")
	if sev != SevDebug {

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

func severityTag(sev Severity) string {
	name := strings.ToUpper(strings.TrimSpace(string(sev)))
	if name == "" {
		name = "INFO"
	}
	return fmt.Sprintf("%-8s", name)
}

func sentenceCase(msg string) string {
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
