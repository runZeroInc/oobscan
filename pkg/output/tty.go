package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/redfish"
)

type ttyEmitter struct {
	mu         sync.Mutex
	out        *bufio.Writer
	errw       io.Writer
	records    *bufio.Writer
	enc        *json.Encoder
	done       int
	sev        map[string]int
	active     map[string]activeState
	checks     map[string]checkProgress
	checkDone  int
	checkTotal int
	styles     styleSet
	log        *Logger
	verbose    bool
	lastReport time.Time
	running    map[string]map[string]time.Time
	emitted    map[string]map[string]struct{}
	writeErr   error
}

type activeState struct {
	what  string
	since time.Time
}

type styleSet struct {
	crit, high, med, low, warn, info, pass, dim lipgloss.Style
}

func newStyleSet(noColor bool) styleSet {

	c := func(code string) lipgloss.Style {
		if noColor {
			return lipgloss.NewStyle()
		}
		return lipgloss.NewStyle().Foreground(lipgloss.Color(code))
	}
	crit := c("196")
	if !noColor {
		crit = crit.Bold(true)
	}
	return styleSet{crit: crit, high: c("208"), med: c("214"), low: c("39"), warn: c("214"), info: c("245"), pass: c("42"), dim: c("248")}
}

func (s styleSet) style(sev Severity) lipgloss.Style {
	switch sev {
	case SevCritical:
		return s.crit
	case SevHigh:
		return s.high
	case SevMedium:
		return s.med
	case SevLow:
		return s.low
	case SevWarn:
		return s.warn
	case SevInfo:
		return s.info
	case SevDebug:
		return s.dim
	}
	return s.dim
}

func newTTYEmitterTo(out, errw, records io.Writer, noColor, verbose bool) *ttyEmitter {
	styles := newStyleSet(noColor)
	e := &ttyEmitter{
		out:        bufio.NewWriter(out),
		errw:       errw,
		sev:        map[string]int{},
		active:     map[string]activeState{},
		checks:     map[string]checkProgress{},
		running:    map[string]map[string]time.Time{},
		emitted:    map[string]map[string]struct{}{},
		styles:     styles,
		log:        NewLogger(out, errw, noColor, verbose),
		verbose:    verbose,
		lastReport: time.Now(),
	}
	if records != nil {
		e.records = bufio.NewWriter(records)
		e.enc = json.NewEncoder(e.records)
	}
	return e
}

func (e *ttyEmitter) Start(host string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active[host] = activeState{what: "queued", since: time.Now()}
}
func (e *ttyEmitter) Activity(host, what string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	prev := e.active[host]
	if prev.what == what {
		return
	}
	e.active[host] = activeState{what: what, since: time.Now()}
	if strings.HasPrefix(what, "post-auth ") {
		fmt.Fprintln(e.errw, e.log.Format(SevInfo, host+" "+what))
		e.lastReport = time.Now()
		return
	}
	if what == "" || !e.verbose {
		return
	}
	fmt.Fprintln(e.errw, e.log.Format(SevDebug, host+" "+what))
	e.lastReport = time.Now()
}

type checkProgress struct {
	done  int
	total int
}

func (e *ttyEmitter) Checks(host string, done, total int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if done < 0 {
		done = 0
	}
	if total < 0 {
		total = 0
	}
	if done > total && total > 0 {
		done = total
	}
	prev := e.checks[host]
	e.checkDone += done - prev.done
	e.checkTotal += total - prev.total
	e.checks[host] = checkProgress{done: done, total: total}
}

func (e *ttyEmitter) CheckStart(host, check string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if host == "" || check == "" {
		return
	}
	rh := e.running[host]
	if rh == nil {
		rh = map[string]time.Time{}
		e.running[host] = rh
	}
	rh[check] = time.Now()
}

func (e *ttyEmitter) CheckDone(host, check string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rh := e.running[host]
	if rh == nil {
		return
	}
	delete(rh, check)
	if len(rh) == 0 {
		delete(e.running, host)
	}
}

func (e *ttyEmitter) Log(msg string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	fmt.Fprintln(e.errw, e.log.Format(SevDebug, msg))
	e.lastReport = time.Now()
}

func (e *ttyEmitter) Emit(t *engine.Target) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if t.Err != "" {
		fmt.Fprintln(e.errw, e.log.Format(SevCritical, "Panic on "+t.Host+": "+firstLine(t.Err)))
	}
	for _, f := range t.FindingsSnapshot() {
		if e.seenFindingLocked(t.Host, f) {
			continue
		}
		if line := e.renderFinding(t, f); line != "" {
			fmt.Fprintln(e.out, line)
			e.sev[riskOf(f)]++
			e.markFindingLocked(t.Host, f)
		}
	}
	if line := e.renderFinal(t); line != "" {
		fmt.Fprintln(e.out, line)
	}

	if e.verbose {
		for _, msg := range postAuthVerboseLines(t) {
			fmt.Fprintln(e.errw, e.log.Format(SevDebug, msg))
		}
	}
	e.done++
	delete(e.active, t.Host)
	delete(e.running, t.Host)
	delete(e.emitted, t.Host)
	delete(e.checks, t.Host)

	if e.enc != nil {
		result := resultFrom(t)
		if resultHasResponsiveData(result) {
			e.rememberWriteError(e.enc.Encode(result))
			e.rememberWriteError(e.records.Flush())
		}
	}

	e.rememberWriteError(e.out.Flush())
	e.lastReport = time.Now()
}

func (e *ttyEmitter) EmitFindings(host string, fs []engine.Finding) {
	if host == "" || len(fs) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	t := &engine.Target{Host: host}
	for _, f := range fs {
		if e.seenFindingLocked(host, f) {
			continue
		}
		if line := e.renderFinding(t, f); line != "" {
			fmt.Fprintln(e.out, line)
			e.sev[riskOf(f)]++
			e.markFindingLocked(host, f)
		}
	}
	e.rememberWriteError(e.out.Flush())
	e.lastReport = time.Now()
}

func (e *ttyEmitter) Status(done, total uint64, force bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !force && time.Since(e.lastReport) < 15*time.Second {
		return
	}
	args := []string{
		"hosts", fmt.Sprintf("%d/%d", done, total),
		"checks", fmt.Sprintf("%d/%d", e.checkDone, e.checkTotal),
		"active", strconv.Itoa(len(e.active)),
		"critical", strconv.Itoa(e.sev["critical"]),
		"high", strconv.Itoa(e.sev["high"]),
		"medium", strconv.Itoa(e.sev["medium"]),
		"low", strconv.Itoa(e.sev["low"]),
	}
	if cur := e.activeSummaryLocked(); cur != "" {
		args = append(args, "current", cur)
	}
	fmt.Fprintln(e.errw, e.log.Format(SevInfo, "Scan status", args...))
	e.lastReport = time.Now()
}

func (e *ttyEmitter) StatusDetailed(done, total uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	running := e.runningCountLocked()
	if running == 0 {
		fmt.Fprintln(e.errw, e.log.Format(SevInfo, "Scan status detail",
			"hosts", fmt.Sprintf("%d/%d", done, total),
			"activeHosts", strconv.Itoa(len(e.active)),
			"runningChecks", "0"))
		if len(e.active) > 0 {
			e.printActiveHostPhaseSummaryLocked()
		} else {
			fmt.Fprintln(e.errw, e.log.Format(SevInfo, "No running checks"))
		}
		e.lastReport = time.Now()
		return
	}

	type checkAgg struct {
		count    int
		min, max time.Duration
	}
	byCheck := map[string]*checkAgg{}
	var oldHost, oldCheck string
	var oldElapsed time.Duration
	now := time.Now()
	for host, checks := range e.running {
		for name, start := range checks {
			el := now.Sub(start)
			if el > oldElapsed {
				oldElapsed, oldHost, oldCheck = el, host, name
			}
			a := byCheck[name]
			if a == nil {
				a = &checkAgg{min: el, max: el}
				byCheck[name] = a
			}
			if el < a.min {
				a.min = el
			}
			if el > a.max {
				a.max = el
			}
			a.count++
		}
	}

	fmt.Fprintln(e.errw, e.log.Format(SevInfo, "Scan status detail",
		"hosts", fmt.Sprintf("%d/%d", done, total),
		"activeHosts", strconv.Itoa(len(e.active)),
		"runningChecks", strconv.Itoa(running),
		"checks", strconv.Itoa(len(byCheck))))

	names := make([]string, 0, len(byCheck))
	for n := range byCheck {
		names = append(names, n)
	}

	sort.Slice(names, func(i, j int) bool {
		ai, aj := byCheck[names[i]], byCheck[names[j]]
		if ai.count != aj.count {
			return ai.count > aj.count
		}
		if ai.max != aj.max {
			return ai.max > aj.max
		}
		return names[i] < names[j]
	})

	const topN = 6
	omittedChecks, omittedHosts := 0, 0
	for i, n := range names {
		if i >= topN {
			omittedChecks++
			omittedHosts += byCheck[n].count
			continue
		}
		a := byCheck[n]
		fmt.Fprintln(e.errw, e.log.Format(SevInfo, "Check in progress",
			"check", n,
			"hosts", strconv.Itoa(a.count),
			"elapsed", fmt.Sprintf("%s..%s", a.min.Round(time.Second), a.max.Round(time.Second))))
	}
	if omittedChecks > 0 {
		fmt.Fprintln(e.errw, e.log.Format(SevInfo, "More checks in progress",
			"checks", strconv.Itoa(omittedChecks),
			"hosts", strconv.Itoa(omittedHosts)))
	}

	fmt.Fprintln(e.errw, e.log.Format(SevInfo, "Oldest check",
		"host", oldHost,
		"check", oldCheck,
		"elapsed", oldElapsed.Round(time.Second).String()))
	e.lastReport = time.Now()
}

func (e *ttyEmitter) printActiveHostPhaseSummaryLocked() {
	if len(e.active) == 0 {
		return
	}
	type phaseAgg struct {
		count    int
		min, max time.Duration
	}
	byPhase := map[string]*phaseAgg{}
	now := time.Now()
	for _, state := range e.active {
		phase := state.what
		if phase == "" {
			phase = "working"
		}
		var el time.Duration
		if !state.since.IsZero() {
			el = now.Sub(state.since)
		}
		p := byPhase[phase]
		if p == nil {
			p = &phaseAgg{min: el, max: el}
			byPhase[phase] = p
		}
		if el < p.min {
			p.min = el
		}
		if el > p.max {
			p.max = el
		}
		p.count++
	}
	phases := make([]string, 0, len(byPhase))
	for ph := range byPhase {
		phases = append(phases, ph)
	}
	sort.Slice(phases, func(i, j int) bool {
		if byPhase[phases[i]].count != byPhase[phases[j]].count {
			return byPhase[phases[i]].count > byPhase[phases[j]].count
		}
		return phases[i] < phases[j]
	})
	for _, ph := range phases {
		p := byPhase[ph]
		fmt.Fprintln(e.errw, e.log.Format(SevInfo, "Active host phase",
			"phase", ph,
			"hosts", strconv.Itoa(p.count),
			"elapsed", fmt.Sprintf("%s..%s", p.min.Round(time.Second), p.max.Round(time.Second))))
	}
}

func (e *ttyEmitter) runningCountLocked() int {
	n := 0
	for _, checks := range e.running {
		n += len(checks)
	}
	return n
}

func (e *ttyEmitter) seenFindingLocked(host string, f engine.Finding) bool {
	m, ok := e.emitted[host]
	if !ok {
		return false
	}
	_, ok = m[findingKey(f)]
	return ok
}

func (e *ttyEmitter) markFindingLocked(host string, f engine.Finding) {
	m := e.emitted[host]
	if m == nil {
		m = map[string]struct{}{}
		e.emitted[host] = m
	}
	m[findingKey(f)] = struct{}{}
}

func findingKey(f engine.Finding) string {
	var b strings.Builder
	b.WriteString(f.Check)
	b.WriteByte('|')
	b.WriteString(f.Category)
	b.WriteByte('|')
	b.WriteString(f.Risk)
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(f.Port))
	b.WriteByte('|')
	b.WriteString(f.Transport)
	b.WriteByte('|')
	b.WriteString(f.Protocol)
	b.WriteByte('|')
	b.WriteString(f.Address)
	b.WriteByte('|')
	for _, c := range f.CVE {
		b.WriteString(c)
		b.WriteByte(',')
	}
	b.WriteByte('|')
	for _, fld := range f.Fields {
		b.WriteString(fld.Key)
		b.WriteByte('=')
		b.WriteString(fld.Val)
		b.WriteByte(';')
	}
	return b.String()
}

func (e *ttyEmitter) activeSummaryLocked() string {
	if len(e.active) == 0 {
		return ""
	}
	hosts := make([]string, 0, len(e.active))
	for host := range e.active {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	host := hosts[0]
	state := e.active[host]
	what := state.what
	if what == "" {
		what = "working"
	}
	if cp, ok := e.checks[host]; ok && cp.total > 0 && !strings.HasPrefix(what, "running ") {
		what = fmt.Sprintf("%s (%d/%d checks)", what, cp.done, cp.total)
	}
	if state.since.IsZero() {
		return host + " " + what
	}
	return fmt.Sprintf("%s %s for %s", host, what, time.Since(state.since).Round(time.Second))
}

func postAuthVerboseLines(t *engine.Target) []string {
	v, ok := t.Evidenced("redfish.postAuth")
	if !ok {
		return nil
	}
	post, ok := v.(*redfish.PostAuthSnapshot)
	if !ok || post == nil {
		return nil
	}
	b, err := json.Marshal(post)
	if err != nil {
		return nil
	}
	return []string{"    " + t.Host + " redfish post-auth " + string(b)}
}

func (e *ttyEmitter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, err := fmt.Fprintln(e.out, e.summary())
	e.rememberWriteError(err)
	e.lastReport = time.Now()
	e.rememberWriteError(e.out.Flush())
	if e.records != nil {
		e.rememberWriteError(e.records.Flush())
	}
	return e.writeErr
}

func (e *ttyEmitter) rememberWriteError(err error) {
	if err != nil && e.writeErr == nil {
		e.writeErr = err
	}
}

func (e *ttyEmitter) renderFinding(t *engine.Target, f engine.Finding) string {
	risk := riskOf(f)
	if engine.RiskRank(risk) < engine.RiskRank("info") {
		return ""
	}
	tag := e.sevStyle(risk).Render(fmt.Sprintf("%-8s", strings.ToUpper(risk)))

	msg := ""
	if loc := locationStr(f); loc != "" {
		msg = e.styles.dim.Render(loc) + " "
	}
	msg += displayFields(f.Fields)

	if cves := realCVEs(f.CVE); len(cves) > 0 {
		msg = strings.TrimRight(msg, " ")
		if msg != "" {
			msg += " "
		}
		msg += e.styles.dim.Render("[" + strings.Join(cves, " ") + "]")
	}
	return strings.TrimRight(fmt.Sprintf("%s %-15s %-24s %s", tag, t.Host, f.Check, msg), " ")
}

func displayFields(fs engine.Fields) string {
	hasArchive := false
	isStaticDisclosure := false
	archiveCount := 0
	for _, f := range fs {
		key := engine.CanonicalFieldKey(f.Key)
		switch key {
		case "archiveContents":
			hasArchive = strings.TrimSpace(f.Val) != ""
		case "match":
			for part := range strings.SplitSeq(f.Val, ",") {
				if strings.TrimSpace(part) == "staticDisclosure" {
					isStaticDisclosure = true
					break
				}
			}
		case "archiveCount":
			if n, err := strconv.Atoi(strings.TrimSpace(f.Val)); err == nil && n > 0 {
				archiveCount = n
			}
		}
	}

	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		key := engine.CanonicalFieldKey(f.Key)
		if key == "response" && hasArchive && isStaticDisclosure {
			continue
		}
		v := engine.CanonicalFieldValue(key, f.Val)
		if v == "" {
			continue
		}
		if key == "archiveContents" && hasArchive {
			v = summarizeArchiveContents(v, 7)
			if archiveCount == 0 {
				archiveCount = 1 + strings.Count(v, ",")
			}
		}
		v = trimTTYField(key, v)
		if strings.ContainsAny(v, " \t") {
			v = strconv.Quote(v)
		}
		parts = append(parts, key+"="+v)
	}
	return strings.Join(parts, " ")
}

func trimTTYField(key, val string) string {
	const max = 180
	if val == "" {
		return ""
	}

	lk := strings.ToLower(key)
	if lk == "hash" {
		return val
	}
	forceTrim := strings.HasSuffix(lk, "full") || lk == "raw"
	if !forceTrim && len(val) <= max {
		return val
	}
	if len(val) <= max {
		return val
	}
	return truncateUTF8Bytes(val, max) + "..."
}

func summarizeArchiveContents(s string, keep int) string {
	if keep <= 0 {
		return s
	}
	rawParts := strings.Split(s, ",")
	parts := make([]string, 0, len(rawParts))
	for _, part := range rawParts {
		part = strings.TrimSpace(part)
		if part != "" {
			parts = append(parts, part)
		}
	}
	if len(parts) <= keep {
		return strings.Join(parts, ",")
	}
	return strings.Join(parts[:keep], ",") + ",..."
}

func (e *ttyEmitter) renderFinal(t *engine.Target) string {
	fin := t.Final
	if fin == nil || (fin.Vendor == "" && fin.Class == engine.ClassUnknown) {
		return ""
	}
	tag := e.sevStyle("info").Render(fmt.Sprintf("%-8s", "INFO"))

	product := fin.Product
	if fin.Generation != "" {
		product = fin.Generation
	}
	kv := []string{"vendor=" + orDashS(fin.Vendor)}
	if product != "" {
		kv = append(kv, "product="+product)
	}
	if fin.Version != "" {
		kv = append(kv, "version="+fin.Version)
	}
	kv = append(kv, "type="+string(fin.Class), "confidence="+string(fin.Confidence))
	msg := strings.Join(kv, " ")
	if flags := fin.FlagsString(); flags != "" {
		msg += " " + e.styles.dim.Render(flags)
	}
	return strings.TrimRight(fmt.Sprintf("%s %-15s %-24s %s", tag, t.Host, "id.final", msg), " ")
}

func orDashS(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

var cveRe = regexp.MustCompile(`^CVE-\d{4}-\d+$`)

func realCVEs(ids []string) []string {
	var out []string
	for _, id := range ids {
		if cveRe.MatchString(id) {
			out = append(out, id)
		}
	}
	return out
}

func locationStr(f engine.Finding) string {
	if f.Port == 0 && f.Protocol == "" {
		return ""
	}
	s := ""
	if f.Port != 0 {
		s = fmt.Sprintf("%d", f.Port)
		if f.Transport != "" {
			s += "/" + f.Transport
		}
	}
	if f.Protocol != "" {
		if s != "" {
			s += " "
		}
		s += f.Protocol
	}
	return s
}

func riskOf(f engine.Finding) string {
	if f.Risk == "" {
		return "none"
	}
	return f.Risk
}

func (e *ttyEmitter) sevStyle(sev string) lipgloss.Style {
	return e.styles.style(Severity(sev))
}

func (e *ttyEmitter) summary() string {
	kv := make([]string, 0, 10)
	for _, k := range []string{"critical", "high", "medium", "low", "info"} {
		if n := e.sev[k]; n > 0 {
			kv = append(kv, k, strconv.Itoa(n))
		}
	}
	msg := fmt.Sprintf("Scanned %d target(s)", e.done)
	return e.log.Format(SevInfo, msg, kv...)
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
