package convert

import (
	"bytes"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/runZeroInc/oobscan/pkg/check"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

// The quality audit is the data-hygiene, coverage and proof-completeness pass over
// a corpus. It runs as a stage of the conversion so the file that gets audited is
// the file that gets written. It reports: registered checks that never fired,
// findings with mangled proof (NUL, U+FFFD, invalid UTF-8), critical/high findings
// with no proof field, findings that should have been collapsed, and crypto
// material that repeats across hosts.

// exampleHostCap bounds how many example hosts are kept per issue: enough to
// reproduce, few enough to read.
const exampleHostCap = 5

// QualityReport is the outcome of the audit.
type QualityReport struct {
	Records int

	// Histogram counts emitted findings per check id, and Dark lists the checks
	// the binary can emit that this corpus never produced.
	Histogram map[string]int
	Dark      []string

	// Each issue map is keyed by "check.field" (or an attribute path) and holds
	// a capped list of example hosts.
	NullByte        map[string][]string
	ReplacementChar map[string][]string
	InvalidUTF8     map[string][]string
	MissingProof    map[string][]string

	// DuplicateURL counts the surplus findings in an uncollapsed cluster, keyed
	// by "check|match".
	DuplicateURL map[string]int

	// The four rules below cover defect classes the earlier rules missed entirely.

	// ConstantEvidence flags a "check.field" whose value never varied across the whole
	// corpus, keyed to the finding count that shared it. A `proof` that is
	// byte-identical on every host proves nothing host-specific, and a long field that
	// never changes is per-check documentation stored per host.
	ConstantEvidence map[string]int

	// BinaryEvidence flags a "check.field" holding a binary body rather than text: the
	// ASCII that survives dropping the other bytes is unverifiable and reads as text to
	// anything consuming the field.
	BinaryEvidence map[string][]string

	// Contradiction flags a host where two findings on the same port disagree about
	// whether the surface answered.
	Contradiction map[string][]string

	// SilentPartial flags a finding that under-reports without saying so: post-auth
	// inventory missing sections while carrying no coverage/access/error marker.
	SilentPartial map[string][]string

	// Reused crypto material, keyed by fingerprint. Triage only: reuse across
	// hosts does not by itself prove the private key is publicly known.
	ReusedSSHKey  map[string][]string
	ReusedTLSCert map[string][]string
}

// Dirty reports whether the audit found anything worth failing a build over.
// Reused keys and dark checks are excluded: both are observations about the
// corpus, not defects in it.
func (q *QualityReport) Dirty() bool {
	return len(q.NullByte) > 0 || len(q.ReplacementChar) > 0 ||
		len(q.InvalidUTF8) > 0 || len(q.MissingProof) > 0 || len(q.DuplicateURL) > 0 ||
		len(q.ConstantEvidence) > 0 || len(q.BinaryEvidence) > 0 ||
		len(q.Contradiction) > 0 || len(q.SilentPartial) > 0
}

// SortedHistogram returns the check histogram most-frequent first.
func (q *QualityReport) SortedHistogram() []CheckCount {
	out := make([]CheckCount, 0, len(q.Histogram))
	for k, v := range q.Histogram {
		out = append(out, CheckCount{Check: k, Count: v})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Check < out[j].Check
	})
	return out
}

// CheckCount is one row of the check histogram.
type CheckCount struct {
	Check string
	Count int
}

// qualityAuditor accumulates the audit across a record stream.
type qualityAuditor struct {
	records      int
	histogram    map[string]int
	nullByte     map[string][]string
	replacement  map[string][]string
	invalidUTF8  map[string][]string
	missingProof map[string][]string
	duplicateURL map[string]int
	sshKeyHosts  map[string]map[string]struct{}
	tlsCertHosts map[string]map[string]struct{}

	// fieldSeen tracks, per "check.field", how many findings carried it and how many
	// carried the first value observed. When those two are equal at the end, the
	// field never varied. Two counters and one string per slot, so the constant-value
	// rule costs no per-host memory.
	fieldSeen map[string]*fieldConstancy
	binary    map[string][]string
	contra    map[string][]string
	silent    map[string][]string
}

// fieldConstancy accumulates the never-varied test for one check.field slot.
type fieldConstancy struct {
	first   string
	total   int
	matched int
}

func newQualityAuditor() *qualityAuditor {
	return &qualityAuditor{
		histogram:    map[string]int{},
		nullByte:     map[string][]string{},
		replacement:  map[string][]string{},
		invalidUTF8:  map[string][]string{},
		missingProof: map[string][]string{},
		duplicateURL: map[string]int{},
		sshKeyHosts:  map[string]map[string]struct{}{},
		tlsCertHosts: map[string]map[string]struct{}{},
		fieldSeen:    map[string]*fieldConstancy{},
		binary:       map[string][]string{},
		contra:       map[string][]string{},
		silent:       map[string][]string{},
	}
}

// observe folds one record into the audit. raw is the undecoded JSON line when
// there is one (a native input) and nil when the record was synthesized by a
// conversion.
func (a *qualityAuditor) observe(rec *scanfile.Record, raw []byte) {
	a.records++
	a.observeIPMIPost(rec)
	a.observeRawFindings(rec, raw)

	for i := range rec.Findings {
		f := &rec.Findings[i]
		if f.Check == "" {
			continue
		}
		a.histogram[f.Check]++

		if needsProofField(f) && !hasProofField(f) {
			addExample(a.missingProof, f.Check, rec.Host)
		}

		if f.Check == "ssh.version" || f.Check == "ssh.sharedHostKey" {
			if key := fieldValue(f, "hostkeyFingerprint", "fingerprint"); key != "" {
				addKeyHost(a.sshKeyHosts, key, rec.Host)
			}
		}
		if strings.HasPrefix(engine.CanonicalCheckID(f.Check), "tls.") {
			if key := fieldValue(f, "sha256", "spki"); key != "" {
				addKeyHost(a.tlsCertHosts, key, rec.Host)
			}
		}
	}
	for k, extra := range duplicateURLClusters(rec) {
		a.duplicateURL[k] += extra
	}
	a.observeEvidenceQuality(rec)
	a.observeContradictions(rec)
	a.observeSilentPartial(rec)
}

// duplicateURLClusters returns, per "check|match" signature on this record, how many
// findings past the first shared it. A cluster of one is not reported.
func duplicateURLClusters(rec *scanfile.Record) map[string]int {
	var seen map[string]int
	for i := range rec.Findings {
		f := &rec.Findings[i]
		if engine.CanonicalCheckID(f.Check) != "http.exposure" {
			continue
		}
		match := fieldValue(f, "match")
		if match == "" {
			continue
		}
		if seen == nil {
			seen = map[string]int{}
		}
		seen["http.exposure|"+match]++
	}
	out := map[string]int{}
	for k, n := range seen {
		if n > 1 {
			out[k] = n - 1
		}
	}
	return out
}

// constantEvidenceMinFindings is how many findings a check.field must appear on
// before "it never varied" is evidence of a defect rather than a small sample.
const constantEvidenceMinFindings = 200

// proseFieldBytes is the length past which a never-varying field is per-check
// documentation being stored per host rather than a short stable label. Values
// like "usbanywhere" or "aten-vmedia" are legitimately constant descriptors.
const proseFieldBytes = 60

// observeEvidenceQuality runs the constant-value and binary-body rules over a
// record's finding fields.
func (a *qualityAuditor) observeEvidenceQuality(rec *scanfile.Record) {
	for i := range rec.Findings {
		f := &rec.Findings[i]
		if f.Check == "" {
			continue
		}
		for _, fd := range f.Fields {
			if fd.Val == "" {
				continue
			}
			key := f.Check + "." + fd.Key
			// Constancy: only proof-bearing fields and prose-length values are held to
			// this. A short label that never changes is fine.
			if fd.Key == "proof" || len(fd.Val) >= proseFieldBytes {
				c := a.fieldSeen[key]
				if c == nil {
					c = &fieldConstancy{first: fd.Val}
					a.fieldSeen[key] = c
				}
				c.total++
				if fd.Val == c.first {
					c.matched++
				}
			}
			if looksBinary(fd.Val) {
				addExample(a.binary, key, rec.Host)
			}
		}
	}
}

// looksBinary reports whether a field value is a binary body rather than the
// text a device serves. Invalid UTF-8 is caught by the mangled-bytes rules on the
// raw line; this catches the survivor case, where the producer already dropped the
// unprintable bytes and stored the ASCII residue -- which is still not evidence.
func looksBinary(v string) bool {
	if len(v) < 16 {
		return false
	}
	for _, magic := range []string{"7zXZ", "PK\x03\x04", "hsqs", "sqsh", "\x1f\x8b", "\x7fELF", "%PDF"} {
		if strings.HasPrefix(v, magic) {
			return true
		}
	}
	// A JAR/zip whose local-file-header bytes were stripped still starts "PK" and
	// names its manifest.
	if strings.HasPrefix(v, "PK") && strings.Contains(v[:min(len(v), 64)], "META-INF") {
		return true
	}
	return false
}

// unreachableClaimChecks are the diagnostics that assert a surface did not answer.
var unreachableClaimChecks = map[string]bool{"http.surfaceUnreachable": true}

// contradictionPair is one place in a record where a "surface did not answer"
// diagnostic shares a port with a finding that only exists because the surface
// answered. Key is the reported signature "claim|check".
type contradictionPair struct {
	Key  string
	Port int
}

// contradictionPairs returns every contradicting pair in a record. It is the whole
// contradiction rule, kept as a pure function of the record so the audit and the
// replay harness cannot drift apart on what counts as a contradiction.
func contradictionPairs(rec *scanfile.Record) []contradictionPair {
	var claimed map[int]string
	for i := range rec.Findings {
		f := &rec.Findings[i]
		id := engine.CanonicalCheckID(f.Check)
		if !unreachableClaimChecks[id] {
			continue
		}
		if claimed == nil {
			claimed = map[int]string{}
		}
		claimed[f.Port] = id
	}
	if len(claimed) == 0 {
		return nil
	}
	var out []contradictionPair
	for i := range rec.Findings {
		f := &rec.Findings[i]
		id := engine.CanonicalCheckID(f.Check)
		if unreachableClaimChecks[id] {
			continue
		}
		// Only an HTTP-family finding on the same port contradicts the claim; a finding
		// from another protocol on another port says nothing about the web surface.
		if !strings.HasPrefix(id, "http.") && !strings.HasPrefix(id, "web.") {
			continue
		}
		claim, ok := claimed[f.Port]
		if !ok {
			continue
		}
		out = append(out, contradictionPair{Key: claim + "|" + id, Port: f.Port})
	}
	return out
}

// observeContradictions folds the contradicting pairs of one record into the audit.
func (a *qualityAuditor) observeContradictions(rec *scanfile.Record) {
	for _, p := range contradictionPairs(rec) {
		addExample(a.contra, p.Key, rec.Host)
	}
}

// postAuthCoverageMarkers are the fields that declare a post-auth run incomplete.
var postAuthCoverageMarkers = []string{"coverage", "missingSections", "access", "error", "collected"}

// silentPartialKeys returns one key per post-auth finding that under-reports without
// saying so: inventory sections are absent and the finding carries no coverage,
// access or error marker. The record then reads as a complete measurement, and an
// analyst cannot tell "nothing to find" from "we never looked". Pure function of the
// record, shared by the audit and the replay harness.
func silentPartialKeys(rec *scanfile.Record) []string {
	if !rawPresent(rec.IPMIPost) {
		return nil
	}
	var post map[string]json.RawMessage
	if json.Unmarshal(rec.IPMIPost, &post) != nil {
		return nil
	}
	var missing []string
	for _, s := range []string{"mcInfo", "chassis", "users", "lan", "fru"} {
		if !rawPresent(post[s]) {
			missing = append(missing, s)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	var out []string
	for i := range rec.Findings {
		f := &rec.Findings[i]
		if engine.CanonicalCheckID(f.Check) != "ipmi.postAuthEnum" {
			continue
		}
		if fieldValue(f, postAuthCoverageMarkers...) == "" {
			out = append(out, "ipmi.postAuthEnum|missing="+strings.Join(missing, ","))
		}
	}
	return out
}

// observeSilentPartial folds the silent-partial keys of one record into the audit.
func (a *qualityAuditor) observeSilentPartial(rec *scanfile.Record) {
	for _, k := range silentPartialKeys(rec) {
		addExample(a.silent, k, rec.Host)
	}
}

// mangledMarkers are the on-the-wire spellings of the byte problems the audit
// hunts for: a JSON-escaped NUL, a literal NUL, and the UTF-8 encoding of
// U+FFFD.
var mangledMarkers = [][]byte{[]byte(`\u0000`), {0x00}, []byte("\uFFFD")}

// observeRawFindings runs the mangled-bytes rules against the finding fields as
// they appear on disk. It must not use the decoded record: engine.Fields sanitizes
// values while decoding (and again while encoding), so by the time a finding is a
// typed value every NUL and invalid sequence is gone and the rules cannot fire. The
// full re-decode is gated behind a byte scan of the line, so only a dirty record
// pays for it.
func (a *qualityAuditor) observeRawFindings(rec *scanfile.Record, raw []byte) {
	walkRawFieldText(rec, raw, func(path, val string) {
		a.checkText(path, val, rec.Host)
	})
}

// walkRawFieldText calls fn for every finding field value that could still be
// carrying mangled bytes, keyed by "check.field". Shared by the audit and the replay
// harness.
func walkRawFieldText(rec *scanfile.Record, raw []byte, fn func(path, val string)) {
	if raw == nil {
		// Synthesized record: the typed fields are the only source there is.
		for i := range rec.Findings {
			f := &rec.Findings[i]
			for _, fd := range f.Fields {
				fn(f.Check+"."+engine.CanonicalFieldKey(fd.Key), fd.Val)
			}
		}
		return
	}
	clean := utf8.Valid(raw)
	for _, m := range mangledMarkers {
		if bytes.Contains(raw, m) {
			clean = false
			break
		}
	}
	if clean {
		return
	}
	var probe struct {
		Findings []struct {
			Check  string            `json:"check"`
			Fields map[string]string `json:"fields"`
		} `json:"findings"`
	}
	if json.Unmarshal(raw, &probe) != nil {
		return
	}
	for _, f := range probe.Findings {
		for k, v := range f.Fields {
			fn(engine.CanonicalCheckID(f.Check)+"."+engine.CanonicalFieldKey(k), v)
		}
	}
}

// textIssueKinds names the mangled-byte problems in one value, or nothing when it is
// clean. The names double as replay table keys.
func textIssueKinds(val string) []string {
	var out []string
	if strings.ContainsRune(val, '\x00') {
		out = append(out, "nul")
	}
	if strings.ContainsRune(val, '�') {
		out = append(out, "replacementChar")
	}
	if !utf8.ValidString(val) {
		out = append(out, "invalidUTF8")
	}
	return out
}

// observeIPMIPost looks for mangled strings in the post-auth LAN config, which
// is where a raw device buffer (notably the SNMP community string) reaches the
// output with the least processing in between.
func (a *qualityAuditor) observeIPMIPost(rec *scanfile.Record) {
	if !rawPresent(rec.IPMIPost) {
		return
	}
	var post struct {
		LAN map[string]string `json:"lan"`
	}
	if json.Unmarshal(rec.IPMIPost, &post) != nil {
		return
	}
	for _, key := range []string{"communityString", "community_string"} {
		if v := post.LAN[key]; v != "" {
			a.checkText("ipmiPostAuth.lan.communityString", v, rec.Host)
			break
		}
	}
}

// checkText records the mangled-bytes issues for one value.
func (a *qualityAuditor) checkText(path, val, host string) {
	for _, kind := range textIssueKinds(val) {
		switch kind {
		case "nul":
			addExample(a.nullByte, path, host)
		case "replacementChar":
			addExample(a.replacement, path, host)
		case "invalidUTF8":
			addExample(a.invalidUTF8, path, host)
		}
	}
}

// report finalizes the audit.
func (a *qualityAuditor) report() *QualityReport {
	return &QualityReport{
		Records:         a.records,
		Histogram:       a.histogram,
		Dark:            darkChecks(RegisteredCheckIDs(), a.histogram),
		NullByte:        a.nullByte,
		ReplacementChar: a.replacement,
		InvalidUTF8:     a.invalidUTF8,
		MissingProof:    a.missingProof,
		DuplicateURL:    a.duplicateURL,
		ReusedSSHKey:    reusedKeyClusters(a.sshKeyHosts, 2),
		ReusedTLSCert:   reusedKeyClusters(a.tlsCertHosts, 2),

		ConstantEvidence: constantFields(a.fieldSeen),
		BinaryEvidence:   a.binary,
		Contradiction:    a.contra,
		SilentPartial:    a.silent,
	}
}

// constantEvidenceAllowed are check.field slots adjudicated as legitimately
// constant, with the reason. Keep this list short and justified: every entry is a
// field a reader might otherwise expect to vary.
//
//   - tls.sharedKey.key names which known shared private key matched, so one label is
//     the correct answer for every host that matched it; the host-specific evidence is
//     carried by the spki/subject fields alongside it.
var constantEvidenceAllowed = map[string]string{
	"tls.sharedKey.key": "names which known shared key matched; spki/subject carry the per-host evidence",
}

// constantFields returns the check.field slots whose value never varied across a
// large enough sample to mean something.
func constantFields(seen map[string]*fieldConstancy) map[string]int {
	out := map[string]int{}
	for key, c := range seen {
		if _, allowed := constantEvidenceAllowed[key]; allowed {
			continue
		}
		if c.total >= constantEvidenceMinFindings && c.matched == c.total {
			out[key] = c.total
		}
	}
	return out
}

func isSevereRisk(risk string) bool {
	switch risk {
	case "critical", "high":
		return true
	}
	return false
}

// needsProofField reports whether a finding is making a claim that has to be backed
// by device-reported evidence.
//
// It is not only about severity. An `exposure`-category finding asserts that something
// was disclosed, so a body -- or at least its length -- is the whole claim, whatever
// risk it carries. Restricting the rule to critical/high lets a whole family ship with
// an empty snippet that engine.F then drops, carrying no trace of what was disclosed.
func needsProofField(f *engine.Finding) bool {
	return isSevereRisk(f.Risk) || f.Category == "exposure"
}

// proofFieldKeys are the canonical field keys that count as device-reported
// evidence for a finding.
var proofFieldKeys = []string{"proof", "response", "banner", "raw", "evidenceEndpoint", "hash", "snippet", "bodyBytes"}

// hasProofField reports whether a finding carries any evidence field.
func hasProofField(f *engine.Finding) bool {
	for _, fd := range f.Fields {
		if strings.TrimSpace(fd.Val) == "" {
			continue
		}
		if slices.Contains(proofFieldKeys, engine.CanonicalFieldKey(fd.Key)) {
			return true
		}
	}
	return false
}

// fieldValue returns the first non-empty value among the named canonical keys.
func fieldValue(f *engine.Finding, keys ...string) string {
	for _, want := range keys {
		for _, fd := range f.Fields {
			if engine.CanonicalFieldKey(fd.Key) == engine.CanonicalFieldKey(want) && fd.Val != "" {
				return fd.Val
			}
		}
	}
	return ""
}

// RegisteredCheckIDs returns the set of canonical check ids this binary can
// emit: the enabled entries of the check registry, plus the ids that are only
// ever produced inline by a probe and so never appear as a registry Name.
func RegisteredCheckIDs() map[string]bool {
	out := map[string]bool{}
	for _, c := range check.All() {
		if !c.Enabled {
			continue
		}
		id := c.Name
		if id == "http.redfish.authPathProbe" {
			id = "http.redfish.authPathError"
		}
		out[engine.CanonicalCheckID(id)] = true
	}
	for _, id := range []string{
		"ipmi.v20.cipherZero", "ipmi.v20.rakpHash", "ipmi.v20.defaultCreds",
		"ipmi.v20.usernameOracle", "ipmi.v15.usernameOracle",
		"ipmi.v15.defaultCreds", "ipmi.v15.authNoneSession",
		"ipmi.v15.authMethods", "ipmi.rmcpPing", "ipmi.versions",
		"ipmi.ciphers", "ipmi.weakCiphers", "ipmi.guid",
		"ipmi.authNull", "ipmi.authAnon",
		"ipmi.postAuthEnum",
		"http.redfish.postAuthEnum", "http.redfish.defaultCreds",
		"http.redfish.authPathError",
		// http.wsman.postAuthEnum is deliberately not listed: it is registered with
		// Enabled: false, so it cannot fire in a default scan and force-adding it here
		// bypassed the !c.Enabled filter above and reported it as dark on every run.
		"http.wsman.defaultCreds",
		"http.exposure", "http.endpoint", "http.surfaceUnreachable",
		// Negative (measured-clean / not-measured) arms of the SMC RAKP probes. Emitted
		// inline by the same checks, never as their own registry entries.
		"ipmi.smc.rakpUnordered.negative", "ipmi.smc.rakpReservedRole.negative",
	} {
		out[engine.CanonicalCheckID(id)] = true
	}
	return out
}

// neverDarkChecks are ids whose absence is the healthy state, so listing them as
// dark would train the reader to ignore the dark list. check.panic is emitted only
// when a check crashes; a clean run has none by design.
var neverDarkChecks = map[string]bool{"check.panic": true}

// producerChecks are registry entries that never emit a finding under their own name:
// each is a probe whose results ship as differently-named findings. They can therefore
// never be anything but "dark", and listing them buries the checks that are genuinely
// silent.
//
// The value is what the entry actually emits, so the mapping is checkable;
// TestProducerChecksNeverEmitOwnName fails if one of these starts self-emitting.
var producerChecks = map[string]string{
	"http.surface":                  "http.exposure / http.endpoint / http.surfaceUnreachable",
	"ipmi.surface":                  "ipmi.rmcpPing / ipmi.guid / ipmi.versions / ipmi.ciphers / ...",
	"ipmi.defaultCreds":             "ipmi.v20.* / ipmi.v15.* credential findings",
	"ipmi.v15.session":              "ipmi.v15.* session findings",
	"ssh.exposure":                  "ssh.version / ssh.weakCrypto / ssh.defaultCreds / ...",
	"snmp":                          "snmp.v3 / snmp.defaultCreds / snmp.vendorCommunity",
	"tls.cert":                      "tls.sharedKey / tls.expired / tls.selfSigned / tls.defaultCert",
	"pdu.exposure":                  "pdu.fingerprint",
	"pdu.confirm":                   "http.apc.* confirmations",
	"serialconsole.exposure":        "serialconsole.fingerprint",
	"ipkvm.posture":                 "ipkvm.noAuth",
	"http.web.defaultCreds":         "http.<vendor>.defaultCreds",
	"http.megarac.webDefaultCreds":  "http.<vendor>.defaultCreds",
	"http.smc.webDefaultCreds":      "http.<vendor>.defaultCreds",
	"http.redfish.ami.cve202454085": "http.redfish.amiBypass",
	"http.lenovo.xcc.preAuth":       "http.lenovo.xcc.deviceInfo",
	"http.cyberpower.ppe":           "http.cyberpower.ppe.missingAuth / .sqli",
}

// darkChecks lists the registered checks this corpus never emitted.
func darkChecks(registered map[string]bool, histogram map[string]int) []string {
	emitted := make(map[string]bool, len(histogram))
	for id := range histogram {
		emitted[engine.CanonicalCheckID(id)] = true
	}
	var dark []string
	for id := range registered {
		canon := engine.CanonicalCheckID(id)
		if emitted[canon] || neverDarkChecks[canon] {
			continue
		}
		if _, producer := producerChecks[canon]; producer {
			continue
		}
		dark = append(dark, id)
	}
	sort.Strings(dark)
	return dark
}

// addExample records a capped, deduplicated example host for an issue.
func addExample(m map[string][]string, key, host string) {
	cur := m[key]
	if slices.Contains(cur, host) || len(cur) >= exampleHostCap {
		m[key] = cur
		return
	}
	m[key] = append(cur, host)
}

func addKeyHost(m map[string]map[string]struct{}, key, host string) {
	key = strings.TrimSpace(key)
	host = strings.TrimSpace(host)
	if key == "" || host == "" {
		return
	}
	if _, ok := m[key]; !ok {
		m[key] = map[string]struct{}{}
	}
	m[key][host] = struct{}{}
}

// reusedKeyClusters returns the fingerprints seen on at least minHosts hosts,
// with a capped example host list each.
func reusedKeyClusters(m map[string]map[string]struct{}, minHosts int) map[string][]string {
	out := map[string][]string{}
	for key, hosts := range m {
		if len(hosts) < minHosts {
			continue
		}
		names := make([]string, 0, len(hosts))
		for h := range hosts {
			names = append(names, h)
		}
		sort.Strings(names)
		if len(names) > 8 {
			names = names[:8]
		}
		out[key] = names
	}
	return out
}
