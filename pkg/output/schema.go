// Package output renders scan results. It implements engine.Emitter twice: a
// mutex-guarded NDJSON emitter (machine mode) and a lipgloss TTY emitter
// (interactive mode). New auto-selects based on output settings and whether stderr is a
// terminal. The two streams are kept strictly separate: structured NDJSON goes
// to the output writer (stdout/file); all TTY chrome goes to stderr, so a
// piped `oobscan scan --output out.jsonl` never sees an escape sequence.
package output

import (
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/ilo"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/redfish"
	"github.com/runZeroInc/oobscan/pkg/ssh"
	"github.com/runZeroInc/oobscan/pkg/tlscert"
)

const ndjsonRawFieldMax = 16 << 10 // 16 KiB

// RawFieldMax is the ceiling for a single raw captured value. It is exported so
// an importer building records outside the scan pipeline (`oobscan convert`)
// bounds a preserved attribute bag with the same budget the scanner uses.
const RawFieldMax = ndjsonRawFieldMax

// Result is one NDJSON record: everything learned about a responsive target or
// target error. Ports is the discovered open surface
// ("port/transport" -> "proto,proto").
type Result struct {
	Host            string                    `json:"host"`
	TS              int64                     `json:"timestamp,omitempty"`
	Ports           engine.OpenPorts          `json:"ports,omitempty"`
	Identity        *engine.Identity          `json:"identity,omitempty"`
	Final           *engine.Final             `json:"finalIdentity,omitempty"` // post-check aggregate identity + derived flags
	Findings        []engine.Finding          `json:"findings,omitempty"`
	AttemptedChecks string                    `json:"attemptedChecks,omitempty"` // sorted CSV of checks that ran and produced a "none" (clean) result
	Services        []ServiceRecord           `json:"services,omitempty"`        // raw per-service attributes (TLS/SSH crypto material, ...) for lossless downstream use
	Attributes      map[string]string         `json:"attributes,omitempty"`      // host-level attributes (class/vendor/product/version + identity attrs)
	RAKP            []RAKPRecord              `json:"rakp,omitempty"`
	ILO             *ilo.XMLData              `json:"ilo,omitempty"` // pre-auth /xmldata RIMP doc, verbatim (server model, MP.PN/MP.ST, NIC MAC/IPs)
	IPMIPost        *ipmi.PostAuthCollection  `json:"ipmiPostAuth,omitempty"`
	RFPost          *redfish.PostAuthSnapshot `json:"redfishPostAuth,omitempty"`
	WebLogin        *httpx.Transcript         `json:"webLogin,omitempty"` // full request/response transcript of the web default-login check (for field debugging)
	// Evidence carries the probe results that are not otherwise representable in a
	// finding, keyed by evidence handle. See serializedEvidenceKeys for what is
	// included and why. Without it these were in-process only and vanished with the
	// scan -- a confirmed OpenBMC bypass, for instance, discarded the one value needed
	// to reproduce it.
	Evidence map[string]json.RawMessage `json:"evidence,omitempty"`
	Error    string                     `json:"error,omitempty"`
}

// serializedEvidenceKeys is the allowlist of evidence handles projected into the
// record, each with the reason it cannot be reconstructed from the rest of the row.
//
// An allowlist, not a wholesale dump: `http` holds the full httpscan report with a
// retained body per endpoint, `ipmi.auth` holds the RAKP material that ships as rakp[]
// rows, and `tls`/`ssh.*` are what services[].attributes exists for. Adding a probe
// means adding one line; TestSerializedEvidenceKeysAreCanonical rejects a typo.
var serializedEvidenceKeys = map[string]string{
	// The SMC RAKP state-machine probes. Their negative arm (0x0f conformant rejection
	// for CVE-2026-65219, 0x09/0x0a/0x12 for CVE-2026-65220) and the control-arm statuses only exist
	// here; the findings carry the positive case. Without them a corpus of all-positive
	// findings cannot show the discriminator ever discriminated.
	"ipmi.smc.rakpUnordered":    "CVE-2026-65219 probe: RAKP4 status, echoed SID, spec-conformant flag",
	"ipmi.smc.rakpReservedRole": "CVE-2026-65220 probe: reserved/control/admin role statuses",

	// The OpenBMC chain. The default-userKey probe's winning bmcRandomNum is the only
	// reusable output of a confirmed bypass -- reopening the session needs it -- and the
	// sweep bounds/truncation are what separate an exhaustive miss from a timed-out one.
	"ipmi.openBmcDefaultUserKey":         "OBMC bypass: winning bmcRandomNum, attempts, sweep bounds/truncation",
	"ipmi.openBmcSetupState":             "OBMC setup-state probe: admin-priv acceptance and the relabel target account",
	"ipmi.openBmcDisabledSetupOverwrite": "OBMC disabled-account setup-overwrite probe",

	// Pre-auth IPMI surface detail that no finding carries in full.
	"ipmi.authCaps":     "raw Get Channel Auth Caps reply, so the parse can be re-derived without a re-scan",
	"ipmi.nullUserPriv": "null/anonymous-user privilege probe (what an unauthenticated session reaches, incl. SOL)",
	"ipmi.preAuthMap":   "which IPMI commands answer with no session",
	"ipmi.ipmb":         "IPMB bridging sweep results",
	"ipmi.v15":          "IPMI 1.5 report: offered auth methods, auth-none result, default credential",

	// The third post-auth snapshot. ipmiPostAuth and redfishPostAuth are already
	// top-level fields; this one was simply never wired, so authenticated WS-Man
	// inventory was collected and thrown away.
	"wsman.postAuth": "post-auth WS-Man inventory (the analogue of ipmiPostAuth/redfishPostAuth)",

	// The Redfish auth-path anomaly pattern: four status codes whose combination is the
	// signal, of which the finding keeps only a summary.
	"redfish.authPathError": "Redfish auth-path status pattern (unauth/basic/session/challenge)",
}

// maxEvidenceBytes caps one serialized evidence blob. A probe that grows unexpectedly
// large is dropped with a note rather than silently truncated or silently omitted, so
// the record never implies the probe did not run.
const maxEvidenceBytes = 256 * 1024

// evidenceForRecord marshals the allowlisted evidence present on t.
func evidenceForRecord(t *engine.Target) map[string]json.RawMessage {
	var out map[string]json.RawMessage
	for key, why := range serializedEvidenceKeys {
		v, ok := t.Evidenced(key)
		if !ok || v == nil {
			continue
		}
		raw, err := json.Marshal(v)
		if err != nil {
			continue
		}
		if len(raw) > maxEvidenceBytes {
			raw, err = json.Marshal(map[string]any{
				"omitted": "evidence exceeded maxEvidenceBytes",
				"bytes":   len(raw),
				"reason":  why,
			})
			if err != nil {
				continue
			}
		}
		if out == nil {
			out = map[string]json.RawMessage{}
		}
		out[key] = raw
	}
	return out
}

// ServiceRecord is one open service with its raw runZero-style attribute bag. It
// preserves the crypto material a consumer needs to reason about exposure without
// re-probing, notably the TLS leaf and SSH host-key badkeys bkhashes that key a
// shared/default-firmware-key match. Attribute keys mirror the runZero service_data
// vocabulary so both corpora stay directly comparable.
//
// Summary, VHost and Address are never set by a live scan, which probes one address
// at a time and derives no service summary. They exist so a converted runZero export
// keeps those per-service columns instead of flattening them into the attribute bag.
type ServiceRecord struct {
	Port       int               `json:"port,omitempty"`
	Transport  string            `json:"transport,omitempty"`
	Protocols  []string          `json:"protocols,omitempty"`
	Summary    string            `json:"summary,omitempty"`
	VHost      string            `json:"vhost,omitempty"`
	Address    string            `json:"address,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// RAKPRecord carries the raw RAKP-2 material for offline re-cracking. Hashcat
// holds the ready-to-crack hashcat -m 7300 line when the negotiated algorithm is
// HMAC-SHA1 (empty for HMAC-MD5/SHA256, which have no hashcat mode -- the sids,
// nonces, guid, and hmac fields still allow offline cracking).
//
// Redacted marks a row whose hash material was withheld by the source rather than
// never captured; only `convert` sets it. It is what lets a consumer distinguish a
// BMC that leaked no hash from one whose leaked hash is not being carried.
type RAKPRecord struct {
	Username   string `json:"username"`
	AuthAlgo   byte   `json:"authAlgo"`
	ClientSID  uint32 `json:"clientSid"`
	BMCSID     uint32 `json:"bmcSid"`
	ClientRand string `json:"clientRand"`
	BMCRand    string `json:"bmcRand"`
	BMCGUID    string `json:"bmcGuid"`
	RAKPHash   string `json:"rakpHash"`
	Hashcat    string `json:"hashcat,omitempty"`
	Cracked    string `json:"cracked,omitempty"`
	Redacted   bool   `json:"redacted,omitempty"`
}

// resultFrom builds the NDJSON record for a finished target, pulling any RAKP
// hashes out of the stashed IPMI auth evidence.
func resultFrom(t *engine.Target) Result {
	now := time.Now().UnixNano()
	// Split findings: positive (risk >= info) stay in the Findings array;
	// "none" (clean/negative-result) findings are aggregated into
	// AttemptedChecks so consumers see "we tried check X and it came back
	// clean" without a per-check row in the findings list.
	all := t.FindingsSnapshot()
	findings := make([]engine.Finding, 0, len(all))
	attemptedSeen := map[string]struct{}{}
	var attempted []string
	for _, f := range all {
		risk := f.Risk
		if risk == "" {
			risk = "none"
		}
		if engine.RiskRank(risk) < engine.RiskRank("info") {
			if f.Check == "" {
				continue
			}
			if _, ok := attemptedSeen[f.Check]; ok {
				continue
			}
			attemptedSeen[f.Check] = struct{}{}
			attempted = append(attempted, f.Check)
			continue
		}
		if f.TS == 0 {
			f.TS = now
		}
		f.Fields = capJSONLargeFields(f.Fields)
		findings = append(findings, f)
	}
	sort.Strings(attempted)
	// Most-severe first, stable within a risk level (preserves discovery order).
	sort.SliceStable(findings, func(i, j int) bool {
		return engine.RiskRank(findings[i].Risk) > engine.RiskRank(findings[j].Risk)
	})
	r := Result{
		Host:            t.Host,
		TS:              now,
		Ports:           t.OpenSnapshot(),
		Identity:        t.Identity,
		Final:           t.Final,
		Findings:        findings,
		AttemptedChecks: engine.SortedCSV(attempted),
		Error:           t.Err,
	}
	if v, ok := t.Evidenced("ipmi.auth"); ok {
		if rep, ok := v.(*ipmi.AuthReport); ok && rep != nil {
			for i := range rep.Results {
				r.RAKP = append(r.RAKP, rakpRecord(&rep.Results[i]))
			}
		}
	}
	if v, ok := t.Evidenced("ipmi.postAuth"); ok {
		if post, ok := v.(*ipmi.PostAuthCollection); ok && post != nil {
			r.IPMIPost = post
		}
	}
	if v, ok := t.Evidenced("redfish.postAuth"); ok {
		if post, ok := v.(*redfish.PostAuthSnapshot); ok && post != nil {
			r.RFPost = post
		}
	}
	if v, ok := t.Evidenced("web.login.transcript"); ok {
		if tr, ok := v.(*httpx.Transcript); ok && tr != nil {
			r.WebLogin = tr
		}
	}
	r.Evidence = evidenceForRecord(t)
	// The pre-auth iLO RIMP doc, verbatim. It was previously evidence-only, so
	// MP.PN/MP.ST -- the two fields Generation() reads -- never reached the
	// output and a generation fall-through could not be diagnosed without a
	// re-scan. It also carries the server model and the pre-auth NIC MAC/IP
	// inventory that no other source provides.
	if v, ok := t.Evidenced("ilo"); ok {
		if x, ok := v.(*ilo.XMLData); ok && x != nil {
			r.ILO = x
		}
	}
	r.Services = serviceRecordsFrom(t)
	r.Attributes = hostAttributesFrom(t)
	return r
}

// serviceRecordsFrom projects the discovered open surface plus the stashed raw
// TLS/SSH evidence onto per-service attribute bags. The attribute keys mirror
// the runZero service_data vocabulary (tls.fp.bkhash, tls.fp.sha256, tls.*,
// ssh.hostKey.bkhash, ...) so nothing crypto-relevant is dropped and a consumer
// can run shared/default-key detection without re-probing the host.
func serviceRecordsFrom(t *engine.Target) []ServiceRecord {
	open := t.OpenSnapshot()
	if len(open) == 0 {
		return nil
	}
	byPort := make(map[int]*ServiceRecord)
	keys := make([]string, 0, len(open))
	for k := range open {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	svcs := make([]ServiceRecord, 0, len(open))
	for _, k := range keys {
		port, transport := splitPortKey(k)
		if port == 0 {
			continue
		}
		svcs = append(svcs, ServiceRecord{
			Port:      port,
			Transport: transport,
			Protocols: csvToSortedSlice(open[k]),
		})
	}
	for i := range svcs {
		byPort[svcs[i].Port] = &svcs[i]
	}

	// Attach the served TLS leaf evidence (badkeys bkhash + fingerprint + cert
	// posture) to its port. This is the primary "record where missing" win: the
	// bkhash is exactly the shared/default-key detection input.
	if v, ok := t.Evidenced("tls"); ok {
		if ci, ok := v.(*tlscert.CertInfo); ok && ci != nil {
			rec := byPort[ci.Port]
			if rec == nil {
				svcs = append(svcs, ServiceRecord{Port: ci.Port, Transport: "tcp"})
				rec = &svcs[len(svcs)-1]
				byPort[ci.Port] = rec
			}
			rec.Attributes = mergeAttrs(rec.Attributes, tlsCertAttrs(ci))
		}
	}

	// Attach captured SSH host-key material (bkhash + fingerprint + key type).
	if v, ok := t.Evidenced("ssh.hostKeys"); ok {
		if caps, ok := v.(map[int]ssh.HostKeyCapture); ok {
			for port, cap := range caps {
				rec := byPort[port]
				if rec == nil {
					svcs = append(svcs, ServiceRecord{Port: port, Transport: "tcp"})
					rec = &svcs[len(svcs)-1]
					byPort[port] = rec
				}
				rec.Attributes = mergeAttrs(rec.Attributes, sshHostKeyAttrs(cap))
			}
		}
	}

	sort.SliceStable(svcs, func(i, j int) bool {
		if svcs[i].Port != svcs[j].Port {
			return svcs[i].Port < svcs[j].Port
		}
		return svcs[i].Transport < svcs[j].Transport
	})
	return svcs
}

// tlsCertAttrs renders a served-leaf CertInfo as runZero-style tls.* attributes.
func tlsCertAttrs(ci *tlscert.CertInfo) map[string]string {
	a := map[string]string{}
	putStr := func(k, v string) {
		if v != "" {
			a[k] = v
		}
	}
	putStr("tls.fp.bkhash", ci.BadKeyHash)
	putStr("tls.fp.sha256", ci.SHA256)
	putStr("tls.fp.spkiSha256", ci.SPKI256)
	putStr("tls.subject", ci.SubjectCN)
	putStr("tls.subjectO", ci.SubjectO)
	putStr("tls.issuer", ci.IssuerCN)
	if !ci.NotBefore.IsZero() {
		a["tls.notBefore"] = ci.NotBefore.UTC().Format(time.RFC3339)
	}
	if !ci.NotAfter.IsZero() {
		a["tls.notAfter"] = ci.NotAfter.UTC().Format(time.RFC3339)
	}
	a["tls.selfSigned"] = strconv.FormatBool(ci.SelfSigned)
	if ci.Expired {
		a["tls.expired"] = "true"
	}
	if ci.KeyBits > 0 {
		a["tls.keyBits"] = strconv.Itoa(ci.KeyBits)
	}
	if ci.SharedKeyMatch != nil || ci.SharedKeyBySPKI != nil || ci.BadKeyMatch != nil {
		a["tls.sharedKey"] = "true"
	}
	putStr("tls.vendor", ci.Vendor)
	putStr("tls.product", ci.Product)
	if len(a) == 0 {
		return nil
	}
	return a
}

// sshHostKeyAttrs renders a captured SSH host key as runZero-style ssh.* attrs.
func sshHostKeyAttrs(cap ssh.HostKeyCapture) map[string]string {
	a := map[string]string{}
	if cap.BKHash != "" {
		a["ssh.hostKey.bkhash"] = cap.BKHash
	}
	if cap.Fingerprint != "" {
		a["ssh.hostKey.fingerprint"] = cap.Fingerprint
	}
	if cap.KeyType != "" {
		a["ssh.hostKeyType"] = cap.KeyType
	}
	if cap.SharedMatch || (cap.BadKeyMatch && cap.BadKey.Kind == "FW/SSH") {
		a["ssh.hostKey.shared"] = "true"
	}
	if len(a) == 0 {
		return nil
	}
	return a
}

// hostAttributesFrom renders the resolved host identity as a flat attribute map
// (class/vendor/product/generation/version plus any captured identity
// attributes), so a consumer has the asset-level context without re-deriving it.
func hostAttributesFrom(t *engine.Target) map[string]string {
	a := map[string]string{}
	put := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			a[k] = v
		}
	}
	if t.Final != nil {
		put("class", string(t.Final.Class))
		put("vendor", t.Final.Vendor)
		put("product", t.Final.Product)
		put("generation", t.Final.Generation)
		put("version", t.Final.Version)
	}
	if t.Identity != nil {
		if a["class"] == "" {
			put("class", string(t.Identity.Class))
		}
		put("vendor", firstNonEmpty(a["vendor"], t.Identity.Vendor))
		put("product", firstNonEmpty(a["product"], t.Identity.Product))
		put("generation", firstNonEmpty(a["generation"], t.Identity.Generation))
		for k, v := range engine.CanonicalStringMap(t.Identity.Attributes) {
			put(k, v)
		}
	}
	if len(a) == 0 {
		return nil
	}
	return a
}

// csvToSortedSlice splits a comma-joined protocol string into a sorted, unique,
// non-empty slice.
func csvToSortedSlice(v string) []string {
	if v == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// splitPortKey parses an OpenPorts key ("623/udp") into its port and transport.
func splitPortKey(k string) (port int, transport string) {
	slash := strings.LastIndexByte(k, '/')
	if slash < 0 {
		if n, err := strconv.Atoi(k); err == nil {
			return n, "tcp"
		}
		return 0, ""
	}
	n, err := strconv.Atoi(k[:slash])
	if err != nil {
		return 0, ""
	}
	return n, k[slash+1:]
}

// mergeAttrs merges src into dst (allocating dst when nil) and returns it.
func mergeAttrs(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]string, len(src))
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func resultHasResponsiveData(r Result) bool {
	if len(r.Ports) > 0 || len(r.Findings) > 0 || len(r.RAKP) > 0 || r.IPMIPost != nil || r.RFPost != nil || r.WebLogin != nil || r.Error != "" {
		return true
	}
	return r.Identity != nil && (r.Identity.Class != engine.ClassUnknown || len(r.Identity.Signals) > 0)
}

// ndjsonFieldMax is the universal per-field ceiling in the machine output. It is
// ~25x the largest legitimate non-raw field observed at internet scale, so it
// only bites runaway values (signature-DB banner dumps, catalog-prose blobs).
const ndjsonFieldMax = 4 << 10 // 4 KiB

// uncappedFields are exempt from ndjsonFieldMax because a truncated value is
// useless: `hash` is crackable RAKP material that must stay byte-complete.
var uncappedFields = map[string]struct{}{"hash": {}}

// CapFindingFields applies the emitted-record field ceilings to an existing
// finding's fields. Live scans get this for free through resultFrom; it is
// exported so a record read back off disk (`oobscan convert`) can be re-bounded
// under the current rules instead of carrying a blob an older build emitted.
func CapFindingFields(fields engine.Fields) engine.Fields {
	return capJSONLargeFields(fields)
}

func capJSONLargeFields(fields engine.Fields) engine.Fields {
	if len(fields) == 0 {
		return fields
	}
	out := make(engine.Fields, len(fields))
	copy(out, fields)
	for i := range out {
		key := engine.CanonicalFieldKey(out[i].Key)
		if _, ok := uncappedFields[key]; ok {
			continue
		}
		// `response` (raw captured payloads) keeps the larger 16 KiB budget; every
		// other field is bounded universally so no check can ship an uncapped blob.
		max := ndjsonFieldMax
		if key == "response" {
			max = ndjsonRawFieldMax
		}
		if len(out[i].Val) > max {
			out[i].Val = truncateUTF8Bytes(out[i].Val, max)
		}
	}
	return out
}

func truncateUTF8Bytes(value string, maxBytes int) string {
	if maxBytes < 0 || len(value) <= maxBytes {
		return value
	}
	end := maxBytes
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	if end == 0 {
		return strings.ToValidUTF8(value[:maxBytes], "?")
	}
	return value[:end]
}

func rakpRecord(rr *ipmi.RAKPResult) RAKPRecord {
	rec := RAKPRecord{
		Username:   rr.Username,
		AuthAlgo:   rr.AuthAlgo,
		ClientSID:  rr.ClientSID,
		BMCSID:     rr.BMCSID,
		ClientRand: hex.EncodeToString(rr.ClientRand),
		BMCRand:    hex.EncodeToString(rr.BMCRand),
		BMCGUID:    hex.EncodeToString(rr.BMCGUID),
		RAKPHash:   hex.EncodeToString(rr.RAKPHash),
		Hashcat:    rr.Hashcat(),
	}
	if rr.Crack != nil {
		rec.Cracked = rr.Crack.Password
	}
	return rec
}
