package output

import (
	"encoding/hex"
	"encoding/json"
	"maps"
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

const ndjsonRawFieldMax = 16 << 10

const RawFieldMax = ndjsonRawFieldMax

type Result struct {
	Host            string                    `json:"host"`
	TS              int64                     `json:"timestamp,omitempty"`
	Ports           engine.OpenPorts          `json:"ports,omitempty"`
	Identity        *engine.Identity          `json:"identity,omitempty"`
	Final           *engine.Final             `json:"finalIdentity,omitempty"`
	Findings        []engine.Finding          `json:"findings,omitempty"`
	AttemptedChecks string                    `json:"attemptedChecks,omitempty"`
	Services        []ServiceRecord           `json:"services,omitempty"`
	Attributes      map[string]string         `json:"attributes,omitempty"`
	RAKP            []RAKPRecord              `json:"rakp,omitempty"`
	ILO             *ilo.XMLData              `json:"ilo,omitempty"`
	IPMIPost        *ipmi.PostAuthCollection  `json:"ipmiPostAuth,omitempty"`
	RFPost          *redfish.PostAuthSnapshot `json:"redfishPostAuth,omitempty"`
	WebLogin        *httpx.Transcript         `json:"webLogin,omitempty"`

	Evidence map[string]json.RawMessage `json:"evidence,omitempty"`
	Error    string                     `json:"error,omitempty"`
}

var serializedEvidenceKeys = map[string]string{

	"ipmi.smc.rakpStateMachine": "SMC RAKP ordering probe: RAKP4 status, echoed SID, spec-conformant flag",
	"ipmi.smc.privEsc":          "SMC RAKP role probe: reserved/control/admin role statuses",

	"ipmi.openBmcRakpState":     "OpenBMC RAKP ordering probe: message 2 and message 4 statuses",
	"ipmi.openBmcSetupState":    "OpenBMC setup-state probe: which session commands answer before authentication completes",
	"ipmi.openBmcSetupIdentity": "OpenBMC disabled-account setup-slot probe",

	"ipmi.authCaps":     "raw Get Channel Auth Caps reply, so the parse can be re-derived without a re-scan",
	"ipmi.nullUserPriv": "null/anonymous-user privilege probe (what an unauthenticated session reaches, incl. SOL)",
	"ipmi.preAuthMap":   "which IPMI commands answer with no session",
	"ipmi.ipmb":         "IPMB bridging sweep results",
	"ipmi.v15":          "IPMI 1.5 report: offered auth methods, auth-none result, default credential",

	"wsman.postAuth": "post-auth WS-Man inventory (the analogue of ipmiPostAuth/redfishPostAuth)",

	"redfish.authPathError": "Redfish auth-path status pattern (unauth/basic/session/challenge)",
}

const maxEvidenceBytes = 256 * 1024

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

type ServiceRecord struct {
	Port       int               `json:"port,omitempty"`
	Transport  string            `json:"transport,omitempty"`
	Protocols  []string          `json:"protocols,omitempty"`
	Summary    string            `json:"summary,omitempty"`
	VHost      string            `json:"vhost,omitempty"`
	Address    string            `json:"address,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

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

func resultFrom(t *engine.Target) Result {
	now := time.Now().UnixNano()

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

	if v, ok := t.Evidenced("ilo"); ok {
		if x, ok := v.(*ilo.XMLData); ok && x != nil {
			r.ILO = x
		}
	}
	r.Services = serviceRecordsFrom(t)
	r.Attributes = hostAttributesFrom(t)
	return r
}

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

func csvToSortedSlice(v string) []string {
	if v == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for p := range strings.SplitSeq(v, ",") {
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

func mergeAttrs(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]string, len(src))
	}
	maps.Copy(dst, src)
	return dst
}

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

const ndjsonFieldMax = 4 << 10

var uncappedFields = map[string]struct{}{"hash": {}}

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
