// Package engine drives the concurrent scan: it expands targets, runs one
// panic-isolated goroutine per host, and streams results to an Emitter. It owns
// the domain types (Target, Identity, Finding) so that the identify and check
// packages can depend on engine without an import cycle; the per-target
// pipeline (identify -> checks -> optional IPMI walk) is supplied by the caller
// as a RunFunc.
package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/runZeroInc/oobscan/pkg/sanitize"
)

// Proto is a transport protocol for a probe port.
type Proto string

const (
	ProtoTCP Proto = "tcp"
	ProtoUDP Proto = "udp"
)

// Port is a candidate service port on a target.
type Port struct {
	Num   int   `json:"num"`
	Proto Proto `json:"proto"`
}

// OpenPorts maps "port/transport" (e.g. "623/udp") to a comma-joined list of the
// protocols observed on it (e.g. "ipmi"), so the record shows the real reachable
// surface of a host instead of the static candidate list.
type OpenPorts map[string]string

// MarshalJSON keeps protocol lists in the discovered port map as sorted CSV.
func (op OpenPorts) MarshalJSON() ([]byte, error) {
	if len(op) == 0 {
		return []byte("{}"), nil
	}
	out := make(map[string]string, len(op))
	for k, v := range op {
		out[k] = SortedCSVString(v)
	}
	return json.Marshal(out)
}

// Cred is a login credential offered to authenticated checks.
type Cred struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

// DeviceClass is the coarse family of out-of-band device. New classes are added
// here and mapped from pkg/oob categories in the identify package.
type DeviceClass string

const (
	ClassUnknown       DeviceClass = "unknown"  // reachable OOB-ish surface, unattributed
	ClassBMC           DeviceClass = "bmc"      // server baseboard management (iDRAC/iLO/SMC/CIMC/OpenBMC)
	ClassKVM           DeviceClass = "kvm"      // IP-KVM (Raritan/Avocent/PiKVM/Adder)
	ClassSerialConsole DeviceClass = "serial"   // serial-over-IP / console server (Lantronix/Moxa/Digi/Opengear)
	ClassPDU           DeviceClass = "pdu"      // networked power (APC/Raritan PX/Eaton)
	ClassAMT           DeviceClass = "amt"      // Intel AMT / vPro
	ClassFirmware      DeviceClass = "firmware" // UEFI/BIOS-side surface
	ClassHoneypot      DeviceClass = "honeypot" // deception node emulating OOB surfaces; flagged and skipped
)

// Confidence grades how strongly the identify step attributed a device.
type Confidence string

const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

// Signal is one piece of evidence that contributed to an Identity.
type Signal struct {
	Source string `json:"source"` // "ipmi.deviceId","guid","http.server","redfish","ilo","idrac","tls","lantronix","lantronix.telnet","moxa","digi.addp","digi.realport","wsman","snmp"
	Vendor string `json:"vendor,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Identity is the output of the identify step and the join key for selecting
// device-specific checks.
type Identity struct {
	Class      DeviceClass       `json:"class"`
	Vendor     string            `json:"vendor,omitempty"`  // lowercase slug (matches creds/oob vendor keys)
	Product    string            `json:"product,omitempty"` // e.g. "iDRAC9","iLO5","ATEN IPMI","NPort"
	Generation string            `json:"generation,omitempty"`
	Confidence Confidence        `json:"confidence"`
	Signals    []Signal          `json:"signals,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"` // fw version, service tag, MAC, GUID family, IANA PEN
}

// MarshalJSON renders Identity with normalized camelCase attribute keys while
// leaving the in-memory dotted keys intact for identify/check heuristics.
func (id Identity) MarshalJSON() ([]byte, error) {
	type identityJSON struct {
		Class      DeviceClass       `json:"class"`
		Vendor     string            `json:"vendor,omitempty"`
		Product    string            `json:"product,omitempty"`
		Generation string            `json:"generation,omitempty"`
		Confidence Confidence        `json:"confidence"`
		Signals    []Signal          `json:"signals,omitempty"`
		Attributes map[string]string `json:"attributes,omitempty"`
	}
	return json.Marshal(identityJSON{
		Class:      id.Class,
		Vendor:     id.Vendor,
		Product:    id.Product,
		Generation: id.Generation,
		Confidence: id.Confidence,
		Signals:    id.Signals,
		Attributes: CanonicalStringMap(id.Attributes),
	})
}

// Field is one structured key/value detail of a finding. Order is preserved so
// text and JSON render the same data in the same order.
type Field struct {
	Key string
	Val string
}

// Fields is an ordered set of finding details. It marshals to a JSON object
// (preserving order) and renders as space-separated key=val pairs in text, so
// the machine and human outputs carry identical data.
type Fields []Field

// canonicalKeyAliases folds synonym finding-field keys onto a single canonical key
// so every check speaks one output vocabulary (applied to the NDJSON and the TTY
// view via CanonicalFieldKey). Lookup is single-level: an entry must point at the
// final canonical spelling, not an intermediate alias.
//
// Canonical concepts: proof (device-reported evidence marker), response (raw
// response bytes; banner and sysdescr keep their own keys), username/password (the
// credential; community stays distinct), source (credential provenance), loginVia
// (the auth mechanism, distinct from source), status (HTTP status; the paired
// status1/status2 stay distinct).
var canonicalKeyAliases = map[string]string{
	"firmware":             "firmwareVersion",
	"firmware_revision":    "firmwareVersion",
	"firmware_version":     "firmwareVersion",
	"backup_gw_ip":         "backupGatewayIp",
	"backup_gw_mac":        "backupGatewayMac",
	"moxa.firmware":        "moxaFirmwareVersion",
	"cn":                   "commonName",
	"default":              "defaultCredential",
	"default_cred_profile": "defaultCredentialProfile",
	"default_creds":        "defaultCreds",
	"default_gw_ip":        "defaultGatewayIp",
	"default_gw_mac":       "defaultGatewayMac",
	"default_pass":         "password",
	"default_user":         "username",
	"defaultPassword":      "password",
	"defaultUsername":      "username",
	"evidence":             "proof",
	"fw":                   "firmwareVersion",
	"http_status":          "status",
	"httpStatus":           "status",
	"ip_addr":              "ipAddress",
	"ipv6_ipv4_enables":    "ipv6Ipv4Enabled",
	"mfr":                  "manufacturer",
	"model_name":           "model",
	"output":               "response",
	"pass":                 "password",
	"raw":                  "response",
	"rmcp_udp_port":        "rmcpUdpPort",
	"rmcp_secondary_port":  "rmcpSecondaryPort",
	"sample":               "response",
	"serial":               "serialNumber",
	"serial_number":        "serialNumber",
	"snippet":              "response",
	"user":                 "username",
	"via":                  "source",
}

var canonicalTokenAliases = map[string]string{
	"cred":        "credential",
	"fw":          "firmwareVersion",
	"mfr":         "manufacturer",
	"postauth":    "postAuth",
	"preauth":     "preAuth",
	"usbanywhere": "usbAnywhere",
}

var csvFieldKeys = map[string]struct{}{
	"archiveContents":     {},
	"extraUrls":           {},
	"ipmiSupported":       {},
	"match":               {},
	"methods":             {},
	"nics":                {},
	"otherPreauthObjects": {},
	"ports":               {},
	"recovered":           {},
	"securityProfiles":    {},
	"suites":              {},
	"vendors":             {},
	"versions":            {},
}

var canonicalEvidenceAliases = map[string]string{
	"ipmi.authcaps":           "ipmi.authCaps",
	"ipmi.postauth":           "ipmi.postAuth",
	"redfish.auth_path_error": "redfish.authPathError",
	"redfish.postauth":        "redfish.postAuth",
	"snmpv3":                  "snmp.v3",
}

// canonicalCheckIDAliases maps a retired check id to its current spelling, so
// older scan/convert output keeps matching the same check across a rename.
var canonicalCheckIDAliases = map[string]string{
	"ssh.hpe.iloRdpktOverflow": "ssh.hpe.iloSSHOverflow",
}

// CanonicalFieldKey returns the emitted JSON spelling for dynamic finding keys
// and identity/flag map keys. It converts dotted/snake names to lower camelCase
// and applies a few semantic aliases so equivalent concepts use one key.
func CanonicalFieldKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if alias, ok := canonicalKeyAliases[key]; ok {
		return alias
	}
	return lowerCamelKey(key)
}

// CanonicalFieldValue normalizes emitted values for known multi-value string
// fields to sorted CSV.
func CanonicalFieldValue(key, val string) string {
	val = string(sanitize.Bytes([]byte(val)))
	key = CanonicalFieldKey(key)
	if _, ok := csvFieldKeys[key]; ok {
		return SortedCSVString(val)
	}
	return val
}

// CanonicalEvidenceKey returns the in-memory evidence handle spelling used by
// probes and checks. Evidence handles keep dotted namespaces, but each segment
// is normalized to lower camelCase.
func CanonicalEvidenceKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if alias, ok := canonicalEvidenceAliases[key]; ok {
		return alias
	}
	parts := strings.Split(key, ".")
	for i, part := range parts {
		parts[i] = lowerCamelKey(part)
	}
	return strings.Join(parts, ".")
}

// CanonicalCheckID returns the canonical in-memory finding/check identifier.
// Check IDs keep dotted namespaces, while each non-version segment is
// normalized to lower camelCase so legacy snake_case or dashed spellings map to
// one internal form.
func CanonicalCheckID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	if alias, ok := canonicalCheckIDAliases[id]; ok {
		id = alias
	}
	parts := strings.Split(id, ".")
	for i, part := range parts {
		if part == "" {
			continue
		}
		if isAllDigits(part) {
			parts[i] = "v" + part
			continue
		}
		if len(part) > 1 && (part[0] == 'v' || part[0] == 'V') && isAllDigits(part[1:]) {
			parts[i] = "v" + part[1:]
			continue
		}
		parts[i] = lowerCamelKey(part)
	}
	return strings.Join(parts, ".")
}

// SortedCSV renders values as a deterministic comma-separated string.
func SortedCSV(values []string) string {
	return sortedCSVValues(values)
}

// SortedCSVString normalizes an existing comma-separated string.
func SortedCSVString(value string) string {
	return sortedCSVValues(splitCSV(value))
}

func CanonicalStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := in[k]
		ck := CanonicalFieldKey(k)
		if ck == "" {
			continue
		}
		cv := CanonicalFieldValue(ck, v)
		if cv == "" {
			continue
		}
		out[ck] = cv
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func lowerCamelKey(key string) string {
	parts := strings.FieldsFunc(key, func(r rune) bool {
		return r == '.' || r == '_' || r == '-' || r == ' ' || r == '/'
	})
	if len(parts) == 0 {
		return ""
	}
	var b strings.Builder
	for i, part := range parts {
		if part == "" {
			continue
		}
		word := canonicalWord(part)
		if i == 0 {
			b.WriteString(lowerFirst(word))
			continue
		}
		b.WriteString(upperFirst(word))
	}
	return b.String()
}

func canonicalWord(word string) string {
	if alias, ok := canonicalTokenAliases[strings.ToLower(word)]; ok {
		return alias
	}
	return word
}

func lowerFirst(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToLower(s[:1]) + s[1:]
}

func upperFirst(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func sortedCSVValues(values []string) string {
	if len(values) == 0 {
		return ""
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func normalizeFields(fs Fields) Fields {
	if len(fs) == 0 {
		return nil
	}
	out := make(Fields, 0, len(fs))
	seen := map[string]int{}
	for _, f := range fs {
		key := CanonicalFieldKey(f.Key)
		if key == "" {
			continue
		}
		val := CanonicalFieldValue(key, f.Val)
		if val == "" {
			continue
		}
		if idx, ok := seen[key]; ok {
			out[idx].Val = mergeFieldValues(key, out[idx].Val, val)
			continue
		}
		seen[key] = len(out)
		out = append(out, Field{Key: key, Val: val})
	}
	return out
}

func mergeFieldValues(key, oldVal, newVal string) string {
	if oldVal == "" || oldVal == newVal {
		return newVal
	}
	if newVal == "" {
		return oldVal
	}
	if _, ok := csvFieldKeys[CanonicalFieldKey(key)]; ok {
		return sortedCSVValues(append(splitCSV(oldVal), splitCSV(newVal)...))
	}
	return newVal
}

// F builds Fields from alternating key, value arguments. Empty values are
// dropped so optional details don't clutter the output.
func F(kv ...string) Fields {
	var out Fields
	for i := 0; i+1 < len(kv); i += 2 {
		key := CanonicalFieldKey(kv[i])
		if key == "" {
			continue
		}
		val := CanonicalFieldValue(key, kv[i+1])
		if val == "" {
			continue
		}
		out = append(out, Field{key, val})
	}
	return out
}

// MarshalJSON renders Fields as an ordered JSON object.
func (fs Fields) MarshalJSON() ([]byte, error) {
	fs = normalizeFields(fs)
	var b bytes.Buffer
	b.WriteByte('{')
	for i, f := range fs {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(f.Key)
		v, _ := json.Marshal(f.Val)
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// UnmarshalJSON reads a JSON object back into ordered Fields (order preserved
// via the token stream), so NDJSON records round-trip through consumers.
func (fs *Fields) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		*fs = nil
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("fields: expected object, got %v", tok)
	}
	var out Fields
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := keyTok.(string)
		var val string
		if err := dec.Decode(&val); err != nil {
			return err
		}
		out = append(out, Field{Key: CanonicalFieldKey(key), Val: CanonicalFieldValue(key, val)})
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return err
	}
	*fs = out
	return nil
}

// String renders Fields as space-separated key=val pairs for text output. A
// value containing spaces is quoted.
func (fs Fields) String() string {
	fs = normalizeFields(fs)
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		v := f.Val
		if strings.ContainsAny(v, " \t") {
			v = strconv.Quote(v)
		}
		parts = append(parts, f.Key+"="+v)
	}
	return strings.Join(parts, " ")
}

// Finding is one result emitted by a check. Risk is the single signal (there is
// no separate status field): critical/high/medium/low/info for actionable-to-
// informational results, and "none" for a check that ran clean (e.g. a closed
// port), which the interactive view hides. Address/Port/Transport/Protocol pin
// down where the result was observed; all other specifics live in Fields, so the
// text and NDJSON outputs carry identical data.
type Finding struct {
	Check     string   `json:"check"` // short stable id, e.g. "ipmi.v20.rakpHash"
	TS        int64    `json:"timestamp,omitempty"`
	Category  string   `json:"category,omitempty"`
	Risk      string   `json:"risk"` // critical/high/medium/low/info/none
	Address   string   `json:"address,omitempty"`
	Port      int      `json:"port,omitempty"`
	Transport string   `json:"transport,omitempty"` // tcp/udp
	Protocol  string   `json:"protocol,omitempty"`  // ipmi/redfish/vnc/ssh/https/...
	Fields    Fields   `json:"fields,omitempty"`
	CVE       []string `json:"cves,omitempty"`
	Duration  float64  `json:"durationSeconds,omitempty"`
}

// MarshalJSON keeps Finding.CVE as a convenient slice in Go while emitting CVEs
// as a sorted CSV string in JSON.
func (f Finding) MarshalJSON() ([]byte, error) {
	type findingJSON struct {
		Check           string  `json:"check"`
		Timestamp       int64   `json:"timestamp,omitempty"`
		Category        string  `json:"category,omitempty"`
		Risk            string  `json:"risk"`
		Address         string  `json:"address,omitempty"`
		Port            int     `json:"port,omitempty"`
		Transport       string  `json:"transport,omitempty"`
		Protocol        string  `json:"protocol,omitempty"`
		Fields          Fields  `json:"fields,omitempty"`
		CVEs            string  `json:"cves,omitempty"`
		DurationSeconds float64 `json:"durationSeconds,omitempty"`
	}
	return json.Marshal(findingJSON{
		Check:           CanonicalCheckID(f.Check),
		Timestamp:       f.TS,
		Category:        f.Category,
		Risk:            f.Risk,
		Address:         f.Address,
		Port:            f.Port,
		Transport:       f.Transport,
		Protocol:        f.Protocol,
		Fields:          f.Fields,
		CVEs:            SortedCSV(f.CVE),
		DurationSeconds: f.Duration,
	})
}

// UnmarshalJSON accepts both the current CSV cves form and the older array form.
func (f *Finding) UnmarshalJSON(b []byte) error {
	var raw struct {
		Check           string          `json:"check"`
		Timestamp       int64           `json:"timestamp,omitempty"`
		LegacyTS        int64           `json:"ts,omitempty"`
		Category        string          `json:"category,omitempty"`
		Risk            string          `json:"risk"`
		Address         string          `json:"address,omitempty"`
		Port            int             `json:"port,omitempty"`
		Transport       string          `json:"transport,omitempty"`
		Protocol        string          `json:"protocol,omitempty"`
		Fields          Fields          `json:"fields,omitempty"`
		CVEs            json.RawMessage `json:"cves,omitempty"`
		DurationSeconds float64         `json:"durationSeconds,omitempty"`
		LegacyDuration  float64         `json:"duration_seconds,omitempty"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	f.Check = CanonicalCheckID(raw.Check)
	f.TS = raw.Timestamp
	if f.TS == 0 {
		f.TS = raw.LegacyTS
	}
	f.Category = raw.Category
	f.Risk = raw.Risk
	f.Address = raw.Address
	f.Port = raw.Port
	f.Transport = raw.Transport
	f.Protocol = raw.Protocol
	f.Fields = raw.Fields
	f.CVE = cvesFromJSON(raw.CVEs)
	f.Duration = raw.DurationSeconds
	if f.Duration == 0 {
		f.Duration = raw.LegacyDuration
	}
	return nil
}

func cvesFromJSON(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return splitCSV(s)
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return splitCSV(SortedCSV(list))
	}
	return nil
}

// RiskRank orders risk from most to least severe for sorting and thresholds.
func RiskRank(risk string) int {
	switch risk {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default: // "none"/unset
		return 0
	}
}

// Target is one host under scan. The pipeline owns scalar fields, while checks
// may run concurrently and must use the synchronized evidence, finding, and
// open-port methods. Identity is immutable once the check phase begins.
type Target struct {
	Host                     string        `json:"host"`
	Ports                    []Port        `json:"-"` // candidate probe ports (from --ports); not serialized
	WebPort                  int           `json:"-"` // explicit web port hint from a host:port arg (or --web-port); 0 = none
	Open                     OpenPorts     `json:"-"` // discovered open ports -> protocols; serialized by the output layer
	Timeout                  time.Duration `json:"-"` // per-probe I/O timeout
	Cred                     Cred          `json:"-"`
	Creds                    []Cred        `json:"-"`
	Destructive              bool          `json:"-"`
	IPMIFull                 bool          `json:"-"` // run the full IPMI NetFn/IPMB walk
	IPMINullPriv             bool          `json:"-"` // open a session as the advertised null/anonymous IPMI account to measure the privilege it actually holds
	OpenBMCDefaultUserKey    bool          `json:"-"` // run the slow/aggressive OpenBMC default-userKey heap-grooming auth-bypass check
	OpenBMCUserKeyBMCRand    string        `json:"-"` // optional operator-supplied stale bmcRandomNum (hex) to try first in the OpenBMC default-userKey check
	OpenBMCUserKeyHeapStart  string        `json:"-"` // optional hex start of the OpenBMC default-userKey heap-pointer sweep range (empty = default)
	OpenBMCUserKeyHeapEnd    string        `json:"-"` // optional hex end of the OpenBMC default-userKey heap-pointer sweep range (empty = default)
	OpenBMCUserKeyPageOffset string        `json:"-"` // optional in-page offset(s) (hex, comma-separated) to restrict the blind heap sweep to; empty = step all offsets
	OpenBMCUserKeySkipFast   bool          `json:"-"` // skip the constant-string/zero residue rounds; isolates the heap-pointer sweep for validation
	DisableLogins            bool          `json:"-"` // disable active online login attempts (default false)
	SNMPV3LocalizedKey       string        `json:"-"` // operator-supplied raw localized USM key: "user:authHex[:privHex]" (SHA-256/AES assumed)
	Progress                 func(string)  `json:"-"` // live progress sink set by the scan pipeline
	DebugLog                 func(string)  `json:"-"` // debug/progress sink set by the scan pipeline

	Identity *Identity      `json:"identity,omitempty"`
	Evidence map[string]any `json:"-"` // raw probe results keyed by source, reused by checks
	Findings []Finding      `json:"findings,omitempty"`
	Final    *Final         `json:"-"` // post-check aggregate identity (id.final); serialized by the output layer
	Err      string         `json:"error,omitempty"`

	mu sync.Mutex
}

// IPMIPort returns the configured UDP/623 port for this target, defaulting to
// 623 when no UDP port is listed.
func (t *Target) IPMIPort() int {
	for _, p := range t.Ports {
		if p.Proto == ProtoUDP && (p.Num == 623 || p.Num == 664) {
			return p.Num
		}
	}
	for _, p := range t.Ports {
		if p.Proto == ProtoUDP {
			return p.Num
		}
	}
	return 623
}

// MarkOpen records that a port/transport was found open, optionally tagging the
// protocol observed on it. Safe for concurrent use.
func (t *Target) MarkOpen(port int, transport, protocol string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Open == nil {
		t.Open = OpenPorts{}
	}
	key := strconv.Itoa(port) + "/" + transport
	cur := t.Open[key]
	if protocol == "" {
		if _, ok := t.Open[key]; !ok {
			t.Open[key] = ""
		}
		return
	}
	for _, p := range strings.Split(cur, ",") {
		if p == protocol {
			return // already recorded
		}
	}
	if cur == "" {
		t.Open[key] = protocol
	} else {
		t.Open[key] = SortedCSV(append(splitCSV(cur), protocol))
	}
}

// IsOpen reports whether a port/transport was recorded open by an earlier
// probe. Used by identify's honeypot detector to test for a specific
// responding-port signature.
func (t *Target) IsOpen(port int, transport string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Open == nil {
		return false
	}
	_, ok := t.Open[strconv.Itoa(port)+"/"+transport]
	return ok
}

// OpenLen returns the number of discovered open port entries.
func (t *Target) OpenLen() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.Open)
}

// OpenSnapshot returns a shallow copy of the discovered open port map.
// Callers may iterate the returned map without holding t.mu.
func (t *Target) OpenSnapshot() OpenPorts {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.Open) == 0 {
		return nil
	}
	out := make(OpenPorts, len(t.Open))
	for k, v := range t.Open {
		out[k] = v
	}
	return out
}

// SetEvidence stores a raw probe result for later reuse by checks.
func (t *Target) SetEvidence(key string, val any) {
	key = CanonicalEvidenceKey(key)
	if key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Evidence == nil {
		t.Evidence = map[string]any{}
	}
	t.Evidence[key] = val
}

// SetEvidenceIfAbsent stores val under key only when key is not already
// present. It returns true when the value was inserted, false when an existing
// value was kept. This makes cross-check "emit once" guards race-safe when
// checks run concurrently.
func (t *Target) SetEvidenceIfAbsent(key string, val any) bool {
	key = CanonicalEvidenceKey(key)
	if key == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Evidence == nil {
		t.Evidence = map[string]any{}
	}
	if _, ok := t.Evidence[key]; ok {
		return false
	}
	t.Evidence[key] = val
	return true
}

// Evidenced returns a stored probe result.
func (t *Target) Evidenced(key string) (any, bool) {
	key = CanonicalEvidenceKey(key)
	if key == "" {
		return nil, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.Evidence[key]
	return v, ok
}

// AddFindings appends findings from a check, stamping each with the target
// address (where observed) when the check did not set one.
func (t *Target) AddFindings(fs ...Finding) {
	if len(fs) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range fs {
		fs[i].Check = CanonicalCheckID(fs[i].Check)
		if fs[i].Address == "" {
			fs[i].Address = t.Host
		}
		if fs[i].Risk == "" {
			fs[i].Risk = "none"
		}
	}
	t.Findings = append(t.Findings, fs...)
}

// FindingsSnapshot returns a copy safe for concurrent iteration.
func (t *Target) FindingsSnapshot() []Finding {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]Finding(nil), t.Findings...)
}

// ReplaceFindings swaps every finding whose check matches id for the given
// replacements, leaving all other findings (and all evidence) intact. Used by the
// late honeypot reclassification to refresh the `id` finding with the honeypot
// verdict without discarding the rest of the record.
func (t *Target) ReplaceFindings(id string, replacement ...Finding) {
	id = CanonicalCheckID(id)
	t.mu.Lock()
	defer t.mu.Unlock()
	kept := t.Findings[:0]
	for _, f := range t.Findings {
		if f.Check != id {
			kept = append(kept, f)
		}
	}
	for i := range replacement {
		replacement[i].Check = CanonicalCheckID(replacement[i].Check)
		if replacement[i].Address == "" {
			replacement[i].Address = t.Host
		}
		if replacement[i].Risk == "" {
			replacement[i].Risk = "none"
		}
		kept = append(kept, replacement[i])
	}
	t.Findings = kept
}

// Emitter is the sink for scan output. engine calls Start when a target begins
// and Emit once it finishes; the concrete implementations (JSON / lipgloss TTY)
// live in pkg/output. Implementations must be safe for concurrent use.
type Emitter interface {
	Start(host string)          // a target began processing
	Activity(host, what string) // the target's current phase (identify / check name), for the live view
	Checks(host string, done, total int)
	Emit(t *Target) // a target finished; render/serialize its result
	Log(msg string) // diagnostic line (--verbose); never touches stdout NDJSON
	Status(done, total uint64, force bool)
	Close() error // finalize (repaint final bar / flush writer)
}
