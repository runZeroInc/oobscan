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

type Proto string

const (
	ProtoTCP Proto = "tcp"
	ProtoUDP Proto = "udp"
)

type Port struct {
	Num   int   `json:"num"`
	Proto Proto `json:"proto"`
}

type OpenPorts map[string]string

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

type Cred struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type DeviceClass string

const (
	ClassUnknown       DeviceClass = "unknown"
	ClassBMC           DeviceClass = "bmc"
	ClassKVM           DeviceClass = "kvm"
	ClassSerialConsole DeviceClass = "serial"
	ClassPDU           DeviceClass = "pdu"
	ClassAMT           DeviceClass = "amt"
	ClassFirmware      DeviceClass = "firmware"
	ClassHoneypot      DeviceClass = "honeypot"
)

type Confidence string

const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

type Signal struct {
	Source string `json:"source"`
	Vendor string `json:"vendor,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type Identity struct {
	Class      DeviceClass       `json:"class"`
	Vendor     string            `json:"vendor,omitempty"`
	Product    string            `json:"product,omitempty"`
	Generation string            `json:"generation,omitempty"`
	Confidence Confidence        `json:"confidence"`
	Signals    []Signal          `json:"signals,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

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

type Field struct {
	Key string
	Val string
}

type Fields []Field

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

var canonicalCheckIDAliases = map[string]string{
	"ssh.hpe.iloRdpktOverflow": "ssh.hpe.iloSSHOverflow",
}

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

func CanonicalFieldValue(key, val string) string {
	val = string(sanitize.Bytes([]byte(val)))
	key = CanonicalFieldKey(key)
	if _, ok := csvFieldKeys[key]; ok {
		return SortedCSVString(val)
	}
	return val
}

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

func SortedCSV(values []string) string {
	return sortedCSVValues(values)
}

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
	if _, err := dec.Token(); err != nil {
		return err
	}
	*fs = out
	return nil
}

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

type Finding struct {
	Check     string   `json:"check"`
	TS        int64    `json:"timestamp,omitempty"`
	Category  string   `json:"category,omitempty"`
	Risk      string   `json:"risk"`
	Address   string   `json:"address,omitempty"`
	Port      int      `json:"port,omitempty"`
	Transport string   `json:"transport,omitempty"`
	Protocol  string   `json:"protocol,omitempty"`
	Fields    Fields   `json:"fields,omitempty"`
	CVE       []string `json:"cves,omitempty"`
	Duration  float64  `json:"durationSeconds,omitempty"`
}

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
	default:
		return 0
	}
}

type Target struct {
	Host               string        `json:"host"`
	Ports              []Port        `json:"-"`
	WebPort            int           `json:"-"`
	Open               OpenPorts     `json:"-"`
	Timeout            time.Duration `json:"-"`
	Cred               Cred          `json:"-"`
	Creds              []Cred        `json:"-"`
	Destructive        bool          `json:"-"`
	IPMIFull           bool          `json:"-"`
	IPMINullPriv       bool          `json:"-"`
	DisableLogins      bool          `json:"-"`
	SNMPV3LocalizedKey string        `json:"-"`
	Progress           func(string)  `json:"-"`
	DebugLog           func(string)  `json:"-"`

	Identity *Identity      `json:"identity,omitempty"`
	Evidence map[string]any `json:"-"`
	Findings []Finding      `json:"findings,omitempty"`
	Final    *Final         `json:"-"`
	Err      string         `json:"error,omitempty"`

	mu sync.Mutex
}

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
			return
		}
	}
	if cur == "" {
		t.Open[key] = protocol
	} else {
		t.Open[key] = SortedCSV(append(splitCSV(cur), protocol))
	}
}

func (t *Target) IsOpen(port int, transport string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Open == nil {
		return false
	}
	_, ok := t.Open[strconv.Itoa(port)+"/"+transport]
	return ok
}

func (t *Target) OpenLen() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.Open)
}

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

func (t *Target) FindingsSnapshot() []Finding {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]Finding(nil), t.Findings...)
}

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

type Emitter interface {
	Start(host string)
	Activity(host, what string)
	Checks(host string, done, total int)
	Emit(t *Target)
	Log(msg string)
	Status(done, total uint64, force bool)
	Close() error
}
