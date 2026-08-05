package convert

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

const redactedText = "[redacted]"

type action int

const (
	actScrub action = iota
	actKeep
	actDrop
	actName
	actToken
	actAddr
	actMAC
)

var keyExempt = []string{
	"alg", "version", "cipher", "keybits", "keytype", "keylen",
	"guid.vendor", "guid.format", "guid.meta.format",
	"vendor", "product", "model", "generation", "class",
	"hashalgo", "authalgo", "keyexchange", "oid",
}

type keyRule struct {
	frag string
	act  action
}

var keyRules = []keyRule{

	{"password", actDrop}, {"passwd", actDrop}, {"secret", actDrop},
	{"credential", actDrop}, {"community", actDrop}, {"cracked", actDrop},
	{"privkey", actDrop}, {"privatekey", actDrop}, {"lastuser", actDrop},

	{"banner", actDrop}, {"body", actDrop}, {"response", actDrop},
	{"sysdesc", actDrop}, {"screenshot", actDrop}, {"html", actDrop},
	{"title", actDrop}, {"motd", actDrop}, {"comment", actDrop},
	{"description", actDrop}, {"location", actDrop}, {"contact", actDrop},
	{"proof", actDrop}, {"transcript", actDrop},

	{"mdns", actDrop}, {"dns.replies", actDrop}, {"llmnr", actDrop},
	{"nbns", actDrop}, {"netbios", actDrop}, {"dcerpc", actDrop},
	{"epm", actDrop}, {"ntlmssp", actDrop},
	{"ldap", actDrop}, {"kerberos", actDrop}, {"krb5", actDrop},
	{"tls.ca", actDrop}, {"tls.crl", actDrop}, {"tls.ocsp", actDrop},
	{"tls.issuing", actDrop}, {"image.url", actDrop},

	{"mssql", actDrop}, {"smb", actDrop}, {"rdg", actDrop},
	{"nfs", actDrop}, {"afp", actDrop},

	{"mac", actMAC},
	{"address", actAddr}, {"addr", actAddr}, {"gateway", actAddr},
	{"netmask", actAddr}, {"subnet", actAddr}, {"nameserver", actAddr},
	{"ipv4", actAddr}, {"ipv6", actAddr},

	{"hostname", actName}, {"dnsname", actName}, {"tls.names", actName},
	{"subject", actName}, {"issuer", actName}, {"commonname", actName},
	{"tls.cn", actName}, {"tls.dn", actName}, {"cert.cn", actName},
	{"tls.uri", actName}, {"tls.sans", actName}, {"sans", actName},
	{"vhost", actName}, {"domain", actName}, {"fqdn", actName},
	{"computer", actName}, {"workstation", actName}, {"workgroup", actName},
	{"names", actName}, {"name", actName},

	{"fingerprint", actToken}, {"bkhash", actToken}, {"thumbprint", actToken},
	{"spki", actToken}, {"sha256", actToken}, {"sha1", actToken},
	{"md5", actToken}, {"hash", actToken}, {"salt", actToken}, {"hmac", actToken},
	{"certificate", actToken}, {"pubkey", actToken}, {"publickey", actToken},
	{"serial", actToken}, {"servicetag", actToken}, {"assettag", actToken},
	{"uuid", actToken}, {"guid", actToken}, {"token", actToken},
	{"session", actToken}, {"cookie", actToken}, {"nonce", actToken},
	{"engineid", actToken}, {"asset", actToken},

	{"rdp.fp", actToken}, {"image.key", actToken},
}

func foldKey(k string) string {
	var b strings.Builder
	b.Grow(len(k))
	for i := 0; i < len(k); i++ {
		switch c := k[i]; {
		case c == '.' || c == '_' || c == '-' || c == ' ':
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + ('a' - 'A'))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

var (
	foldedExempt = foldAll(keyExempt)
	foldedRules  = foldRules(keyRules)
)

func foldAll(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = foldKey(v)
	}
	return out
}

func foldRules(in []keyRule) []keyRule {
	out := make([]keyRule, len(in))
	for i, r := range in {
		out[i] = keyRule{foldKey(r.frag), r.act}
	}
	return out
}

func actionFor(key string) action {
	raw := strings.TrimSpace(key)
	if raw == "" {
		return actScrub
	}

	if raw[0] == '_' {
		return actDrop
	}
	k := foldKey(raw)
	for _, ex := range foldedExempt {
		if strings.Contains(k, ex) {
			return actKeep
		}
	}
	for _, r := range foldedRules {
		if strings.Contains(k, r.frag) {
			return r.act
		}
	}
	return actScrub
}

type RedactionStats struct {
	InternalAddrs int
	ExternalAddrs int
	Names         int
	Tokens        int
	MACs          int
	Dropped       int
}

type Redactor struct {
	mu     sync.Mutex
	addrs  map[string]string
	names  map[string]string
	tokens map[string]string

	nextV4Internal uint32
	nextV4External uint32
	nextV6Internal uint64
	nextV6External uint64

	stats RedactionStats
}

func NewRedactor() *Redactor {
	return &Redactor{
		addrs:  map[string]string{},
		names:  map[string]string{},
		tokens: map[string]string{},
	}
}

func (r *Redactor) Stats() *RedactionStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.stats
	return &s
}

func (r *Redactor) Record(rec *scanfile.Record) {
	rec.Host = r.addressList(rec.Host)
	rec.Attributes = r.attrs(rec.Attributes)

	for i := range rec.Services {
		s := &rec.Services[i]
		s.Address = r.addressList(s.Address)
		s.VHost = r.nameList(s.VHost)

		if s.Summary != "" {
			s.Summary = redactedText
			r.drop(1)
		}
		s.Attributes = r.attrs(s.Attributes)
	}

	for i := range rec.Findings {
		f := &rec.Findings[i]
		f.Address = r.addressList(f.Address)
		for j := range f.Fields {
			f.Fields[j].Val = r.value(f.Fields[j].Key, f.Fields[j].Val)
		}
	}

	if rec.Identity != nil {
		rec.Identity.Attributes = r.attrs(rec.Identity.Attributes)

		for i := range rec.Identity.Signals {
			rec.Identity.Signals[i].Detail = r.scrub(rec.Identity.Signals[i].Detail)
		}
	}

	for i := range rec.RAKP {
		k := &rec.RAKP[i]
		k.ClientSID, k.BMCSID = 0, 0
		k.ClientRand, k.BMCRand, k.BMCGUID = "", "", ""
		k.RAKPHash, k.Hashcat = "", ""
		if k.Cracked != "" {
			k.Cracked = "yes"
		}
		if k.Username != "" {
			r.drop(1)
		}
	}

	rec.IPMIPost = r.rawJSON(rec.IPMIPost)
	rec.RFPost = r.rawJSON(rec.RFPost)
	rec.WebLogin = r.rawJSON(rec.WebLogin)
	rec.Error = r.scrub(rec.Error)
}

func (r *Redactor) attrs(in map[string]string) map[string]string {
	if len(in) == 0 {
		return in
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = r.value(k, v)
	}
	return out
}

func (r *Redactor) value(key, val string) string {
	if val == "" {
		return val
	}
	switch actionFor(key) {
	case actKeep:
		return val
	case actDrop:
		r.drop(1)
		return redactedText
	case actName:
		return r.nameList(val)
	case actToken:
		return r.tokenList(val)
	case actAddr:
		return r.addressList(val)
	case actMAC:

		return r.scrub(val)
	default:
		return r.scrub(val)
	}
}

const (
	addrSeps = "\t,; /"
	nameSeps = "\t,; "
)

func mapList(val, seps string, fn func(string) string) string {
	if !strings.ContainsAny(val, seps) {
		return fn(val)
	}
	var b strings.Builder
	b.Grow(len(val))
	start := -1
	for i := 0; i <= len(val); i++ {
		isSep := i == len(val) || strings.IndexByte(seps, val[i]) >= 0
		switch {
		case !isSep && start < 0:
			start = i
		case isSep && start >= 0:
			b.WriteString(fn(val[start:i]))
			start = -1
		}
		if isSep && i < len(val) {
			b.WriteByte(val[i])
		}
	}
	return b.String()
}

func (r *Redactor) addressList(val string) string {
	return mapList(val, addrSeps, r.address)
}

func (r *Redactor) nameList(val string) string {
	return mapList(val, nameSeps, r.name)
}

func (r *Redactor) tokenList(val string) string {
	return mapList(val, nameSeps, r.token)
}

func (r *Redactor) address(val string) string {
	host, suffix := splitAddrSuffix(val)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return r.scrub(val)
	}

	if ip.Is4() && reservedV4(ip) {
		return val
	}
	return r.addressFor(ip) + suffix
}

func (r *Redactor) addressFor(ip netip.Addr) string {
	key := ip.String()
	r.mu.Lock()
	defer r.mu.Unlock()
	if got, ok := r.addrs[key]; ok {
		return got
	}
	internal := isInternal(ip)
	var out string
	switch {
	case ip.Is4() && internal:
		out = v4From(0x0A000000, r.nextV4Internal)
		r.nextV4Internal++
		r.stats.InternalAddrs++
	case ip.Is4():
		out = v4From(0xE0000000, r.nextV4External)
		r.nextV4External++
		r.stats.ExternalAddrs++
	case internal:

		out = v6From([8]byte{0xfd, 0, 0, 0, 0, 0, 0, 0}, r.nextV6Internal)
		r.nextV6Internal++
		r.stats.InternalAddrs++
	default:

		out = v6From([8]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0}, r.nextV6External)
		r.nextV6External++
		r.stats.ExternalAddrs++
	}
	r.addrs[key] = out
	return out
}

func v4From(base, n uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], base+n)
	return netip.AddrFrom4(b).String()
}

func v6From(prefix [8]byte, n uint64) string {
	var b [16]byte
	copy(b[:8], prefix[:])
	binary.BigEndian.PutUint64(b[8:], n)
	return netip.AddrFrom16(b).String()
}

func isInternal(ip netip.Addr) bool {
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}

	if ip.Is4() {
		b := ip.As4()
		return b[0] == 100 && b[1] >= 64 && b[1] <= 127
	}
	return false
}

func splitAddrSuffix(val string) (host, suffix string) {
	host = strings.TrimSpace(val)
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host, suffix = host[:i], host[i:]
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host, suffix = host[:i], host[i:]+suffix
	}
	host = strings.Trim(host, "[]")
	return host, suffix
}

func (r *Redactor) name(val string) string {
	v := strings.TrimSpace(val)
	if v == "" {
		return val
	}

	if ip, err := netip.ParseAddr(strings.Trim(v, "[]")); err == nil {
		if ip.Is4() && reservedV4(ip) {
			return val
		}
		return r.addressFor(ip)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if got, ok := r.names[v]; ok {
		return got
	}
	out := fmt.Sprintf("host-%d.invalid", len(r.names)+1)
	r.names[v] = out
	r.stats.Names++
	return out
}

func (r *Redactor) token(val string) string {
	v := strings.TrimSpace(val)
	if v == "" {
		return val
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if got, ok := r.tokens[v]; ok {
		return got
	}
	out := fmt.Sprintf("redacted-%d", len(r.tokens)+1)
	r.tokens[v] = out
	r.stats.Tokens++
	return out
}

func (r *Redactor) mac(val string) string {
	hw, err := net.ParseMAC(val)
	if err != nil || len(hw) != 6 {
		return val
	}
	sep := "-"
	if strings.Contains(val, ":") {
		sep = ":"
	}
	out := fmt.Sprintf("%02x%s%02x%s%02x%s%02x%s00%s00",
		hw[0], sep, hw[1], sep, hw[2], sep, hw[3], sep, sep)
	if strings.ToUpper(val) == val {
		out = strings.ToUpper(out)
	}
	r.mu.Lock()
	r.stats.MACs++
	r.mu.Unlock()
	return out
}

func (r *Redactor) drop(n int) {
	r.mu.Lock()
	r.stats.Dropped += n
	r.mu.Unlock()
}

var (
	macPattern = regexp.MustCompile(`\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b|\b[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}\b`)
	v4Pattern  = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)

	v6Pattern = regexp.MustCompile(`\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b`)

	fqdnPattern = regexp.MustCompile(`\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})\.)+[A-Za-z]{2,24}\b`)
)

func (r *Redactor) scrub(s string) string {
	if s == "" {
		return s
	}
	s = macPattern.ReplaceAllStringFunc(s, r.mac)
	s = replaceStandalone(s, v6Pattern, v6Boundary, func(m string) (string, bool) {
		ip, err := netip.ParseAddr(m)
		if err != nil || ip.Is4() {
			return "", false
		}
		return r.addressFor(ip), true
	})
	s = replaceStandalone(s, v4Pattern, v4Boundary, func(m string) (string, bool) {
		ip, err := netip.ParseAddr(m)
		if err != nil || !ip.Is4() || reservedV4(ip) {
			return "", false
		}
		return r.addressFor(ip), true
	})
	return fqdnPattern.ReplaceAllStringFunc(s, func(m string) string {
		if !fqdnLike(m) {
			return m
		}
		return r.name(m)
	})
}

func fqdnLike(m string) bool {
	dot := strings.LastIndexByte(m, '.')
	if dot < 0 {
		return false
	}
	tld := strings.ToLower(m[dot+1:])
	if tld == "invalid" || tld == "local" || tld == "arpa" {
		return false
	}
	if strings.Count(m, ".") == 1 && fileExt[tld] {
		return false
	}
	return true
}

var fileExt = map[string]bool{
	"json": true, "xml": true, "html": true, "htm": true, "css": true, "js": true,
	"png": true, "jpg": true, "jpeg": true, "gif": true, "ico": true, "svg": true,
	"txt": true, "csv": true, "pdf": true, "zip": true, "gz": true, "tar": true,
	"cgi": true, "php": true, "asp": true, "jsp": true, "do": true, "action": true,
}

func replaceStandalone(s string, pat *regexp.Regexp, boundary func(s string, start, end int) bool, fn func(string) (string, bool)) string {
	locs := pat.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		if start < last {
			continue
		}
		if !boundary(s, start, end) {
			continue
		}
		repl, ok := fn(s[start:end])
		if !ok {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString(repl)
		last = end
	}
	b.WriteString(s[last:])
	return b.String()
}

func v4Boundary(s string, start, end int) bool {
	if start > 0 {
		if c := s[start-1]; c >= '0' && c <= '9' {
			return false
		}
	}
	if end < len(s) {
		switch c := s[end]; {
		case c >= '0' && c <= '9':
			return false
		case c == '.':

			if end+1 < len(s) && s[end+1] >= '0' && s[end+1] <= '9' {
				return false
			}
		}
	}
	return true
}

func v6Boundary(s string, start, end int) bool {
	return !isHexRunByte(s, start-1) && !isHexRunByte(s, end)
}

func isHexRunByte(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return false
	}
	c := s[i]
	return c == '.' || c == ':' || (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func reservedV4(ip netip.Addr) bool {
	b := ip.As4()
	return b[0] == 0 || b[0] == 255
}

func (r *Redactor) rawJSON(raw json.RawMessage) json.RawMessage {
	if !rawPresent(raw) {
		return raw
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {

		return json.RawMessage(`"` + redactedText + `"`)
	}
	out, err := json.Marshal(r.walk("", v))
	if err != nil {
		return json.RawMessage(`"` + redactedText + `"`)
	}
	return out
}

func (r *Redactor) walk(key string, v any) any {
	switch t := v.(type) {
	case string:
		return r.value(key, t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, sub := range t {
			out[k] = r.walk(k, sub)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, sub := range t {
			out[i] = r.walk(key, sub)
		}
		return out
	default:
		return v
	}
}

func rawPresent(m json.RawMessage) bool {
	s := strings.TrimSpace(string(m))
	return s != "" && s != "null"
}

func (r *Redactor) Mapping() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.addrs))
	for k, v := range r.addrs {
		out = append(out, k+" -> "+v)
	}
	sort.Strings(out)
	return out
}
