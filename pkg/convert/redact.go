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

// Redaction produces a shareable corpus that does not disclose which assets it
// describes. The governing rule is to preserve equality, not content: every
// rewrite is a stable one-to-one mapping held for the life of the conversion, so
// values that were equal before redaction stay equal after it and cross-host
// clustering survives. The same policy is applied inside opaque post-auth captures
// by walking their JSON generically, so nothing hides behind a blob boundary.

// redactedText is the stand-in for a dropped free-text or credential value.
const redactedText = "[redacted]"

// action is what redaction does to one value.
type action int

const (
	actScrub action = iota // keep, but rewrite embedded addresses/MACs
	actKeep                // keep verbatim, rewriting nothing
	actDrop                // replace with redactedText
	actName                // replace with a stable host-N.invalid pseudonym
	actToken               // replace with a stable redacted-N pseudonym
	actAddr                // renumber as an address (or list of addresses)
	actMAC                 // zero the low two octets of each MAC
)

// keyExempt lists key fragments that look identifying under the rules below but
// describe a device class rather than a device: algorithm and version names,
// key sizes and types, vendor attributions, and the numeric OID space. Checked
// before every other rule, and kept verbatim rather than merely scrubbed --
// several of these hold dotted decimal strings (a firmware version "0.1.0.0",
// an SNMP OID "1.3.6.1.4.1.674") that the free-text address rewriter would
// otherwise mistake for addresses and renumber.
var keyExempt = []string{
	"alg", "version", "cipher", "keybits", "keytype", "keylen",
	"guid.vendor", "guid.format", "guid.meta.format",
	"vendor", "product", "model", "generation", "class",
	"hashalgo", "authalgo", "keyexchange", "oid",
}

// keyRule maps a key fragment to an action. The list is ordered: the first
// fragment contained in the (lowercased) key wins, so the more specific
// fragments come first. Matching on fragments rather than exact keys is
// deliberate -- runZero's service_data vocabulary is fingerprint-driven and
// open-ended, and an exact-match allowlist would silently pass through every
// key we had not seen yet.
type keyRule struct {
	frag string
	act  action
}

var keyRules = []keyRule{
	// Credential material and PII: blanked, never pseudonymized. "lastuser"
	// covers crowdstrike.lastUser and any *.lastUser -- a person's account name.
	{"password", actDrop}, {"passwd", actDrop}, {"secret", actDrop},
	{"credential", actDrop}, {"community", actDrop}, {"cracked", actDrop},
	{"privkey", actDrop}, {"privatekey", actDrop}, {"lastuser", actDrop},

	// Free text that cannot be filtered safely. "sysdesc" (not "sysdescr")
	// matches both snmp.sysDesc and *.sysDescr; the SNMP sysDescr embeds the
	// device's own hostname ("Linux bldsrv161.corp.example.com 5.14 ...").
	{"banner", actDrop}, {"body", actDrop}, {"response", actDrop},
	{"sysdesc", actDrop}, {"screenshot", actDrop}, {"html", actDrop},
	{"title", actDrop}, {"motd", actDrop}, {"comment", actDrop},
	{"description", actDrop}, {"location", actDrop}, {"contact", actDrop},
	{"proof", actDrop}, {"transcript", actDrop},

	// Name-dense protocol namespaces. These carry hostnames, NetBIOS names,
	// directory paths and AD domains inside composed values -- "issuer=CN=..."
	// in tls.caUnknown, "host._raop._tcp.local.=TXT,..." in mdns.replies -- so
	// there is no single name to substitute and the value goes as a whole.
	{"mdns", actDrop}, {"dns.replies", actDrop}, {"llmnr", actDrop},
	{"nbns", actDrop}, {"netbios", actDrop}, {"dcerpc", actDrop},
	{"epm", actDrop}, {"ntlmssp", actDrop},
	{"ldap", actDrop}, {"kerberos", actDrop}, {"krb5", actDrop},
	{"tls.ca", actDrop}, {"tls.crl", actDrop}, {"tls.ocsp", actDrop},
	{"tls.issuing", actDrop}, {"image.url", actDrop},
	// Windows enterprise-service namespaces. Not out-of-band device signal, and
	// dense with computer names, domains and share paths (mssql.nps carries a
	// "\\HOST\pipe\..." named-pipe path, smb its computer/domain names).
	{"mssql", actDrop}, {"smb", actDrop}, {"rdg", actDrop},
	{"nfs", actDrop}, {"afp", actDrop},

	// Addresses and MACs.
	{"mac", actMAC},
	{"address", actAddr}, {"addr", actAddr}, {"gateway", actAddr},
	{"netmask", actAddr}, {"subnet", actAddr}, {"nameserver", actAddr},
	{"ipv4", actAddr}, {"ipv6", actAddr},

	// Names. tls.cn / tls.dn are runZero's spelling of the certificate subject;
	// tls.uri is the cert's SAN URI list (a tab-joined mix of https:// URLs that
	// carry a hostname and urn:uuid: URNs that carry a UUID), so each element is
	// pseudonymized rather than kept.
	{"hostname", actName}, {"dnsname", actName}, {"tls.names", actName},
	{"subject", actName}, {"issuer", actName}, {"commonname", actName},
	{"tls.cn", actName}, {"tls.dn", actName}, {"cert.cn", actName},
	{"tls.uri", actName}, {"tls.sans", actName}, {"sans", actName},
	{"vhost", actName}, {"domain", actName}, {"fqdn", actName},
	{"computer", actName}, {"workstation", actName}, {"workgroup", actName},
	{"names", actName}, {"name", actName},

	// Unique identifiers.
	{"fingerprint", actToken}, {"bkhash", actToken}, {"thumbprint", actToken},
	{"spki", actToken}, {"sha256", actToken}, {"sha1", actToken},
	{"md5", actToken}, {"hash", actToken}, {"salt", actToken}, {"hmac", actToken},
	{"certificate", actToken}, {"pubkey", actToken}, {"publickey", actToken},
	{"serial", actToken}, {"servicetag", actToken}, {"assettag", actToken},
	{"uuid", actToken}, {"guid", actToken}, {"token", actToken},
	{"session", actToken}, {"cookie", actToken}, {"nonce", actToken},
	{"engineid", actToken}, {"asset", actToken},
	// Composite fingerprints that embed the host name they identify.
	{"rdp.fp", actToken}, {"image.key", actToken},
}

// foldKey normalizes a key for rule matching by lowercasing it and dropping the
// separators. The same concept is spelled several ways across the vocabularies
// this package handles -- runZero writes "tls.cn" and "mac_vendors", oobscan
// canonicalizes finding fields to "tlsCn" and "macVendors" -- and folding both
// sides means one rule covers every spelling.
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

// actionFor resolves the action for an attribute or field key.
func actionFor(key string) action {
	raw := strings.TrimSpace(key)
	if raw == "" {
		return actScrub
	}
	// runZero prefixes its internal bookkeeping keys with an underscore
	// (_asset.match, _macs.ipmap, _icons, _sources). They are scan metadata
	// rather than device observations, and they are dense with addresses,
	// MACs, tenant UUIDs and match strings, so a shareable corpus does without
	// them entirely.
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

// RedactionStats counts what a redaction pass rewrote. The address, name and
// identifier counts are distinct source values (one per mapping allocated);
// MACs and dropped values are occurrences, since neither is mapped.
type RedactionStats struct {
	InternalAddrs int
	ExternalAddrs int
	Names         int
	Tokens        int
	MACs          int
	Dropped       int
}

// Redactor holds the mappings for one conversion. It is safe for concurrent use:
// the pipeline redacts records on several worker goroutines, so the mapping
// tables, counters and stats are guarded by mu. Only the map lookup/allocate is
// inside the lock; regex scanning and JSON walking stay outside it.
//
// Pseudonym numbers are therefore assigned in processing order, not input order:
// two runs can number the same host differently. Equal values still map to one
// stand-in within a run and the emitted mapping still reverses it, so only the
// numbering is non-deterministic.
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

// NewRedactor returns a Redactor with empty mappings.
func NewRedactor() *Redactor {
	return &Redactor{
		addrs:  map[string]string{},
		names:  map[string]string{},
		tokens: map[string]string{},
	}
}

// Stats returns the counts accumulated so far. Call it after all redaction is
// finished; it locks so a mid-run call is at least race-free.
func (r *Redactor) Stats() *RedactionStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.stats
	return &s
}

// Record redacts one record in place.
func (r *Redactor) Record(rec *scanfile.Record) {
	rec.Host = r.addressList(rec.Host)
	rec.Attributes = r.attrs(rec.Attributes)

	for i := range rec.Services {
		s := &rec.Services[i]
		s.Address = r.addressList(s.Address)
		s.VHost = r.nameList(s.VHost)
		// The summary is usually a short label ("HTTPS"), but runZero also puts
		// a whole HTTP response in it -- headers, cookies, redirect targets and
		// all. It is free text, so it gets the free-text treatment.
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
		// Signal details are model/fingerprint strings (product names, firmware
		// build ids) that are shared across a fleet, not host-unique, so they are
		// kept -- but they are banner-derived free text, so an address or MAC
		// could ride along in one; scrub rewrites those in place.
		for i := range rec.Identity.Signals {
			rec.Identity.Signals[i].Detail = r.scrub(rec.Identity.Signals[i].Detail)
		}
	}

	// RAKP rows keep the account and the fact that a hash leaked; the crackable
	// bytes (and any recovered password) are dropped outright.
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

// attrs redacts an attribute bag, returning a new map.
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

// value applies the policy for key to one value.
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
		// Scrub as well: runZero's MAC-keyed attributes are mappings, not bare
		// MACs -- _macs.ipmap is "aa:bb:cc:dd:ee:ff=192.168.30.56" pairs, so the
		// address half needs renumbering too.
		return r.scrub(val)
	default:
		return r.scrub(val)
	}
}

// Separators for multi-value attributes, so a list is mapped element by element
// rather than pseudonymized as one opaque blob. Addresses also split on '/' for
// slash-joined traceroute hop lists (this handles CIDR too, since a prefix length
// is not an address and falls through). Names must not split on '/', and
// identifiers are not split at all: a base64 hash uses '/' and '+' as payload.
const (
	addrSeps = "\t,; /"
	nameSeps = "\t,; "
)

// mapList applies fn to each element of a separated list, preserving the
// original separators.
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

// address renumbers one address. A value that is not an address is scrubbed as
// free text instead, since address-shaped keys also carry things like
// "dhcp"/"static" and CIDR-suffixed forms.
func (r *Redactor) address(val string) string {
	host, suffix := splitAddrSuffix(val)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return r.scrub(val)
	}
	// A netmask or an all-zero placeholder is not a host: renumbering it would
	// destroy the topology it describes and hide nothing.
	if ip.Is4() && reservedV4(ip) {
		return val
	}
	return r.addressFor(ip) + suffix
}

// addressFor returns the stable replacement for a parsed address. It self-locks
// and calls no other locking method, so it is the leaf of the lock order.
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
		out = v4From(0x0A000000, r.nextV4Internal) // 10.0.0.0
		r.nextV4Internal++
		r.stats.InternalAddrs++
	case ip.Is4():
		out = v4From(0xE0000000, r.nextV4External) // 224.0.0.0
		r.nextV4External++
		r.stats.ExternalAddrs++
	case internal:
		// fd00::/8, the unique-local range: the IPv6 analogue of 10/8.
		out = v6From([8]byte{0xfd, 0, 0, 0, 0, 0, 0, 0}, r.nextV6Internal)
		r.nextV6Internal++
		r.stats.InternalAddrs++
	default:
		// 2001:db8::/32, reserved for documentation by RFC 3849.
		out = v6From([8]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0}, r.nextV6External)
		r.nextV6External++
		r.stats.ExternalAddrs++
	}
	r.addrs[key] = out
	return out
}

// v4From renders base+n as a dotted-quad.
func v4From(base, n uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], base+n)
	return netip.AddrFrom4(b).String()
}

// v6From renders an address with the given 8-byte prefix and n in the low 64
// bits.
func v6From(prefix [8]byte, n uint64) string {
	var b [16]byte
	copy(b[:8], prefix[:])
	binary.BigEndian.PutUint64(b[8:], n)
	return netip.AddrFrom16(b).String()
}

// isInternal reports whether an address is one that never routes on the public
// internet, which is the split the renumbering preserves.
func isInternal(ip netip.Addr) bool {
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// 100.64.0.0/10, carrier-grade NAT: not IsPrivate, but not public either.
	if ip.Is4() {
		b := ip.As4()
		return b[0] == 100 && b[1] >= 64 && b[1] <= 127
	}
	return false
}

// splitAddrSuffix peels a /prefix or %zone off an address, and unwraps the
// bracketed form, so the address itself can be parsed.
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

// name returns the stable pseudonym for a hostname-like value.
func (r *Redactor) name(val string) string {
	v := strings.TrimSpace(val)
	if v == "" {
		return val
	}
	// An address that landed in a name field (a certificate IP SAN, a vhost that
	// is really an address) is renumbered, not pseudonymized, so it stays
	// consistent with the same address seen elsewhere.
	if ip, err := netip.ParseAddr(strings.Trim(v, "[]")); err == nil {
		if ip.Is4() && reservedV4(ip) {
			return val
		}
		return r.addressFor(ip) // locks internally; not held here
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

// token returns the stable pseudonym for a unique identifier.
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

// mac keeps the OUI plus the fourth octet and zeroes the last two, which is
// where the per-unit identity lives.
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

// drop records n dropped values under the lock.
func (r *Redactor) drop(n int) {
	r.mu.Lock()
	r.stats.Dropped += n
	r.mu.Unlock()
}

var (
	macPattern = regexp.MustCompile(`\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b|\b[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}\b`)
	v4Pattern  = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	// Deliberately loose: every candidate is validated with netip.ParseAddr
	// before it is rewritten, so over-matching costs nothing.
	v6Pattern = regexp.MustCompile(`\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b`)
	// A hostname embedded in otherwise-kept free text: two or more dot-separated
	// labels ending in an all-letters TLD. The letters-only TLD plus the trailing \b
	// are what exclude a dotted IP and a version string. Every match is validated in
	// fqdnLike before rewriting, so an over-match costs at most a needless pseudonym.
	fqdnPattern = regexp.MustCompile(`\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})\.)+[A-Za-z]{2,24}\b`)
)

// scrub rewrites the addresses, MACs and hostnames embedded in an otherwise-kept
// string. Pass order matters: MACs first, because a MAC and a compact IPv6 address
// are both colon-separated hex and an IPv6-first pass would mangle MACs; the
// hostname pass last, on the address-rewritten string, so a renumbered IP is never
// re-read as a hostname. The hostname pass is what covers the long tail of fields
// that embed an FQDN in free text without a per-key rule for each.
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
		return r.name(m) // stable host-N.invalid; equality-preserving
	})
}

// fqdnLike gates the hostname pass: it rejects a match whose TLD is one of the
// pseudo-suffixes redaction itself mints (so a re-scrubbed value is stable) and
// a bare two-label token whose TLD is a common file/format extension, which in
// scan data is far more often "app.json" or "favicon.ico" than a hostname.
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

// fileExt are dotted suffixes that, on a two-label token, are almost always a
// filename or a MIME/format tag rather than a hostname.
var fileExt = map[string]bool{
	"json": true, "xml": true, "html": true, "htm": true, "css": true, "js": true,
	"png": true, "jpg": true, "jpeg": true, "gif": true, "ico": true, "svg": true,
	"txt": true, "csv": true, "pdf": true, "zip": true, "gz": true, "tar": true,
	"cgi": true, "php": true, "asp": true, "jsp": true, "do": true, "action": true,
}

// replaceStandalone rewrites every match of pat whose neighbouring bytes pass
// boundary, using fn (which may still decline a match).
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
		if start < last { // overlapping match already consumed
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

// v4Boundary accepts a dotted quad that is not a fragment of something longer. A
// match followed by '.' or a digit is rejected, since that is what a bare
// dotted-quad regex hits inside an SNMP OID or a long version string, where
// rewriting corrupts the record and protects nothing. A leading '.' and a trailing
// ':' are deliberately allowed: the first is how an address appears inside a
// composed attribute key, the second is the URL port separator, where most
// embedded addresses live.
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
			// Only a dot that starts another numeric arc means the match was a
			// fragment. A dot followed by anything else is ordinary punctuation
			// or a label separator, as in the mDNS reply "host.192.0.2.5._http".
			if end+1 < len(s) && s[end+1] >= '0' && s[end+1] <= '9' {
				return false
			}
		}
	}
	return true
}

// v6Boundary accepts a colon-hex run that is not a fragment of a longer one.
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

// reservedV4 reports whether a dotted quad is in 0/8 or 255/8. Neither can be a
// real host address, so a match there is far likelier to be a version string
// ("0.1.0.0"), a netmask ("255.255.255.0") or a broadcast placeholder than an
// address worth renumbering.
func reservedV4(ip netip.Addr) bool {
	b := ip.As4()
	return b[0] == 0 || b[0] == 255
}

// rawJSON redacts an opaque post-auth capture by walking its JSON generically:
// object keys drive the same policy the typed fields use, and every string
// value is at minimum scrubbed. Walking rather than passing through matters --
// an IPMI LAN config block is full of addresses, MACs and community strings.
func (r *Redactor) rawJSON(raw json.RawMessage) json.RawMessage {
	if !rawPresent(raw) {
		return raw
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		// Undecodable: drop it rather than ship an unexamined blob.
		return json.RawMessage(`"` + redactedText + `"`)
	}
	out, err := json.Marshal(r.walk("", v))
	if err != nil {
		return json.RawMessage(`"` + redactedText + `"`)
	}
	return out
}

// walk redacts a decoded JSON value. key is the object key the value was found
// under (empty at the root and inside arrays, where the parent key still
// applies).
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

// rawPresent reports whether a raw JSON field holds an actual value.
func rawPresent(m json.RawMessage) bool {
	s := strings.TrimSpace(string(m))
	return s != "" && s != "null"
}

// Mapping returns the address mapping as sorted "original -> replacement"
// lines. It is the only way to reverse a redaction, so it is returned to the
// caller rather than written anywhere by default.
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
