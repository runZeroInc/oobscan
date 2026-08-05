package convert

import (
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/guid"
	"github.com/runZeroInc/oobscan/pkg/ilo"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/tlscert"
)

var kvmMediaPorts = map[int]bool{
	623: true, 2068: true, 3900: true,
	5120: true, 5123: true, 5124: true,
	7578: true, 17988: true, 17990: true,
}

var weakTLSVersions = map[string]bool{
	"sslv2": true, "sslv3": true, "tlsv1.0": true, "tlsv1.1": true,
}

func ipmiService(s *rzService) bool {
	if s.Port == 623 && s.Transport == "udp" {
		return true
	}
	if s.hasProto("ipmi") {
		return true
	}
	return s.get("ipmi.channel") != "" || s.get("ipmi.rakp.hashes") != "" || s.get("ipmi.cipherZero") != ""
}

func snmpService(s *rzService) bool {
	if s.Port == 161 {
		return true
	}
	for _, p := range s.Protocols {
		if strings.HasPrefix(p, "snmp") {
			return true
		}
	}
	return s.get("snmp.version") != "" || s.get("snmp.engineID.raw") != ""
}

type findingBuilder struct {
	out []engine.Finding
}

func (b *findingBuilder) add(s *rzService, check, category, risk string, fields ...string) {
	f := engine.Finding{
		Check:     check,
		Category:  category,
		Risk:      risk,
		Address:   s.Address,
		Port:      s.Port,
		Transport: s.Transport,
	}
	if len(s.Protocols) > 0 {
		f.Protocol = s.Protocols[0]
	}
	for i := 0; i+1 < len(fields); i += 2 {
		if strings.TrimSpace(fields[i+1]) == "" {
			continue
		}
		f.Fields = append(f.Fields, engine.Field{Key: fields[i], Val: fields[i+1]})
	}
	f.Fields = append(f.Fields, engine.Field{Key: "source", Val: "runzero"})
	b.out = append(b.out, f)
}

func (b *findingBuilder) addCVE(cves ...string) {
	if n := len(b.out); n > 0 {
		b.out[n-1].CVE = cves
	}
}

func (h *rzHost) findings() []engine.Finding {
	b := &findingBuilder{}
	for i := range h.services {
		s := &h.services[i]
		b.tls(s)
		b.ssh(s)
		b.console(s)
		b.redfish(s)
		if snmpService(s) {
			b.snmp(s)
		}
		if ipmiService(s) {
			b.ipmi(s, h)
		}
	}

	b.iloExposures(h)
	b.openbmcBypass(h)
	b.smcBypass(h)
	b.weakSessionID(h)
	return b.out
}

func (b *findingBuilder) tls(s *rzService) {
	if !s.hasProto("tls") && s.get("tls.versionName") == "" && s.get("tls.version") == "" {
		return
	}
	if bk := s.get("tls.fp.bkhash"); bk != "" {
		if match, ok := tlscert.MatchBadKey(bk); ok && match.Kind == "FW/TLS" {
			b.add(s, "tls.sharedKey", "tls", "high",
				"proof", "tls.fp.bkhash="+bk, "vendor", match.Vendor, "product", match.Product)
		}
	}
	if s.get("tls.expired") == "true" {
		b.add(s, "tls.expired", "tls", "low", "proof", "tls.expired=true", "notAfter", s.get("tls.notAfter"))
	}
	if s.get("tls.selfSigned") == "true" {
		b.add(s, "tls.selfSigned", "tls", "low", "proof", "tls.selfSigned=true", "subject", s.get("tls.subject"))
	}
	for _, key := range []string{"tls.versionName", "tls.supportedVersionNames"} {
		for _, v := range splitAlgs(s.get(key)) {
			if weakTLSVersions[v] {
				b.add(s, "tls.weakCrypto", "tls", "medium", "proof", key+"="+v, "version", v)
				break
			}
		}
	}
	cipher := strings.ToLower(s.get("tls.cipherName"))
	if cipher != "" && containsAny(cipher, "rc4", "3des", "_des_", "des-", "null", "export", "_md5", "_anon", "anon_") {
		b.add(s, "tls.weakCrypto", "tls", "medium", "proof", "tls.cipherName="+cipher, "cipher", cipher)
	}
	sig := strings.ToLower(s.get("tls.signatureAlgorithm"))
	if sig != "" && (strings.Contains(sig, "md5") || strings.Contains(sig, "sha1")) {
		b.add(s, "tls.weakCrypto", "tls", "medium", "proof", "tls.signatureAlgorithm="+sig, "signatureAlgorithm", sig)
	}
}

func (b *findingBuilder) ssh(s *rzService) {
	if !s.hasProto("ssh") && s.get("ssh.kexAlgs") == "" && s.get("ssh.hostKeyAlgs") == "" {
		return
	}
	if bk := s.get("ssh.hostKey.bkhash"); bk != "" {
		if match, ok := tlscert.MatchBadKey(bk); ok && match.Kind == "FW/SSH" {
			b.add(s, "ssh.sharedHostKey", "ssh", "high",
				"proof", "ssh.hostKey.bkhash="+bk, "vendor", match.Vendor, "product", match.Product,
				"fingerprint", s.get("ssh.hostKey.fingerprint"))
		}
	}
	weak := func(key string, bad func(string) bool) bool {
		for _, v := range splitAlgs(s.get(key)) {
			if bad(v) {
				b.add(s, "ssh.weakCrypto", "ssh", "medium", "proof", key+"="+v, "algorithm", v)
				return true
			}
		}
		return false
	}
	for _, key := range []string{"ssh.toServerCiphers", "ssh.toClientCiphers"} {
		if weak(key, func(c string) bool {
			return c == "none" || containsAny(c, "cbc", "3des", "arcfour", "des-", "-des", "rc4", "blowfish", "cast128", "twofish")
		}) {
			break
		}
	}
	weak("ssh.kexAlgs", func(k string) bool { return strings.Contains(k, "sha1") })
	for _, key := range []string{"ssh.toServerMACs", "ssh.toClientMACs"} {
		if weak(key, func(m string) bool { return containsAny(m, "md5", "-96", "umac-64", "ripemd160") }) {
			break
		}
	}
	weak("ssh.hostKeyAlgs", func(hk string) bool { return strings.Contains(hk, "dss") })
}

func (b *findingBuilder) console(s *rzService) {
	vnc := s.hasProto("vnc") || s.get("vnc.version") != "" ||
		(s.Transport == "tcp" && s.Port >= 5900 && s.Port <= 5903)
	if vnc {
		b.add(s, "kvm.vnc", "kvm", "info", "proof", "vnc on "+s.portKey(), "vncVersion", s.get("vnc.version"))
	}

	if s.Transport == "tcp" && kvmMediaPorts[s.Port] {
		b.add(s, "kvm.exposure", "kvm", "info", "proof", "kvm/vmedia port "+s.portKey()+" open (port-only)")
	}
	if s.Transport == "tcp" && s.Port == 9999 {
		b.add(s, "serialconsole.exposure", "serial", "info", "proof", "serial-over-ip port "+s.portKey()+" open (port-only)")
	}
	if s.hasProto("telnet") || (s.Transport == "tcp" && s.Port == 23) {
		b.add(s, "tcp.telnetBanner", "serial", "info",
			"proof", "telnet on "+s.portKey(), "banner", firstLine(s.get("banner.telnet")))
	}
}

var redfishValueFields = []string{
	"ssdp.head.nt", "ssdp.head.usn", "ssdp.head.st", "ssdp.head.al",
	"http.body", "last.http.body", "http.head.location", "upnp.scpdURL",
}

func (b *findingBuilder) redfish(s *rzService) {
	if s.hasProto("redfish") {
		b.add(s, "http.redfish.exposure", "redfish", "info", "proof", "redfish protocol on "+s.portKey())
		return
	}

	if k := firstMatchingKey(s.Data, "redfish"); k != "" {
		b.add(s, "http.redfish.exposure", "redfish", "info", "proof", k+" present")
		return
	}
	for _, f := range redfishValueFields {
		v := strings.ToLower(s.get(f))
		if v == "" {
			continue
		}
		if strings.Contains(v, "/redfish") || strings.Contains(v, "redfish-rest") {
			b.add(s, "http.redfish.exposure", "redfish", "info", "proof", f+" advertises /redfish")
			return
		}
	}
}

func (b *findingBuilder) snmp(s *rzService) {
	if comms := tabValues(s.get("snmp.defaultCommunities")); len(comms) > 0 {
		b.add(s, "snmp.defaultCreds", "snmp", "high",
			"proof", "snmp.defaultCommunities="+strings.Join(comms, ","), "community", comms[0])
	}
	if containsFlag(s.get("snmp.version"), "3") {
		b.add(s, "snmp.v3", "snmp", "info", "proof", "snmp.version="+s.get("snmp.version"))
	}
}

func (b *findingBuilder) ipmi(s *rzService, h *rzHost) {
	conn := s.get("ipmi.connVersions")
	b.add(s, "ipmi.rmcpPing", "ipmi", "info", "proof", "ipmi responded on "+s.portKey())
	if conn != "" {
		b.add(s, "ipmi.versions", "ipmi", "info",
			"proof", "ipmi.connVersions="+conn, "versions", strings.Join(tabValues(conn), ","))
	}
	if suites := cipherSuites(s); len(suites) > 0 {
		b.add(s, "ipmi.ciphers", "ipmi", "info",
			"proof", "ipmi.ciphers="+strings.Join(suites, ","), "suites", strings.Join(suites, ","))
	}
	if s.get("ipmi.cipherZero") == "enabled" {
		b.add(s, "ipmi.v20.cipherZero", "ipmi", "critical", "proof", "ipmi.cipherZero=enabled")
	}
	pa := s.get("ipmi.passAuth")
	if containsFlag(pa, "null-user") {
		b.add(s, "ipmi.authNull", "ipmi", "high", "proof", "ipmi.passAuth="+pa)
	}
	if containsFlag(pa, "anonymous") {
		b.add(s, "ipmi.authAnon", "ipmi", "high", "proof", "ipmi.passAuth="+pa)
	}
	if guid := s.get("ipmi.system.guid"); guid != "" {
		b.add(s, "ipmi.guid", "ipmi", "info", "proof", "ipmi.system.guid="+guid,
			"guid", guid, "vendor", s.get("ipmi.guid.vendor"))
	}

	hashes := parseRAKPHashes(s.get("ipmi.rakp.hashes"))
	for i := range hashes {
		hs := &hashes[i]
		proof := hs.Salt + ":" + hs.MAC
		if hs.Redacted {
			proof = "<redacted by source>"
		}
		b.add(s, "ipmi.v20.rakpHash", "ipmi", "high",
			"proof", proof, "username", displayUser(hs.Username), "hashAlgo", hs.Algo)
	}

	passwords := parseUserMap(s.get("ipmi.rakp.passwords"))
	cracked := parseUserMap(s.get("ipmi.rakp.cracked"))

	users := make([]string, 0, len(cracked))
	for u := range cracked {
		users = append(users, u)
	}
	sort.Strings(users)
	for _, user := range users {
		kind := cracked[user]
		if !strings.EqualFold(kind, "default") {
			continue
		}
		b.add(s, "ipmi.v20.defaultCreds", "ipmi", "critical",
			"proof", "ipmi.rakp.cracked="+user+":"+kind,
			"username", displayUser(user), "password", passwords[user], "passwordType", kind)
	}
}

func (b *findingBuilder) iloExposures(h *rzHost) {
	gen := iloGeneration(h)
	if gen == "" {
		return
	}

	if gen == "iLO2" || gen == "iLO3" || gen == "iLO4" {
		if s := h.firstIPMIService(); s != nil {
			b.add(s, "ipmi.ilo.authBypass", "auth", "high",
				"proof", "generation "+gen+" (affects all iLO2/3/4 firmware; generation-derived, not live-confirmed)",
				"product", gen, "vendor", "hpe",
				"defect", "rmcp-unauthenticated-session", "authBypassed", "generation-derived")
			b.addCVE("CVE-2026-65206")
		}
	}

	if gen == "iLO2" || gen == "iLO3" || gen == "iLO4" || gen == "iLO5" || gen == "iLO6" {
		for i := range h.services {
			s := &h.services[i]
			banner := mpSSHBanner(s)
			if banner == "" {
				continue
			}
			b.add(s, "ssh.hpe.iloSSHOverflow", "exposure", "high",
				"proof", "mpSSH service on "+s.portKey()+" (affects all pre-iLO7 mpSSH firmware; generation "+gen+", generation-derived)",
				"product", gen, "vendor", "hpe",
				"defect", "ssh-preauth-memory-corruption", "banner", firstLine(banner))
			b.addCVE("CVE-2026-65204")
		}
	}

	fw := iloFirmware(h)
	if fw == "" {
		return
	}
	web := h.firstWebService()
	if web == nil {
		return
	}
	for _, c := range ilo.MatchCVEs(gen, fw) {
		f := []string{
			"proof", "generation " + gen + " firmware " + fw + " < fixed-in " + c.FixedIn,
			"generation", gen, "firmware", fw, "fixed_in", c.FixedIn,
			"cve", c.ID, "title", c.Title,
		}
		if c.AuthBypass {
			f = append(f, "auth_bypass", "true")
		}
		b.add(web, "http.ilo.knownCVEs", "vuln", iloCVERisk(c.Severity), f...)
	}
}

// smcBypass projects the Supermicro SMCRAKP fixed-key finding from captured
// RAKP-2 material. A confirmed X14 board is reported as the weaker
// integrity-bypass; an unresolved or pre-X14 generation as the command-capable
// bypass. Generation-derived, not live-confirmed.
func (b *findingBuilder) smcBypass(h *rzHost) {
	x14 := smcIsX14(h)
	for i := range h.services {
		s := &h.services[i]
		for _, e := range parseRAKPHashes(s.get("ipmi.rakp.hashes")) {
			rr := e.result()
			if rr == nil || !rr.UsesSMCRAKPFixedKey() {
				continue
			}
			if x14 {
				b.add(s, "ipmi.smc.integrityBypass", "auth", "high",
					"proof", "fixed-key RAKP-2 captured; generation resolves X14 (generation-derived, not live-confirmed)",
					"username", displayUser(e.Username), "vendor", "supermicro")
				b.addCVE("CVE-2026-65216")
			} else {
				b.add(s, "ipmi.v20.smcrakpBypass", "auth", "critical",
					"proof", "fixed-key RAKP-2 captured; generation resolves pre-X14 (generation-derived, not live-confirmed)",
					"username", displayUser(e.Username), "vendor", "supermicro")
				b.addCVE("CVE-2026-65214")
			}
			return
		}
	}
}

func (b *findingBuilder) openbmcBypass(h *rzHost) {
	if !isOpenBMC(h) {
		return
	}
	s := h.firstIPMIService()
	if s == nil || !ipmi2Service(s) {
		return
	}
	b.add(s, "ipmi.openbmc.rakpAuthBypass", "auth", "high",
		"proof", "fingerprint OpenBMC + IPMI 2.0",
		"authBypassed", "fingerprint-derived")
	b.addCVE("CVE-2026-16141")
}

func isOpenBMC(h *rzHost) bool {
	for _, v := range []string{h.asset.OS, h.asset.OSVendor, h.asset.OSProduct,
		h.asset.HW, h.asset.HWVendor, h.asset.HWProduct} {
		if strings.Contains(strings.ToLower(v), "openbmc") {
			return true
		}
	}
	return false
}

func ipmi2Service(s *rzService) bool {
	if cv := s.get("ipmi.connVersions"); cv != "" {
		return strings.Contains(cv, "2.0")
	}
	return s.get("ipmi.rakp.hashes") != "" || s.get("ipmi.ciphers") != ""
}

var smcX14ModelRe = regexp.MustCompile(`(?i)^\s*X14[A-Z0-9]`)

func smcIsX14(h *rzHost) bool {
	cands := []string{h.asset.HWProduct, h.asset.OSProduct, h.asset.HW, h.asset.OS}
	cands = append(cands, h.asset.Names...)
	for _, c := range cands {
		if smcX14ModelRe.MatchString(strings.TrimSpace(c)) {
			return true
		}
	}
	for i := range h.services {
		if g := h.services[i].get("ipmi.system.guid"); g != "" {
			if r, err := guid.DecodeHex(g); err == nil && r.Family == "smc-board-serial" {
				if guid.SMCGenerationFromModelPrefix(r.Fields["model_prefix"]) == "X14" {
					return true
				}
			}
		}
	}
	randomSIDs := false
	for i := range h.services {
		sids := parseSessionIDs(h.services[i].get("ipmi.rakp.sessionIDs"))
		if len(sids) < 3 {
			continue
		}
		cls, weak := ipmi.ClassifySessionIDs(sids)
		if weak {
			if cls.Pattern == "fixedStep" && cls.Delta == 0x10 {
				return false
			}
			continue
		}
		randomSIDs = true
	}
	return randomSIDs
}

func (b *findingBuilder) weakSessionID(h *rzHost) {
	smc := strings.EqualFold(h.vendor(), "supermicro")
	for i := range h.services {
		s := &h.services[i]
		sids := parseSessionIDs(s.get("ipmi.rakp.sessionIDs"))
		cls, weak := ipmi.ClassifySessionIDs(sids)
		if !weak {
			continue
		}
		risk := "high"
		if smc {
			risk = "critical"
		}
		b.add(s, cls.CheckID(), "sid", risk,
			"proof", cls.Detail+" (derived from captured session IDs)",
			"pattern", cls.Pattern, "samples", strconv.Itoa(len(sids)))
	}
}

func parseSessionIDs(v string) []uint32 {
	var out []uint32
	for tok := range strings.FieldsSeq(v) {
		if len(tok) != 8 {
			continue
		}
		raw, err := hex.DecodeString(tok)
		if err != nil || len(raw) != 4 {
			continue
		}
		out = append(out, uint32(raw[0])|uint32(raw[1])<<8|uint32(raw[2])<<16|uint32(raw[3])<<24)
	}
	return out
}

var iloGenFields = []string{
	"ilo.mp.pn", "ilo.session.moniker.prodnam", "ilo.session.moniker.prodtag",
	"ilo.session.moniker.prodgen",
}

func iloGeneration(h *rzHost) string {
	var cands []string
	for i := range h.services {
		s := &h.services[i]
		for _, k := range iloGenFields {
			cands = append(cands, s.get(k))
		}
	}
	cands = append(cands, h.asset.OS, h.asset.OSProduct, h.asset.HWProduct, h.asset.HW)
	cands = append(cands, h.asset.Names...)
	for i := range h.services {
		cands = append(cands, h.services[i].get("http.head.server"))
	}
	for _, c := range cands {
		if g := ilo.GenerationFromString(c); g != "" {
			return g
		}
	}
	return ""
}

func iloFirmware(h *rzHost) string {
	for i := range h.services {
		s := &h.services[i]
		for _, k := range []string{"ilo.mp.fwri", "ilo.session.version"} {
			if v := s.get(k); looksLikeVersion(v) {
				return v
			}
		}
	}
	for i := range h.services {
		if fw := iloFWFromServer(h.services[i].get("http.head.server")); fw != "" {
			return fw
		}
	}
	if v := h.version(); looksLikeVersion(v) {
		return v
	}
	return ""
}

func iloFWFromServer(server string) string {
	i := strings.Index(strings.ToLower(server), "ilo")
	if i < 0 {
		return ""
	}
	slash := strings.IndexByte(server[i:], '/')
	if slash < 0 {
		return ""
	}
	rest := server[i+slash+1:]
	if j := strings.IndexAny(rest, " \t;,"); j >= 0 {
		rest = rest[:j]
	}
	rest = strings.TrimSpace(rest)
	if !looksLikeVersion(rest) {
		return ""
	}
	return rest
}

func looksLikeVersion(s string) bool {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, ".") {
		return false
	}
	hasDigit := false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '.':
		default:
			return false
		}
	}
	return hasDigit
}

func mpSSHBanner(s *rzService) string {
	isSSH := s.hasProto("ssh") || (s.Transport == "tcp" && s.Port == 22) ||
		s.get("ssh.hostKeyAlgs") != "" || s.get("ssh.kexAlgs") != ""
	if !isSSH {
		return ""
	}
	for _, k := range []string{"banner.ssh", "ssh.banner", "ssh.software", "banner"} {
		if v := s.get(k); strings.Contains(strings.ToLower(v), "mpssh") {
			return v
		}
	}
	if strings.Contains(strings.ToLower(s.Summary), "mpssh") {
		return s.Summary
	}
	return ""
}

func iloCVERisk(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

func (h *rzHost) firstIPMIService() *rzService {
	for i := range h.services {
		if ipmiService(&h.services[i]) {
			return &h.services[i]
		}
	}
	return nil
}

func (h *rzHost) firstWebService() *rzService {
	for i := range h.services {
		s := &h.services[i]
		if s.hasProto("http") || s.hasProto("https") || s.hasProto("tls") ||
			s.hasProto("redfish") || s.get("http.head.server") != "" {
			return s
		}
	}
	return nil
}

func cipherSuites(s *rzService) []string {
	v := firstNonEmpty(s.get("ipmi.cipherSuites"), s.get("ipmi.ciphers"))
	if v == "" {
		return nil
	}
	fields := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\t' || r == ' ' })
	out := fields[:0]
	for _, id := range fields {
		if id = strings.TrimSpace(id); id != "" {
			if _, err := strconv.Atoi(id); err == nil {
				out = append(out, id)
			}
		}
	}
	return out
}

func splitAlgs(v string) []string {
	if v == "" {
		return nil
	}
	fields := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\t' || r == ' ' })
	out := fields[:0]
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, strings.ToLower(f))
		}
	}
	return out
}

func containsAny(hay string, subs ...string) bool {
	for _, s := range subs {
		if strings.Contains(hay, s) {
			return true
		}
	}
	return false
}

func firstLine(v string) string {
	if i := strings.IndexAny(v, "\r\n"); i >= 0 {
		return strings.TrimSpace(v[:i])
	}
	return strings.TrimSpace(v)
}

func firstMatchingKey(m map[string]string, sub string) string {
	best := ""
	for k := range m {
		if strings.Contains(strings.ToLower(k), sub) && (best == "" || k < best) {
			best = k
		}
	}
	return best
}
