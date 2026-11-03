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

// This file re-derives findings from a runZero export's raw service_data, since
// runZero records what it observed without scoring it the way a scan would.
//
// Two rules keep the reconstruction honest: every finding uses a check id the scan
// battery itself emits, so converted and scanned corpora stay countable side by
// side; and every finding carries the source attribute it was derived from as its
// proof, so the derivation asserts nothing the export did not already say.

// kvmMediaPorts are TCP ports associated with BMC out-of-band KVM / virtual
// media consoles: 623 (RMCP/DCMI), 2068 (HPE iLO Integrated Remote Console),
// 3900 (ATEN / Raritan / Supermicro KVM), 5120/5123/5124 (virtual CD / floppy /
// media), 7578 (AMI MegaRAC KVM), 17988/17990 (HPE iLO virtual media).
var kvmMediaPorts = map[int]bool{
	623: true, 2068: true, 3900: true,
	5120: true, 5123: true, 5124: true,
	7578: true, 17988: true, 17990: true,
}

// weakTLSVersions are the SSL/TLS protocol versions considered weak.
var weakTLSVersions = map[string]bool{
	"sslv2": true, "sslv3": true, "tlsv1.0": true, "tlsv1.1": true,
}

// ipmiService reports whether a service carries IPMI data.
func ipmiService(s *rzService) bool {
	if s.Port == 623 && s.Transport == "udp" {
		return true
	}
	if s.hasProto("ipmi") {
		return true
	}
	return s.get("ipmi.channel") != "" || s.get("ipmi.rakp.hashes") != "" || s.get("ipmi.cipherZero") != ""
}

// snmpService reports whether a service carries SNMP data.
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

// findingBuilder accumulates findings for one host, pinning each to the service
// it was observed on.
type findingBuilder struct {
	out []engine.Finding
}

// add appends one finding for service s. proofKey/proofVal name the source
// attribute the derivation read; extra fields follow it.
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

// addCVE tags the most recently added finding with its allocated CVE id(s), so
// a generation/fingerprint-derived projection carries the same disclosure
// mapping (disclosure/CVE-mapping.md) the live check reports for the identical
// check id.
func (b *findingBuilder) addCVE(cves ...string) {
	if n := len(b.out); n > 0 {
		b.out[n-1].CVE = cves
	}
}

// findings re-derives the host's findings from its services.
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
	// Host-level detections that need to correlate identity across services
	// (an iLO generation observed on the web port, a defect on the IPMI/SSH port).
	b.iloExposures(h)
	b.openbmcBypass(h)
	b.weakSessionID(h)
	return b.out
}

// tls scores the served TLS posture: a shared/default firmware key (matched by
// badkeys bkhash), an expired or self-signed leaf, a deprecated protocol
// version, a weak cipher, or an MD5/SHA-1 certificate signature.
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

// ssh scores the SSH posture: a shared/default firmware host key, a CBC /
// arcfour / DES cipher, a SHA-1 key exchange, an MD5 / truncated / RIPEMD MAC,
// or a DSA host key.
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

// console scores the remote-console surface: VNC/RFB, a KVM or virtual-media
// port, a serial-over-IP port, and a telnet banner.
func (b *findingBuilder) console(s *rzService) {
	vnc := s.hasProto("vnc") || s.get("vnc.version") != "" ||
		(s.Transport == "tcp" && s.Port >= 5900 && s.Port <= 5903)
	if vnc {
		b.add(s, "kvm.vnc", "kvm", "info", "proof", "vnc on "+s.portKey(), "vncVersion", s.get("vnc.version"))
	}
	// Port-only observations. The proof says so explicitly: nothing here spoke
	// to the service, so a host exposing a sequential port range can land on one
	// of these numbers by accident.
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

// redfishValueFields are service_data fields whose value can reveal a Redfish
// service (SSDP notification types, HTTP bodies / redirects, UPnP descriptors).
var redfishValueFields = []string{
	"ssdp.head.nt", "ssdp.head.usn", "ssdp.head.st", "ssdp.head.al",
	"http.body", "last.http.body", "http.head.location", "upnp.scpdURL",
}

// redfish flags a service advertising the DMTF Redfish REST API.
func (b *findingBuilder) redfish(s *rzService) {
	if s.hasProto("redfish") {
		b.add(s, "http.redfish.exposure", "redfish", "info", "proof", "redfish protocol on "+s.portKey())
		return
	}
	// Sorted so the chosen key (and thus the proof) is deterministic: map
	// iteration order is random, and the finding would otherwise vary run to run.
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

// snmp scores the SNMP surface: default/guessable communities and v3 support.
func (b *findingBuilder) snmp(s *rzService) {
	if comms := tabValues(s.get("snmp.defaultCommunities")); len(comms) > 0 {
		b.add(s, "snmp.defaultCreds", "snmp", "high",
			"proof", "snmp.defaultCommunities="+strings.Join(comms, ","), "community", comms[0])
	}
	if containsFlag(s.get("snmp.version"), "3") {
		b.add(s, "snmp.v3", "snmp", "info", "proof", "snmp.version="+s.get("snmp.version"))
	}
}

// ipmi scores the IPMI surface: reachability and negotiated versions, the
// advertised cipher suites, a cipher-zero session, null/anonymous
// authentication, RAKP-2 hash disclosure, the Supermicro/ATEN fixed-key
// integrity bypass, and recovered credentials.
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
		if hs.usesSMCFixedKey() {
			// The RAKP-2 HMAC matching the fixed key is already the whole
			// precondition for the forged session; no live command-capability probe
			// is needed to know it is exploitable on every generation except a
			// confirmed X14 (the one generation known to enforce per-session
			// integrity and reject the unprotected command, per live probing).
			if smcIsX14(h) {
				// X14 still completes the fixed-key handshake (CVE-2026-18449) but enforces
				// per-session integrity, so the unprotected-command defect (CVE-2026-18450)
				// this check id otherwise names does not apply here -- no CVE tag.
				b.add(s, "ipmi.smc.integrityBypass", "ipmi", "critical",
					"proof", "RAKP-2 HMAC verifies against the Supermicro/ATEN fixed key; generation X14 (integrity-enforced, unprotected command rejected)",
					"username", displayUser(hs.Username))
			} else {
				b.add(s, "ipmi.v20.smcrakpBypass", "ipmi", "critical",
					"proof", "RAKP-2 HMAC verifies against the Supermicro/ATEN fixed key; generation-derived, not live-confirmed (pre-X14 forged sessions execute unprotected commands)",
					"username", displayUser(hs.Username), "mode", "smcrakp-fixed-key",
					"smcrakpFixedKey", "true", "exploitable", "true", "state", "generation-derived-exploitable")
				b.addCVE("CVE-2026-18449")
			}
		}
	}

	passwords := parseUserMap(s.get("ipmi.rakp.passwords"))
	cracked := parseUserMap(s.get("ipmi.rakp.cracked"))
	// Sorted usernames so multiple cracked accounts emit findings in a stable
	// order; map iteration order is random and would vary the output run to run.
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

// iloExposures re-derives the HPE iLO detections a live scan would have reported
// from the identity a runZero export already carries: the iLO 2/3/4 IPMI RAKP-none
// bypass, the pre-iLO6 mpSSH overflow, and the version-gated iLO firmware CVEs.
//
// These are generation/version-gated projections, not live confirmations, so each
// finding pins to the service the defect is reached through and its proof says it
// is generation-derived.
func (b *findingBuilder) iloExposures(h *rzHost) {
	gen := iloGeneration(h)
	if gen == "" {
		return // not an iLO, or generation unknown -- nothing to attribute
	}

	// iLO 2/3/4 IPMI auth bypass (RMCP+ Open Session payload-type confusion
	// selecting RAKP-none). The IPMI channel it abuses must be reachable, so it
	// pins to the observed IPMI service the way the live check gates on the port.
	if gen == "iLO2" || gen == "iLO3" || gen == "iLO4" {
		if s := h.firstIPMIService(); s != nil {
			b.add(s, "ipmi.ilo.rakpNoneBypass", "auth", "high",
				"proof", "generation "+gen+" (RAKP-none bypass affects all iLO2/3/4 firmware; generation-derived, not live-confirmed)",
				"product", gen, "vendor", "hpe",
				"defect", "rakp-none-type-confusion", "authBypassed", "generation-derived")
			b.addCVE("CVE-2026-65206")
		}
	}

	// iLO 2/3/4/5 SSH overflow (mpSSH signed packet-length check).
	if gen == "iLO2" || gen == "iLO3" || gen == "iLO4" || gen == "iLO5" {
		for i := range h.services {
			s := &h.services[i]
			banner := mpSSHBanner(s)
			if banner == "" {
				continue
			}
			b.add(s, "ssh.hpe.iloSSHOverflow", "exposure", "high",
				"proof", "mpSSH service on "+s.portKey()+" (SSH overflow affects all pre-iLO6 mpSSH firmware; generation "+gen+", generation-derived)",
				"product", gen, "vendor", "hpe",
				"defect", "ssh-signed-length-check", "banner", firstLine(banner))
			b.addCVE("CVE-2026-65204")
		}
	}

	// Version-gated known iLO firmware CVEs (includes CVE-2017-12542 for iLO4
	// firmware below 2.53). These are web-delivered, so they need a firmware
	// version and a web service to attribute to.
	fw := iloFirmware(h)
	if fw == "" {
		return
	}
	web := h.firstWebService()
	if web == nil {
		return
	}
	for _, c := range ilo.MatchCVEs(gen, fw) {
		proof := "generation " + gen + " firmware " + fw + " < fixed-in " + c.FixedIn
		if c.FixedIn == ilo.NoFix {
			proof = "generation " + gen + " firmware " + fw + ", no fixed firmware"
		}
		f := []string{
			"proof", proof,
			"generation", gen, "firmware", fw, "fixed_in", c.FixedIn,
			"cve", c.ID, "title", c.Title,
		}
		if c.AuthBypass {
			f = append(f, "auth_bypass", "true")
		}
		b.add(web, "http.ilo.knownCVEs", "vuln", iloCVERisk(c.Severity), f...)
	}
}

// openbmcBypass projects the OpenBMC phosphor-net-ipmid pre-auth authentication
// bypass onto a host that fingerprints as OpenBMC and exposes an IPMI 2.0
// channel. The daemon ships a hardcoded default userKey ("0penBmc"), so the
// bypass is a property of the stack, not of any per-host observation -- the
// fingerprint plus a reachable IPMI 2.0 channel is the whole precondition. The
// proof names the fingerprint and marks it derived rather than live-confirmed.
func (b *findingBuilder) openbmcBypass(h *rzHost) {
	if !isOpenBMC(h) {
		return
	}
	s := h.firstIPMIService()
	if s == nil || !ipmi2Service(s) {
		return
	}
	b.add(s, "ipmi.openbmc.defaultUserKeyAuthBypass", "auth", "high",
		"proof", "fingerprint OpenBMC + IPMI 2.0 (phosphor-net-ipmid hardcoded default userKey \"0penBmc\"; fingerprint-derived, not live-confirmed)",
		"vendor", "openbmc", "defect", "phosphor-net-ipmid-default-userkey",
		"authBypassed", "fingerprint-derived")
	b.addCVE("CVE-2026-16141")
}

// isOpenBMC reports whether the asset fingerprints as OpenBMC (Phosphor). The
// runZero export types these boxes explicitly (os/os_vendor/hw_vendor
// "OpenBMC"), which is a positive discriminator rather than a port guess.
func isOpenBMC(h *rzHost) bool {
	for _, v := range []string{h.asset.OS, h.asset.OSVendor, h.asset.OSProduct,
		h.asset.HW, h.asset.HWVendor, h.asset.HWProduct} {
		if strings.Contains(strings.ToLower(v), "openbmc") {
			return true
		}
	}
	return false
}

// ipmi2Service reports whether an IPMI service speaks IPMI 2.0 (RMCP+), the
// version the OpenBMC userKey bypass rides. It reads the negotiated versions
// when present and otherwise infers 2.0 from RMCP+-only artifacts (cipher list
// or a captured RAKP-2), which IPMI 1.5 never produces.
func ipmi2Service(s *rzService) bool {
	if cv := s.get("ipmi.connVersions"); cv != "" {
		return strings.Contains(cv, "2.0")
	}
	return s.get("ipmi.rakp.hashes") != "" || s.get("ipmi.ciphers") != ""
}

// smcX14ModelRe matches a real Supermicro X14 board SKU prefix (e.g.
// "X14DAi-cpu"). X14 is the generation that moved to an OpenBMC-based stack
// and began enforcing per-session integrity on a SMCRAKP-forged session (the
// forged session activates but the unprotected command that makes it
// exploitable is rejected); every earlier X-generation (X8-X13) and the
// non-X families (H1x/M1x/B1x) do not, so X14 is the one generation worth
// specifically excluding rather than a whole ordered generation table.
var smcX14ModelRe = regexp.MustCompile(`(?i)^\s*X14[A-Z0-9]`)

// smcIsX14 reports whether the host's identity resolves to a real Supermicro
// X14 board -- via a leaked board SKU, the GUID board-code prefix ("5601MS"
// is the only X14 code catalogued so far), or captured session-ID entropy.
// It is used only to withhold the command-capable SMCRAKP upgrade from a
// confirmed X14; every other generation, including one that cannot be
// resolved at all, defaults to pre-X14 since X14 is the newest and
// least-deployed generation in the fleet.
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
	// Session-ID entropy is a secondary signal when no board SKU or GUID code
	// resolved the generation: the pre-X14 ATEN stack steps managed RMCP+ session
	// IDs by a fixed +0x10, while X14 uses OpenBMC's RNG, so a well-distributed
	// sample is itself evidence of X14. A confirmed fixed step on any service beats
	// an apparently random sample on another, being the more specific signature.
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

// weakSessionID flags a BMC whose captured RMCP+ session IDs (ipmi.rakp.sessionIDs,
// the BMC-assigned managed SIDs runZero recorded across its RAKP probes) show a
// predictable or low-entropy assignment: fixed across probes, a constant step,
// or confined to a tiny window of the 32-bit space. A guessable session ID lets
// an off-path attacker inject into or hijack a session. The Supermicro/ATEN
// small-SID-space defect is the archetype, so a Supermicro host is scored
// critical; others high.
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

// parseSessionIDs decodes a runZero ipmi.rakp.sessionIDs attribute -- whitespace-
// separated 4-byte hex tokens in wire (little-endian) order, the same encoding
// the RAKP salt uses for the managed SID -- into their numeric values.
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

// iloGenFields are the per-service runZero attributes that name the iLO
// generation on a record that carried a parsed RIMP/moniker (the dedicated
// ilo.* keys), most specific first.
var iloGenFields = []string{
	"ilo.mp.pn", "ilo.session.moniker.prodnam", "ilo.session.moniker.prodtag",
	"ilo.session.moniker.prodgen",
}

// iloGeneration resolves the host's iLO generation label from the runZero
// identity strings, most authoritative first: the dedicated ilo.* product
// fields runZero parses from the pre-auth RIMP document, then the asset
// product/OS names, then per-service Server headers. Returns "" when no string
// carries a generation token (so the caller treats the box as a non-iLO or an
// iLO of unknown generation and attributes nothing).
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

// iloFirmware resolves the iLO firmware version for the host, most authoritative
// first: the dedicated ilo.mp.fwri / ilo.session.version fields runZero parsed
// from the RIMP document, then the "HP-iLO-N/x.yy" Server header, then the
// asset's version column when it reads like an iLO firmware string.
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

// iloFWFromServer extracts the firmware version from an iLO "Server" header of
// the form "HP-iLO-4/2.55" (the version follows the '/' after the iLO token).
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

// looksLikeVersion reports whether s is a dotted-numeric version ("2.55",
// "2.55.1"): digits and dots only, with at least one dot and one digit.
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

// mpSSHBanner returns the SSH identification banner of an SSH service that
// advertises HPE's iLO management-processor SSH ("mpSSH"), or "" when the
// service is not SSH or is not mpSSH.
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

// iloCVERisk maps an iLO CVE severity onto an oobscan risk level.
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

// firstIPMIService returns the host's first IPMI-bearing service, or nil.
func (h *rzHost) firstIPMIService() *rzService {
	for i := range h.services {
		if ipmiService(&h.services[i]) {
			return &h.services[i]
		}
	}
	return nil
}

// firstWebService returns the host's first HTTP/TLS/Redfish service, or nil.
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

// cipherSuites returns the advertised IPMI cipher suite ids. The export mixes
// tab- and comma-separated encodings, so split on both.
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

// splitAlgs splits a runZero algorithm list (space-, comma- or tab-separated)
// into lowercased tokens.
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

// firstMatchingKey returns the lexicographically first key of m that contains
// sub (case-insensitive), or "". It scans in sorted order so the result does
// not depend on Go's random map iteration order -- the projection must be
// deterministic (a converted corpus is diffed and re-converted).
func firstMatchingKey(m map[string]string, sub string) string {
	best := ""
	for k := range m {
		if strings.Contains(strings.ToLower(k), sub) && (best == "" || k < best) {
			best = k
		}
	}
	return best
}
