// Package identify runs the first stage of the per-target pipeline: it probes a
// host across several protocols, fuses the signals into a single Identity
// (device class + vendor + product), and stashes the raw probe results on the
// Target so later checks can reuse them without re-probing.
package identify

import (
	"context"
	"fmt"
	"maps"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/runZeroInc/oobscan/pkg/bmcfp"
	"github.com/runZeroInc/oobscan/pkg/creds"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

// tcpOpen reports whether a TCP connect to host:port succeeds within timeout. A
// fast reachability gate so identify skips expensive HTTP sweeps on dead hosts.
func tcpOpen(host string, port int, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// confRank orders confidence levels for candidate selection.
var confRank = map[engine.Confidence]int{engine.ConfLow: 1, engine.ConfMedium: 2, engine.ConfHigh: 3}

// sourcePriority ranks signal sources for deterministic tie-breaking when two
// candidates share the same confidence (lower = more trusted). This keeps
// Identify deterministic even though collectors run concurrently.
var sourcePriority = map[string]int{
	"idrac": 1, "ilo": 1, "redfish": 1, "lantronix": 1, "moxa": 1, "digi.addp": 1, "digi.realport": 1,
	"lantronix.telnet": 2,
	"fingerprint":      2, "wsman": 3, "tls": 4, "ipmi.deviceId": 5,
	"http": 6, "ipmi.authCaps": 7, "ipmi.cipherSuites": 7, "guid": 8, "http.vendors": 9, "snmp": 10,
	// http.apc-nmc is a dedicated vendor-unique probe, ranked with the other device
	// probes. tls-cn is a certificate-CN heuristic, so it stays at the generic tls rank.
	"http.apc-nmc": 1, "slp": 3, "tls-cn": 4, "mdns": 6, "http.title": 6, "snmp.sysdescr": 10,
}

// unrankedSourcePriority is the rank given to a source missing from
// sourcePriority. It must be numerically higher (less trusted) than every ranked
// source: a bare map lookup yields 0, which would let an unranked or misspelled
// source win the tie-break as the most trusted signal.
const unrankedSourcePriority = 99

func rankSource(source string) int {
	if p, ok := sourcePriority[source]; ok {
		return p
	}
	return unrankedSourcePriority
}

// candidate is one vendor/product guess contributed by a collector.
type candidate struct {
	vendor     string
	product    string
	generation string
	conf       engine.Confidence
	source     string
}

// acc accumulates evidence across collectors before it is fused into Identity.
// Collectors run concurrently, so every mutation is guarded by mu.
type acc struct {
	mu          sync.Mutex
	cands       []candidate
	signals     []engine.Signal
	attrs       map[string]string
	fp          map[bmcfp.Kind]string // fingerprint inputs for bmcfp.MatchAll
	ipmiUp      bool
	forcedClass engine.DeviceClass // set by direct-hit probes (Lantronix/Moxa/AMT)
	folded      bool               // foldFingerprint has run
	honeypot    bool               // detectHoneypot flagged this host as a deception node
	honeypotWhy string             // human-readable reason for the honeypot verdict
	logf        func(string)       // optional per-collector debug logger (nil = quiet)
}

type accSnapshot struct {
	cands       []candidate
	signals     []engine.Signal
	attrs       map[string]string
	ipmiUp      bool
	forcedClass engine.DeviceClass
	honeypot    bool
	honeypotWhy string
}

func (a *acc) snapshot() accSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	return accSnapshot{
		cands:       slices.Clone(a.cands),
		signals:     slices.Clone(a.signals),
		attrs:       maps.Clone(a.attrs),
		ipmiUp:      a.ipmiUp,
		forcedClass: a.forcedClass,
		honeypot:    a.honeypot,
		honeypotWhy: a.honeypotWhy,
	}
}

// foldFingerprint runs the accumulated fingerprint inputs (TLS DN, Server
// header, HTML title, favicon) through bmcfp once, adding a high-confidence
// candidate. Idempotent so it can be called after phase 1 and again in resolve.
func (a *acc) foldFingerprint() {
	a.mu.Lock()
	if a.folded {
		a.mu.Unlock()
		return
	}
	a.folded = true
	fp := maps.Clone(a.fp)
	a.mu.Unlock()
	if v, p, weak, ok := bmcfp.MatchAllWeighted(fp); ok {
		// A generic/shared tell (stock web-server version, shared OEM cert, reused
		// favicon) is real but collision-prone, so fold it at low confidence: it
		// then needs corroboration to win pick() and never alone decides a device
		// class (see the confidence floor in resolve).
		conf := engine.ConfHigh
		if weak {
			conf = engine.ConfLow
		}
		a.addVendor(v, p, "", conf, "fingerprint")
	}
}

func newAcc() *acc {
	return &acc{attrs: map[string]string{}, fp: map[bmcfp.Kind]string{}}
}

// log emits a per-collector diagnostic when --debug supplied a logger.
func (a *acc) log(msg string) {
	if a.logf != nil {
		a.logf(msg)
	}
}

// addVendor records a vendor/product candidate, normalizing the vendor to the
// short slug used by creds/oob. Empty vendors are ignored.
func (a *acc) addVendor(vendor, product, generation string, conf engine.Confidence, source string) {
	slug := creds.NormalizeVendor(vendor)
	if slug == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cands = append(a.cands, candidate{slug, product, generation, conf, source})
	a.signals = append(a.signals, engine.Signal{Source: source, Vendor: slug, Detail: product})
}

func (a *acc) addFP(kind bmcfp.Kind, val string) {
	if val == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fp[kind] = val
}

func (a *acc) markIPMI() {
	a.mu.Lock()
	a.ipmiUp = true
	a.mu.Unlock()
}

func (a *acc) isIPMI() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ipmiUp
}

func (a *acc) setAttr(key, val string) {
	a.mu.Lock()
	a.attrs[key] = val
	a.mu.Unlock()
}

// setAttrIfUnset records an attribute only when it has not already been set, so a
// late-running collector (e.g. a dedicated-port web-app probe) does not clobber a
// primary web.port/scheme the main web collector already established.
func (a *acc) setAttrIfUnset(key, val string) {
	a.mu.Lock()
	if _, ok := a.attrs[key]; !ok {
		a.attrs[key] = val
	}
	a.mu.Unlock()
}

func (a *acc) forceClass(c engine.DeviceClass) {
	a.mu.Lock()
	a.forcedClass = c
	a.mu.Unlock()
}

// attrVal / fpVal are locked getters used by detectHoneypot to read evidence the
// collectors accumulated without racing them.
func (a *acc) attrVal(key string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.attrs[key]
}

func (a *acc) fpVal(kind bmcfp.Kind) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fp[kind]
}

func (a *acc) markHoneypot(reason string) {
	a.mu.Lock()
	a.honeypot = true
	if a.honeypotWhy == "" {
		a.honeypotWhy = reason
	}
	a.mu.Unlock()
}

// isHoneypotNoiseAttr reports whether an identity attribute key should be
// re-prefixed under honeypot.attr.* when the host is flagged as a honeypot:
// keys a downstream indexer would otherwise treat as genuine management
// signals. Basic surface metadata (http.server, http.title, tls.cert.*, banner)
// is deliberately left alone, since triage reads those keys.
func isHoneypotNoiseAttr(key string) bool {
	prefixes := []string{
		"wsman.", "redfish.", "ipmi.", "idrac.", "ilo.",
		"favicon.", "snmp.engine", "amt.", "ssdp.", "slp.",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// honeypotTitlePatterns are web <title> substrings (lowercased) that no real OOB
// device serves but that ship as defaults in deception grids (T-Pot, canary
// templates): placeholder blog/wiki/site pages under a literal "user" account.
var honeypotTitlePatterns = []string{
	"user's blog", "user's wiki", "user's site", "welcome to user's", "user blog",
	"honeypot", "canary", "decoy", "t-pot", "tpot",
}

// honeypotHTTPServerPatterns are Server-header substrings (lowercased) that only
// appear on decoy stacks. Real BMCs advertise stable Server strings (Appweb,
// GoAhead, cherokee, mpsseweb, embedthis).
var honeypotHTTPServerPatterns = []string{
	"cowrie", "kippo", "dionaea", "conpot", "glutton", "honeypot",
}

// honeypotSSHBannerPatterns are SSH banner substrings that identify canonical SSH
// decoys. Real BMC banners are mpSSH / Dropbear / OpenBSD OpenSSH.
var honeypotSSHBannerPatterns = []string{
	"cowrie", "kippo", "honeypot",
}

// honeypotPortBreadthThreshold is the open-port count at or above which a host is
// treated as an ACK-all tarpit (heuristic 7). Real OOB devices top out around 11
// open ports; a lower cutoff clips real BMCs. Shared by the identify-time
// detector and the post-battery re-evaluation so the two cannot drift apart.
const honeypotPortBreadthThreshold = 12

// honeypotBreadthReason formats the heuristic-7 verdict string for n open ports.
func honeypotBreadthReason(n int) string {
	return "implausible open-port breadth (" + strconv.Itoa(n) + " ports)"
}

// detectHoneypot flags obvious deception nodes so the scan records them and then
// skips the credential/exposure battery, which against a decoy only manufactures
// bogus findings. Nine heuristics, numbered to match the branches below; the
// first one to fire owns the reason string.
func detectHoneypot(t *engine.Target, a *acc) {
	if a.honeypot {
		return // already marked; keep the first reason
	}
	// (1) TLS cert self-labels as honeypot / decoy.
	for _, cn := range []string{a.fpVal(bmcfp.TLSSubjectCN), a.fpVal(bmcfp.TLSIssuerCN), a.fpVal(bmcfp.TLSSubjectDN)} {
		low := strings.ToLower(cn)
		if strings.Contains(low, "honeypot") || strings.Contains(low, "canary") || strings.Contains(low, "decoy") {
			a.markHoneypot("TLS certificate advertises 'honeypot/canary/decoy'")
			return
		}
	}
	// (2) placeholder / deception web title.
	title := strings.ToLower(a.attrVal("http.title"))
	if title == "" {
		title = strings.ToLower(a.fpVal(bmcfp.HTMLTitle))
	}
	for _, pat := range honeypotTitlePatterns {
		if title != "" && strings.Contains(title, pat) {
			a.markHoneypot("deception placeholder web title (" + pat + ")")
			return
		}
	}
	// (3) known decoy HTTP Server framework.
	server := strings.ToLower(a.attrVal("http.server"))
	if server == "" {
		server = strings.ToLower(a.fpVal(bmcfp.HTTPServerHeader))
	}
	for _, pat := range honeypotHTTPServerPatterns {
		if server != "" && strings.Contains(server, pat) {
			a.markHoneypot("known honeypot HTTP Server header (" + pat + ")")
			return
		}
	}
	// (4) SSH banner from a known decoy framework (if evidence is available).
	sshBanner := strings.ToLower(a.fpVal(bmcfp.SSHBanner))
	if sshBanner == "" {
		if v, ok := t.Evidenced("ssh.banner"); ok {
			if s, ok := v.(string); ok {
				sshBanner = strings.ToLower(s)
			}
		}
	}
	for _, pat := range honeypotSSHBannerPatterns {
		if sshBanner != "" && strings.Contains(sshBanner, pat) {
			a.markHoneypot("known honeypot SSH banner (" + pat + ")")
			return
		}
	}
	// (8) SSH banner is actually an HTTP response: a single ACK-all handler
	// answering the SSH probe with "HTTP/1.1 4xx ...". A real sshd emits an "SSH-"
	// banner. (sshBanner is lowercased above.)
	if strings.HasPrefix(sshBanner, "http/") {
		a.markHoneypot("SSH banner is an HTTP response (single ACK-all handler)")
		return
	}
	// (9) oversized / multi-token banner blob: a decoy dumping its whole
	// signature database into one Server/title/SSH banner. Real multi-module
	// banners stay short (<=3 commas, well under 200 chars).
	for _, v := range []string{server, title, sshBanner} {
		if len(v) > 200 || strings.Count(v, ",") >= 4 {
			a.markHoneypot("oversized/multi-token banner (signature-DB dump)")
			return
		}
	}
	// (5) implausible power-management port triad: CyberPower PowerPanel (53568)
	// plus Eaton IPM (4679+4680) on one host. No real deployment runs two
	// competing vendors' power suites at once.
	if t.IsOpen(53568, "tcp") && t.IsOpen(4679, "tcp") && t.IsOpen(4680, "tcp") {
		a.markHoneypot("implausible CyberPower+Eaton mgmt port triad (4679+4680+53568)")
		return
	}
	// (6) contradictory BMC-family fingerprints on one host (iDRAC + iLO +
	// Supermicro/ATEN, or a Redfish "Dell" service plus an APC NMC Server header).
	if reason := detectContradictoryBMCFamily(a); reason != "" {
		a.markHoneypot(reason)
		return
	}
	// (7) implausible open-port breadth (ACK-all tarpit). Checked last so a more
	// specific reason above wins the label. At identify time t.Open holds only the
	// ports the identify probes touched, so this is just a fast path; the
	// authoritative evaluation is ReclassifyHoneypotByBreadth after the battery,
	// when t.Open is complete.
	if n := t.OpenLen(); n >= honeypotPortBreadthThreshold {
		a.markHoneypot(honeypotBreadthReason(n))
		return
	}
}

// detectContradictoryBMCFamily returns a human-readable reason when the
// accumulated attributes place the host in two or more mutually-exclusive BMC
// families at once. The compared families (Dell iDRAC, HPE iLO, Supermicro
// IPMI/ATEN, APC NMC PDU) each have distinct pre-auth fingerprints that a single
// real device cannot legitimately emit.
func detectContradictoryBMCFamily(a *acc) string {
	families := map[string]string{}
	// iDRAC: any idrac.* attribute or Redfish claiming Dell.
	if a.attrVal("idrac.fw") != "" || a.attrVal("idrac.version") != "" || a.attrVal("dell.service_tag") != "" ||
		strings.EqualFold(a.attrVal("redfish.vendor"), "dell") {
		families["dell.idrac"] = "idrac/redfish-dell"
	}
	// iLO: any ilo.* attribute or Redfish claiming HPE.
	if a.attrVal("ilo.fw") != "" || a.attrVal("ilo.serial") != "" ||
		strings.EqualFold(a.attrVal("redfish.vendor"), "hpe") ||
		strings.EqualFold(a.attrVal("redfish.vendor"), "hp") {
		families["hpe.ilo"] = "ilo/redfish-hpe"
	}
	// Supermicro / ATEN IPMI: SMC-specific Redfish vendor.
	if strings.EqualFold(a.attrVal("redfish.vendor"), "supermicro") ||
		strings.EqualFold(a.attrVal("redfish.vendor"), "aten") {
		families["supermicro"] = "redfish-supermicro"
	}
	// APC NMC PDU: dedicated attribute + Redfish claim of APC.
	if a.attrVal("http.apc_nmc") != "" ||
		strings.EqualFold(a.attrVal("redfish.vendor"), "apc") {
		families["apc.nmc"] = "http.apc_nmc"
	}
	if len(families) < 2 {
		return ""
	}
	var reasons []string
	for _, r := range families {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	return "contradictory BMC-family fingerprints on one host (" + strings.Join(reasons, " + ") + ")"
}

// markIdentityHoneypot rewrites an Identity in place into the canonical honeypot
// form: class honeypot at high confidence, the reason under the "honeypot"
// attribute, and management-signal attributes re-prefixed under "honeypot.attr."
// so they survive for debugging without being mistaken for a real endpoint.
// Shared by resolve() and ReclassifyHoneypotByBreadth so the identify-time and
// post-battery paths emit identical records. An already-recorded reason wins.
func markIdentityHoneypot(id *engine.Identity, reason string) {
	id.Class = engine.ClassHoneypot
	id.Confidence = engine.ConfHigh
	if id.Attributes == nil {
		id.Attributes = map[string]string{}
	}
	if id.Attributes["honeypot"] == "" {
		id.Attributes["honeypot"] = reason
	}
	var toRename []string
	for k := range id.Attributes {
		if k == "honeypot" || strings.HasPrefix(k, "honeypot.") {
			continue
		}
		if isHoneypotNoiseAttr(k) {
			toRename = append(toRename, k)
		}
	}
	for _, k := range toRename {
		id.Attributes["honeypot.attr."+k] = id.Attributes[k]
		delete(id.Attributes, k)
	}
}

// ReclassifyHoneypotByBreadth re-runs honeypot heuristic 7 (implausible open-port
// breadth) against the final discovered-port surface. It mutates only the
// identity: the caller must also discard the battery's now-invalid findings and
// re-emit the identity finding, so the record matches an identify-time-flagged
// decoy. Returns false when the host is already a honeypot or is under the
// threshold.
func ReclassifyHoneypotByBreadth(t *engine.Target) bool {
	if t == nil || t.Identity == nil {
		return false
	}
	if t.Identity.Class == engine.ClassHoneypot {
		return false // already flagged during identify; keep that verdict
	}
	n := t.OpenLen()
	if n < honeypotPortBreadthThreshold {
		return false
	}
	markIdentityHoneypot(t.Identity, honeypotBreadthReason(n))
	return true
}

// Identify probes the target and returns a non-nil Identity. An unreachable or
// unattributable host yields {Class: ClassUnknown, Confidence: ConfLow}. logf,
// when non-nil, receives a per-collector diagnostic line (wired to --debug).
func Identify(ctx context.Context, t *engine.Target, logf func(string)) *engine.Identity {
	a := newAcc()
	a.logf = logf

	// Bound total identify time so a saturated/locked-out board, whose web and IPMI
	// probes each hang to their own timeout, cannot compound to minutes. Once the
	// deadline elapses runCollectors abandons stragglers and we resolve with the
	// evidence gathered so far.
	ictx, cancel := context.WithTimeout(ctx, identifyBudget(t))
	defer cancel()

	// Phase 1: cheap, always-run probes (one round-trip each), concurrently. The
	// vendor-specific iDRAC and iLO probes are expensive and are deferred to phase 2.
	// The HTTP-based collectors are the slowest part against an unreachable host, so
	// they are gated on a quick TCP connect.
	phase1 := []func(*engine.Target, *acc){collectIPMI}
	// Probe the web tier if either a TLS port (443/8443/4443) or plain HTTP/80 is
	// reachable. Many OOB devices (PDUs, legacy console gear) are HTTP-only or ship
	// with HTTPS disabled; gating solely on the TLS port leaves them ClassUnknown
	// with no checks run. collectWeb falls back to http:// on its own.
	probeTimeout := min(t.Timeout, 900*time.Millisecond)
	webUp := false
	for _, p := range likelyHTTPSPorts(t) {
		if tcpOpen(t.Host, p, probeTimeout) {
			webUp = true
			break
		}
	}
	if !webUp {
		for _, p := range likelyHTTPFallbackPorts(t) {
			if tcpOpen(t.Host, p, probeTimeout) {
				webUp = true
				break
			}
		}
	}
	if webUp {
		// collectWeb (title/server) + redfish + tls are cheap and give the vendor;
		// the heavier endpoint sweep runs as a bounded concurrent check.
		phase1 = append(phase1, collectTLS, collectWeb, collectRedfish)
	} else {
		a.log("web liveness probe: no HTTPS/HTTP management ports reachable; skipping HTTP probes")
	}
	if hasPort(t, 5985, engine.ProtoTCP) || hasPort(t, 5986, engine.ProtoTCP) || hasPort(t, 16992, engine.ProtoTCP) || hasPort(t, 16993, engine.ProtoTCP) {
		phase1 = append(phase1, collectWSMAN)
	}
	if hasPort(t, 30718, engine.ProtoUDP) {
		phase1 = append(phase1, collectLantronix)
	}
	if hasPort(t, 9999, engine.ProtoTCP) {
		phase1 = append(phase1, collectLantronixTelnet)
	}
	if hasPort(t, 4800, engine.ProtoUDP) {
		phase1 = append(phase1, collectMoxa)
	}
	if hasPort(t, 427, engine.ProtoUDP) {
		phase1 = append(phase1, collectSLP)
	}
	if hasPort(t, 2362, engine.ProtoUDP) {
		phase1 = append(phase1, collectDigiADDP)
	}
	if hasPort(t, 771, engine.ProtoTCP) || hasPort(t, 1027, engine.ProtoTCP) {
		phase1 = append(phase1, collectDigiRealPort)
	}
	if hasPort(t, 5988, engine.ProtoTCP) || hasPort(t, 5989, engine.ProtoTCP) {
		phase1 = append(phase1, collectCIM)
	}
	if hasPort(t, 5353, engine.ProtoUDP) {
		phase1 = append(phase1, collectMDNS)
	}
	if hasPort(t, 3702, engine.ProtoUDP) {
		phase1 = append(phase1, collectWSDiscovery)
	}
	// SNMP discovery runs on every target regardless of the configured port list:
	// the v2c/v1 sysObjectID and the SNMPv3 engine ID are high-value identification
	// signals, so UDP/161 is always probed (bounded, short per-attempt timeout).
	phase1 = append(phase1, collectSNMP)
	// SSH banner grab also runs on every target: the banner is a high-value tell
	// (iLO mpSSH, ILOM, APC cryptlib) and stashing it as evidence lets the
	// always-on ssh.exposure check reuse it rather than re-dial 22.
	phase1 = append(phase1, collectSSH)
	// OOB-management web apps that listen on dedicated ports (not 443/80) are
	// probed here so a bare `scan <ip>` still attributes them; each is a separate
	// collector (concurrent) gated on a quick TCP connect, so a host without the
	// port costs one connect timeout at most. Like the SNMP/IPMI probes, these run
	// independent of --ports.
	phase1 = append(phase1,
		mgmtSoftwareProbe(53568, "https"), // CyberPower PowerPanel Enterprise (PDNU)
		mgmtSoftwareProbe(4680, "https"),  // Eaton Intelligent Power Manager
		mgmtSoftwareProbe(4679, "http"),   // Eaton Intelligent Power Manager (HTTP)
	)
	runCollectors(ictx, t, a, phase1)

	// Fold fingerprints and pick a tentative vendor to decide phase 2.
	a.foldFingerprint()
	tentative := ""
	if best := a.pick(); best != nil {
		tentative = best.vendor
	}
	// Run detectHoneypot before phase 2 so decoy nodes never receive the expensive
	// vendor probes.
	detectHoneypot(t, a)
	// Skip the vendor probes when phase 1 already burned the identify budget; on a
	// locked-out board they would only pile stalled connections onto an elapsed
	// deadline.
	budgetLeft := ictx.Err() == nil
	var phase2 []func(*engine.Target, *acc)
	if budgetLeft && !a.honeypot && webUp && (tentative == "" || tentative == "dell") {
		phase2 = append(phase2, collectIDRAC)
	}
	if budgetLeft && !a.honeypot && webUp && (tentative == "" || tentative == "hpe") {
		phase2 = append(phase2, collectILO)
	}
	// Record a budget-driven skip as an attribute. Phase 2 owns the vendor-specific
	// generation probes; when skipped, refineGeneration falls back to a coarser
	// inferred range, so this makes the precision loss visible rather than letting
	// it look like a normal identify.
	if !budgetLeft && !a.honeypot && webUp && (tentative == "" || tentative == "dell" || tentative == "hpe") {
		a.setAttr("identify.phase2Skipped", "budget-exhausted")
	}
	if a.logf != nil {
		a.log(fmt.Sprintf("phase1 vendor=%q honeypot=%v budgetLeft=%v; phase2=%d probe(s)", tentative, a.honeypot, budgetLeft, len(phase2)))
	}
	runCollectors(ictx, t, a, phase2)

	// Re-run honeypot detection after phase 2 in case those probes surfaced a
	// giveaway that phase 1 alone couldn't see (e.g. an emulated iDRAC that
	// also emits an iLO response -- mutually exclusive on real hardware).
	if !a.honeypot {
		detectHoneypot(t, a)
	}

	id := a.resolve()
	// Fill/upgrade the device generation from sessionless evidence (TLS cert
	// product, HTTP Server header, cipher suites, SNMP engine ID) when the
	// collectors did not attribute one. Skipped for honeypots (no real device).
	if id.Class != engine.ClassHoneypot {
		refineGeneration(t, id)
	}
	seedExplicitWebPort(t, id)
	return id
}

// seedExplicitWebPort records an explicit host:port (or --web-port) as web.port /
// web.scheme so downstream web checks target the port the operator named rather
// than falling back to 443. A port that actually answered wins: collectWeb sets
// web.port/web.scheme itself, so this only fills the gap when no live web probe
// succeeded. The scheme guess is a fallback; --assume-scheme, applied after
// identify, remains authoritative.
func seedExplicitWebPort(t *engine.Target, id *engine.Identity) {
	if t.WebPort <= 0 || id == nil {
		return
	}
	if id.Attributes == nil {
		id.Attributes = map[string]string{}
	}
	if id.Attributes["web.port"] == "" {
		id.Attributes["web.port"] = strconv.Itoa(t.WebPort)
	}
	if id.Attributes["web.scheme"] == "" {
		// Guess from the port that actually ended up in web.port, not from t.WebPort.
		// collectWeb may already have set web.port to a different port it successfully
		// probed, in which case deriving the scheme from the operator's argument
		// describes a port we are not going to use, and web.port/web.scheme ship
		// disagreeing with each other.
		id.Attributes["web.scheme"] = netaddr.DefaultScheme(resolvedWebPort(id, t.WebPort))
	}
}

// resolvedWebPort returns the port recorded in web.port, falling back to def when
// it is absent or unparseable.
func resolvedWebPort(id *engine.Identity, def int) int {
	if n, err := strconv.Atoi(id.Attributes["web.port"]); err == nil && n > 0 {
		return n
	}
	return def
}

// runCollectors returns when all collectors finish or the identify budget
// expires. Collectors that outlive the budget may continue updating acc, so
// consumers must use a snapshot.
func runCollectors(ctx context.Context, t *engine.Target, a *acc, fns []func(*engine.Target, *acc)) {
	if len(fns) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, fn := range fns {
		wg.Add(1)
		go func(f func(*engine.Target, *acc)) {
			defer wg.Done()
			defer func() {
				if recovered := recover(); recovered != nil {
					a.log(fmt.Sprintf("identify collector panic: %v", recovered))
				}
			}()
			f(t, a)
		}(fn)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		a.log("identify budget elapsed; abandoning straggling collectors")
	}
}

// resolve fuses accumulated evidence into a single Identity.
func (a *acc) resolve() *engine.Identity {
	// Fold the fingerprint inputs through bmcfp (TLS DN > Server header > title
	// > favicon ranking is internal to MatchAll) as one high-confidence signal.
	a.foldFingerprint()

	state := a.snapshot()
	best := pickCandidate(state.cands)
	id := &engine.Identity{
		Confidence: engine.ConfLow,
		Signals:    state.signals,
		Attributes: state.attrs,
	}
	if best != nil {
		id.Vendor = best.vendor
		id.Product = best.product
		id.Generation = best.generation
		id.Confidence = best.conf
	}

	// A honeypot verdict overrides vendor/class resolution: whatever vendor a
	// collector recognized on a decoy is noise. Keep the vendor and signals for
	// context, pin the class to honeypot, and record why; check.ForIdentity then
	// runs only the id reporter against it.
	if state.honeypot {
		markIdentityHoneypot(id, state.honeypotWhy)
		return id
	}

	// Class resolution: direct-hit probes win; else registry lookup; else an
	// IPMI-reachable host with no other tell is a generic BMC.
	switch {
	case state.forcedClass != "" && (best == nil || confRank[best.conf] < confRank[engine.ConfHigh]):
		id.Class = state.forcedClass
	default:
		// Only derive a hardware class from the vendor/product when the winning
		// attribution is at least medium-confidence. A ConfLow-only guess (SNMP
		// enterprise-ID, IPMI GUID, weak fingerprint) is a usable vendor hint but a
		// poor class signal: a Cisco switch's SNMP arc should not resolve to
		// "Cisco CIMC BMC". Such hosts keep the vendor label and fall through to the
		// IPMI/unknown resolution below.
		classOK := false
		if c, ok := classForVendorProduct(id.Vendor, id.Product); ok && best != nil && confRank[best.conf] >= confRank[engine.ConfMedium] {
			id.Class = c
			classOK = true
		}
		if !classOK {
			if state.forcedClass != "" {
				id.Class = state.forcedClass
			} else if state.ipmiUp {
				id.Class = engine.ClassBMC
			} else {
				id.Class = engine.ClassUnknown
			}
		}
	}
	if len(id.Attributes) == 0 {
		id.Attributes = nil
	}
	return id
}

// pick chooses the best candidate: highest confidence, then one that carries a
// product, then earliest (most-trusted) source.
func (a *acc) pick() *candidate {
	a.mu.Lock()
	cands := slices.Clone(a.cands)
	a.mu.Unlock()
	return pickCandidate(cands)
}

func pickCandidate(cands []candidate) *candidate {
	if len(cands) == 0 {
		return nil
	}
	idx := make([]int, len(cands))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(i, j int) bool {
		ci, cj := cands[idx[i]], cands[idx[j]]
		if confRank[ci.conf] != confRank[cj.conf] {
			return confRank[ci.conf] > confRank[cj.conf]
		}
		if (ci.product != "") != (cj.product != "") {
			return ci.product != ""
		}
		// Prefer a candidate that names a generation before falling back to source
		// trust. Without this, collectRedfish's generic ("iLO", "") and collectILO's
		// specific ("iLO4", "iLO4") tie on both confidence and source priority, so the
		// winner would come down to concurrent append order and the generation could
		// be silently discarded.
		if (ci.generation != "") != (cj.generation != "") {
			return ci.generation != ""
		}
		// Deterministic tie-break by source trust (collectors run concurrently,
		// so append order is not stable).
		if pi, pj := rankSource(ci.source), rankSource(cj.source); pi != pj {
			return pi < pj
		}
		return ci.vendor < cj.vendor
	})
	best := cands[idx[0]]
	return &best
}

func hasPort(t *engine.Target, num int, proto engine.Proto) bool {
	for _, p := range t.Ports {
		if p.Num == num && p.Proto == proto {
			return true
		}
	}
	return false
}
