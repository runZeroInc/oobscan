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

func tcpOpen(host string, port int, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

var confRank = map[engine.Confidence]int{engine.ConfLow: 1, engine.ConfMedium: 2, engine.ConfHigh: 3}

var sourcePriority = map[string]int{
	"idrac": 1, "ilo": 1, "redfish": 1, "lantronix": 1, "moxa": 1, "digi.addp": 1, "digi.realport": 1,
	"lantronix.telnet": 2,
	"fingerprint":      2, "wsman": 3, "tls": 4, "ipmi.deviceId": 5,
	"http": 6, "ipmi.authCaps": 7, "ipmi.cipherSuites": 7, "guid": 8, "http.vendors": 9, "snmp": 10,

	"http.apc-nmc": 1, "slp": 3, "tls-cn": 4, "mdns": 6, "http.title": 6, "snmp.sysdescr": 10,
}

const unrankedSourcePriority = 99

func rankSource(source string) int {
	if p, ok := sourcePriority[source]; ok {
		return p
	}
	return unrankedSourcePriority
}

type candidate struct {
	vendor     string
	product    string
	generation string
	conf       engine.Confidence
	source     string
}

type acc struct {
	mu          sync.Mutex
	cands       []candidate
	signals     []engine.Signal
	attrs       map[string]string
	fp          map[bmcfp.Kind]string
	ipmiUp      bool
	forcedClass engine.DeviceClass
	folded      bool
	honeypot    bool
	honeypotWhy string
	logf        func(string)
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

func (a *acc) log(msg string) {
	if a.logf != nil {
		a.logf(msg)
	}
}

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

var honeypotTitlePatterns = []string{
	"user's blog", "user's wiki", "user's site", "welcome to user's", "user blog",
	"honeypot", "canary", "decoy", "t-pot", "tpot",
}

var honeypotHTTPServerPatterns = []string{
	"cowrie", "kippo", "dionaea", "conpot", "glutton", "honeypot",
}

var honeypotSSHBannerPatterns = []string{
	"cowrie", "kippo", "honeypot",
}

const honeypotPortBreadthThreshold = 12

func honeypotBreadthReason(n int) string {
	return "implausible open-port breadth (" + strconv.Itoa(n) + " ports)"
}

func detectHoneypot(t *engine.Target, a *acc) {
	if a.honeypot {
		return
	}

	for _, cn := range []string{a.fpVal(bmcfp.TLSSubjectCN), a.fpVal(bmcfp.TLSIssuerCN), a.fpVal(bmcfp.TLSSubjectDN)} {
		low := strings.ToLower(cn)
		if strings.Contains(low, "honeypot") || strings.Contains(low, "canary") || strings.Contains(low, "decoy") {
			a.markHoneypot("TLS certificate advertises 'honeypot/canary/decoy'")
			return
		}
	}

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

	if strings.HasPrefix(sshBanner, "http/") {
		a.markHoneypot("SSH banner is an HTTP response (single ACK-all handler)")
		return
	}

	for _, v := range []string{server, title, sshBanner} {
		if len(v) > 200 || strings.Count(v, ",") >= 4 {
			a.markHoneypot("oversized/multi-token banner (signature-DB dump)")
			return
		}
	}

	if t.IsOpen(53568, "tcp") && t.IsOpen(4679, "tcp") && t.IsOpen(4680, "tcp") {
		a.markHoneypot("implausible CyberPower+Eaton mgmt port triad (4679+4680+53568)")
		return
	}

	if reason := detectContradictoryBMCFamily(a); reason != "" {
		a.markHoneypot(reason)
		return
	}

	if n := t.OpenLen(); n >= honeypotPortBreadthThreshold {
		a.markHoneypot(honeypotBreadthReason(n))
		return
	}
}

func detectContradictoryBMCFamily(a *acc) string {
	families := map[string]string{}

	if a.attrVal("idrac.fw") != "" || a.attrVal("idrac.version") != "" || a.attrVal("dell.service_tag") != "" ||
		strings.EqualFold(a.attrVal("redfish.vendor"), "dell") {
		families["dell.idrac"] = "idrac/redfish-dell"
	}

	if a.attrVal("ilo.fw") != "" || a.attrVal("ilo.serial") != "" ||
		strings.EqualFold(a.attrVal("redfish.vendor"), "hpe") ||
		strings.EqualFold(a.attrVal("redfish.vendor"), "hp") {
		families["hpe.ilo"] = "ilo/redfish-hpe"
	}

	if strings.EqualFold(a.attrVal("redfish.vendor"), "supermicro") ||
		strings.EqualFold(a.attrVal("redfish.vendor"), "aten") {
		families["supermicro"] = "redfish-supermicro"
	}

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

func ReclassifyHoneypotByBreadth(t *engine.Target) bool {
	if t == nil || t.Identity == nil {
		return false
	}
	if t.Identity.Class == engine.ClassHoneypot {
		return false
	}
	n := t.OpenLen()
	if n < honeypotPortBreadthThreshold {
		return false
	}
	markIdentityHoneypot(t.Identity, honeypotBreadthReason(n))
	return true
}

func Identify(ctx context.Context, t *engine.Target, logf func(string)) *engine.Identity {
	a := newAcc()
	a.logf = logf

	ictx, cancel := context.WithTimeout(ctx, identifyBudget(t))
	defer cancel()

	phase1 := []func(*engine.Target, *acc){collectIPMI}

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

	phase1 = append(phase1, collectSNMP)

	phase1 = append(phase1, collectSSH)

	phase1 = append(phase1,
		mgmtSoftwareProbe(53568, "https"),
		mgmtSoftwareProbe(4680, "https"),
		mgmtSoftwareProbe(4679, "http"),
	)
	runCollectors(ictx, t, a, phase1)

	a.foldFingerprint()
	tentative := ""
	if best := a.pick(); best != nil {
		tentative = best.vendor
	}

	detectHoneypot(t, a)

	budgetLeft := ictx.Err() == nil
	var phase2 []func(*engine.Target, *acc)
	if budgetLeft && !a.honeypot && webUp && (tentative == "" || tentative == "dell") {
		phase2 = append(phase2, collectIDRAC)
	}
	if budgetLeft && !a.honeypot && webUp && (tentative == "" || tentative == "hpe") {
		phase2 = append(phase2, collectILO)
	}

	if !budgetLeft && !a.honeypot && webUp && (tentative == "" || tentative == "dell" || tentative == "hpe") {
		a.setAttr("identify.phase2Skipped", "budget-exhausted")
	}
	if a.logf != nil {
		a.log(fmt.Sprintf("phase1 vendor=%q honeypot=%v budgetLeft=%v; phase2=%d probe(s)", tentative, a.honeypot, budgetLeft, len(phase2)))
	}
	runCollectors(ictx, t, a, phase2)

	if !a.honeypot {
		detectHoneypot(t, a)
	}

	id := a.resolve()

	if id.Class != engine.ClassHoneypot {
		refineGeneration(t, id)
	}
	seedExplicitWebPort(t, id)
	return id
}

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

		id.Attributes["web.scheme"] = netaddr.DefaultScheme(resolvedWebPort(id, t.WebPort))
	}
}

func resolvedWebPort(id *engine.Identity, def int) int {
	if n, err := strconv.Atoi(id.Attributes["web.port"]); err == nil && n > 0 {
		return n
	}
	return def
}

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

func (a *acc) resolve() *engine.Identity {

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

	if state.honeypot {
		markIdentityHoneypot(id, state.honeypotWhy)
		return id
	}

	switch {
	case state.forcedClass != "" && (best == nil || confRank[best.conf] < confRank[engine.ConfHigh]):
		id.Class = state.forcedClass
	default:

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

		if (ci.generation != "") != (cj.generation != "") {
			return ci.generation != ""
		}

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
