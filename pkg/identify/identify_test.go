package identify

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/bmcfp"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/redfish"
)

func TestResolvePrefersHighConfidenceProduct(t *testing.T) {
	a := newAcc()
	a.ipmiUp = true
	a.addVendor("Super Micro Computer", "", "", engine.ConfMedium, "ipmi.deviceId") // slug: supermicro
	a.addVendor("Dell Inc.", "iDRAC9", "9", engine.ConfHigh, "idrac")               // slug: dell
	id := a.resolve()
	if id.Vendor != "dell" || id.Product != "iDRAC9" {
		t.Fatalf("resolved %s/%s, want dell/iDRAC9", id.Vendor, id.Product)
	}
	if id.Class != engine.ClassBMC {
		t.Errorf("class = %s, want bmc", id.Class)
	}
}

func TestResolveUnknownButIPMIUp(t *testing.T) {
	a := newAcc()
	a.ipmiUp = true
	id := a.resolve()
	if id.Class != engine.ClassBMC {
		t.Errorf("IPMI-reachable unknown vendor should be bmc, got %s", id.Class)
	}
	if id.Confidence != engine.ConfLow {
		t.Errorf("confidence = %s, want low", id.Confidence)
	}
}

func TestOpenBMCCipherSuiteOnlyIsAdvisoryOnly(t *testing.T) {
	// The predicate still recognizes the suite-17-only shape (used to set a triage
	// attribute)...
	if !openBMCCipherSuiteOnly([]int{17}) {
		t.Fatal("suite 17 only should be recognized as an OpenBMC triage candidate")
	}
	for _, ids := range [][]int{{}, {3}, {3, 17}, {17, 3}} {
		if openBMCCipherSuiteOnly(ids) {
			t.Fatalf("cipher suites %v should not be an OpenBMC-only candidate", ids)
		}
	}

	// ...but suite-17-only no longer casts an OpenBMC vendor vote: suite 17 is
	// common on modern non-OpenBMC BMCs, and identify now records a confirmed
	// suite 17 into ipmi.ciphers for any SHA256-capable 2.0 host whose sessionless
	// enumeration was empty. A host whose only signal is IPMI-up plus the
	// suite-17-only candidate attribute must not resolve to openbmc.
	a := newAcc()
	a.ipmiUp = true
	a.setAttr("ipmi.openbmcCandidate", "suite17Only")
	id := a.resolve()
	if id.Vendor == "openbmc" {
		t.Fatalf("suite-17-only must not label a host openbmc by itself; resolved vendor=%q", id.Vendor)
	}
}

// rmcpPlusSuiteForAlgo maps the confirmed RAKP auth algorithm (from an accepted
// RMCP+ Open Session) to the cipher suite ID recorded in ipmi.ciphers when the
// sessionless enumeration was empty.
func TestRMCPPlusSuiteForAlgo(t *testing.T) {
	cases := []struct {
		algo byte
		want []int
	}{
		{ipmi.RAKPHMACSHA256, []int{17}},
		{ipmi.RAKPHMACSHA1, []int{3}},
		{ipmi.RAKPHMACMD5, nil},
		{0xff, nil},
	}
	for _, c := range cases {
		got := rmcpPlusSuiteForAlgo(c.algo)
		if !slices.Equal(got, c.want) {
			t.Fatalf("rmcpPlusSuiteForAlgo(0x%02x) = %v, want %v", c.algo, got, c.want)
		}
	}
}

func TestForcedClassSerialConsole(t *testing.T) {
	a := newAcc()
	a.forcedClass = engine.ClassSerialConsole
	a.addVendor("lantronix", "XPort", "", engine.ConfHigh, "lantronix")
	id := a.resolve()
	if id.Class != engine.ClassSerialConsole {
		t.Errorf("class = %s, want serial", id.Class)
	}
}

func TestDetectHoneypotPortTriad(t *testing.T) {
	// CyberPower (53568) + Eaton (4679+4680) all responding on one host is the
	// deception-grid signature; the honeypot verdict must override even a
	// high-confidence redfish vendor guess (the emulated BMC surface).
	tgt := &engine.Target{Host: "192.0.2.1"}
	tgt.MarkOpen(4679, "tcp", "http")
	tgt.MarkOpen(4680, "tcp", "https")
	tgt.MarkOpen(53568, "tcp", "https")
	a := newAcc()
	a.addVendor("ami", "", "", engine.ConfHigh, "redfish")
	detectHoneypot(tgt, a)
	id := a.resolve()
	if id.Class != engine.ClassHoneypot {
		t.Fatalf("class = %s, want honeypot", id.Class)
	}
	if id.Attributes["honeypot"] == "" {
		t.Error("honeypot reason not recorded on identity")
	}
}

func TestDetectHoneypotTLSAndTitle(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*acc)
	}{
		{"tls-cn", func(a *acc) { a.addFP(bmcfp.TLSSubjectCN, "honeypot") }},
		{"placeholder-title", func(a *acc) { a.setAttr("http.title", "user's Wiki!") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newAcc()
			tc.setup(a)
			detectHoneypot(&engine.Target{Host: "192.0.2.2"}, a)
			if !a.honeypot {
				t.Fatalf("%s should flag honeypot", tc.name)
			}
		})
	}
}

func TestDetectHoneypotNegative(t *testing.T) {
	// A real BMC: IPMI up, a single legit Eaton port, benign title. Must not trip.
	tgt := &engine.Target{Host: "192.0.2.3"}
	tgt.MarkOpen(4680, "tcp", "https")
	a := newAcc()
	a.ipmiUp = true
	a.setAttr("http.title", "OpenBMC Web UI")
	detectHoneypot(tgt, a)
	if a.honeypot {
		t.Fatalf("legit host wrongly flagged honeypot: %s", a.honeypotWhy)
	}
	if id := a.resolve(); id.Class != engine.ClassBMC {
		t.Errorf("class = %s, want bmc", id.Class)
	}
}

func TestDetectHoneypotDecoyServerHeader(t *testing.T) {
	for _, tc := range []struct{ name, server string }{
		{"cowrie", "Cowrie SSH Honeypot 2.0"},
		{"dionaea", "dionaea/0.5.0"},
		{"conpot", "ConPot 0.6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newAcc()
			a.setAttr("http.server", tc.server)
			detectHoneypot(&engine.Target{Host: "192.0.2.4"}, a)
			if !a.honeypot {
				t.Fatalf("%s server header should flag honeypot", tc.server)
			}
		})
	}
}

func TestDetectHoneypotDecoySSHBanner(t *testing.T) {
	a := newAcc()
	tgt := &engine.Target{Host: "192.0.2.5"}
	tgt.SetEvidence("ssh.banner", "SSH-2.0-Cowrie-honeypot")
	detectHoneypot(tgt, a)
	if !a.honeypot {
		t.Fatalf("cowrie SSH banner should flag honeypot")
	}
}

func TestDetectHoneypotContradictoryBMCFamily(t *testing.T) {
	// A single host that responds as both iDRAC and iLO cannot be real.
	a := newAcc()
	a.setAttr("idrac.fw", "6.10.30.00")
	a.setAttr("ilo.fw", "iLO 5 v3.10")
	detectHoneypot(&engine.Target{Host: "192.0.2.6"}, a)
	if !a.honeypot {
		t.Fatalf("iDRAC + iLO on one host should flag honeypot: reason=%q", a.honeypotWhy)
	}
	if !strings.Contains(a.honeypotWhy, "contradictory") {
		t.Errorf("reason should mention contradictory: %q", a.honeypotWhy)
	}
}

// TestDetectHoneypotPortBreadth covers the heuristic-7 rule in isolation: >=12
// open ports flags an ACK-all tarpit, while a real BMC at the 11-port ceiling
// must not trip. This is the post-hoc, port-map-already-full check; it does not
// exercise the identify->battery ordering that made the rule inert in production
// (that is TestReclassifyHoneypotByBreadthLivePath below).
func TestDetectHoneypotPortBreadth(t *testing.T) {
	// 12 open ports -> honeypot.
	tgt := &engine.Target{Host: "192.0.2.20"}
	for _, p := range []int{22, 80, 443, 623, 2068, 3900, 5120, 5900, 7578, 8000, 8080, 9443} {
		tgt.MarkOpen(p, "tcp", "svc")
	}
	a := newAcc()
	detectHoneypot(tgt, a)
	if !a.honeypot {
		t.Fatalf("12-port host should flag honeypot")
	}
	if !strings.Contains(a.honeypotWhy, "open-port breadth") {
		t.Errorf("reason should mention open-port breadth: %q", a.honeypotWhy)
	}

	// 11 ports (the observed real-BMC ceiling) -> must not flag.
	tgt2 := &engine.Target{Host: "192.0.2.21"}
	for _, p := range []int{22, 80, 443, 623, 5900, 5988, 8000, 8080, 9443, 17990, 2068} {
		tgt2.MarkOpen(p, "tcp", "svc")
	}
	a2 := newAcc()
	a2.ipmiUp = true
	detectHoneypot(tgt2, a2)
	if a2.honeypot {
		t.Fatalf("11-port host wrongly flagged honeypot: %s", a2.honeypotWhy)
	}
}

// TestReclassifyHoneypotByBreadthLivePath guards the ordering that makes
// heuristic 7 work: detectHoneypot runs during identify, before the check battery
// calls MarkOpen, so it reads a nearly-empty port map and cannot see the ports a
// tarpit answers only once the battery probes them. The test reuses one target to
// walk that sequence: prove the identify-time detector stays quiet, then fill the
// map the way the battery would and prove the post-battery pass catches it.
func TestReclassifyHoneypotByBreadthLivePath(t *testing.T) {
	// Identity as identify would leave a bare ACK-all tarpit: unattributed.
	tgt := &engine.Target{
		Host:     "192.0.2.30",
		Identity: &engine.Identity{Class: engine.ClassUnknown, Confidence: engine.ConfLow},
	}
	// Ports known at identify time: only the few the identify probes touched
	// (well under the threshold). This is the map detectHoneypot actually sees.
	for _, p := range []int{443, 623} {
		tgt.MarkOpen(p, "tcp", "svc")
	}
	a := newAcc()
	detectHoneypot(tgt, a)
	if a.honeypot {
		t.Fatalf("identify-time detector wrongly flagged a 2-port map: %s", a.honeypotWhy)
	}
	if ReclassifyHoneypotByBreadth(tgt) {
		t.Fatal("breadth reclassification fired on a 2-port map")
	}

	// Now the battery runs and MarkOpen balloons the surface past the threshold,
	// exactly as an ACK-all tarpit answers every probed port.
	for _, p := range []int{22, 23, 80, 2068, 3900, 5120, 5900, 7578, 10001, 10002} {
		tgt.MarkOpen(p, "tcp", "svc")
	}
	if got := tgt.OpenLen(); got < honeypotPortBreadthThreshold {
		t.Fatalf("test setup: OpenLen=%d, want >=%d", got, honeypotPortBreadthThreshold)
	}
	if !ReclassifyHoneypotByBreadth(tgt) {
		t.Fatal("breadth reclassification did NOT fire on the final >=12-port map")
	}
	if tgt.Identity.Class != engine.ClassHoneypot {
		t.Fatalf("class = %s, want honeypot", tgt.Identity.Class)
	}
	if tgt.Identity.Confidence != engine.ConfHigh {
		t.Errorf("confidence = %s, want high", tgt.Identity.Confidence)
	}
	if why := tgt.Identity.Attributes["honeypot"]; !strings.Contains(why, "open-port breadth") {
		t.Errorf("honeypot reason = %q, want it to mention open-port breadth", why)
	}
}

// TestReclassifyHoneypotByBreadthBelowThreshold confirms the real-BMC ceiling is
// untouched: a host at 11 open ports (the observed maximum for a real device) is
// not reclassified even on the final port map.
func TestReclassifyHoneypotByBreadthBelowThreshold(t *testing.T) {
	tgt := &engine.Target{
		Host:     "192.0.2.31",
		Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "supermicro", Confidence: engine.ConfHigh},
	}
	for _, p := range []int{22, 80, 443, 623, 5900, 5988, 8000, 8080, 9443, 17990, 2068} {
		tgt.MarkOpen(p, "tcp", "svc")
	}
	if tgt.OpenLen() != honeypotPortBreadthThreshold-1 {
		t.Fatalf("test setup: OpenLen=%d, want %d", tgt.OpenLen(), honeypotPortBreadthThreshold-1)
	}
	if ReclassifyHoneypotByBreadth(tgt) {
		t.Fatal("11-port host wrongly reclassified as honeypot")
	}
	if tgt.Identity.Class != engine.ClassBMC {
		t.Fatalf("class = %s, want bmc (unchanged)", tgt.Identity.Class)
	}
}

// TestReclassifyHoneypotByBreadthKeepsIdentifyVerdict confirms a host already
// flagged during identify (by a more specific heuristic) is left alone: no
// re-flag, and its original, more-informative reason is preserved.
func TestReclassifyHoneypotByBreadthKeepsIdentifyVerdict(t *testing.T) {
	const orig = "known honeypot SSH banner (cowrie)"
	tgt := &engine.Target{
		Host: "192.0.2.32",
		Identity: &engine.Identity{
			Class:      engine.ClassHoneypot,
			Confidence: engine.ConfHigh,
			Attributes: map[string]string{"honeypot": orig},
		},
	}
	for p := 1; p <= 20; p++ {
		tgt.MarkOpen(p, "tcp", "svc")
	}
	if ReclassifyHoneypotByBreadth(tgt) {
		t.Fatal("already-honeypot host should not be reclassified again")
	}
	if why := tgt.Identity.Attributes["honeypot"]; why != orig {
		t.Errorf("honeypot reason = %q, want the original identify-time reason %q", why, orig)
	}
}

// TestReclassifyHoneypotByBreadthRewritesNoiseAttrs confirms the shared honeypot
// conversion also runs on the late path: a fingerprint attribute a fleet indexer
// would treat as a genuine management signal is re-prefixed under honeypot.attr.*
// so a decoy caught late looks identical to one caught during identify.
func TestReclassifyHoneypotByBreadthRewritesNoiseAttrs(t *testing.T) {
	tgt := &engine.Target{
		Host: "192.0.2.33",
		Identity: &engine.Identity{
			Class:      engine.ClassUnknown,
			Confidence: engine.ConfLow,
			Attributes: map[string]string{"redfish.vendor": "dell", "http.server": "nginx"},
		},
	}
	for p := 1; p <= 12; p++ {
		tgt.MarkOpen(p, "tcp", "svc")
	}
	if !ReclassifyHoneypotByBreadth(tgt) {
		t.Fatal("12-port host should reclassify as honeypot")
	}
	attrs := tgt.Identity.Attributes
	if _, ok := attrs["redfish.vendor"]; ok {
		t.Error("redfish.vendor should have been re-prefixed, not left as a real signal")
	}
	if attrs["honeypot.attr.redfish.vendor"] != "dell" {
		t.Errorf("redfish.vendor not moved to honeypot.attr.*: %v", attrs)
	}
	// Surface metadata (http.server) is deliberately left alone for triage.
	if attrs["http.server"] != "nginx" {
		t.Errorf("http.server should be preserved, got %q", attrs["http.server"])
	}
}

// TestDetectHoneypotSSHIsHTTP covers heuristic 8: an SSH banner that is an HTTP
// response is a single ACK-all handler; a real "SSH-" banner must not trip.
func TestDetectHoneypotSSHIsHTTP(t *testing.T) {
	a := newAcc()
	tgt := &engine.Target{Host: "192.0.2.22"}
	tgt.SetEvidence("ssh.banner", "HTTP/1.1 400 Bad Request")
	detectHoneypot(tgt, a)
	if !a.honeypot {
		t.Fatalf("HTTP-response SSH banner should flag honeypot")
	}

	a2 := newAcc()
	tgt2 := &engine.Target{Host: "192.0.2.23"}
	tgt2.SetEvidence("ssh.banner", "SSH-2.0-OpenSSH_8.9p1 Ubuntu")
	detectHoneypot(tgt2, a2)
	if a2.honeypot {
		t.Fatalf("real SSH banner wrongly flagged honeypot: %s", a2.honeypotWhy)
	}
}

// TestDetectHoneypotBannerBlob covers heuristic 9: a signature-DB dump (very
// long or many-comma banner) flags, but a normal multi-module header does not.
func TestDetectHoneypotBannerBlob(t *testing.T) {
	a := newAcc()
	a.setAttr("http.server", "360 web server, Boa, GoAhead, lighttpd, nginx, Apache, iRMC S4, iLO 5")
	detectHoneypot(&engine.Target{Host: "192.0.2.24"}, a)
	if !a.honeypot {
		t.Fatalf("multi-comma signature-DB banner should flag honeypot")
	}

	// A legitimate 2-comma multi-module Server header must not trip.
	a2 := newAcc()
	a2.ipmiUp = true
	a2.setAttr("http.server", "Linux-i386-2.6.33.2, UPnP/1.0, PMS/1.21.1")
	detectHoneypot(&engine.Target{Host: "192.0.2.25"}, a2)
	if a2.honeypot {
		t.Fatalf("legit multi-module Server header wrongly flagged: %s", a2.honeypotWhy)
	}
}

// TestDetectHoneypotWSManNormalBehaviorNotFlagged guards the deliberate
// decision not to treat an all-zero WSMan OS version or an RFC1918 WS-Discovery
// address as a honeypot tell: the pre-auth WSMan Identify legitimately returns
// 0.0.0 on many stacks, and NAT'd devices legitimately advertise their own
// private WS-Discovery address. Neither may flag a host on its own.
func TestDetectHoneypotWSManNormalBehaviorNotFlagged(t *testing.T) {
	a := newAcc()
	a.setAttr("wsman.product", "OS: 0.0.0 SP: 0.0 Stack: 3.0")
	detectHoneypot(&engine.Target{Host: "192.0.2.26"}, a)
	if a.honeypot {
		t.Fatalf("all-zero WSMan OS version is normal, must NOT flag honeypot: %s", a.honeypotWhy)
	}

	a2 := newAcc()
	a2.setAttr("wsdiscovery.xaddrs", "http://192.168.1.1:3702/ onvif")
	detectHoneypot(&engine.Target{Host: "192.0.2.27"}, a2)
	if a2.honeypot {
		t.Fatalf("RFC1918 WS-Discovery address is normal for NAT'd devices, must NOT flag: %s", a2.honeypotWhy)
	}
}

func TestHTMLTitle(t *testing.T) {
	body := []byte(`<html><head><meta><title>OpenBMC Web UI</title></head><body>`)
	if got := htmlTitle(body); got != "OpenBMC Web UI" {
		t.Errorf("htmlTitle = %q, want %q", got, "OpenBMC Web UI")
	}
	if got := htmlTitle([]byte("<html>no title</html>")); got != "" {
		t.Errorf("htmlTitle(no title) = %q, want empty", got)
	}
}

// TestOpenBMCTitleResolves proves an OpenBMC SPA (identified only by its title)
// resolves to the openbmc vendor and BMC class, outranking a weaker HTTP guess.
func TestOpenBMCTitleResolves(t *testing.T) {
	a := newAcc()
	a.ipmiUp = true
	a.addVendor("asrockrack", "MegaRAC-SP", "", engine.ConfMedium, "http") // httpscan's wrong guess
	a.addFP(bmcfp.HTMLTitle, "OpenBMC Web UI")                             // fed by collectWeb
	id := a.resolve()
	if id.Vendor != "openbmc" {
		t.Errorf("resolved vendor = %q, want openbmc", id.Vendor)
	}
	if id.Class != engine.ClassBMC {
		t.Errorf("class = %q, want bmc", id.Class)
	}
}

func TestSpiderTitleResolvesLantronixKVM(t *testing.T) {
	a := newAcc()
	a.addVendor("lantronix", "", "", engine.ConfLow, "snmp")
	a.addFP(bmcfp.HTTPServerHeader, "GoAhead-Webs")
	a.addFP(bmcfp.HTMLTitle, "Spider Authentication")
	id := a.resolve()
	if id.Vendor != "lantronix" || id.Product != "SecureLinx Spider" {
		t.Fatalf("resolved %s/%s, want lantronix/SecureLinx Spider", id.Vendor, id.Product)
	}
	if id.Class != engine.ClassKVM {
		t.Errorf("class = %s, want kvm", id.Class)
	}
}

func TestRedfishVendorOpenBMC(t *testing.T) {
	// Real OpenBMC service root: no Oem block, manager id "bmc".
	root := []byte(`{
	  "Id": "RootService", "Name": "Root Service", "RedfishVersion": "1.17.0",
	  "Links": { "ManagerProvidingService": { "@odata.id": "/redfish/v1/Managers/bmc" } }
	}`)
	var sr redfish.ServiceRoot
	if err := json.Unmarshal(root, &sr); err != nil {
		t.Fatal(err)
	}
	res := &redfish.Result{Status: 200, ServiceRoot: &sr, RawRoot: root}
	if v, p := redfishVendor(res); v != "openbmc" || p != "OpenBMC" {
		t.Errorf("redfishVendor = %q/%q, want openbmc/OpenBMC", v, p)
	}
}

func TestRedfishVendorOem(t *testing.T) {
	var sr redfish.ServiceRoot
	_ = json.Unmarshal([]byte(`{"Oem":{"Dell":{"x":1}}}`), &sr)
	if v, _ := redfishVendor(&redfish.Result{ServiceRoot: &sr}); v != "dell" {
		t.Errorf("Dell Oem -> %q, want dell", v)
	}
}

func TestCollectRedfish_ConfiguredPortAndAttrs(t *testing.T) {
	h := http.NewServeMux()
	root := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Id":"RootService","RedfishVersion":"1.17.0","UUID":"abc-123","Vendor":"OpenBMC","Product":"bmcweb","Links":{"ManagerProvidingService":{"@odata.id":"/redfish/v1/Managers/bmc"}}}`))
	}
	h.HandleFunc("/redfish/v1/", root)
	h.HandleFunc("/redfish/v1", root)
	h.HandleFunc("/redfish/v1/Managers/bmc", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"FirmwareVersion":"2.14.0"}`))
	})
	srv := httptest.NewTLSServer(h)
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split hostport: %v", err)
	}
	port, _ := strconv.Atoi(portStr)
	tg := &engine.Target{Host: host, Timeout: 2 * time.Second, Ports: []engine.Port{{Num: port, Proto: engine.ProtoTCP}}}
	a := newAcc()
	collectRedfish(tg, a)

	v, ok := tg.Evidenced("redfish")
	if !ok || v == nil {
		t.Fatal("expected redfish evidence")
	}
	if !tg.IsOpen(port, "tcp") {
		t.Fatalf("expected redfish port %d marked open", port)
	}
	if got := a.attrVal("redfish.version"); got != "1.17.0" {
		t.Fatalf("redfish.version=%q want 1.17.0", got)
	}
	if got := a.attrVal("redfish.fw"); got != "2.14.0" {
		t.Fatalf("redfish.fw=%q want 2.14.0", got)
	}
}

// TestIdentifyRecordsExplicitWebPort proves that an operator-named non-standard
// web port (a `scan host:8643` arg or --web-port, carried on Target.WebPort) is
// probed by identify and recorded as web.port/web.scheme, so downstream web
// checks (webPort/webProto) target that port instead of falling back to 443.
func TestIdentifyRecordsExplicitWebPort(t *testing.T) {
	h := http.NewServeMux()
	h.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "test-web")
		_, _ = w.Write([]byte(`<html><head><title>Supermicro BMC Login</title></head><body></body></html>`))
	})
	srv := httptest.NewTLSServer(h)
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split hostport: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	tg := &engine.Target{Host: host, WebPort: port, Timeout: 500 * time.Millisecond}
	id := Identify(context.Background(), tg, nil)
	if id == nil || id.Attributes == nil {
		t.Fatal("Identify returned no attributes")
	}
	if got := id.Attributes["web.port"]; got != portStr {
		t.Fatalf("web.port=%q, want the explicit port %q (not the 443 fallback)", got, portStr)
	}
	if got := id.Attributes["web.scheme"]; got != "https" {
		t.Fatalf("web.scheme=%q, want https", got)
	}
}

// TestSeedExplicitWebPortFallback proves the seed step records the explicit web
// port even when no live web probe determined a scheme (e.g. the port answered
// neither http nor https), and that an already-probed web.port is preserved.
func TestSeedExplicitWebPortFallback(t *testing.T) {
	// No probed web.port: seed from the explicit hint, guessing the scheme.
	tg := &engine.Target{Host: "192.0.2.10", WebPort: 8643}
	id := &engine.Identity{}
	seedExplicitWebPort(tg, id)
	if id.Attributes["web.port"] != "8643" || id.Attributes["web.scheme"] != "https" {
		t.Fatalf("seed: web.port=%q web.scheme=%q, want 8643/https", id.Attributes["web.port"], id.Attributes["web.scheme"])
	}
	// A probed web.port/scheme wins over the bare hint.
	tg2 := &engine.Target{Host: "192.0.2.11", WebPort: 8643}
	id2 := &engine.Identity{Attributes: map[string]string{"web.port": "80", "web.scheme": "http"}}
	seedExplicitWebPort(tg2, id2)
	if id2.Attributes["web.port"] != "80" || id2.Attributes["web.scheme"] != "http" {
		t.Fatalf("seed clobbered probed port: web.port=%q web.scheme=%q, want 80/http", id2.Attributes["web.port"], id2.Attributes["web.scheme"])
	}
}

// TestFoldAdvantechEKIRealm proves the Basic-auth realm disambiguates an
// Advantech EKI serial device server from the many embedded stacks that share
// its Boa web server: pre-auth the EKI only names itself in
// realm="EKI-<model>", so the WWWAuthenticate fingerprint must carry it to a
// confident advantech/serialConsole identity.
func TestFoldAdvantechEKIRealm(t *testing.T) {
	a := newAcc()
	a.addFP(bmcfp.HTTPServerHeader, "Boa/0.93.15")
	a.addFP(bmcfp.WWWAuthenticate, `Basic realm="EKI-1524-CE"`)
	id := a.resolve()
	if id.Vendor != "advantech" {
		t.Fatalf("vendor=%q, want advantech (EKI realm must win over the shared Boa header)", id.Vendor)
	}
	if id.Class != engine.ClassSerialConsole {
		t.Errorf("class=%s, want serial", id.Class)
	}
	if confRank[id.Confidence] < confRank[engine.ConfMedium] {
		t.Errorf("confidence=%s, want >= medium for a model-specific realm", id.Confidence)
	}
}

// TestFoldAdvantechEKITitle proves the authenticated page title
// "EKI-<model> Web Server" also attributes advantech (the fail-open / post-auth
// path where the model reaches the <title> rather than only the realm).
func TestFoldAdvantechEKITitle(t *testing.T) {
	a := newAcc()
	a.addFP(bmcfp.HTTPServerHeader, "Boa/0.93.15")
	a.addFP(bmcfp.HTMLTitle, "EKI-1524-CE Web Server")
	id := a.resolve()
	if id.Vendor != "advantech" {
		t.Fatalf("vendor=%q, want advantech from the EKI web-server title", id.Vendor)
	}
}

// TestFoldBareBoaNotSupermicro is the disambiguation guard: a bare Boa/0.93.15
// web tier with no EKI-specific realm/title (Boa is shared with the legacy SMC
// X10 ATEN stack and countless embedded devices) must not be attributed to any
// vendor from the Server header alone -- least of all supermicro at high
// confidence. It stays unknown until a corroborating signal appears.
func TestFoldBareBoaNotSupermicro(t *testing.T) {
	a := newAcc()
	a.addFP(bmcfp.HTTPServerHeader, "Boa/0.93.15")
	a.addFP(bmcfp.WWWAuthenticate, `Basic realm="index.html"`) // generic realm, not EKI
	id := a.resolve()
	if id.Vendor == "supermicro" {
		t.Fatalf("bare Boa attributed to supermicro; want no Server-header-only vendor")
	}
	if id.Vendor != "" {
		t.Fatalf("vendor=%q, want empty (bare Boa is not vendor-specific)", id.Vendor)
	}
}

// TestCollectWebAdvantechEKI verifies that collectWeb feeds the EKI realm into
// the fingerprint fold without probing unrelated services on the test host.
func TestCollectWebAdvantechEKI(t *testing.T) {
	h := http.NewServeMux()
	h.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Boa/0.93.15")
		w.Header().Set("WWW-Authenticate", `Basic realm="EKI-1524-CE"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("<html><head><title>401 Unauthorized</title></head><body></body></html>"))
	})
	srv := httptest.NewServer(h) // Boa serves plain HTTP, like the real EKI
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split hostport: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	tg := &engine.Target{Host: host, WebPort: port, Timeout: 2 * time.Second}
	a := newAcc()
	collectWeb(tg, a)
	id := a.resolve()
	if id == nil {
		t.Fatal("Identify returned nil")
	}
	if id.Vendor != "advantech" {
		t.Fatalf("vendor=%q, want advantech (EKI realm fed from the 401 challenge)", id.Vendor)
	}
	if id.Class != engine.ClassSerialConsole {
		t.Errorf("class=%s, want serial", id.Class)
	}
	if got := id.Attributes["http.wwwauth"]; !strings.Contains(got, "EKI-1524-CE") {
		t.Errorf("http.wwwauth=%q, want it to record the EKI realm", got)
	}
}

func TestClassForVendorProduct(t *testing.T) {
	if c, ok := classForVendorProduct("dell", "iDRAC9"); !ok || c != engine.ClassBMC {
		t.Errorf("dell/iDRAC9 -> %s ok=%v, want bmc", c, ok)
	}
	if _, ok := classForVendorProduct("nonesuch", ""); ok {
		t.Error("unknown vendor should not resolve")
	}
	// A Raritan PX PDU (bmcfp emits product "PX") must class as pdu, not fall
	// through to the Dominion KX entry and mis-class as kvm.
	if c, ok := classForVendorProduct("raritan", "PX"); !ok || c != engine.ClassPDU {
		t.Errorf("raritan/PX -> %s ok=%v, want pdu (regressed PX-PDU mis-class)", c, ok)
	}
}

// TestRunCollectorsRespectsBudget verifies that a timed-out collector neither
// blocks identification nor mutates an identity resolved from the accumulator.
func TestRunCollectorsRespectsBudget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	a := newAcc()
	tgt := &engine.Target{Host: "192.0.2.1", Timeout: time.Second}
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	slow := func(_ *engine.Target, late *acc) {
		close(started)
		<-release
		late.setAttr("late.result", "ignored")
		late.addVendor("dell", "late result", "", engine.ConfHigh, "test")
		close(finished)
	}
	done := make(chan struct{})
	start := time.Now()
	go func() { runCollectors(ctx, tgt, a, []func(*engine.Target, *acc){slow}); close(done) }()
	select {
	case <-done:
		if el := time.Since(start); el > time.Second {
			t.Fatalf("runCollectors blocked %v; want to abandon the straggler near the 150ms budget", el)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runCollectors did not return after the ctx budget elapsed (straggler blocked it)")
	}
	<-started
	id := a.resolve()
	close(release)
	<-finished
	if _, ok := id.Attributes["late.result"]; ok {
		t.Error("late collector mutated resolved identity attributes")
	}
	if id.Vendor != "" {
		t.Errorf("resolved vendor = %q, want empty before late collector result", id.Vendor)
	}
}

// TestIdentifyBudgetBounds sanity-checks the budget/timeout helpers so the
// fail-fast contract (bounded identify, modest per-probe web timeout) can't
// silently regress into the minutes-long stalls we observed on locked-out ATEN
// boards.
func TestIdentifyBudgetBounds(t *testing.T) {
	def := &engine.Target{Timeout: 4 * time.Second}
	// Large enough that phase 2 is reached, but still bounded: this runs on every host,
	// so the cap keeps a locked-out ATEN board from stalling for minutes, and every
	// second here is paid once per host across the whole scan.
	if got := identifyBudget(def); got != 20*time.Second {
		t.Fatalf("identifyBudget(default 4s)=%v, want 20s", got)
	}
	if got := webIdentifyTimeout(def); got != 8*time.Second {
		t.Fatalf("webIdentifyTimeout(default 4s)=%v, want 8s", got)
	}
	wide := &engine.Target{Timeout: 30 * time.Second}
	if got := identifyBudget(wide); got != 30*time.Second {
		t.Fatalf("identifyBudget(wide 30s)=%v, want cap 30s", got)
	}
	if got := webIdentifyTimeout(wide); got != 10*time.Second {
		t.Fatalf("webIdentifyTimeout(wide 30s)=%v, want cap 10s", got)
	}
}

// TestPickCandidatePrefersGeneration pins the tie-break that decides whether a
// probed generation survives. collectRedfish contributes ("hpe","iLO","") and
// collectILO contributes ("hpe","iLO4","iLO4") -- both ConfHigh, and "redfish"
// and "ilo" share source-priority tier 1, so before this rule the winner was
// decided by concurrent append order and the generation was frequently lost.
func TestPickCandidatePrefersGeneration(t *testing.T) {
	generic := candidate{"hpe", "iLO", "", engine.ConfHigh, "redfish"}
	specific := candidate{"hpe", "iLO4", "iLO4", engine.ConfHigh, "ilo"}

	// Must win regardless of append order.
	for _, cands := range [][]candidate{
		{generic, specific},
		{specific, generic},
	} {
		got := pickCandidate(cands)
		if got == nil {
			t.Fatal("pickCandidate returned nil")
		}
		if got.generation != "iLO4" || got.product != "iLO4" {
			t.Errorf("picked product=%q generation=%q, want iLO4/iLO4", got.product, got.generation)
		}
	}

	// Confidence still outranks specificity: a low-confidence generation must
	// not beat a high-confidence candidate.
	got := pickCandidate([]candidate{
		{"hpe", "iLO", "", engine.ConfHigh, "redfish"},
		{"hpe", "iLO4", "iLO4", engine.ConfLow, "guid"},
	})
	if got.conf != engine.ConfHigh {
		t.Errorf("confidence was outranked by specificity: got conf=%v", got.conf)
	}
}
