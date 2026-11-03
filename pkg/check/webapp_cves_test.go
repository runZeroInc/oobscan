package check

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// mkTarget builds a Target pointed at an httptest server, with the identity
// attributes the web-port helpers read.
func mkTarget(t *testing.T, srvURL, vendor string) *engine.Target {
	t.Helper()
	hostport := strings.TrimPrefix(srvURL, "http://")
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("split %q: %v", hostport, err)
	}
	// A representative product per vendor so the product-scoped resolvers
	// (ppeTarget/ipmTarget) match; other checks ignore it.
	product := map[string]string{
		"cyberpower": "PowerPanel Enterprise",
		"eaton":      "Intelligent Power Manager (IPM)",
		"lantronix":  "SecureLinx Spider",
	}[vendor]
	return mkTargetWithIdentity(t, host, portStr, vendor, product, map[string]string{"web.port": portStr, "web.scheme": "http"})
}

func mkTargetWithIdentity(t *testing.T, host, portStr, vendor, product string, attrs map[string]string) *engine.Target {
	t.Helper()
	return &engine.Target{
		Host:          host,
		Timeout:       2 * time.Second,
		DisableLogins: false,
		Identity: &engine.Identity{
			Vendor:     vendor,
			Product:    product,
			Attributes: attrs,
		},
	}
}

func hasFinding(fs []engine.Finding, name string) *engine.Finding {
	for i := range fs {
		if fs[i].Check == name {
			return &fs[i]
		}
	}
	return nil
}

func TestCyberPowerPPEMissingAuth(t *testing.T) {
	// Vulnerable: the PDNU REST API returns device credentials unauthenticated.
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/devices" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"success","data":[{"account":"admin","passwd":"s3cr3t"}]}`))
			return
		}
		http.Error(w, "no", http.StatusNotFound)
	}))
	defer vuln.Close()

	got := runCyberPowerPPE(context.Background(), mkTarget(t, vuln.URL, "cyberpower"))
	f := hasFinding(got, "http.cyberpower.ppe.missingAuth")
	if f == nil {
		t.Fatal("expected cyberpower.ppe_missing_auth on a server leaking account/passwd")
	}
	if len(f.CVE) == 0 || f.CVE[0] != "CVE-2024-32735" {
		t.Errorf("CVE = %v, want CVE-2024-32735", f.CVE)
	}

	// Patched: the API requires auth (login page), so nothing is asserted.
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("<html>login</html>"))
	}))
	defer safe.Close()
	if got := runCyberPowerPPE(context.Background(), mkTarget(t, safe.URL, "cyberpower")); len(got) != 0 {
		t.Errorf("expected no findings against an authenticated API, got %d", len(got))
	}
}

func TestCyberPowerPPESQLiDifferential(t *testing.T) {
	// Vulnerable: the balanced UNION injection executes (success), while the
	// unbalanced-quote control errors. That differential is the proof.
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.RawQuery, "UNION") {
			_, _ = w.Write([]byte(`{"success":true,"result":"finished","modifiedtime":"12345"}`))
			return
		}
		// unbalanced quote -> SQL error
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"sql syntax"}`))
	}))
	defer vuln.Close()
	got := runCyberPowerPPE(context.Background(), mkTarget(t, vuln.URL, "cyberpower"))
	if f := hasFinding(got, "http.cyberpower.ppe.sqli"); f == nil {
		t.Fatal("expected cyberpower.ppe_sqli when injection succeeds and control errors")
	}

	// Not vulnerable: the endpoint returns success for everything (the quote is
	// not in a SQL context), so the differential fails and nothing is asserted.
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"result":"finished","modifiedtime":"12345"}`))
	}))
	defer safe.Close()
	if f := hasFinding(runCyberPowerPPE(context.Background(), mkTarget(t, safe.URL, "cyberpower")), "http.cyberpower.ppe.sqli"); f != nil {
		t.Error("SQLi asserted without a differential (control also succeeded) - false positive")
	}
}

func TestEatonIPMLFI(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "node_upgrade_srv.js") && strings.Contains(r.URL.RawQuery, "etc/passwd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"))
			return
		}
		http.Error(w, "no", http.StatusNotFound)
	}))
	defer vuln.Close()
	f := hasFinding(runEatonIPMLFI(context.Background(), mkTarget(t, vuln.URL, "eaton")), "http.eaton.ipmLfi")
	if f == nil {
		t.Fatal("expected eaton.ipm_lfi when traversal returns /etc/passwd")
	}
	if len(f.CVE) == 0 || f.CVE[0] != "CVE-2018-12031" {
		t.Errorf("CVE = %v, want CVE-2018-12031", f.CVE)
	}

	// A 200 that does not return a system file is not a traversal.
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("firmware not found"))
	}))
	defer safe.Close()
	if got := runEatonIPMLFI(context.Background(), mkTarget(t, safe.URL, "eaton")); len(got) != 0 {
		t.Errorf("expected no finding when no system file is returned, got %d", len(got))
	}
}

func TestLantronixSpiderXSS(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte("<html><title>Spider Authentication</title></html>"))
		case "/auth.asp":
			// reflect the nickname param unescaped
			_, _ = w.Write([]byte("<html>hi " + r.URL.Query().Get("nickname") + "</html>"))
		}
	}))
	defer vuln.Close()
	if hasFinding(runLantronixSpiderXSS(context.Background(), mkTarget(t, vuln.URL, "lantronix")), "http.lantronix.spiderXss") == nil {
		t.Fatal("expected lantronix.spider_xss when the payload reflects unescaped")
	}

	// Misattributed identity should still run when title/server fingerprints match
	// Spider.
	hostport := strings.TrimPrefix(vuln.URL, "http://")
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("split %q: %v", hostport, err)
	}
	mis := mkTargetWithIdentity(t, host, portStr, "ami", "MegaRAC", map[string]string{
		"web.port":    portStr,
		"web.scheme":  "http",
		"http.title":  "Spider Authentication",
		"http.server": "GoAhead-Webs",
	})
	if hasFinding(runLantronixSpiderXSS(context.Background(), mis), "http.lantronix.spiderXss") == nil {
		t.Fatal("expected lantronix.spider_xss on Spider title/server even when vendor misattributed")
	}

	// Escaped output is not exploitable -> no finding.
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte("<title>Spider Authentication</title>"))
		case "/auth.asp":
			_, _ = w.Write([]byte("<html>hi &quot;&gt;&lt;style&gt;</html>"))
		}
	}))
	defer safe.Close()
	if got := runLantronixSpiderXSS(context.Background(), mkTarget(t, safe.URL, "lantronix")); len(got) != 0 {
		t.Errorf("expected no finding when payload is escaped, got %d", len(got))
	}
}

func TestGudeDefaultCreds(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if ok && u == "admin" && p == "admin" {
			_, _ = w.Write([]byte("<html><body>Control Panel</body></html>"))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer vuln.Close()
	finding := hasFinding(runGudeDefaultCreds(context.Background(), mkTarget(t, vuln.URL, "gude")), "http.gude.defaultCreds")
	if finding == nil {
		t.Fatal("expected gude.defaultCreds when admin:admin returns the Control Panel")
	}
	if proof := findingField(*finding, "proof"); !strings.Contains(proof, "status=200") || !strings.Contains(proof, `marker="Control Panel"`) {
		t.Fatalf("default credential proof = %q", proof)
	}

	// Wrong default -> 401 -> no finding.
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer safe.Close()
	if got := runGudeDefaultCreds(context.Background(), mkTarget(t, safe.URL, "gude")); len(got) != 0 {
		t.Errorf("expected no finding when the default login is rejected, got %d", len(got))
	}
	// --disable-logins suppresses the active login entirely.
	off := mkTarget(t, vuln.URL, "gude")
	off.DisableLogins = true
	if got := runGudeDefaultCreds(context.Background(), off); len(got) != 0 {
		t.Errorf("gude login should be skipped under --disable-logins, got %d", len(got))
	}
}

// TestPPEPortGate confirms the cross-vendor PPE check does nothing on an
// unrelated target (no CyberPower identity, port 53568 not in scan).
func TestPPEPortGate(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.1", Timeout: time.Second, Identity: &engine.Identity{Vendor: "dell"}}
	if got := runCyberPowerPPE(context.Background(), tgt); got != nil {
		t.Errorf("PPE check should no-op on a non-CyberPower target with no 53568 in scan, got %v", got)
	}
	// With 53568 in the scan set the gate opens (resolves a target to probe).
	tgt.Ports = []engine.Port{{Num: 53568, Proto: engine.ProtoTCP}}
	if _, _, ok := ppeTarget(tgt); !ok {
		t.Error("ppeTarget should resolve when 53568/tcp is in the scan set")
	}
}

func TestPPETargetFallsBackToHTTPTitle(t *testing.T) {
	tgt := mkTargetWithIdentity(t,
		"192.0.2.44",
		"443",
		"cyberpower",
		"RMCARD",
		map[string]string{
			"web.port":   "443",
			"web.scheme": "https",
			"http.title": "PowerPanel Enterprise - CyberPower",
		},
	)
	scheme, port, ok := ppeTarget(tgt)
	if !ok || scheme != "https" || port != 443 {
		t.Fatalf("ppeTarget() = (%q, %d, %v), want (https, 443, true)", scheme, port, ok)
	}

	tgt.Identity.Attributes["http.title"] = "CyberPower RMCARD205"
	if _, _, ok := ppeTarget(tgt); ok {
		t.Fatal("ppeTarget should stay closed for a non-PowerPanel CyberPower title when 53568 is absent")
	}
}
