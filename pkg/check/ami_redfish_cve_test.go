package check

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/redfish"
)

func amiNoXFFTarget() *engine.Target {
	return &engine.Target{
		Host:    "127.0.0.1",
		Ports:   []engine.Port{{Proto: engine.ProtoTCP, Num: 443}},
		Timeout: 3 * time.Second,
		Identity: &engine.Identity{
			Class:  engine.ClassBMC,
			Vendor: "ami",
		},
	}
}

// amiCVETarget builds a ClassBMC/ami target pointed at an httptest server.
func amiCVETarget(t *testing.T, srvURL, vendor string) *engine.Target {
	t.Helper()
	hp := strings.TrimPrefix(srvURL, "https://")
	host, ps, err := net.SplitHostPort(hp)
	if err != nil {
		t.Fatalf("split %q: %v", hp, err)
	}
	port, _ := strconv.Atoi(ps)
	return &engine.Target{
		Host:    host,
		Ports:   []engine.Port{{Proto: engine.ProtoTCP, Num: port}},
		Timeout: 3 * time.Second,
		Identity: &engine.Identity{
			Class:      engine.ClassBMC,
			Vendor:     vendor,
			Attributes: map[string]string{"web.port": ps, "web.scheme": "https"},
		},
	}
}

func TestAMIRedfishCVE_Vulnerable(t *testing.T) {
	// Vulnerable: Systems is served only for the exact published Host spoof.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redfish/v1/Systems" {
			if r.Host != "169.254.0.17" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Server-Addr") != "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"@odata.type":"#ComputerSystemCollection","Members":[]}`))
			return
		}
		// Service root fingerprints as AMI so isAMIRedfish passes even for a blank vendor.
		_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","Vendor":"AMI","Product":"MegaRAC"}`))
	}))
	defer srv.Close()

	tg := amiCVETarget(t, srv.URL, "ami")
	got := runAMIRedfishCVE202334329(context.Background(), tg)
	f := hasFinding(got, "http.redfish.ami.cve202334329")
	if f == nil {
		t.Fatalf("expected CVE-2023-34329 finding, got %+v", got)
	}
	if f.Risk != "critical" {
		t.Errorf("risk = %q, want critical", f.Risk)
	}
	if len(f.CVE) != 1 || f.CVE[0] != "CVE-2023-34329" {
		t.Errorf("CVE = %v, want [CVE-2023-34329]", f.CVE)
	}
}

func TestAMIRedfishCVE_PatchedNoFinding(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redfish/v1/Systems" {
			w.WriteHeader(http.StatusUnauthorized) // denied regardless of spoof
			return
		}
		_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","Vendor":"AMI","Product":"MegaRAC"}`))
	}))
	defer srv.Close()

	tg := amiCVETarget(t, srv.URL, "ami")
	if got := runAMIRedfishCVE202334329(context.Background(), tg); len(got) != 0 {
		t.Errorf("patched server must yield no finding, got %+v", got)
	}
}

func TestAMIRedfishCVE54085_Vulnerable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redfish/v1/Systems" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Server-Addr") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-Server-Addr") != "169.254.0.17:" || r.Header.Get("X-Forwarded-For") != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"@odata.type":"#ComputerSystemCollection","Members":[]}`))
	}))
	defer srv.Close()

	tg := amiCVETarget(t, srv.URL, "ami")
	got := runRedfishAMICVE(context.Background(), tg)
	f := hasFinding(got, "http.redfish.amiBypass")
	if f == nil {
		t.Fatalf("expected CVE-2024-54085 finding, got %+v", got)
	}
	if f.Port != webPort(tg) {
		t.Errorf("port = %d, want discovered Redfish port %d", f.Port, webPort(tg))
	}
	if len(f.CVE) != 1 || f.CVE[0] != "CVE-2024-54085" {
		t.Errorf("CVE = %v, want [CVE-2024-54085]", f.CVE)
	}
	if got := fieldVal(f.Fields, "spoofHeader"); got != "X-Server-Addr: 169.254.0.17:" {
		t.Errorf("spoofHeader = %q, want exact published header", got)
	}
}

func TestAMIRedfishCVE54085_ConfirmedOnAdminResource(t *testing.T) {
	// Vulnerable MegaRAC: admin-scoped resources are denied anonymously and
	// served once X-Server-Addr carries the host-interface address.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("check issued %s; it must be read-only", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/redfish/v1" && r.Header.Get("X-Server-Addr") == "" {
			// Service root readable pre-auth, as on a real BMC.
			_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","Vendor":"AMI","Product":"MegaRAC"}`))
			return
		}
		if r.Header.Get("X-Server-Addr") != "169.254.0.17:" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/redfish/v1/AccountService/Accounts":
			_, _ = w.Write([]byte(`{"@odata.type":"#ManagerAccountCollection","Members":[{"@odata.id":"/redfish/v1/AccountService/Accounts/1"}]}`))
		case "/redfish/v1/AccountService/Accounts/1":
			_, _ = w.Write([]byte(`{"UserName":"admin","RoleId":"Administrator","Enabled":true}`))
		case "/redfish/v1/Managers":
			_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/redfish/v1/Managers/Self"}]}`))
		case "/redfish/v1/Managers/Self":
			_, _ = w.Write([]byte(`{"Id":"Self","Manufacturer":"AMI","Model":"MegaRAC","FirmwareVersion":"12.5"}`))
		default:
			_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","Vendor":"AMI","Product":"MegaRAC"}`))
		}
	}))
	defer srv.Close()

	tg := amiCVETarget(t, srv.URL, "ami")
	got := runRedfishAMICVE(context.Background(), tg)
	f := hasFinding(got, "http.redfish.amiBypass")
	if f == nil {
		t.Fatalf("expected CVE-2024-54085 finding, got %+v", got)
	}
	if f.Risk != "critical" {
		t.Errorf("risk = %q, want critical", f.Risk)
	}
	if got := fieldVal(f.Fields, "confirmation"); got != "adminResource" {
		t.Errorf("confirmation = %q, want adminResource", got)
	}
	if got := fieldVal(f.Fields, "url"); got != "/redfish/v1/AccountService/Accounts" {
		t.Errorf("url = %q, want the admin-scoped resource", got)
	}
	if got := fieldVal(f.Fields, "firmwareVersion"); got != "12.5" {
		t.Errorf("firmwareVersion = %q, want inventory pulled over the bypass", got)
	}
	if got := fieldVal(f.Fields, "accountRole"); got != "Administrator" {
		t.Errorf("accountRole = %q, want Administrator", got)
	}
	// The bypass yields privileged access, so it must feed the shared post-auth
	// snapshot the same way the mTLS bypass does.
	v, ok := tg.Evidenced("redfish.postAuth")
	if !ok {
		t.Fatal("confirmed bypass must record a redfish.postAuth snapshot")
	}
	post, _ := v.(*redfish.PostAuthSnapshot)
	if post == nil || post.Info.FirmwareVersion != "12.5" {
		t.Errorf("postAuth snapshot = %+v, want the pulled inventory", post)
	}
}

func TestAMIRedfishCVE54085_UnauthReadableNotConfirmed(t *testing.T) {
	// Everything readable anonymously: a pre-auth exposure, but the header
	// proves nothing, so neither the admin-scoped nor the published
	// differential may attribute it to CVE-2024-54085.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","Vendor":"AMI","Product":"MegaRAC","Members":[]}`))
	}))
	defer srv.Close()

	tg := amiCVETarget(t, srv.URL, "ami")
	if got := runRedfishAMICVE(context.Background(), tg); len(got) != 0 {
		t.Errorf("unauth-readable host must not be reported as the bypass, got %+v", got)
	}
}

func TestAMIRedfishPorts(t *testing.T) {
	// Eclypsium's PoC targets :8443 while identify prefers :443 for web.port, so
	// the canonical Redfish ports must be probed alongside the discovered one.
	tg := &engine.Target{
		Host: "192.0.2.10",
		Ports: []engine.Port{
			{Proto: engine.ProtoTCP, Num: 443},
			{Proto: engine.ProtoTCP, Num: 8443},
			{Proto: engine.ProtoTCP, Num: 80},
			{Proto: engine.ProtoUDP, Num: 4443},
		},
		Identity: &engine.Identity{Attributes: map[string]string{"web.port": "443"}},
	}
	got := amiRedfishPorts(tg)
	want := []int{443, 8443}
	if len(got) != len(want) {
		t.Fatalf("ports = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ports = %v, want %v (web.port first, no dupes, TCP only)", got, want)
		}
	}
}

func TestAMIRedfishCVE54085_RegisteredEnabled(t *testing.T) {
	for _, c := range All() {
		if c.Name == "http.redfish.ami.cve202454085" {
			if !c.Enabled {
				t.Error("cve202454085 should be enabled by default (safe read-only differential)")
			}
			if c.Destructive || c.Authenticated {
				t.Error("cve202454085 must be neither destructive nor authenticated")
			}
			return
		}
	}
	t.Fatal("http.redfish.ami.cve202454085 not registered")
}

func TestAMIRedfishCVE54085_ExplainerReachable(t *testing.T) {
	// The explainer must be keyed on the FINDING name the check emits, not the
	// registered check name, or it never renders.
	if _, ok := GetExplainer("http.redfish.amiBypass"); !ok {
		t.Fatal("no explainer registered for the emitted finding name")
	}
}

func TestAMIRedfishCVE_NonAMISkipped(t *testing.T) {
	// A non-AMI Redfish service must be skipped even if it would answer the probe.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","Vendor":"Dell","Product":"iDRAC9"}`))
	}))
	defer srv.Close()
	tg := amiCVETarget(t, srv.URL, "dell")
	if got := runAMIRedfishCVE202334329(context.Background(), tg); len(got) != 0 {
		t.Errorf("non-AMI target must be skipped, got %+v", got)
	}
}

func TestAMIRedfishCVE_RegisteredEnabled(t *testing.T) {
	// Safe pre-auth differential: must be in the default (Enabled) set.
	for _, c := range All() {
		if c.Name == "http.redfish.ami.cve202334329" {
			if !c.Enabled {
				t.Error("ami.redfish_cve_2023_34329 should be enabled by default (safe pre-auth)")
			}
			if c.Destructive || c.Authenticated {
				t.Error("ami.redfish_cve_2023_34329 must be neither destructive nor authenticated")
			}
			return
		}
	}
	t.Fatal("ami.redfish_cve_2023_34329 not registered")
}

func TestAMINoXFFBypass_Vulnerable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:9080")
	if err != nil {
		t.Skipf("port 9080 unavailable: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/redfish/v1/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("X-Forwarded-For") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/AccountService/Accounts","Members":[]}`))
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	tg := amiNoXFFTarget()
	got := runAMINoXFFBypass(context.Background(), tg)
	f := hasFinding(got, "http.redfish.ami.noXffBypass")
	if f == nil {
		t.Fatalf("expected no-XFF bypass finding, got %+v", got)
	}
	if f.Risk != "critical" {
		t.Errorf("risk = %q, want critical", f.Risk)
	}
	if !strings.Contains(strings.ToLower(fieldVal(f.Fields, "proof")), "xff") {
		t.Errorf("proof should include XFF differential, got %q", fieldVal(f.Fields, "proof"))
	}
}

func TestAMINoXFFBypass_PatchedNoFinding(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:9080")
	if err != nil {
		t.Skipf("port 9080 unavailable: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	tg := amiNoXFFTarget()
	if got := runAMINoXFFBypass(context.Background(), tg); len(got) != 0 {
		t.Errorf("patched server must yield no finding, got %+v", got)
	}
}

func TestAMINoXFFBypass_NoDifferentialNoFinding(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:9080")
	if err != nil {
		t.Skipf("port 9080 unavailable: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/AccountService/Accounts","Members":[]}`))
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	tg := amiNoXFFTarget()
	if got := runAMINoXFFBypass(context.Background(), tg); len(got) != 0 {
		t.Fatalf("expected no finding without XFF differential, got %+v", got)
	}
}

func TestAMIGlobalLuaTables_Available(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redfish/v1/GlobalLuaTables" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/GlobalLuaTables","Members":[],"Members@odata.count":0}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer vuln.Close()
	tg := lenovoTarget(t, vuln.URL)
	tg.Identity.Vendor = "ami"
	got := runAMIGlobalLuaTables(context.Background(), tg)
	f := hasFinding(got, "http.redfish.ami.globalLuaTables")
	if f == nil {
		t.Fatalf("expected GlobalLuaTables finding, got %+v", got)
	}
	if f.Risk != "info" {
		t.Fatalf("expected informational GlobalLuaTables finding, got risk=%q", f.Risk)
	}
}

func TestAMIGlobalLuaTables_Patched(t *testing.T) {
	patched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer patched.Close()
	tg := lenovoTarget(t, patched.URL)
	tg.Identity.Vendor = "ami"
	if got := runAMIGlobalLuaTables(context.Background(), tg); len(got) != 0 {
		t.Fatalf("expected no GlobalLuaTables finding on auth-gated endpoint, got %+v", got)
	}
}

func TestAMINoXFFBypass_RegisteredEnabled(t *testing.T) {
	for _, c := range All() {
		if c.Name == "http.redfish.ami.noXffBypass" {
			if !c.Enabled {
				t.Error("http.redfish.ami.noXffBypass should be enabled by default")
			}
			if c.Destructive || c.Authenticated {
				t.Error("http.redfish.ami.noXffBypass must be neither destructive nor authenticated")
			}
			return
		}
	}
	t.Fatal("http.redfish.ami.noXffBypass not registered")
}
