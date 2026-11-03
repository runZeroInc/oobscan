package identify

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/bmcfp"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

// TestMgmtSoftwareTitlesResolve confirms the fingerprint rules attribute the
// dedicated-port management apps from their page title alone.
func TestMgmtSoftwareTitlesResolve(t *testing.T) {
	for _, tc := range []struct{ title, vendor, product string }{
		{"PDNU", "cyberpower", "PowerPanel Enterprise"},
		{"Eaton Intelligent Power Manager", "eaton", "Intelligent Power Manager"},
		{"HPE OneView", "hpe", "OneView / SIM"},
	} {
		a := newAcc()
		a.addFP(bmcfp.HTMLTitle, tc.title)
		id := a.resolve()
		if id.Vendor != tc.vendor || id.Product != tc.product {
			t.Errorf("title %q resolved to %q/%q, want %q/%q", tc.title, id.Vendor, id.Product, tc.vendor, tc.product)
		}
	}
}

// TestMgmtSoftwareProbe drives the collector against a stand-in PowerPanel
// Enterprise server: it must read the title (attributing CyberPower) and record
// the port as open so the cyberpower.ppe check resolves it on a bare scan.
func TestMgmtSoftwareProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><head><title>PDNU</title></head></html>"))
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	tgt := &engine.Target{Host: host, Timeout: 2 * time.Second}
	a := newAcc()
	mgmtSoftwareProbe(port, "http")(tgt, a)

	if _, ok := tgt.Open[portStr+"/tcp"]; !ok {
		t.Errorf("probe did not record %s/tcp open; Open=%v", portStr, tgt.Open)
	}
	if id := a.resolve(); id.Vendor != "cyberpower" {
		t.Errorf("resolved vendor = %q, want cyberpower", id.Vendor)
	}

	// A closed port is a clean no-op (no panic, nothing recorded).
	tgt2 := &engine.Target{Host: "127.0.0.1", Timeout: 200 * time.Millisecond}
	a2 := newAcc()
	mgmtSoftwareProbe(1, "http")(tgt2, a2) // port 1: connect refused
	if len(tgt2.Open) != 0 {
		t.Errorf("closed-port probe recorded ports: %v", tgt2.Open)
	}
}
