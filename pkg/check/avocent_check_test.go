package check

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func TestRunAvocentACSRedfishRoot(t *testing.T) {
	// ACS8000: the mini Redfish service root is served as a static file, no auth.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redfish/v1/index.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Product":"ACS","Vendor":"Avocent","SerialNumber":"","CertificateSupport":false}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	got := runAvocentACSRedfishRoot(context.Background(), webTarget(t, srv.URL, "avocent", engine.ClassSerialConsole))
	f := hasFinding(got, "http.avocent.acsRedfishRoot")
	if f == nil {
		t.Fatal("expected http.avocent.acsRedfishRoot for an unauthenticated Avocent ACS service root")
	}
	if f.Risk != "medium" {
		t.Errorf("risk = %s, want medium", f.Risk)
	}
	if v := fieldVal(f.Fields, "vendor"); v != "Avocent" {
		t.Errorf("vendor field = %q, want Avocent", v)
	}

	// A standard non-Avocent Redfish root must not match.
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","Vendor":"HPE","Product":"iLO"}`))
	}))
	defer other.Close()
	if got := runAvocentACSRedfishRoot(context.Background(), webTarget(t, other.URL, "avocent", engine.ClassSerialConsole)); len(got) != 0 {
		t.Errorf("expected no finding for a non-Avocent Redfish root, got %v", got)
	}
}
