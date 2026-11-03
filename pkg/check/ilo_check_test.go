package check

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// iloBypassPath mirrors the unexported ilo.bypassPath (the credential-protected
// iLO4 REST resource the CVE-2017-12542 differential targets).
const iloBypassPath = "/rest/v1/AccountService/Accounts"

func iloAuthBypassServer(t *testing.T, vulnerable bool) (host string, closeFn func()) {
	t.Helper()
	restBody := `{"Type":"Collection.0","Name":"Accounts","MemberType":"AccountService.0.10.0","AccountService":true}`
	mux := http.NewServeMux()
	mux.HandleFunc(iloBypassPath, func(w http.ResponseWriter, r *http.Request) {
		if vulnerable && len(r.Header.Get("Connection")) == 29 {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(restBody))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewTLSServer(mux)
	return strings.TrimPrefix(srv.URL, "https://"), srv.Close
}

func iloTarget(host string, disableLogins bool) *engine.Target {
	return &engine.Target{
		Host:          host,
		Timeout:       3 * time.Second,
		DisableLogins: disableLogins,
		Identity: &engine.Identity{
			Class:      engine.ClassBMC,
			Vendor:     "hpe",
			Product:    "iLO4",
			Confidence: engine.ConfHigh,
		},
	}
}

func TestRunILOAuthBypass(t *testing.T) {
	t.Run("vulnerable", func(t *testing.T) {
		host, closeFn := iloAuthBypassServer(t, true)
		defer closeFn()
		fs := runILOAuthBypass(context.Background(), iloTarget(host, false))
		if len(fs) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(fs))
		}
		f := fs[0]
		if f.Check != "http.ilo.authBypass" || f.Risk != "critical" {
			t.Fatalf("unexpected finding check/risk: %+v", f)
		}
		if len(f.CVE) != 1 || f.CVE[0] != "CVE-2017-12542" {
			t.Fatalf("expected CVE-2017-12542, got %v", f.CVE)
		}
	})

	t.Run("patched", func(t *testing.T) {
		host, closeFn := iloAuthBypassServer(t, false)
		defer closeFn()
		if fs := runILOAuthBypass(context.Background(), iloTarget(host, false)); len(fs) != 0 {
			t.Fatalf("patched target should yield no finding, got %d", len(fs))
		}
	})

	t.Run("disable-logins skips", func(t *testing.T) {
		host, closeFn := iloAuthBypassServer(t, true)
		defer closeFn()
		if fs := runILOAuthBypass(context.Background(), iloTarget(host, true)); len(fs) != 0 {
			t.Fatalf("DisableLogins must skip the active bypass, got %d findings", len(fs))
		}
	})
}

func TestILOChecksSkipUnrelatedTarget(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := &engine.Target{
		Host:    strings.TrimPrefix(srv.URL, "https://"),
		Timeout: time.Second,
		Identity: &engine.Identity{
			Class:  engine.ClassUnknown,
			Vendor: "dell",
		},
	}
	if got := runILOLicenseKey(t.Context(), target); len(got) != 0 {
		t.Fatalf("license check returned findings for unrelated target: %+v", got)
	}
	if got := runILOXMLData(t.Context(), target); len(got) != 0 {
		t.Fatalf("XML check returned findings for unrelated target: %+v", got)
	}
	if got := runILOAuthBypass(t.Context(), target); len(got) != 0 {
		t.Fatalf("bypass check returned findings for unrelated target: %+v", got)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("iLO checks sent %d requests to unrelated target", got)
	}
}
