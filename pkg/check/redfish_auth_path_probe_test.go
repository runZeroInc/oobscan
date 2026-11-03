package check

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func TestRedfishAuthPathProbeRequiresFingerprint(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	target := &engine.Target{Host: strings.TrimPrefix(srv.URL, "https://")}
	if got := runRedfishAuthPathProbe(t.Context(), target); len(got) != 0 {
		t.Fatalf("unconfirmed Redfish target returned findings: %+v", got)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("auth-path check sent %d requests without a Redfish fingerprint", got)
	}
}
