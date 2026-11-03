package check

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/redfish"
)

func TestRedfishPostAuthEnum_Success(t *testing.T) {
	bmc := &redfishBMC{user: "root", pass: "0penBmc"}
	srv := httptest.NewTLSServer(bmc.handler())
	defer srv.Close()

	tg := mkRedfishTarget(t, srv.URL, "openbmc", true)
	tg.Cred = engine.Cred{User: "root", Pass: "0penBmc"}
	got := runRedfishPostAuthEnum(context.Background(), tg)
	f := hasFinding(got, "http.redfish.postAuthEnum")
	if f == nil {
		t.Fatalf("expected redfish.postAuth finding, got %+v", got)
	}
	if f.Risk != "info" {
		t.Fatalf("risk = %q, want info", f.Risk)
	}
	fields := f.Fields.String()
	// Finding carries a compact fingerprint; the exhaustive inventory
	// (serviceUuid / biosVersion / powerState / accountRole /
	// accountEnabled) lives on the top-level redfishPostAuth snapshot,
	// asserted below.
	for _, want := range []string{"username=root", "loginVia=session", "bmcVendor=ASRockRack", "model=X470D4U", "firmwareVersion=7.11", "redfishVersion=1.16.0", "product=MegaRAC"} {
		if !strings.Contains(fields, want) {
			t.Fatalf("fields %q missing %q", fields, want)
		}
	}
	v, ok := tg.Evidenced("redfish.postAuth")
	if !ok {
		t.Fatal("expected redfish.postAuth evidence")
	}
	post, ok := v.(*redfish.PostAuthSnapshot)
	if !ok || post == nil {
		t.Fatalf("unexpected redfish.postAuth type: %T", v)
	}
	if post.Method != "providedCreds" || post.User != "root" {
		t.Fatalf("unexpected postauth snapshot: %+v", post)
	}
	if post.Info.ServiceUUID == "" || post.Info.BIOSVersion == "" || post.Info.PowerState == "" || post.Info.AccountRole == "" {
		t.Fatalf("redfishPostAuth snapshot missing inventory fields: %+v", post.Info)
	}
}

func TestRedfishPostAuthEnum_OfflineGate(t *testing.T) {
	bmc := &redfishBMC{user: "root", pass: "0penBmc"}
	srv := httptest.NewTLSServer(bmc.handler())
	defer srv.Close()

	tg := mkRedfishTarget(t, srv.URL, "openbmc", false)
	tg.Cred = engine.Cred{User: "root", Pass: "0penBmc"}
	if got := runRedfishPostAuthEnum(context.Background(), tg); got != nil {
		t.Fatalf("offline mode must skip redfish postauth, got %+v", got)
	}
}

func TestRedfishPostAuthEnum_AuthPathErrorFinding(t *testing.T) {
	srv := httptest.NewTLSServer(redfishAuthCrashHandler())
	defer srv.Close()

	tg := mkRedfishTarget(t, srv.URL, "supermicro", true)
	tg.Cred = engine.Cred{User: "ADMIN", Pass: "ADMIN"}
	got := runRedfishPostAuthEnum(context.Background(), tg)
	f := hasFinding(got, "http.redfish.authPathError")
	if f == nil {
		t.Fatalf("expected redfish auth path error finding, got %+v", got)
	}
	if f.Risk != "info" {
		t.Fatalf("risk = %q, want info", f.Risk)
	}
	if s := f.Fields.String(); !strings.Contains(s, `proof="errorStatus=500 resource=/redfish/v1/Managers unauthStatus=401 basicStatus=500 sessionStatus=500"`) {
		t.Fatalf("unexpected fields: %q", s)
	}
}

func TestRedfishPostAuthEnum_AuthPathErrorCriticalWhenVerifiable(t *testing.T) {
	srv := httptest.NewTLSServer(redfishAuthCrashButVerifiableHandler())
	defer srv.Close()

	tg := mkRedfishTarget(t, srv.URL, "supermicro", true)
	tg.Cred = engine.Cred{User: "ADMIN", Pass: "ADMIN"}
	got := runRedfishPostAuthEnum(context.Background(), tg)
	f := hasFinding(got, "http.redfish.authPathError")
	if f == nil {
		t.Fatalf("expected redfish auth path error finding, got %+v", got)
	}
	if f.Risk != "critical" {
		t.Fatalf("risk = %q, want critical", f.Risk)
	}
}
