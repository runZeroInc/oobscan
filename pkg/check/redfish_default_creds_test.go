package check

import (
	"context"
	"io"
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

func redfishAuthCrashHandler() http.Handler {
	mux := http.NewServeMux()
	root := func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","Vendor":"Supermicro","Product":"BMC"}`))
	}
	mux.HandleFunc("/redfish/v1", root)
	mux.HandleFunc("/redfish/v1/", root)
	mux.HandleFunc("/redfish/v1/AccountService/Accounts", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `xBasic realm="RedfishService"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/redfish/v1/Managers", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `xBasic realm="RedfishService"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/redfish/v1/SessionService/Sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("WWW-Authenticate", `xBasic realm="RedfishService"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	return mux
}

func redfishAuthCrashButVerifiableHandler() http.Handler {
	mux := http.NewServeMux()
	root := func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","Vendor":"Supermicro","Product":"BMC"}`))
	}
	mux.HandleFunc("/redfish/v1", root)
	mux.HandleFunc("/redfish/v1/", root)
	// Primary differential path stays broken.
	mux.HandleFunc("/redfish/v1/Managers", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `xBasic realm="RedfishService"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	// Secondary protected path proves valid credentials can authenticate.
	mux.HandleFunc("/redfish/v1/Systems", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `xBasic realm="RedfishService"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authz := r.Header.Get("Authorization")
		if authz == "Basic QURNSU46QURNSU4=" || authz == "xBasic QURNSU46QURNSU4=" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Members":[]}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/redfish/v1/AccountService/Accounts", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `xBasic realm="RedfishService"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/redfish/v1/SessionService/Sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	return mux
}

// redfishBMC is a fake BMC Redfish endpoint for the default-creds check. It
// mints a session token for the configured user/pass and gates admin resources
// behind that token.
type redfishBMC struct {
	user, pass string
	token      string
}

func (b *redfishBMC) handler() http.Handler {
	mux := http.NewServeMux()
	root := func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","Vendor":"AMI","Product":"MegaRAC","RedfishVersion":"1.16.0","UUID":"svc-uuid-check"}`))
	}
	mux.HandleFunc("/redfish/v1", root)
	mux.HandleFunc("/redfish/v1/", root)
	mux.HandleFunc("/redfish/v1/SessionService/Sessions", func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		body := string(buf)
		if strings.Contains(body, `"UserName":"`+b.user+`"`) && strings.Contains(body, `"Password":"`+b.pass+`"`) {
			b.token = "TKN"
			w.Header().Set("X-Auth-Token", b.token)
			w.Header().Set("Location", "/redfish/v1/SessionService/Sessions/1")
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	admin := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if b.token == "" || r.Header.Get("X-Auth-Token") != b.token {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(body))
		}
	}
	mux.HandleFunc("/redfish/v1/AccountService/Accounts", admin(`{"@odata.type":"#ManagerAccountCollection","Members":[{"@odata.id":"/redfish/v1/AccountService/Accounts/1"}]}`))
	mux.HandleFunc("/redfish/v1/AccountService/Accounts/1", admin(`{"@odata.id":"/redfish/v1/AccountService/Accounts/1","UserName":"root","RoleId":"Administrator","Enabled":true}`))
	mux.HandleFunc("/redfish/v1/Managers", admin(`{"Members":[{"@odata.id":"/redfish/v1/Managers/Self"}]}`))
	mux.HandleFunc("/redfish/v1/Managers/Self", admin(`{"Id":"BMC","Manufacturer":"AMI","Model":"MegaRAC-SP-X","FirmwareVersion":"7.11"}`))
	mux.HandleFunc("/redfish/v1/Systems", admin(`{"Members":[{"@odata.id":"/redfish/v1/Systems/Self"}]}`))
	mux.HandleFunc("/redfish/v1/Systems/Self", admin(`{"Id":"System","Manufacturer":"ASRockRack","Model":"X470D4U","SerialNumber":"SN9","BiosVersion":"P3.40","PowerState":"On"}`))
	return mux
}

func mkRedfishTarget(t *testing.T, srvURL, vendor string, credsOnline bool) *engine.Target {
	t.Helper()
	hp := strings.TrimPrefix(srvURL, "https://")
	host, ps, err := net.SplitHostPort(hp)
	if err != nil {
		t.Fatalf("split %q: %v", hp, err)
	}
	port, _ := strconv.Atoi(ps)
	return &engine.Target{
		Host:          host,
		Ports:         []engine.Port{{Proto: engine.ProtoTCP, Num: port}},
		Timeout:       3 * time.Second,
		DisableLogins: !credsOnline,
		Identity: &engine.Identity{
			Class:      engine.ClassBMC,
			Vendor:     vendor,
			Attributes: map[string]string{"web.port": ps, "web.scheme": "https"},
		},
	}
}

func TestRedfishDefaultCreds_Success(t *testing.T) {
	bmc := &redfishBMC{user: "root", pass: "0penBmc"}
	srv := httptest.NewTLSServer(bmc.handler())
	defer srv.Close()

	// nvidia BlueField default root:0penBmc must be tried and succeed.
	tg := mkRedfishTarget(t, srv.URL, "nvidia", true)
	got := runRedfishDefaultCreds(context.Background(), tg)
	f := hasFinding(got, "http.redfish.defaultCreds")
	if f == nil {
		t.Fatalf("expected redfish.default-creds finding, got %+v", got)
	}
	if f.Risk != "critical" {
		t.Errorf("risk = %q, want critical", f.Risk)
	}
	fields := f.Fields.String()
	for _, want := range []string{"username=root", "password=0penBmc", "loginVia=session", "source=firmware-image"} {
		if !strings.Contains(fields, want) {
			t.Errorf("fields %q missing %q", fields, want)
		}
	}
	for _, duplicate := range []string{"firmwareVersion", "model", "redfishVersion", "bmcVendor", "product", "evidenceEndpoint"} {
		if got := fieldVal(f.Fields, duplicate); got != "" {
			t.Errorf("field %s=%q duplicates redfishPostAuth", duplicate, got)
		}
	}
	var proof string
	for _, fl := range f.Fields {
		if fl.Key == "proof" {
			proof = fl.Val
		}
	}
	for _, want := range []string{"auth=session", "resource=admin", "status=201", "tokenLen=3", "model=X470D4U", "firmwareVersion=7.11", "serviceUuid=svc-uuid-check"} {
		if !strings.Contains(proof, want) {
			t.Errorf("proof %q missing dynamic marker %q", proof, want)
		}
	}
	for _, prose := range []string{";", "authenticated Redfish", "returned an authenticated", "session token minted"} {
		if strings.Contains(proof, prose) {
			t.Errorf("proof %q contains prose marker %q", proof, prose)
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
	if post.Method != "defaultCreds" || post.User != "root" {
		t.Fatalf("unexpected postauth snapshot: %+v", post)
	}
	// The full inventory must land on the top-level snapshot.
	for _, want := range []struct{ label, got string }{
		{"serviceUuid", post.Info.ServiceUUID},
		{"biosVersion", post.Info.BIOSVersion},
		{"powerState", post.Info.PowerState},
		{"accountRole", post.Info.AccountRole},
	} {
		if want.got == "" {
			t.Errorf("redfishPostAuth snapshot missing %s", want.label)
		}
	}
}

func TestRedfishDefaultCreds_WrongCredsNoFinding(t *testing.T) {
	// BMC accepts only USERID:PASSW0RD; a dell-vendored target sprays root:calvin
	// etc. first and should not authenticate (miss).
	bmc := &redfishBMC{user: "nobody", pass: "no-such-pass-xyz"}
	srv := httptest.NewTLSServer(bmc.handler())
	defer srv.Close()
	tg := mkRedfishTarget(t, srv.URL, "dell", true)
	if got := runRedfishDefaultCreds(context.Background(), tg); len(got) != 0 {
		t.Errorf("expected no finding on credential miss, got %+v", got)
	}
}

func TestRedfishDefaultCreds_BlankPasswordReported(t *testing.T) {
	bmc := &redfishBMC{user: "ADMIN", pass: ""}
	srv := httptest.NewTLSServer(bmc.handler())
	defer srv.Close()

	tg := mkRedfishTarget(t, srv.URL, "supermicro", true)
	got := runRedfishDefaultCreds(context.Background(), tg)
	f := hasFinding(got, "http.redfish.defaultCreds")
	if f == nil {
		t.Fatalf("expected redfish.default-creds finding, got %+v", got)
	}
	fields := f.Fields.String()
	for _, want := range []string{"username=ADMIN", "password=(blank)", "source=vendor-doc"} {
		if !strings.Contains(fields, want) {
			t.Fatalf("fields %q missing %q", fields, want)
		}
	}
}

func TestRedfishDefaultCreds_OfflineGate(t *testing.T) {
	bmc := &redfishBMC{user: "root", pass: "0penBmc"}
	srv := httptest.NewTLSServer(bmc.handler())
	defer srv.Close()
	// DisableLogins=true must fully disable the login even if selected.
	tg := mkRedfishTarget(t, srv.URL, "nvidia", false)
	if got := runRedfishDefaultCreds(context.Background(), tg); got != nil {
		t.Errorf("offline mode must not attempt a login, got %+v", got)
	}
}

func TestRedfishDefaultCreds_RegisteredEnabled(t *testing.T) {
	// The check must be present and in the default (Enabled) set: a default
	// selector on an identified-vendor BMC must select it.
	var found bool
	for _, c := range All() {
		if c.Name == "http.redfish.defaultCreds" {
			found = true
			if !c.Enabled {
				t.Error("redfish.default-creds must be registered enabled (on by default)")
			}
		}
	}
	if !found {
		t.Fatal("redfish.default-creds not registered")
	}
	bmc := &engine.Identity{Class: engine.ClassBMC, Vendor: "nvidia"}
	selectedByDefault := false
	for _, c := range ForIdentity(bmc, Selector{}) {
		if c.Name == "http.redfish.defaultCreds" {
			selectedByDefault = true
		}
	}
	if !selectedByDefault {
		t.Error("redfish.default-creds must be selected by the default set")
	}
	// Explicit selection by name must also select it.
	selected := false
	for _, c := range ForIdentity(bmc, Selector{Checks: []string{"http.redfish.defaultCreds"}}) {
		if c.Name == "http.redfish.defaultCreds" {
			selected = true
		}
	}
	if !selected {
		t.Error("explicit --checks redfish.default-creds should select it")
	}
}

func TestRedfishDefaultCreds_UnknownVendorIteratesDefaults(t *testing.T) {
	// Targeting fallback: when Redfish is confirmed present but the vendor could
	// not be fingerprinted, the check must still iterate the documented
	// cross-vendor defaults (here root:0penBmc) rather than skipping.
	bmc := &redfishBMC{user: "root", pass: "0penBmc"}
	srv := httptest.NewTLSServer(bmc.handler())
	defer srv.Close()
	tg := mkRedfishTarget(t, srv.URL, "", true)
	got := runRedfishDefaultCreds(context.Background(), tg)
	if f := hasFinding(got, "http.redfish.defaultCreds"); f == nil {
		t.Fatalf("unknown vendor with a live default must be found via documented defaults, got %+v", got)
	}
}

func TestRedfishDefaultCreds_NonRedfishNoLogin(t *testing.T) {
	// Presence gate: a WAF/VPN/honeypot that answers 200 on /redfish/v1/ with an
	// HTML login page (no Redfish JSON) must not be treated as Redfish, so the
	// check spends zero logins and returns no finding.
	var attempted bool
	mux := http.NewServeMux()
	html := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><form>login</form></body></html>`))
	}
	mux.HandleFunc("/redfish/v1", html)
	mux.HandleFunc("/redfish/v1/", html)
	mux.HandleFunc("/redfish/v1/SessionService/Sessions", func(w http.ResponseWriter, r *http.Request) {
		attempted = true
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	tg := mkRedfishTarget(t, srv.URL, "dell", true)
	if got := runRedfishDefaultCreds(context.Background(), tg); got != nil {
		t.Fatalf("non-Redfish HTML 200 must yield no finding, got %+v", got)
	}
	if attempted {
		t.Fatalf("check attempted a login against a non-Redfish endpoint")
	}
}

func TestRedfishDefaultCreds_AuthPathErrorFinding(t *testing.T) {
	srv := httptest.NewTLSServer(redfishAuthCrashHandler())
	defer srv.Close()
	tg := mkRedfishTarget(t, srv.URL, "supermicro", true)
	got := runRedfishDefaultCreds(context.Background(), tg)
	f := hasFinding(got, "http.redfish.authPathError")
	if f == nil {
		t.Fatalf("expected redfish auth path error finding, got %+v", got)
	}
	if f.Risk != "info" {
		t.Fatalf("risk = %q, want info", f.Risk)
	}
	fields := f.Fields.String()
	for _, want := range []string{"resource=/redfish/v1/Managers", "unauthStatus=401", "basicStatus=500", "sessionStatus=500", `proof="errorStatus=500 resource=/redfish/v1/Managers unauthStatus=401 basicStatus=500 sessionStatus=500"`} {
		if !strings.Contains(fields, want) {
			t.Fatalf("fields %q missing %q", fields, want)
		}
	}
}

func TestRedfishDefaultCreds_AuthPathErrorCriticalWhenVerifiable(t *testing.T) {
	srv := httptest.NewTLSServer(redfishAuthCrashButVerifiableHandler())
	defer srv.Close()
	tg := mkRedfishTarget(t, srv.URL, "supermicro", true)
	got := runRedfishDefaultCreds(context.Background(), tg)
	f := hasFinding(got, "http.redfish.authPathError")
	if f == nil {
		t.Fatalf("expected redfish auth path error finding, got %+v", got)
	}
	if f.Risk != "critical" {
		t.Fatalf("risk = %q, want critical", f.Risk)
	}
}
