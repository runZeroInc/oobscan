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

	"github.com/runZeroInc/oobscan/pkg/cim"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

// cimMethodResponse is a minimal EnumerateClassNames success body: an
// IMETHODRESPONSE carrying two CLASSNAME elements (the dynamic per-run marker).
const cimMethodResponse = `<?xml version="1.0" encoding="utf-8"?>` +
	`<CIM CIMVERSION="2.0" DTDVERSION="2.0"><MESSAGE ID="1" PROTOCOLVERSION="1.0">` +
	`<SIMPLERSP><IMETHODRESPONSE NAME="EnumerateClassNames"><IRETURNVALUE>` +
	`<CLASSNAME NAME="CIM_ManagedElement"/><CLASSNAME NAME="CIM_Component"/>` +
	`</IRETURNVALUE></IMETHODRESPONSE></SIMPLERSP></MESSAGE></CIM>`

const cimSystemResponse = `<?xml version="1.0" encoding="utf-8"?>` +
	`<CIM CIMVERSION="2.0" DTDVERSION="2.0"><MESSAGE ID="2" PROTOCOLVERSION="1.0">` +
	`<SIMPLERSP><IMETHODRESPONSE NAME="EnumerateInstances"><IRETURNVALUE>` +
	`<VALUE.NAMEDINSTANCE><INSTANCE CLASSNAME="CIM_ComputerSystem">` +
	`<PROPERTY NAME="Name" TYPE="string"><VALUE>bmc01.example</VALUE></PROPERTY>` +
	`<PROPERTY NAME="ElementName" TYPE="string"><VALUE>IBM Integrated Management Module</VALUE></PROPERTY>` +
	`<PROPERTY NAME="Manufacturer" TYPE="string"><VALUE>IBM</VALUE></PROPERTY>` +
	`<PROPERTY NAME="Model" TYPE="string"><VALUE>IMM2</VALUE></PROPERTY>` +
	`<PROPERTY NAME="SerialNumber" TYPE="string"><VALUE>SN123456</VALUE></PROPERTY>` +
	`<PROPERTY NAME="UUID" TYPE="string"><VALUE>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</VALUE></PROPERTY>` +
	`</INSTANCE></VALUE.NAMEDINSTANCE></IRETURNVALUE></IMETHODRESPONSE></SIMPLERSP></MESSAGE></CIM>`

// credentialedCIMOM emulates a properly-authenticating CIMOM (sfcb-style): it
// 401s when the Authorization header is missing or carries any credential other
// than the one good pair, and only 200s the read-only EnumerateClassNames for the
// exact good credential.
func credentialedCIMOM(goodUser, goodPass string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/cimom", func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != goodUser || p != goodPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="cimom"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("CIMOperation", "MethodResponse")
		w.WriteHeader(http.StatusOK)
		if r.Header.Get("CIMMethod") == "EnumerateInstances" {
			_, _ = w.Write([]byte(cimSystemResponse))
			return
		}
		_, _ = w.Write([]byte(cimMethodResponse))
	})
	return mux
}

// acceptAnyCIMOM emulates a live FP shape seen in the wild: it 401s only when no
// Authorization header is present, but returns a 200 MethodResponse for any
// credential (it never validates the pair). A naive "200 + MethodResponse ==
// accepted" check reports the first default tried; the negative control must
// suppress that.
func acceptAnyCIMOM() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/cimom", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="cimom"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("CIMOperation", "MethodResponse")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(cimMethodResponse))
	})
	return mux
}

// anonymousCIMOM emulates the live FP shape on an OpenPegasus host that 200s every
// request regardless of (or absent) credentials.
func anonymousCIMOM() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/cimom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CIMOperation", "MethodResponse")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(cimMethodResponse))
	})
	return mux
}

func mkCIMTarget(t *testing.T, srvURL, user, pass string, online bool) *engine.Target {
	t.Helper()
	hp := strings.TrimPrefix(srvURL, "http://")
	host, ps, err := net.SplitHostPort(hp)
	if err != nil {
		t.Fatalf("split %q: %v", hp, err)
	}
	port, _ := strconv.Atoi(ps)
	tg := &engine.Target{
		Host:          host,
		Timeout:       3 * time.Second,
		DisableLogins: !online,
		Cred:          engine.Cred{User: user, Pass: pass},
	}
	tg.SetEvidence("cim", &cim.Result{Port: port, Scheme: "http", AuthReq: true})
	return tg
}

func TestCIMDefaultCreds_Success(t *testing.T) {
	srv := httptest.NewServer(credentialedCIMOM("USERID", "PASSW0RD"))
	defer srv.Close()

	tg := mkCIMTarget(t, srv.URL, "USERID", "PASSW0RD", true)
	got := runCIMDefaultCreds(context.Background(), tg)
	f := hasFinding(got, "http.cim.defaultCreds")
	if f == nil {
		t.Fatalf("expected cim default-creds finding on a credentialed CIMOM, got %+v", got)
	}
	if f.Risk != "critical" {
		t.Errorf("risk = %q, want critical", f.Risk)
	}
	wantFields := map[string]string{
		"username": "USERID", "password": "PASSW0RD", "scheme": "http",
		"sessionAuthenticated": "true", "classCount": "2", "negativeControl": "rejected",
		"systemName": "bmc01.example", "elementName": "IBM Integrated Management Module",
		"manufacturer": "IBM", "model": "IMM2", "serialNumber": "SN123456",
		"uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
	}
	for key, want := range wantFields {
		if got := explainField(*f, key); got != want {
			t.Errorf("field %s = %q, want %q", key, got, want)
		}
	}
	proof := explainField(*f, "proof")
	for _, want := range []string{"sessionAuthenticated=true", "authProbe=EnumerateClassNames", "classCount=2", "negativeControl=rejected"} {
		if !strings.Contains(proof, want) {
			t.Errorf("proof %q missing %q", proof, want)
		}
	}
}

func TestCIMDefaultCreds_AcceptAnyNoFinding(t *testing.T) {
	// A CIMOM that 200s any credential (validates nothing) must not yield a
	// default-cred finding: the invalid-credential negative control is accepted,
	// so no specific default can be attributed.
	srv := httptest.NewServer(acceptAnyCIMOM())
	defer srv.Close()

	tg := mkCIMTarget(t, srv.URL, "ADMIN", "ADMIN", true)
	if got := runCIMDefaultCreds(context.Background(), tg); len(got) != 0 {
		t.Fatalf("accept-any CIMOM must yield no finding (negative control), got %+v", got)
	}
}

func TestCIMDefaultCreds_AnonymousNoFinding(t *testing.T) {
	// A CIMOM that 200s every request regardless of auth must not yield a finding.
	srv := httptest.NewServer(anonymousCIMOM())
	defer srv.Close()

	tg := mkCIMTarget(t, srv.URL, "root", "calvin", true)
	if got := runCIMDefaultCreds(context.Background(), tg); len(got) != 0 {
		t.Fatalf("anonymous CIMOM must yield no finding (negative control), got %+v", got)
	}
}

func TestCIMDefaultCreds_OfflineGate(t *testing.T) {
	srv := httptest.NewServer(credentialedCIMOM("USERID", "PASSW0RD"))
	defer srv.Close()
	tg := mkCIMTarget(t, srv.URL, "USERID", "PASSW0RD", false)
	if got := runCIMDefaultCreds(context.Background(), tg); got != nil {
		t.Errorf("offline mode must not attempt a CIM login, got %+v", got)
	}
}
