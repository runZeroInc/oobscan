package cim

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbeContextHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result := ProbeContext(ctx, http.DefaultClient, "http", "192.0.2.1:5988"); result != nil {
		t.Fatalf("cancelled probe returned result: %#v", result)
	}
}

func TestProbeDetectsCIMOM(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CIMOperation", "MethodResponse")
		w.Header().Set("Server", "OpenPegasus/2.14.1")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><CIM CIMVERSION="2.0"><MESSAGE/></CIM>`))
	}))
	defer ts.Close()
	res := Probe(ts.Client(), "http", strings.TrimPrefix(ts.URL, "http://"))
	if res == nil {
		t.Fatal("Probe returned nil for a CIMOM response")
	}
	if res.Broker != "OpenPegasus" {
		t.Fatalf("broker=%q, want OpenPegasus", res.Broker)
	}
}

func TestProbeRejectsPlainWeb(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html>not found</html>"))
	}))
	defer ts.Close()
	if res := Probe(ts.Client(), "http", strings.TrimPrefix(ts.URL, "http://")); res != nil {
		t.Fatalf("Probe should reject a plain web server, got %+v", res)
	}
}

func TestProbeDetectsAuthGatedCIMOM(t *testing.T) {
	// A bare 401 (no CIM markers) on the CIM-dedicated port must still be detected
	// so the default-credential check can reach an SMC-style auth-gated WBEM.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="cimom"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()
	res := Probe(ts.Client(), "http", strings.TrimPrefix(ts.URL, "http://"))
	if res == nil || !res.AuthReq {
		t.Fatalf("Probe should flag an auth-gated CIMOM (401 + WWW-Authenticate), got %+v", res)
	}
}

func TestAuthenticate(t *testing.T) {
	const user, pass = "ADMIN", "ADMIN"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != user || p != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="cimom"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("CIMOperation", "MethodResponse")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><CIM><MESSAGE><SIMPLERSP>` +
			`<IMETHODRESPONSE NAME="EnumerateClassNames"><IRETURNVALUE>` +
			`<CLASSNAME NAME="CIM_ComputerSystem"/></IRETURNVALUE></IMETHODRESPONSE>` +
			`</SIMPLERSP></MESSAGE></CIM>`))
	}))
	defer ts.Close()
	hp := strings.TrimPrefix(ts.URL, "http://")

	if ok, _ := Authenticate(ts.Client(), "http", hp, "ADMIN", "wrong"); ok {
		t.Fatal("Authenticate accepted a wrong password (should 401)")
	}
	ok, evidence := Authenticate(ts.Client(), "http", hp, user, pass)
	if !ok {
		t.Fatal("Authenticate rejected the correct password")
	}
	if evidence == nil || evidence.ClassCount != 1 {
		t.Fatalf("authentication evidence = %+v", evidence)
	}
}

func TestParseComputerSystem(t *testing.T) {
	body := []byte(`<CIM><MESSAGE><SIMPLERSP><IMETHODRESPONSE><IRETURNVALUE>` +
		`<VALUE.NAMEDINSTANCE><INSTANCE CLASSNAME="CIM_ComputerSystem">` +
		`<PROPERTY NAME="Name"><VALUE>bmc01</VALUE></PROPERTY>` +
		`<PROPERTY NAME="Manufacturer"><VALUE>IBM</VALUE></PROPERTY>` +
		`<PROPERTY NAME="Model"><VALUE>IMM2</VALUE></PROPERTY>` +
		`<PROPERTY NAME="SerialNumber"><VALUE>SN123</VALUE></PROPERTY>` +
		`</INSTANCE></VALUE.NAMEDINSTANCE></IRETURNVALUE></IMETHODRESPONSE></SIMPLERSP></MESSAGE></CIM>`)
	info, ok := parseComputerSystem(body)
	if !ok || info.Name != "bmc01" || info.Manufacturer != "IBM" || info.Model != "IMM2" || info.SerialNumber != "SN123" {
		t.Fatalf("parseComputerSystem() = %+v/%v", info, ok)
	}
}
