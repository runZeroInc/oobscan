package check

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/wsman"
)

const wsmanIdentify = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><IdentifyResponse><ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</ProtocolVersion><ProductVendor>OpenBMC</ProductVendor><ProductVersion>2.14.0</ProductVersion><SecurityProfileName>HTTPS-Basic</SecurityProfileName></IdentifyResponse></s:Body></s:Envelope>`

const wsmanSystemInfo = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><EnumerateResponse><Items><CIM_ComputerSystem><Name>openbmc.example</Name><ElementName>OpenBMC</ElementName><Manufacturer>OpenBMC</Manufacturer><Model>2.14.0</Model><UUID>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</UUID></CIM_ComputerSystem></Items></EnumerateResponse></s:Body></s:Envelope>`

func TestWSMANDetected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/wsman" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(wsmanIdentify))
	}))
	defer ts.Close()

	host, port := testHostPort(t, ts.URL)
	tgt := &engine.Target{Host: host, Timeout: 800 * time.Millisecond}
	tgt.Ports = []engine.Port{{Num: port, Proto: engine.ProtoTCP}}
	tgt.SetEvidence("wsman", &wsman.Identity{URL: ts.URL + "/wsman", ProductVendor: "OpenBMC"})

	got := runWSMANDetected(t.Context(), tgt)
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %d", len(got))
	}
	f := got[0]
	if f.Check != "http.wsman.detected" || f.Risk != "info" {
		t.Fatalf("unexpected finding: %+v", f)
	}
	if f.Protocol != "wsman" || f.Port != port {
		t.Fatalf("unexpected protocol/port: %+v", f)
	}
}

func TestWSMANDefaultCreds(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wsman" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("SOAPAction") == `"http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"` {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(wsmanSystemInfo))
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "root" || p != "calvin" {
			w.Header().Set("WWW-Authenticate", `Basic realm="wsman"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(wsmanIdentify))
	}))
	defer ts.Close()

	host, port := testHostPort(t, ts.URL)
	tgt := &engine.Target{Host: host, Timeout: 800 * time.Millisecond, DisableLogins: false}
	tgt.Ports = []engine.Port{{Num: port, Proto: engine.ProtoTCP}}
	tgt.Identity = &engine.Identity{Class: engine.ClassBMC, Vendor: "dell"}
	tgt.SetEvidence("wsman", &wsman.Identity{URL: ts.URL + "/wsman", ProductVendor: "OpenBMC"})

	got := runWSMANDefaultCreds(t.Context(), tgt)
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %d", len(got))
	}
	f := got[0]
	if f.Check != "http.wsman.defaultCreds" || f.Risk != "critical" {
		t.Fatalf("unexpected finding: %+v", f)
	}
	if fieldVal(f.Fields, "username") != "root" || fieldVal(f.Fields, "password") != "calvin" {
		t.Fatalf("missing default credential fields: %+v", f.Fields)
	}
	if fieldVal(f.Fields, "manufacturer") != "OpenBMC" || fieldVal(f.Fields, "proof") == "" {
		t.Fatalf("missing authenticated proof fields: %+v", f.Fields)
	}
}

func TestWSMANDefaultCredsRequiresFingerprint(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10", Identity: &engine.Identity{Vendor: "dell"}}
	if got := runWSMANDefaultCreds(t.Context(), tgt); len(got) != 0 {
		t.Fatalf("unconfirmed WS-Man target returned findings: %+v", got)
	}
}

func TestWSMANPostAuthEnum(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.1", Timeout: 800 * time.Millisecond, DisableLogins: false}
	got := runWSMANPostAuthEnum(t.Context(), tgt)
	if len(got) != 0 {
		t.Fatalf("expected no findings from legacy post-auth enum path, got %+v", got)
	}
}

func TestWSMANCandidatePortsPreferDedicated(t *testing.T) {
	tgt := &engine.Target{
		Host: "192.0.2.1",
		Ports: []engine.Port{
			{Num: 443, Proto: engine.ProtoTCP},
			{Num: 8443, Proto: engine.ProtoTCP},
			{Num: 80, Proto: engine.ProtoTCP},
		},
		Identity: &engine.Identity{Attributes: map[string]string{"webPort": "443"}},
	}
	got := wsmanCandidatePorts(tgt)
	want := []int{5986, 5985, 16993, 16992, 443, 80, 8443}
	if len(got) < len(want) {
		t.Fatalf("candidate port list too short: got %v want prefix %v", got, want)
	}
	for i, p := range want {
		if got[i] != p {
			t.Fatalf("candidate ports[%d]=%d, want %d; full=%v", i, got[i], p, got)
		}
	}
}

func testHostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return u.Hostname(), p
}

func fieldVal(fs engine.Fields, key string) string {
	for _, f := range fs {
		if f.Key == key {
			return f.Val
		}
	}
	return ""
}
