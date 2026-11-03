package wsman

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

const identifyResp = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><IdentifyResponse><ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</ProtocolVersion><ProductVendor>Dell Inc.</ProductVendor><ProductVersion>iDRAC9</ProductVersion><SecurityProfileName>HTTPS-Mutual</SecurityProfileName></IdentifyResponse></s:Body></s:Envelope>`

const systemInfoResp = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><EnumerateResponse><Items><CIM_ComputerSystem><Name>idrac.example</Name><ElementName>iDRAC</ElementName><Manufacturer>Dell Inc.</Manufacturer><Model>iDRAC9</Model><UUID>12345678-1234-1234-1234-123456789abc</UUID></CIM_ComputerSystem></Items></EnumerateResponse></s:Body></s:Envelope>`

const systemInfoEnumerateCtxResp = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"><s:Body><wsen:EnumerateResponse><wsen:EnumerationContext>ctx-123</wsen:EnumerationContext></wsen:EnumerateResponse></s:Body></s:Envelope>`

const systemInfoPullResp = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:n1="http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_ComputerSystem"><s:Body><wsen:PullResponse><wsen:EnumerationContext>ctx-123</wsen:EnumerationContext><wsen:Items><n1:DCIM_ComputerSystem><n1:Name>srv:system</n1:Name><n1:OtherIdentifyingInfo>4c4c4544-0037-5710-8030-b1c04f473832</n1:OtherIdentifyingInfo><n1:OtherIdentifyingInfo>17W0G82</n1:OtherIdentifyingInfo></n1:DCIM_ComputerSystem></wsen:Items></wsen:PullResponse></s:Body></s:Envelope>`

func TestProbe(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/wsman" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(identifyResp))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	port, _ := strconv.Atoi(u.Port())
	id, err := Probe(u.Hostname(), []int{port}, time.Second)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if id == nil || id.ProductVendor != "Dell Inc." || id.ProductVersion != "iDRAC9" {
		t.Fatalf("unexpected identity: %#v", id)
	}
	if len(id.SecurityProfile) != 1 || id.SecurityProfile[0] != "HTTPS-Mutual" {
		t.Fatalf("security profile parse failed: %#v", id.SecurityProfile)
	}
}

func TestAuthenticateIdentifyBasic(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wsman" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if strings.Contains(r.Header.Get("SOAPAction"), "Enumerate") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(systemInfoResp))
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "root" || p != "calvin" {
			w.Header().Set("WWW-Authenticate", `Basic realm="wsman"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(identifyResp))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	port, _ := strconv.Atoi(u.Port())
	res, err := AuthenticateIdentify(u.Hostname(), []int{port}, time.Second, "root", "calvin")
	if err != nil {
		t.Fatalf("AuthenticateIdentify error: %v", err)
	}
	if res == nil || !res.Authenticated || res.Auth != "basic" {
		t.Fatalf("unexpected auth result: %#v", res)
	}
	if res.Identity == nil || res.Identity.ProductVendor == "" {
		t.Fatalf("missing parsed identity: %#v", res)
	}
}

func TestAuthenticateIdentifyDigest(t *testing.T) {
	const challenge = `Digest realm="wsman", nonce="abc123", qop="auth"`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wsman" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		auth := r.Header.Get("Authorization")
		cnonce := parseDigestChallenge(auth)["cnonce"]
		expect := digestAuthorizationWithCnonce(challenge, "POST", "/wsman", "admin", "admin", cnonce)
		if strings.Contains(r.Header.Get("SOAPAction"), "Enumerate") {
			if cnonce == "" || auth != expect {
				w.Header().Set("WWW-Authenticate", challenge)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(systemInfoResp))
			return
		}
		if cnonce == "" || auth != expect {
			w.Header().Set("WWW-Authenticate", challenge)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(identifyResp))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	port, _ := strconv.Atoi(u.Port())
	res, err := AuthenticateIdentify(u.Hostname(), []int{port}, time.Second, "admin", "admin")
	if err != nil {
		t.Fatalf("AuthenticateIdentify error: %v", err)
	}
	if res == nil || !res.Authenticated || res.Auth != "digest" {
		t.Fatalf("expected digest auth success, got %#v", res)
	}
}

func TestSystemInfoRequestEnumerateThenPull(t *testing.T) {
	endpoint := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wsman" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(r.Header.Get("SOAPAction"), "Enumerate") {
			if !strings.Contains(string(body), "<wsa:MessageID>") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if !strings.Contains(string(body), endpoint) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(systemInfoEnumerateCtxResp))
			return
		}
		if strings.Contains(r.Header.Get("SOAPAction"), "Pull") {
			if !strings.Contains(string(body), "ctx-123") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(systemInfoPullResp))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()
	endpoint = ts.URL + "/wsman"

	info, err := systemInfoRequest(http.DefaultClient, endpoint, 2*time.Second, basicAuth("root", "calvin"))
	if err != nil {
		t.Fatalf("systemInfoRequest error: %v", err)
	}
	if info == nil {
		t.Fatal("expected system info")
	}
	if info.Name != "srv:system" {
		t.Fatalf("unexpected name: %#v", info)
	}
	if info.UUID != "4c4c4544-0037-5710-8030-b1c04f473832" {
		t.Fatalf("unexpected UUID extraction: %#v", info)
	}
}

func TestParseURL(t *testing.T) {
	s, h, p := ParseURL("https://10.0.0.1:5986/wsman")
	if s != "https" || h != "10.0.0.1" || p != 5986 {
		t.Fatalf("ParseURL mismatch: %s %s %d", s, h, p)
	}
}

func TestDigestAuthorizationDeterministic(t *testing.T) {
	h := digestAuthorizationWithCnonce(`Digest realm="wsman", nonce="n1", qop="auth", opaque="zzz"`, "POST", "/wsman", "u", "p", "fixed")
	if !strings.Contains(h, `Digest username="u"`) {
		t.Fatalf("missing digest username: %s", h)
	}
	if !strings.Contains(h, `response="`) {
		t.Fatalf("missing digest response: %s", h)
	}
	if !strings.Contains(h, `opaque="zzz"`) {
		t.Fatalf("missing digest opaque: %s", h)
	}
	if strings.Contains(h, fmt.Sprintf("%q", "")) {
		t.Fatalf("unexpected empty quoted value: %s", h)
	}
}

func TestDigestAuthorizationUsesFreshCnonce(t *testing.T) {
	challenge := `Digest realm="wsman", nonce="n1", qop="auth"`
	first := parseDigestChallenge(digestAuthorization(challenge, "POST", "/wsman", "u", "p"))["cnonce"]
	second := parseDigestChallenge(digestAuthorization(challenge, "POST", "/wsman", "u", "p"))["cnonce"]
	if first == "" || second == "" || first == second {
		t.Fatalf("cnonces must be non-empty and unique: %q, %q", first, second)
	}
}

func TestSchemesForPort(t *testing.T) {
	tests := []struct {
		port int
		want []string
	}{
		{port: 5986, want: []string{"https", "http"}},
		{port: 5985, want: []string{"http", "https"}},
		{port: 16993, want: []string{"https", "http"}},
		{port: 16992, want: []string{"http", "https"}},
		{port: 443, want: []string{"https", "http"}},
	}
	for _, tc := range tests {
		got := schemesForPort(tc.port)
		if len(got) != len(tc.want) {
			t.Fatalf("port %d returned %v, want %v", tc.port, got, tc.want)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Fatalf("port %d returned %v, want %v", tc.port, got, tc.want)
			}
		}
	}
}
