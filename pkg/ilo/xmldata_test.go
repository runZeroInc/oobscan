package ilo

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/httpx"
)

// Verifies pre-auth /xmldata NICS parsing for per-port MAC and IP data.
func TestXMLDataNICSMACIPs(t *testing.T) {
	raw := `<?xml version="1.0"?>
<RIMP>
 <HSI>
  <SPN>ProLiant DL360 Gen9</SPN>
  <SBSN>CZ3447HTCW</SBSN>
  <NICS>
   <NIC><PORT>1</PORT><DESCRIPTION>iLO 4</DESCRIPTION><LOCATION>Embedded</LOCATION><MACADDR>00:11:22:33:44:55</MACADDR><IPADDR>10.0.0.5</IPADDR><STATUS>OK</STATUS></NIC>
   <NIC><PORT>2</PORT><DESCRIPTION>iLO 4</DESCRIPTION><MACADDR>00:11:22:33:44:56</MACADDR><IPADDR></IPADDR><STATUS>Disabled</STATUS></NIC>
   <NIC><PORT>3</PORT><MACADDR></MACADDR><IPADDR></IPADDR></NIC>
  </NICS>
 </HSI>
 <MP><PN>Integrated Lights-Out 4</PN><FWRI>2.77</FWRI><ST>7</ST></MP>
</RIMP>`
	var x XMLData
	if err := xml.Unmarshal([]byte(raw), &x); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := x.Generation(); got != "iLO4" {
		t.Errorf("Generation = %q, want iLO4", got)
	}
	if x.HSI.SBSN != "CZ3447HTCW" {
		t.Errorf("SBSN = %q", x.HSI.SBSN)
	}
	if len(x.HSI.NICS.NIC) != 3 {
		t.Fatalf("parsed %d NICs, want 3", len(x.HSI.NICS.NIC))
	}
	macips := x.MACIPs()
	// Port 3 has an empty MAC and must be skipped; ports 1 and 2 are kept.
	if len(macips) != 2 {
		t.Fatalf("MACIPs = %v, want 2 entries", macips)
	}
	if macips[0] != "00:11:22:33:44:55 10.0.0.5" {
		t.Errorf("MACIPs[0] = %q, want %q", macips[0], "00:11:22:33:44:55 10.0.0.5")
	}
	if macips[1] != "00:11:22:33:44:56" {
		t.Errorf("MACIPs[1] = %q, want MAC only (no IP)", macips[1])
	}
}

// iloRIMP is a minimal but realistic pre-auth /xmldata?item=all body.
const iloRIMP = `<?xml version="1.0"?>
<RIMP>
 <HSI><SPN>ProLiant DL360 Gen10</SPN><PRODUCTID>867959-B21</PRODUCTID>
  <SBSN>CZ3816YAAA</SBSN><UUID>ILO868703CZ3816YAAA</UUID></HSI>
 <MP><PN>Integrated Lights-Out 5</PN><FWRI>2.82</FWRI><ST>8</ST><SN>ILOCZ3816YC8E</SN></MP>
</RIMP>`

// emptyRIMPServer answers /xmldata with a 200 that parses but names no iLO --
// what a generic web server (a NAT'd router UI on 443) does.
func newXMLServer(t *testing.T, body string) (host string, port int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse test server port: %v", err)
	}
	return u.Hostname(), p
}

// TestFetchPortsNonStandardPort covers the gap that made iLOs published on
// 8443/4443/8083 invisible: Fetch built its URL from a bare host, so /xmldata
// only ever reached 443/80.
func TestFetchPortsNonStandardPort(t *testing.T) {
	host, port := newXMLServer(t, iloRIMP)
	x, err := FetchPorts(httpx.Client(3*time.Second), host, nil, []int{port})
	if err != nil || x == nil {
		t.Fatalf("FetchPorts on non-standard port: err=%v doc=%v", err, x)
	}
	if got := x.Generation(); got != "iLO5" {
		t.Errorf("Generation = %q, want iLO5", got)
	}
	if x.HSI.SPN != "ProLiant DL360 Gen10" {
		t.Errorf("SPN = %q, want the server model", x.HSI.SPN)
	}
}

// TestFetchPortsEmptyDocDoesNotMaskRealILO covers the ordering half of the same
// bug: a non-iLO 200 on the first candidate port used to be returned
// immediately, hiding a real iLO forwarded to a later port.
func TestFetchPortsEmptyDocDoesNotMaskRealILO(t *testing.T) {
	decoyHost, decoyPort := newXMLServer(t, `<html><body>Vigor Login Page</body></html>`)
	iloHost, iloPort := newXMLServer(t, iloRIMP)
	if decoyHost != iloHost {
		t.Skipf("test servers on different hosts (%s vs %s)", decoyHost, iloHost)
	}
	x, err := FetchPorts(httpx.Client(3*time.Second), iloHost, nil, []int{decoyPort, iloPort})
	if err != nil || x == nil {
		t.Fatalf("FetchPorts: err=%v doc=%v", err, x)
	}
	if got := x.Generation(); got != "iLO5" {
		t.Fatalf("Generation = %q, want iLO5 -- the empty doc from the first "+
			"candidate port masked the real iLO", got)
	}
}

// TestGenerationFromString covers the data-only generation resolver used by the
// convert path: it must place an iLO from a product string or a Server header,
// return "" for a generation-agnostic string (an mpSSH banner, a bare ProLiant
// model), and not false-positive on look-alikes ("silo-4", a stray "out 5").
func TestGenerationFromString(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Integrated Lights-Out 4", "iLO4"},
		{"Integrated Lights-Out 5", "iLO5"},
		{"Integrated Lights-Out 6", "iLO6"},
		{"HP-iLO-4/2.55", "iLO4"},
		{"HP-iLO-5/2.95", "iLO5"},
		{"iLO4", "iLO4"},
		{"iLO 3", "iLO3"},
		{"ilo-2", "iLO2"},
		// No generation token: the caller must treat these as unknown, not iLO4.
		{"ProLiant DL360 Gen10", ""},
		{"SSH-2.0-mpSSH_0.2.1", ""},
		{"Apache/2.4", ""},
		{"", ""},
		// Look-alikes that must not match.
		{"silo-4", ""},
		{"time out 5 seconds", ""},
	}
	for _, c := range cases {
		if got := GenerationFromString(c.in); got != c.want {
			t.Errorf("GenerationFromString(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestFetchPortsFallsBackToEmptyDoc preserves Fetch's original contract: when
// nothing names an iLO, a parsed doc is still returned rather than an error.
func TestFetchPortsFallsBackToEmptyDoc(t *testing.T) {
	host, port := newXMLServer(t, `<RIMP></RIMP>`)
	x, err := FetchPorts(httpx.Client(3*time.Second), host, nil, []int{port})
	if err != nil || x == nil {
		t.Fatalf("want empty doc, got err=%v doc=%v", err, x)
	}
	if x.Populated() {
		t.Errorf("Populated = true for an empty <RIMP/> shell")
	}
	// Generation deliberately falls back to a bare "iLO"; it is not an
	// emptiness test and callers must not use it as one.
	if got := x.Generation(); got != "iLO" {
		t.Errorf("Generation = %q, want the bare \"iLO\" fallback", got)
	}
}

// TestGenerationILO7 checks that an iLO7 product name maps to iLO7 rather than
// an earlier generation.
func TestGenerationILO7(t *testing.T) {
	x := &XMLData{}
	x.MP.PN = "Integrated Lights-Out 7 (iLO 7)"
	if got := x.Generation(); got != "iLO7" {
		t.Errorf("Generation = %q, want iLO7", got)
	}
}
