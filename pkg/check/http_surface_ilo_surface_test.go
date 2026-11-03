package check

import (
	"context"
	"encoding/xml"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ilo"
)

// rimpDoc is a populated /xmldata?item=all reply, the shape an iLO serves pre-auth.
const rimpDoc = `<?xml version="1.0"?><RIMP><HSI><SPN>ProLiant DL380 G7</SPN>` +
	`<SBSN>CZ21100C5L</SBSN><UUID>470065CZ21100C5L</UUID></HSI>` +
	`<MP><ST>1</ST><PN>Integrated Lights-Out 3 (iLO 3)</PN><FWRI>1.94</FWRI>` +
	`<SN>ILOCZ21100C5L</SN></MP></RIMP>`

func populatedXMLData(t *testing.T) *ilo.XMLData {
	t.Helper()
	x := &ilo.XMLData{}
	if err := xml.Unmarshal([]byte(rimpDoc), x); err != nil {
		t.Fatalf("unmarshal RIMP: %v", err)
	}
	if !x.Populated() {
		t.Fatal("the test document is empty; it proves nothing")
	}
	return x
}

// iloOnlyServer answers /xmldata and drops the connection on every other path, the
// shape that produces the contradiction: the endpoint sweep fails at the transport
// layer while the small static handler on the same port serves the disclosures.
func iloOnlyServer(t *testing.T, hits *int64) (host string, port int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/xmldata") {
			hj, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		if hits != nil {
			atomic.AddInt64(hits, 1)
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(rimpDoc))
	}))
	t.Cleanup(srv.Close)
	return splitHostPortNum(t, srv.URL)
}

func splitHostPortNum(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(rawURL, "http://"))
	if err != nil {
		t.Fatalf("split %q: %v", rawURL, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}
	return host, port
}

func hpeTargetAt(host string, port int, scheme string) *engine.Target {
	tg := bmcTargetAt(host, port, scheme)
	tg.Identity.Vendor = "hpe"
	tg.Identity.Product = "iLO3"
	tg.Identity.Generation = "iLO3"
	return tg
}

// findingsForPort returns the check names a set of findings reports against port.
func findingsForPort(fs []engine.Finding, port int) []string {
	var out []string
	for _, f := range fs {
		if f.Port == port {
			out = append(out, f.Check)
		}
	}
	return out
}

// A port cannot both be reported unreachable and be the port an iLO disclosure was
// read from. The two checks run concurrently, so the guarantee has to hold whichever
// of them resolves the surface first: they resolve it through one shared read whose
// answer is settled on the first call.
func TestILODisclosureAndUnreachableNeverShareAPort(t *testing.T) {
	xml := populatedXMLData(t)

	newDeadPortWithIdentifyRead := func() *engine.Target {
		tg := hpeTargetAt("127.0.0.1", closedPort(t), "https")
		// What the fingerprint stage leaves after reading /xmldata and nothing else:
		// no Server header, no title, and the parsed document on file.
		delete(tg.Identity.Attributes, "http.server")
		delete(tg.Identity.Attributes, "http.title")
		tg.SetEvidence("ilo", xml)
		return tg
	}
	newDeadPortWithSignalOnly := func() *engine.Target {
		tg := hpeTargetAt("127.0.0.1", closedPort(t), "https")
		tg.Identity.Signals = []engine.Signal{{Source: "ilo", Vendor: "hpe", Detail: "iLO3"}}
		return tg
	}
	newLiveXMLDataOnly := func() *engine.Target {
		host, port := iloOnlyServer(t, nil)
		return hpeTargetAt(host, port, "http")
	}
	newDeadPortNoRead := func() *engine.Target {
		return hpeTargetAt("127.0.0.1", closedPort(t), "https")
	}

	shapes := []struct {
		name string
		make func() *engine.Target
	}{
		{"identify read /xmldata, port now dead", newDeadPortWithIdentifyRead},
		{"identify signal only, port now dead", newDeadPortWithSignalOnly},
		{"only /xmldata answers, sweep fails at the transport", newLiveXMLDataOnly},
		{"nothing answers", newDeadPortNoRead},
	}
	orders := []struct {
		name  string
		first func(context.Context, *engine.Target) []engine.Finding
		then  func(context.Context, *engine.Target) []engine.Finding
	}{
		{"surface first", runHTTPSurface, runILOXMLData},
		{"ilo first", runILOXMLData, runHTTPSurface},
	}

	for _, shape := range shapes {
		for _, order := range orders {
			t.Run(shape.name+"/"+order.name, func(t *testing.T) {
				tg := shape.make()
				ctx := context.Background()
				var fs []engine.Finding
				fs = append(fs, order.first(ctx, tg)...)
				fs = append(fs, order.then(ctx, tg)...)

				ports := map[int]bool{}
				for _, f := range fs {
					ports[f.Port] = true
				}
				for port := range ports {
					checks := findingsForPort(fs, port)
					unreachable, disclosed := false, false
					for _, c := range checks {
						switch c {
						case "http.surfaceUnreachable":
							unreachable = true
						case "http.ilo.xmlData", "http.ilo.licenseKey":
							disclosed = true
						}
					}
					if unreachable && disclosed {
						t.Fatalf("port %d is reported unreachable and disclosed in the same record: %v",
							port, checks)
					}
				}
			})
		}
	}
}

// The disclosure has to name the port it was read from. The read used to go to the
// default web ports whatever port the target's web tier was on, and the finding was
// then stamped with the target's web port regardless -- so the claim could name a
// port the document never came from.
func TestILOXMLDataReadsThePortItReports(t *testing.T) {
	host, port := iloOnlyServer(t, nil)
	tg := hpeTargetAt(host, port, "http")

	fs := runILOXMLData(context.Background(), tg)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want the disclosure read from the target's web port %d", len(fs), port)
	}
	if fs[0].Port != port {
		t.Errorf("finding port = %d, want %d (the port the document was read from)", fs[0].Port, port)
	}
	if fs[0].Protocol != "http" {
		t.Errorf("finding protocol = %q, want the scheme the read used", fs[0].Protocol)
	}
	if got := findingField(fs[0], "serial"); got != "CZ21100C5L" {
		t.Errorf("serial = %q, want the value the endpoint served", got)
	}
}

// The read is resolved once per target. Each check that needs it would otherwise
// open its own connection, and two reads of one surface can disagree -- which is
// how the port ends up reported unreachable by one check and disclosed by another.
func TestILOSurfaceResolvesOnce(t *testing.T) {
	var hits int64
	host, port := iloOnlyServer(t, &hits)
	tg := hpeTargetAt(host, port, "http")

	first := iloSurface(tg)
	if first == nil || first.data == nil {
		t.Fatal("the surface answered but was not resolved")
	}
	second := iloSurface(tg)
	if second != first {
		t.Errorf("second call returned a different answer (%p vs %p)", second, first)
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Errorf("/xmldata was read %d times, want 1: the resolved answer is not being shared", got)
	}
}

// A negative answer is shared too, so a surface that did not respond is not re-read
// by every caller and cannot answer differently for one of them.
func TestILOSurfaceSharesTheNegativeAnswer(t *testing.T) {
	tg := hpeTargetAt("127.0.0.1", closedPort(t), "https")
	if r := iloSurface(tg); r != nil {
		t.Fatalf("a dead port resolved to a read: %+v", r)
	}
	if _, ok := tg.Evidenced(iloSurfaceEvidenceKey); !ok {
		t.Error("the negative answer was not recorded; every later caller will re-read the surface")
	}
	if r := iloSurface(tg); r != nil {
		t.Fatalf("the second call disagreed with the first: %+v", r)
	}
}

// Evidence left behind by a sibling check is not a witness that this port answered.
// The document a generic web server leaves when it returns 200 to /xmldata parses
// and carries no iLO field at all, and treating its presence as a read suppressed
// the unreachable diagnostic on ports that genuinely did not answer.
func TestHTTPSurfaceUnreachableSurvivesEmptyILOEvidence(t *testing.T) {
	tg := bmcTargetAt("127.0.0.1", closedPort(t), "https")
	delete(tg.Identity.Attributes, "http.server")
	delete(tg.Identity.Attributes, "http.title")
	// A RIMP document that parsed but disclosed nothing.
	tg.SetEvidence("ilo", &ilo.XMLData{})

	fs := runHTTPSurface(context.Background(), tg)
	found := false
	for _, f := range fs {
		if f.Check == "http.surfaceUnreachable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a dead port was not reported unreachable: an empty /xmldata document on file "+
			"was taken as proof the surface was read; got %+v", fs)
	}
}

// The candidate list decides which port a disclosure can be attributed to. The web
// port the fingerprint stage settled on comes first; the plain-HTTP fallback the
// default fetch always had is kept, but as its own candidate so the answer names
// the port that served it.
func TestILOSurfaceEndpointOrder(t *testing.T) {
	cases := []struct {
		name  string
		build func() *engine.Target
		want  []webEndpoint
	}{
		{
			name: "web port first, plain http second when the target lists it",
			build: func() *engine.Target {
				tg := hpeTargetAt("192.0.2.10", 8443, "https")
				tg.Ports = []engine.Port{{Num: 80, Proto: engine.ProtoTCP}, {Num: 8443, Proto: engine.ProtoTCP}}
				return tg
			},
			want: []webEndpoint{{port: 8443, scheme: "https"}, {port: 80, scheme: "http"}},
		},
		{
			name: "no plain-http port listed",
			build: func() *engine.Target {
				tg := hpeTargetAt("192.0.2.10", 443, "https")
				tg.Ports = []engine.Port{{Num: 443, Proto: engine.ProtoTCP}}
				return tg
			},
			want: []webEndpoint{{port: 443, scheme: "https"}},
		},
		{
			name: "the web port is already plain http",
			build: func() *engine.Target {
				tg := hpeTargetAt("192.0.2.10", 80, "http")
				tg.Ports = []engine.Port{{Num: 80, Proto: engine.ProtoTCP}}
				return tg
			},
			want: []webEndpoint{{port: 80, scheme: "http"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := iloSurfaceEndpoints(tc.build())
			if len(got) != len(tc.want) {
				t.Fatalf("endpoints = %+v, want %+v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("endpoint %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}
