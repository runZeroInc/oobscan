package httpscan

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAggregatedTargetsIncludesFirmwareFindings(t *testing.T) {
	targets := AggregatedTargets()
	seen := map[string]AggregatedTarget{}
	for _, target := range targets {
		seen[target.Path] = target
	}
	for _, path := range []string{
		"/api/",
		"/rpc/getsysinfo.asp",
		"/cgi/login_oem.cgi",
		"/JsonSchemas.tar.xz",
		"/redfish/v1/",
		"/xmldata?item=all",
		"/device/ui-config.js", // JetKVM IP-KVM fingerprint
		"/device/status",       // JetKVM no-auth mode
	} {
		if _, ok := seen[path]; !ok {
			t.Fatalf("expected target %s in aggregated corpus", path)
		}
	}
	redfish := seen["/redfish/v1/"]
	if len(redfish.Vendors) < 2 {
		t.Fatalf("expected shared redfish target to aggregate multiple vendors, got %#v", redfish.Vendors)
	}
}

func TestTargetsForVendors(t *testing.T) {
	all := AggregatedTargets()
	targets := targetsForVendors(all, []string{"dell"})
	if len(targets) == 0 || len(targets) >= len(all) {
		t.Fatalf("Dell target count = %d, full corpus = %d", len(targets), len(all))
	}
	for _, target := range targets {
		if !slices.Contains(target.Vendors, "dell") {
			t.Fatalf("non-Dell target retained: %+v", target)
		}
	}
}

func TestClassifyReadableLeak(t *testing.T) {
	target := AggregatedTarget{Path: "/rpc/getsysinfo.asp", Match: MatchExact, Tags: []string{"info", "rpc"}}
	rr := RequestResult{Method: http.MethodGet, Status: 200, BodyBytes: 64, Snippet: `<fwVersion>3.65P</fwVersion><session>abc</session>`}
	got := classify(target, rr)
	assertContains(t, got, "preAuthReadable")
	assertContains(t, got, "possibleDataLeak")
}

func TestClassifyStaticHTMLIsNotReadableData(t *testing.T) {
	target := AggregatedTarget{Path: "/page/maintenance.www", Match: MatchExact, Tags: []string{"static", "fingerprint"}}
	body := `<!DOCTYPE html><html><script>function clearSession() { window.location = "/"; }</script></html>`
	rr := RequestResult{
		Method: http.MethodGet, Status: 200, BodyBytes: len(body),
		ContentType: "text/html", Snippet: body, Body: body,
		Fingerprint: Fingerprint{Fingerprint: "html-meta ATEN International Co Ltd.; smc-ui:legacy"},
	}
	got := classify(target, rr)
	assertNotContains(t, got, "preAuthReadable")
	assertNotContains(t, got, "possibleDataLeak")
}

func TestClassifySoftHTMLArchiveResponseIsNotDisclosure(t *testing.T) {
	target := AggregatedTarget{Path: "/JsonSchemas.tar.xz", Match: MatchExact, Tags: []string{"static", "schema", "archive"}}
	body := `<!DOCTYPE html><html><title>Login</title></html>`
	rr := RequestResult{
		Method: http.MethodGet, Status: 200, BodyBytes: len(body),
		ContentType: "text/html", Snippet: body, Body: body,
	}
	got := classify(target, rr)
	assertNotContains(t, got, "preAuthReadable")
	assertNotContains(t, got, "staticDisclosure")
}

func TestClassifyConcreteJSONIdentityIsReadableData(t *testing.T) {
	target := AggregatedTarget{Path: "/DeviceDescription.json", Match: MatchExact, Tags: []string{"info", "json", "static", "fingerprint"}}
	body := `[{"type":"lenovo-xclarity-controller","serial-number":"J300ABC","firmware":"6.10"}]`
	rr := RequestResult{
		Method: http.MethodGet, Status: 200, BodyBytes: len(body),
		ContentType: "application/json", Snippet: body, Body: body,
	}
	got := classify(target, rr)
	assertContains(t, got, "preAuthReadable")
	assertContains(t, got, "possibleDataLeak")
}

func TestClassifyHandlerReachable(t *testing.T) {
	target := AggregatedTarget{Path: "/cgi/", Match: MatchPrefix, Tags: []string{"dynamic", "cgi"}}
	rr := RequestResult{Method: http.MethodHead, Status: 403}
	got := classify(target, rr)
	assertContains(t, got, "handlerReachable")
	assertContains(t, got, "prefixLive")
}

func TestClassifyUploadSurface(t *testing.T) {
	target := AggregatedTarget{Path: "/cgi/firmware_upload.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "upload"}}
	rr := RequestResult{Method: http.MethodPost, Status: 302}
	got := classify(target, rr)
	assertContains(t, got, "redirected")
	assertContains(t, got, "upload-surface")
}

func TestClassifyScansFullBody(t *testing.T) {
	// The leak keyword is present only in the retained body, beyond the preview.
	target := AggregatedTarget{Path: "/redfish/v1/", Match: MatchExact, Tags: []string{"info", "redfish"}}
	filler := strings.Repeat("x", 400)
	rr := RequestResult{
		Method:    http.MethodGet,
		Status:    200,
		BodyBytes: 421,
		Snippet:   filler[:200], // preview carries no keyword
		Body:      filler + "FirmwareVersion=1.2.3",
	}
	got := classify(target, rr)
	assertContains(t, got, "possibleDataLeak")
}

func TestRetainBodyCapsAndStripsBinary(t *testing.T) {
	// Binary/control bytes are dropped (no mojibake), printable text is kept, and
	// the retained copy is capped at defaultBodyCap so a hostile body can't grow
	// memory without bound.
	raw := append([]byte("HELLO\x00\xff\x01world"), bytes.Repeat([]byte("A"), defaultBodyCap)...)
	got := retainBody(raw)
	if len(got) > defaultBodyCap {
		t.Fatalf("retainBody exceeded cap: %d > %d", len(got), defaultBodyCap)
	}
	if strings.IndexByte(got, 0x00) >= 0 || strings.IndexByte(got, 0xff) >= 0 || strings.IndexByte(got, 0x01) >= 0 {
		t.Fatalf("retainBody kept binary bytes")
	}
	if !strings.HasPrefix(got, "HELLOworld") {
		t.Fatalf("retainBody mangled printable text: %.20q", got)
	}
}

func TestExtractTitle(t *testing.T) {
	cases := []struct {
		snippet string
		want    string
	}{
		{`<html><head><title>HP iLO Login</title></head>`, "HP iLO Login"},
		{`<TITLE>Supermicro BMC Login</TITLE>`, "Supermicro BMC Login"},
		{`<title id="t"> iBMC Login </title>`, "iBMC Login"},
		{`<html><body>no title here</body></html>`, ""},
		{``, ""},
	}
	for _, c := range cases {
		if got := extractTitle(c.snippet); got != c.want {
			t.Errorf("extractTitle(%q) = %q, want %q", c.snippet, got, c.want)
		}
	}
}

func TestProbeHostCtxDropsRetainedBodies(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redfish/v1/" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"@odata.id":"/redfish/v1/","FirmwareVersion":"9.9.9"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "https://"))
	if err != nil {
		t.Fatalf("split host:port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	targets := []AggregatedTarget{{
		Path: "/redfish/v1/", Match: MatchExact, Tags: []string{"info", "redfish"},
	}}
	rep, err := probeHostTargets(ctx, host, port, "", 300*time.Millisecond, targets)
	if err != nil {
		t.Fatalf("ProbeHostCtx: %v", err)
	}
	if rep == nil || len(rep.HTTPFindings) == 0 {
		t.Fatalf("expected at least one HTTP finding")
	}
	for i := range rep.HTTPFindings {
		for j := range rep.HTTPFindings[i].Requests {
			if rep.HTTPFindings[i].Requests[j].Body != "" {
				t.Fatalf("retained body was not stripped for %s %s", rep.HTTPFindings[i].Path, rep.HTTPFindings[i].Requests[j].Method)
			}
		}
	}
}

func assertContains(t *testing.T, values []string, want string) {
	t.Helper()
	if slices.Contains(values, want) {
		return
	}
	t.Fatalf("expected %q in %#v", want, values)
}

func assertNotContains(t *testing.T, values []string, unwanted string) {
	t.Helper()
	if slices.Contains(values, unwanted) {
		t.Fatalf("did not expect %q in %#v", unwanted, values)
	}
}
