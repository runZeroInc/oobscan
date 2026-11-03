package check

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func TestLooksLikeIRMCReport(t *testing.T) {
	report := []byte(`<?xml version="1.0"?><?xml-stylesheet href="Report.xslt"?><SystemReport><System><GUID>44454C4C-1234</GUID></System></SystemReport>`)
	if !looksLikeIRMCReport("text/xml", report) {
		t.Error("expected a ServerView system report to be recognized")
	}
	// An unrelated XML doc must not fire.
	if looksLikeIRMCReport("application/xml", []byte(`<?xml version="1.0"?><rss><channel/></rss>`)) {
		t.Error("unrelated XML must not be recognized as an iRMC report")
	}
	// A JSON/HTML body must not fire.
	if looksLikeIRMCReport("text/html", []byte(`<html><body>login</body></html>`)) {
		t.Error("HTML must not be recognized as an iRMC report")
	}
}

func TestFirstXMLValue(t *testing.T) {
	body := []byte(`<SystemReport><GUID>44454C4C-ABCD</GUID></SystemReport>`)
	if got := firstXMLValue(body, "GUID"); got != "44454C4C-ABCD" {
		t.Errorf("firstXMLValue = %q, want %q", got, "44454C4C-ABCD")
	}
	if got := firstXMLValue(body, "nope"); got != "" {
		t.Errorf("firstXMLValue(missing) = %q, want empty", got)
	}
}

func TestRunFujitsuXmldataHTTPFallback(t *testing.T) {
	report := `<?xml version="1.0"?><?xml-stylesheet href="Report.xslt"?><SystemReport><System><GUID>GUID-123</GUID></System></SystemReport>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/report.xml":
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(report))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	tgt := mkTarget(t, srv.URL, "fujitsu")
	tgt.Timeout = 2 * time.Second
	tgt.Identity.Product = "iRMC"
	tgt.Identity.Class = engine.ClassBMC

	got := runFujitsuXmldata(context.Background(), tgt)
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %d", len(got))
	}
	if got[0].Check != "http.fujitsu.irmcReport" {
		t.Fatalf("check=%q, want http.fujitsu.irmcReport", got[0].Check)
	}
	if got[0].Protocol != "http" {
		t.Fatalf("protocol=%q, want http", got[0].Protocol)
	}
	if guid := explainField(got[0], "guid"); guid != "GUID-123" {
		t.Fatalf("guid=%q, want GUID-123", guid)
	}
}

func TestFujitsuReportEndpointsIncludesDiscoveredWebPorts(t *testing.T) {
	tgt := &engine.Target{
		Ports: []engine.Port{
			{Num: 22, Proto: engine.ProtoTCP},
			{Num: 8443, Proto: engine.ProtoTCP},
			{Num: 8080, Proto: engine.ProtoTCP},
		},
		Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "fujitsu"},
	}
	got := fujitsuReportEndpoints(tgt)
	want := map[webPortSpec]bool{
		{port: 443, scheme: "https"}:  true,
		{port: 80, scheme: "http"}:    true,
		{port: 8443, scheme: "https"}: true,
		{port: 8080, scheme: "http"}:  true,
	}
	for _, wp := range got {
		delete(want, wp)
		if wp.port == 22 {
			t.Fatalf("unexpected SSH port in Fujitsu report endpoints: %+v", got)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing Fujitsu report endpoints: %+v (got %+v)", want, got)
	}
}
