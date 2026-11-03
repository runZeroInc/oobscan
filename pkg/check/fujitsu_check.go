package check

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// Fujitsu iRMC (S5/S6, MegaRAC SP-X) serves a ServerView "System Report" at
// GET /report.xml (handler FTS_WebServer EmitHpSimInfo -> Xml_ALLDATAReq,
// descriptor idx 0x3b, authFlag==0), leaking the System GUID, device/firmware
// ID, and chassis power state pre-auth. It is gated by the HP-SIM/ServerView-
// XML config toggle (OID 0x1968), so this only confirms the leak when the
// report actually comes back unauthenticated. Read-only GET, no login or
// state change.
func init() {
	Register(Check{
		Name:        "http.fujitsu.irmcReport",
		Description: "Fujitsu iRMC pre-auth ServerView system report (/report.xml) leaks System GUID / device+firmware ID / power state",
		Category:    "info-leak",
		Applies:     Applicability{Vendors: []string{"fujitsu"}, Classes: []engine.DeviceClass{engine.ClassBMC}},
		Enabled:     true,
		Run:         runFujitsuXmldata,
	})
}

func runFujitsuXmldata(ctx context.Context, t *engine.Target) []engine.Finding {
	client := insecureWebClient(min(t.Timeout, 5*time.Second))
	for _, ep := range fujitsuReportEndpoints(t) {
		if ep.port <= 0 {
			continue
		}
		// /report.xml is the ServerView system report; /xmldata is the item alias.
		for _, path := range []string{"/report.xml", "/xmldata"} {
			st, ctype, body := httpProbe(ctx, client, hostPortURL(ep.scheme, t.Host, ep.port, path), "")
			if st != 200 || len(body) == 0 {
				continue
			}
			if !looksLikeIRMCReport(ctype, body) {
				continue
			}
			return []engine.Finding{{
				Check: "http.fujitsu.irmcReport", Category: "info-leak", Risk: "medium",
				Port: ep.port, Transport: "tcp", Protocol: ep.scheme,
				Fields: engine.F(
					"url", path,
					"guid", firstXMLValue(body, "GUID")),
			}}
		}
	}
	return nil
}

func fujitsuReportEndpoints(t *engine.Target) []webPortSpec {
	seen := map[string]struct{}{}
	var out []webPortSpec
	add := func(port int, scheme string) {
		if port <= 0 || (scheme != "http" && scheme != "https") {
			return
		}
		key := fmt.Sprintf("%s:%d", scheme, port)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, webPortSpec{port: port, scheme: scheme})
	}

	// Probe the identify-chosen web endpoint first (covers HTTP-only iRMC), then
	// common defaults and conventional alternate management web ports observed in
	// the scan scope.
	add(webPort(t), webProto(t))
	add(httpsPort(t), "https")
	add(80, "http")
	for _, wp := range webCandidatePorts(t) {
		add(wp.port, wp.scheme)
	}
	for _, p := range t.Ports {
		if p.Proto != engine.ProtoTCP {
			continue
		}
		switch p.Num {
		case 443, 444, 8443, 9443, 4443, 4433, 10443, 7443, 6443, 4444, 8083, 7548, 9898, 4434, 8081:
			add(p.Num, "https")
		case 80, 8080, 8000, 8888:
			add(p.Num, "http")
		}
	}
	return out
}

// looksLikeIRMCReport reports whether a 200 body is the Fujitsu ServerView
// system report (not an unrelated XML page). Requires an XML shape plus a
// ServerView/report marker so it does not fire on any XML the server returns.
func looksLikeIRMCReport(ctype string, body []byte) bool {
	low := strings.ToLower(string(body))
	if !strings.Contains(low, "<?xml") && !strings.Contains(strings.ToLower(ctype), "xml") {
		return false
	}
	// ServerView report markers observed in FTS_WebServer / Report.xslt output.
	for _, m := range []string{"report.xslt", "systemreport", "serverview", "hpsim", "<system", "irmc"} {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// firstXMLValue extracts the text of the first <tag>...</tag> whose name contains
// the given (case-insensitive) needle, e.g. "GUID". Returns "" if not found.
// A tiny best-effort extractor -- the finding stands on the report presence, the
// GUID is enrichment only.
func firstXMLValue(body []byte, needle string) string {
	low := strings.ToLower(string(body))
	nl := strings.ToLower(needle)
	i := strings.Index(low, nl+">")
	if i < 0 {
		return ""
	}
	start := i + len(nl) + 1
	end := strings.IndexByte(low[start:], '<')
	if end < 0 || end > 128 {
		return ""
	}
	return strings.TrimSpace(string(body[start : start+end]))
}

func init() {
	RegisterExplain("http.fujitsu.irmcReport", explainFujitsuIRMCReport)
}

func explainFujitsuIRMCReport(host string, f engine.Finding) string {
	guid := explainField(f, "guid")
	url := explainField(f, "url")
	if url == "" {
		url = "/report.xml"
	}
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nFujitsu iRMC ServerView `/report.xml` returns System GUID, device/firmware ID,\n")
	b.WriteString("and chassis power state without authentication.\n")
	if guid != "" {
		b.WriteString(fmt.Sprintf("\n**System GUID:** `%s`\n", guid))
	}
	b.WriteString("\n**Retrieve:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk %s%s", baseURL, url),
		fmt.Sprintf("curl -sk %s/redfish/v1/ | python3 -m json.tool", baseURL),
	))
	b.WriteString("\n\n**Impact:** GUID and model enable targeted attack; default creds `admin/admin`\n")
	b.WriteString("may give full iRMC access.\n")
	return b.String()
}
