package check

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

type preauthProbe struct {
	id      string
	vendors []string
	method  string
	path    string
	body    string
	ctype   string
	risk    string

	match func(status int, respCT string, body []byte) bool
}

var preauthProbes = []preauthProbe{
	{
		id: "http.raritan.loginOptions", vendors: []string{"raritan"}, method: "GET",
		path: "/cgi-bin/login_options.cgi", risk: "low",
		match: func(st int, _ string, b []byte) bool {
			if st != 200 {
				return false
			}
			s := strings.ToLower(string(b))
			return strings.Contains(s, "raritan") || strings.Contains(s, "restricted") || strings.Contains(s, "agreement")
		},
	},
	{
		id: "http.rittal.restMetrics", vendors: []string{"rittal"}, method: "GET",
		path: "/rest/v1/system/metrics", risk: "low",
		match: func(st int, ct string, b []byte) bool {
			if st != 200 || !(strings.Contains(ct, "json") || looksLikeJSON(b)) {
				return false
			}
			s := strings.ToLower(string(b))
			return strings.Contains(s, "uptime") || strings.Contains(s, "memory") || strings.Contains(s, "cpu")
		},
	},
	{
		id: "http.westermo.alarmCgi", vendors: []string{"westermo"}, method: "GET",
		path: "/alarm.cgi", risk: "low",
		match: func(st int, _ string, b []byte) bool {
			return st == 200 && strings.Contains(strings.ToLower(string(b)), "alarm")
		},
	},
	{
		id: "http.tripplite.logsXml", vendors: []string{"tripplite"}, method: "GET",
		path: "/logs/datalog.xml", risk: "medium",
		match: func(st int, ct string, b []byte) bool {
			if st != 200 {
				return false
			}
			s := strings.ToLower(string(b))

			if strings.Contains(s, "papwd") || strings.Contains(s, "logincontainer") {
				return false
			}
			return (strings.Contains(ct, "xml") || strings.Contains(s, "<")) && (strings.Contains(s, "log") || strings.Contains(s, "record"))
		},
	},
	{
		id: "http.tinypilot.hostnameLeak", vendors: []string{"tinypilot"}, method: "GET",
		path: "/dedicated-window-placeholder", risk: "low",
		match: func(st int, ct string, b []byte) bool {

			if st != 200 {
				return false
			}
			s := strings.TrimSpace(string(b))
			return s != "" && len(s) < 256 && !strings.Contains(strings.ToLower(s), "<html")
		},
	},
	{
		id: "http.sierra.getPublic", vendors: []string{"sierra", "sierra-wireless"}, method: "POST",
		path: "/xml/GetPublic.xml", body: `<request xmlns="urn:acemanager"></request>`, ctype: "text/xml",
		risk: "low",
		match: func(st int, _ string, b []byte) bool {
			if st != 200 {
				return false
			}
			s := strings.ToLower(string(b))
			return strings.Contains(s, "acemanager") || strings.Contains(s, "network_state") || strings.Contains(s, "rssi")
		},
	},
}

func init() {
	for i := range preauthProbes {
		p := preauthProbes[i]
		Register(Check{
			Name:        p.id,
			Description: "Safe read-only confirmation of a documented pre-auth HTTP disclosure (" + p.path + ")",
			Category:    "exposure",
			Applies:     Applicability{CrossVendor: true},
			Enabled:     true,
			Run:         func(ctx context.Context, t *engine.Target) []engine.Finding { return runPreauthProbe(ctx, t, p) },
		})
	}
}

func runPreauthProbe(ctx context.Context, t *engine.Target, p preauthProbe) []engine.Finding {
	if !vendorMatches(t, p.vendors) {
		return nil
	}
	port := webPort(t)
	if !webPortMaybeOpen(t, port) {
		return nil
	}
	proto := webProto(t)
	client := insecureWebClient(min(t.Timeout, 6*time.Second))
	st, ct, body := preauthRequest(ctx, client, p.method, hostPortURL(proto, t.Host, port, p.path), p.body, p.ctype)
	if !p.match(st, ct, body) {
		return nil
	}
	t.MarkOpen(port, "tcp", proto)

	fields := engine.F(
		"url", p.path,
		"method", p.method,
		"status", strconv.Itoa(st),
		"bodyBytes", strconv.Itoa(len(body)),
		"contentType", ct,
		"snippet", cleanSnippet(string(body)),
	)
	return []engine.Finding{{
		Check: p.id, Category: "exposure", Risk: p.risk,
		Port: port, Transport: "tcp", Protocol: proto,
		Fields: fields,
	}}
}

func vendorMatches(t *engine.Target, vendors []string) bool {
	if t.Identity == nil || t.Identity.Vendor == "" {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(t.Identity.Vendor))
	return slices.Contains(vendors, v)
}

func preauthRequest(ctx context.Context, c *http.Client, method, rawURL, body, ctype string) (int, string, []byte) {
	var rdr io.Reader
	if method == http.MethodPost && body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return 0, "", nil
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, resp.Header.Get("Content-Type"), b
}
