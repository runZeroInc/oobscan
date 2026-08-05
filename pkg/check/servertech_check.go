package check

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func init() {
	Register(Check{
		Name:        "http.servertech.configBakLeak",
		Description: "ServerTech Sentry unauthenticated config.bak exposure",
		Category:    "exposure",
		Applies: Applicability{
			Vendors: []string{"servertech"},
			Classes: []engine.DeviceClass{engine.ClassPDU},
		},
		Enabled: true,
		Run:     runServertechConfigBakLeak,
	})
	Register(Check{
		Name:        "http.servertech.mgrHandshake",
		Description: "ServerTech Sentry pre-auth XML manager handshake reachable",
		Category:    "exposure",
		Applies: Applicability{
			Vendors: []string{"servertech"},
			Classes: []engine.DeviceClass{engine.ClassPDU},
		},
		Enabled: true,
		Run:     runServertechMgrHandshake,
	})
}

func runServertechConfigBakLeak(ctx context.Context, t *engine.Target) []engine.Finding {
	port := webPort(t)
	proto := webProto(t)
	if !webPortMaybeOpen(t, port) {
		return nil
	}
	client := insecureWebClient(min(t.Timeout, 6*time.Second))
	for _, p := range []string{"/config.bak", "/_config.bak", "/RAM0/admn/config.bak", "/RAM0/admn/_config.bak"} {
		st, ct, body := httpProbe(ctx, client, hostPortURL(proto, t.Host, port, p), "")
		if st < 200 || st >= 300 {
			continue
		}
		bl := strings.ToLower(string(body))
		if strings.Contains(bl, "<html") || strings.Contains(bl, "login") {
			continue
		}
		if !strings.Contains(bl, "_secure") && !strings.Contains(bl, "community") && !strings.Contains(bl, "tacacs") && !strings.Contains(bl, "radius") && !strings.Contains(bl, "ldap") {
			continue
		}
		return []engine.Finding{{
			Check: "http.servertech.configBakLeak", Category: "exposure", Risk: "high",
			Port: port, Transport: "tcp", Protocol: proto,
			Fields: engine.F(
				"url", p,
				"status", fmt.Sprintf("%d", st),
				"content_type", cleanSnippet(ct),
				"response", cleanSnippet(string(body))),
		}}
	}
	return nil
}

func runServertechMgrHandshake(ctx context.Context, t *engine.Target) []engine.Finding {
	port := webPort(t)
	proto := webProto(t)
	if !webPortMaybeOpen(t, port) {
		return nil
	}
	url := hostPortURL(proto, t.Host, port, "/")
	payload := []byte(`<init><version>2</version><type>manager</type><company>Server Technology</company></init>`)
	st, ct, body := servertechPostXML(ctx, insecureWebClient(min(t.Timeout, 6*time.Second)), url, payload)
	if st < 200 || st >= 300 {
		return nil
	}
	bl := strings.ToLower(string(body))
	if strings.Contains(bl, "<html") {
		return nil
	}
	if !strings.Contains(ct, "xml") && !strings.HasPrefix(strings.TrimSpace(bl), "<") {
		return nil
	}
	if !strings.Contains(bl, "server") && !strings.Contains(bl, "sentry") && !strings.Contains(bl, "init") && !strings.Contains(bl, "cookie") {
		return nil
	}
	return []engine.Finding{{
		Check: "http.servertech.mgrHandshake", Category: "exposure", Risk: "info",
		Port: port, Transport: "tcp", Protocol: proto,
		Fields: engine.F(
			"url", "/",
			"status", fmt.Sprintf("%d", st),
			"response", cleanSnippet(string(body))),
	}}
}

func servertechPostXML(ctx context.Context, c *http.Client, rawURL string, body []byte) (status int, ctype string, out []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return 0, "", nil
	}
	req.Header.Set("Content-Type", "text/xml")
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, resp.Header.Get("Content-Type"), b
}

func init() {
	RegisterExplain("http.servertech.configBakLeak", explainServertechConfigBakLeak)
	RegisterExplain("http.servertech.mgrHandshake", explainServertechMgrHandshake)
}

func explainServertechConfigBakLeak(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nServerTech served a backup configuration file without authentication.\n")
	b.WriteString("\n**Validate backup exposure:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk %s/config.bak", baseURL),
		fmt.Sprintf("curl -sk %s/_config.bak", baseURL),
		fmt.Sprintf("curl -sk %s/RAM0/admn/config.bak", baseURL),
	))
	return b.String()
}

func explainServertechMgrHandshake(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nServerTech accepted a pre-auth XML manager handshake request.\n")
	b.WriteString("\n**Validate handshake reachability:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf(`curl -sk -X POST %s/ -H 'Content-Type: text/xml' -d '<init><version>2</version><type>manager</type><company>Server Technology</company></init>'`, baseURL),
	))
	return b.String()
}
