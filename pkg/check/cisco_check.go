package check

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/cisco"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

func init() {
	Register(Check{
		Name:        "http.cisco.cimcInfo",
		Description: "Cisco CIMC pre-auth device-identity disclosure via /api/cimcInfo.json",
		Category:    "http",
		Applies:     Applicability{Vendors: []string{"cisco"}},
		Enabled:     true,
		Run:         runCiscoCIMCInfo,
	})
	Register(Check{
		Name:        "http.cisco.xmlApiPresence",
		Description: "Cisco CIMC XML API (/nuova) reachable pre-auth",
		Category:    "exposure",
		Applies:     Applicability{Vendors: []string{"cisco"}},
		Enabled:     true,
		Run:         runCiscoXMLAPIPresence,
	})
}

func runCiscoCIMCInfo(ctx context.Context, t *engine.Target) []engine.Finding {
	info, ok := cisco.FetchCIMCInfo(t.Host, t.Timeout)
	if !ok {
		return nil
	}
	t.SetEvidence("cisco.cimcInfo", info)

	return []engine.Finding{{
		Check: "http.cisco.cimcInfo", Category: "http", Risk: "medium",
		Port: webPort(t), Transport: "tcp", Protocol: webProto(t),
		Fields: engine.F(
			"url", "/api/cimcInfo.json",
			"hostname", info.Hostname,
			"serial_number", info.SerialNumber,
			"model", info.Model,
			"chassis_serial", info.ChassisSerial,
			"banner", info.Banner,
			"session_info", info.SessionInfo,
			"slot_id", info.SlotID),
	}}
}

func runCiscoXMLAPIPresence(ctx context.Context, t *engine.Target) []engine.Finding {
	port := webPort(t)
	proto := webProto(t)
	if !webPortMaybeOpen(t, port) {
		return nil
	}
	url := hostPortURL(proto, t.Host, port, "/nuova")
	body := []byte(`<aaaKeepAlive/>`)
	st, ct, resp := ciscoPostProbe(ctx, insecureWebClient(min(t.Timeout, 6*time.Second)), url, body)
	if st < 200 || st >= 300 {
		return nil
	}
	bl := strings.ToLower(string(resp))
	if !strings.Contains(ct, "xml") && !strings.HasPrefix(strings.TrimSpace(bl), "<") {
		return nil
	}
	if !strings.Contains(bl, "errorcode") && !strings.Contains(bl, "errordescr") && !strings.Contains(bl, "aaakeepalive") {
		return nil
	}
	marker := "aaaKeepAlive"
	if strings.Contains(bl, "errorcode") || strings.Contains(bl, "errordescr") {
		marker = "errorEnvelope"
	}
	return []engine.Finding{{
		Check: "http.cisco.xmlApiPresence", Category: "exposure", Risk: "info",
		Port: port, Transport: "tcp", Protocol: proto,
		Fields: engine.F(
			"url", "/nuova",
			"status", fmt.Sprintf("%d", st),
			"proof", proofKV("path", "/nuova", "status", fmt.Sprintf("%d", st), "marker", marker),
			"response", cleanSnippet(string(resp))),
	}}
}

func ciscoPostProbe(ctx context.Context, c *http.Client, rawURL string, body []byte) (status int, ctype string, out []byte) {
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
	RegisterExplain("http.cisco.cimcInfo", explainCiscoCIMCInfo)
	RegisterExplain("http.cisco.xmlApiPresence", explainCiscoXMLAPIPresence)
}

func explainCiscoCIMCInfo(host string, f engine.Finding) string {
	hostname := explainField(f, "hostname")
	serial := explainField(f, "serial_number")
	model := explainField(f, "model")
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nCisco CIMC serves `/api/cimcInfo.json` without authentication -- hostname,\n")
	b.WriteString("serial number, and model disclosed pre-auth.\n")
	if hostname != "" {
		b.WriteString(fmt.Sprintf("\n**Hostname:** `%s`  **Serial:** `%s`  **Model:** `%s`\n", hostname, serial, model))
	}
	b.WriteString("\n**Retrieve:**\n")
	b.WriteString(explainSh(fmt.Sprintf("curl -sk %s/api/cimcInfo.json | python3 -m json.tool", baseURL)))
	b.WriteString("\n\n**Enumerate the Redfish API:**\n")
	b.WriteString(explainSh(fmt.Sprintf("curl -sk %s/redfish/v1/ | python3 -m json.tool", baseURL)))
	return b.String()
}

func explainCiscoXMLAPIPresence(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nCisco CIMC answered the legacy XML API endpoint `/nuova` without\n")
	b.WriteString("authentication.\n")
	b.WriteString("\n**Validate XML API reachability:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf(`curl -sk -X POST %s/nuova -H 'Content-Type: text/xml' -d '<aaaKeepAlive/>'`, baseURL),
	))
	return b.String()
}
