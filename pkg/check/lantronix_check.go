package check

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/lantronix"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

// Lantronix ships a UDP/30718 (0x77FE) "Setup / Query Port" discovery service
// enabled by default across the XPort/UDS/xPico/EDS/SGX device-server
// families and the SLC/SLB console managers, answering an unauthenticated
// 4-byte query with the unit's MAC, model, and firmware version. On modern
// NUEVO device servers the default admin password derives from the device
// serial, so this leak makes that default pre-auth-computable; the check
// emits the extracted device data, not just a boolean.
func init() {
	Register(Check{
		Name:        "udp.lantronix.setup",
		Description: "Lantronix UDP/30718 Query Port pre-auth device-info leak (MAC/model/firmware)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runLantronixSetupPort,
	})
	Register(Check{
		Name:        "http.lantronix.ntcSkipAuth",
		Description: "Lantronix/NetComm NTC-5xx router skipAuth pre-auth device-info leak (serial/IMEI/cell/WAN)",
		Category:    "exposure",
		// Self-validating (distinctive JSON response), so run cross-vendor: identify
		// does not always attribute the NetComm-based NTC routers to a vendor slug,
		// and the probe is a single unauthenticated GET gated on an open web port.
		Applies: Applicability{CrossVendor: true},
		Enabled: true,
		Run:     runLantronixNTCSkipAuth,
	})
	Register(Check{
		Name:        "http.lantronix.ntcRootPassOracle",
		Description: "Lantronix/NetComm NTC-5xx pre-auth /root_pass password-check oracle presence",
		Category:    "exposure",
		Applies:     Applicability{Vendors: []string{"lantronix"}},
		Enabled:     true,
		Run:         runLantronixNTCRootPassOracle,
	})
}

func runLantronixSetupPort(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	// Reuse the discovery reply identify already captured when it probed 30718;
	// otherwise send the unicast query directly. No auth, one small UDP round-trip.
	var r *lantronix.Response
	if v, ok := t.Evidenced("lantronix"); ok {
		if resp, okc := v.(*lantronix.Response); okc {
			r = resp
		}
	}
	if r == nil {
		if got, err := lantronix.Query(t.Host, t.Timeout); err == nil && got != nil {
			r = got
			t.SetEvidence("lantronix", r)
		}
	}
	if r == nil {
		return nil
	}
	// Only assert the leak when the reply actually carried device data (a bare
	// echo with no MAC/model/firmware is not worth a finding).
	if r.MAC == "" && r.Model == "" && r.Firmware == "" {
		return nil
	}
	return []engine.Finding{{
		Check: "udp.lantronix.setup", Category: "exposure", Risk: "medium",
		Port: lantronix.DiscoveryPort, Transport: "udp", Protocol: "lantronix-setup",
		Fields: engine.F(
			"mac", r.MAC,
			"model", strings.TrimSpace(r.Model),
			"firmware", strings.TrimSpace(r.Firmware),
			"raw", hex.EncodeToString(r.Raw)),
	}}
}

// ntcSkipAuthObjects are the 13 objSts* objects the NTC-5xx Turbo web app marks
// skipAuth=true (userGroupAuth.lua), served without login/CSRF via
// GET /cgi-bin/jsonSrvr.lua?req={"getObject":["<obj>"]} (turbontc.lua
// getObjectHandler @706 -> needsAuthentication @232). StsSystemInfo returns the
// unit's identity; the cellular/network ones additionally leak IMSI/ICCID/
// serving-cell, WAN IPs/DNS/APN, Wi-Fi SSIDs, and VPN tunnel endpoints.
var ntcSkipAuthObjects = []string{
	"StsSystemInfo", "StsLanWanInfo", "StsLanInfo", "WanFailoverInfo",
	"StsCellularConnectionStatus", "StsWWanStatus", "ethWanSt", "StsWlanStatus",
	"StsAdvStatus", "lteCellInfo", "nr5gCellInfo",
}

// runLantronixNTCSkipAuth issues the unauthenticated getObject request for
// StsSystemInfo and, when the distinctive Turbo JSON envelope comes back, emits
// the extracted device identity (serial/IMEI/model/firmware/site/location) as a
// finding. The response shape ({"result":0,"StsSystemInfo":{...}}) is specific
// enough that a match is a positive identification of the pre-auth leak.
func runLantronixNTCSkipAuth(ctx context.Context, t *engine.Target) []engine.Finding {
	// Only probe when a web port is open; try https first, then the two http ports
	// the NTC web server binds (80, 8080).
	type ep struct {
		scheme string
		port   int
	}
	var eps []ep
	if webPortMaybeOpen(t, 443) {
		eps = append(eps, ep{"https", 443})
	}
	if webPortMaybeOpen(t, 80) {
		eps = append(eps, ep{"http", 80})
	}
	if webPortMaybeOpen(t, 8080) {
		eps = append(eps, ep{"http", 8080})
	}
	if len(eps) == 0 {
		return nil
	}
	timeout := t.Timeout
	if timeout <= 0 || timeout > 8*time.Second {
		timeout = 8 * time.Second
	}
	client := httpx.ClientWithRedirect(timeout, func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse })
	// req={"getObject":["StsSystemInfo"]} -- the query string must contain the
	// literal StsSystemInfo for the cookie-free path (turbontc.lua isStatusPage @778).
	query := `/cgi-bin/jsonSrvr.lua?req=%7B%22getObject%22%3A%5B%22StsSystemInfo%22%5D%7D`
	for _, e := range eps {
		url := netaddr.URL(e.scheme, t.Host, e.port, query)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		info := parseNTCSystemInfo(body)
		if info == nil {
			continue
		}
		return []engine.Finding{ntcSkipAuthFinding(e.scheme, e.port, resp.StatusCode, body, info)}
	}
	return nil
}

// ntcSkipAuthFinding builds the pre-auth leak finding from one answered
// getObject request. Every identity key the envelope carried is reported; when
// it carried none, the served bytes and the request that produced them are
// still recorded, so the "envelope matched but empty" case ships the evidence
// behind its high-risk claim instead of only the object name.
func ntcSkipAuthFinding(scheme string, port, status int, body []byte, info map[string]any) engine.Finding {
	fields := engine.Fields{}
	add := func(k, v string) {
		if v = strings.TrimSpace(v); v != "" {
			fields = append(fields, engine.Field{Key: k, Val: v})
		}
	}
	add("serial", ntcStr(info, "serialNumber"))
	add("model", ntcStr(info, "deviceModel"))
	add("imei", ntcStr(info, "imei"))
	add("imeisv", ntcStr(info, "imeisv"))
	add("hwVersion", ntcStr(info, "hw_ver"))
	add("firmware", firstNonEmpty(ntcStr(info, "version"), ntcStr(info, "FirmwareVersion")))
	add("module", ntcStr(info, "moduleModel"))
	add("sitename", ntcStr(info, "sitename"))
	add("location", ntcStr(info, "location"))
	add("uptime", ntcStr(info, "uptime"))
	if len(fields) == 0 {
		// Envelope matched but empty -- still a confirmed pre-auth reachable object.
		add("object", "StsSystemInfo")
	}
	fields = append(fields,
		engine.Field{Key: "endpoint", Val: fmt.Sprintf("%s:%d/cgi-bin/jsonSrvr.lua?req={getObject:[StsSystemInfo]}", scheme, port)},
		engine.Field{Key: "otherPreAuthObjects", Val: strings.Join(ntcSkipAuthObjects[1:], ",")},
		engine.Field{Key: "response", Val: cleanSnippet(string(body))},
		engine.Field{Key: "proof", Val: proofKV(
			"scheme", scheme,
			"tcpPort", strconv.Itoa(port),
			"object", "StsSystemInfo",
			"status", strconv.Itoa(status),
			"bodyBytes", strconv.Itoa(len(body)),
			// The disclosed identity is what makes the proof host-specific; the
			// request half of it is the same on every unit.
			"serialNumber", ntcStr(info, "serialNumber"),
			"deviceModel", ntcStr(info, "deviceModel"),
			"imei", ntcStr(info, "imei"),
		)})
	return engine.Finding{
		Check: "http.lantronix.ntcSkipAuth", Category: "exposure", Risk: "high",
		Port: port, Transport: "tcp", Protocol: scheme,
		Fields: fields,
	}
}

func runLantronixNTCRootPassOracle(ctx context.Context, t *engine.Target) []engine.Finding {
	// Reuse the same endpoint selection as ntcSkipAuth and require a successful
	// unauth NTC object fetch first to avoid cross-vendor false positives.
	type ep struct {
		scheme string
		port   int
	}
	var eps []ep
	if webPortMaybeOpen(t, 443) {
		eps = append(eps, ep{"https", 443})
	}
	if webPortMaybeOpen(t, 80) {
		eps = append(eps, ep{"http", 80})
	}
	if webPortMaybeOpen(t, 8080) {
		eps = append(eps, ep{"http", 8080})
	}
	if len(eps) == 0 {
		return nil
	}
	timeout := t.Timeout
	if timeout <= 0 || timeout > 8*time.Second {
		timeout = 8 * time.Second
	}
	client := httpx.ClientWithRedirect(timeout, func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse })
	for _, e := range eps {
		sysURL := netaddr.URL(e.scheme, t.Host, e.port, "/cgi-bin/jsonSrvr.lua?req=%7B%22getObject%22%3A%5B%22StsSystemInfo%22%5D%7D")
		sst, sbody := lantronixGET(ctx, client, sysURL)
		if sst < 200 || sst >= 300 || parseNTCSystemInfo(sbody) == nil {
			continue
		}
		rootURL := netaddr.URL(e.scheme, t.Host, e.port, "/root_pass")
		controlURL := netaddr.URL(e.scheme, t.Host, e.port, "/session")
		rst, rbody := lantronixGET(ctx, client, rootURL)
		cst, cbody := lantronixGET(ctx, client, controlURL)
		if rst == http.StatusNotFound || rst == http.StatusUnauthorized || rst == http.StatusForbidden {
			continue
		}
		rsnip := strings.ToLower(cleanSnippet(string(rbody)))
		if !strings.Contains(rsnip, "root") && !strings.Contains(rsnip, "pass") && !strings.Contains(rsnip, "invalid") {
			continue
		}
		if rst == cst && cleanSnippet(string(rbody)) == cleanSnippet(string(cbody)) {
			continue
		}
		proof := proofKV(
			"path", "/root_pass", "status", fmt.Sprintf("%d", rst),
			"controlPath", "/session", "controlStatus", fmt.Sprintf("%d", cst),
			"differs", "true")
		return []engine.Finding{{
			Check: "http.lantronix.ntcRootPassOracle", Category: "exposure", Risk: "high",
			Port: e.port, Transport: "tcp", Protocol: e.scheme,
			Fields: engine.F(
				"url", "/root_pass",
				"status", fmt.Sprintf("%d", rst),
				"control", "/session",
				"control_status", fmt.Sprintf("%d", cst),
				"response", cleanSnippet(string(rbody)),
				"proof", proof,
			),
		}}
	}
	return nil
}

func lantronixGET(ctx context.Context, client *http.Client, url string) (int, []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	resp.Body.Close()
	return resp.StatusCode, body
}

// parseNTCSystemInfo returns the StsSystemInfo object from the Turbo JSON
// envelope {"result":0,"StsSystemInfo":{...}}, or nil if the body is not that
// distinctive shape (so a generic 200/login page does not produce a finding).
func parseNTCSystemInfo(body []byte) map[string]any {
	b := strings.TrimSpace(string(body))
	if !strings.HasPrefix(b, "{") || !strings.Contains(b, "StsSystemInfo") {
		return nil
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal([]byte(b), &env); err != nil {
		return nil
	}
	raw, ok := env["StsSystemInfo"]
	if !ok {
		return nil
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	return obj
}

func ntcStr(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	case float64:
		return strings.TrimSuffix(fmt.Sprintf("%v", s), ".0")
	case bool:
		return fmt.Sprintf("%t", s)
	default:
		return ""
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// webPortMaybeOpen reports whether port/tcp is worth probing: true when it is a
// known-open port, or when no port discovery ran for this target (empty Open map
// -> probe anyway rather than silently skip).
func webPortMaybeOpen(t *engine.Target, port int) bool {
	if t.OpenLen() == 0 {
		return true
	}
	return t.IsOpen(port, "tcp")
}

func init() {
	RegisterExplain("udp.lantronix.setup", explainLantronixSetup)
	RegisterExplain("http.lantronix.ntcSkipAuth", explainLantronixNTCSkipAuth)
	RegisterExplain("http.lantronix.ntcRootPassOracle", explainLantronixNTCRootPassOracle)
}

func explainLantronixSetup(host string, f engine.Finding) string {
	mac := explainField(f, "mac")
	model := explainField(f, "model")
	firmware := explainField(f, "firmware")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe Lantronix UDP/30718 discovery service responds without authentication,\n")
	b.WriteString("leaking MAC, model, and firmware. On NUEVO-series devices the **default\n")
	b.WriteString("admin password is derived from the last 8 chars of the serial** (computable from MAC).\n")
	if mac != "" {
		b.WriteString(fmt.Sprintf("\n**MAC:** `%s`  **Model:** `%s`  **Firmware:** `%s`\n", mac, model, firmware))
	}
	b.WriteString("\n**Re-query the setup port:**\n")
	b.WriteString(explainSh(fmt.Sprintf("oobscan scan --checks udp.lantronix.setup %s", host)))
	return b.String()
}

func explainLantronixNTCSkipAuth(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nLantronix/NetComm NTC-5xx Turbo marks 13 REST objects `skipAuth=true`, serving\n")
	b.WriteString("serial, IMEI, firmware, IMSI, ICCID, carrier, WAN, APN, and cell info without login.\n")
	b.WriteString("\n**Retrieve pre-auth system info:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf(`curl -sk '%s/cgi-bin/jsonSrvr.lua?req={"getObject":["StsSystemInfo"]}' | python3 -m json.tool`, baseURL),
		fmt.Sprintf(`curl -sk '%s/cgi-bin/jsonSrvr.lua?req={"getObject":["StsCellularConnectionStatus"]}' | python3 -m json.tool`, baseURL),
	))
	return b.String()
}

func explainLantronixNTCRootPassOracle(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nLantronix/NetComm NTC answered `/root_pass` with a distinct unauthenticated\n")
	b.WriteString("handler response (password-check oracle surface), differentiated from a\n")
	b.WriteString("session-gated endpoint.\n")
	b.WriteString("\n**Validate (GET-only):**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk %s/root_pass", baseURL),
		fmt.Sprintf("curl -sk -i %s/session | head -n 10", baseURL),
	))
	return b.String()
}
