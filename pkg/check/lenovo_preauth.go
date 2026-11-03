package check

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ssdp"
)

// Lenovo XClarity Controller (XCC/XCC2) pre-auth exposures, both info-level
// and gated on the Lenovo vendor slug: (1) POST /api/providers/get_nonce is
// reachable unauthenticated and returns a uuid5 derived deterministically from
// a world-readable seed rather than a CSPRNG -- a weak pre-auth login
// primitive and a reliable fingerprint, no login attempted; (2) XCC answers
// SSDP on UDP/1900 with a Server string leaking system name, firmware,
// machine-type-model and serial number, matching the asset tag.
func init() {
	Register(Check{
		Name:        "http.lenovo.xcc.preAuth",
		Description: "Lenovo XCC pre-auth get_nonce endpoint + SSDP/UPnP MTM/serial identity leak",
		Category:    "exposure",
		Applies:     Applicability{Vendors: []string{"lenovo"}},
		Enabled:     true,
		Run:         runLenovoXCCPreauth,
	})
	Register(Check{
		Name:        "http.lenovo.xcc.deviceInfo",
		Description: "Lenovo XCC pre-auth device metadata disclosure (DeviceDescription/logoninfo/xccenvinfo)",
		Category:    "exposure",
		Applies:     Applicability{Vendors: []string{"lenovo"}},
		Enabled:     true,
		Run:         runLenovoXCCDeviceInfo,
	})
	Register(Check{
		Name:        "http.lenovo.xcc.nonceReplay",
		Description: "Lenovo XCC deterministic pre-auth nonce replay (same nonce across repeated unauth requests)",
		Category:    "exposure",
		Applies:     Applicability{Vendors: []string{"lenovo"}},
		Enabled:     true,
		Run:         runLenovoXCCNonceReplay,
	})
	Register(Check{
		Name:        "http.lenovo.xcc.nonauthEdge",
		Description: "Lenovo XCC /nonauth Edge route presence (GET-only; no state change attempted)",
		Category:    "exposure",
		Applies:     Applicability{Vendors: []string{"lenovo"}},
		Enabled:     true,
		Run:         runLenovoXCCNonauthEdge,
	})
}

func runLenovoXCCPreauth(ctx context.Context, t *engine.Target) []engine.Finding {
	var out []engine.Finding
	if f := lenovoGetNonce(ctx, t); f != nil {
		out = append(out, *f)
	}
	if f := lenovoSSDPLeak(t); f != nil {
		out = append(out, *f)
	}
	return out
}

func runLenovoXCCDeviceInfo(ctx context.Context, t *engine.Target) []engine.Finding {
	port := webPort(t)
	proto := webProto(t)
	if !webPortMaybeOpen(t, port) {
		return nil
	}
	client := insecureWebClient(min(t.Timeout, 6*time.Second))
	for _, p := range []string{"/DeviceDescription.json", "/api/providers/logoninfo", "/api/providers/xccenvinfo"} {
		st, ct, body := httpProbe(ctx, client, hostPortURL(proto, t.Host, port, p), "")
		if st < 200 || st >= 300 {
			continue
		}
		if !strings.Contains(ct, "json") && !looksLikeJSON(body) {
			continue
		}
		if v, ok := parseLenovoDeviceInfo(body); ok {
			// The served body is the disclosure, so carry a snippet of it alongside
			// the parsed fields: which endpoint answered and what it actually
			// returned, rather than only the subset the parser recognized.
			return []engine.Finding{{
				Check: "http.lenovo.xcc.deviceInfo", Category: "exposure", Risk: "info",
				Port: port, Transport: "tcp", Protocol: proto,
				Fields: engine.F(
					"url", p,
					"model", v.Model,
					"serial", v.Serial,
					"firmware", v.Firmware,
					"hostname", v.Hostname,
					"response", cleanSnippet(string(body)),
					"proof", proofKV(
						"url", p,
						"status", strconv.Itoa(st),
						"hostname", v.Hostname,
						"model", v.Model,
						"serialNumber", v.Serial,
						"firmwareVersion", v.Firmware,
					)),
			}}
		}
	}
	return nil
}

func runLenovoXCCNonauthEdge(ctx context.Context, t *engine.Target) []engine.Finding {
	port := webPort(t)
	proto := webProto(t)
	if !webPortMaybeOpen(t, port) {
		return nil
	}
	client := insecureWebClient(min(t.Timeout, 6*time.Second))
	paths := []string{
		"/nonauth/lock_down",
		"/nonauth/secmode",
		"/nonauth/network_setting",
		"/nonauth/activation",
		"/nonauth/reset_counter",
	}
	controlPath := "/nonauth/oobscan-control-404"
	cs, _, cb := httpProbe(ctx, client, hostPortURL(proto, t.Host, port, controlPath), "")
	controlSig := fmt.Sprintf("%d:%s", cs, strings.TrimSpace(cleanSnippet(string(cb))))
	hits := []string{}
	statuses := []string{}
	for _, p := range paths {
		st, ct, body := httpProbe(ctx, client, hostPortURL(proto, t.Host, port, p), "")
		statuses = append(statuses, fmt.Sprintf("%s=%d", p, st))
		if st == http.StatusUnauthorized || st == http.StatusForbidden {
			continue
		}
		if st < 200 || st >= 500 {
			continue
		}
		if !strings.Contains(ct, "json") && !looksLikeJSON(body) {
			continue
		}
		if !parseXCCNonauthEnvelope(body) {
			continue
		}
		sig := fmt.Sprintf("%d:%s", st, strings.TrimSpace(cleanSnippet(string(body))))
		if sig == controlSig {
			continue
		}
		hits = append(hits, p)
	}
	if len(hits) < 2 {
		return nil
	}
	proof := proofKV(
		"routes", fmt.Sprintf("%d", len(hits)),
		"controlPath", controlPath,
		"controlStatus", fmt.Sprintf("%d", cs),
		"differs", "true")
	return []engine.Finding{{
		Check: "http.lenovo.xcc.nonauthEdge", Category: "exposure", Risk: "info",
		Port: port, Transport: "tcp", Protocol: proto,
		Fields: engine.F(
			"hits", strings.Join(hits, ","),
			"status_by_path", strings.Join(statuses, ","),
			"control_path", controlPath,
			"control_status", fmt.Sprintf("%d", cs),
			"proof", proof,
		),
	}}
}

func runLenovoXCCNonceReplay(ctx context.Context, t *engine.Target) []engine.Finding {
	port := webPort(t)
	proto := webProto(t)
	if !webPortMaybeOpen(t, port) {
		return nil
	}
	client := insecureWebClient(min(t.Timeout, 6*time.Second))
	fetch := func() (string, int, bool) {
		url := hostPortURL(proto, t.Host, port, "/api/providers/get_nonce")
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader("{}"))
		if err != nil {
			return "", 0, false
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return "", 0, false
		}
		body := readLimited(resp.Body, 8*1024)
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return "", resp.StatusCode, false
		}
		nonce, ok := parseXCCNonce(body)
		if !ok {
			return "", resp.StatusCode, false
		}
		return nonce, resp.StatusCode, true
	}
	n1, st1, ok1 := fetch()
	n2, st2, ok2 := fetch()
	if !ok1 || !ok2 || n1 == "" || n2 == "" || n1 != n2 || nonceVersion(n1) != 5 {
		return nil
	}
	// The repeated nonce is the evidence, so it belongs in the proof; without it the
	// proof only restates the four constants the guard above already tested.
	proof := proofKV(
		"nonceEqual", "true",
		"repeatedNonce", n1,
		"uuidVersion", "5",
		"status1", fmt.Sprintf("%d", st1),
		"status2", fmt.Sprintf("%d", st2))
	return []engine.Finding{{
		Check: "http.lenovo.xcc.nonceReplay", Category: "exposure", Risk: "low",
		Port: port, Transport: "tcp", Protocol: proto,
		Fields: engine.F(
			"url", "/api/providers/get_nonce",
			"nonce1", n1,
			"nonce2", n2,
			"status1", fmt.Sprintf("%d", st1),
			"status2", fmt.Sprintf("%d", st2),
			"uuid_version", "5",
			"proof", proof,
		),
	}}
}

func nonceVersion(s string) int {
	s = strings.TrimSpace(strings.ToLower(s))
	parts := strings.Split(s, "-")
	if len(parts) != 5 || len(parts[2]) == 0 {
		return 0
	}
	v := parts[2][0]
	if v < '0' || v > '9' {
		return 0
	}
	return int(v - '0')
}

func parseXCCNonauthEnvelope(body []byte) bool {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return false
	}
	for _, k := range []string{"return", "token", "reason", "error", "status"} {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

type lenovoDeviceInfo struct {
	Model    string
	Serial   string
	Firmware string
	Hostname string
}

func parseLenovoDeviceInfo(body []byte) (lenovoDeviceInfo, bool) {
	var out lenovoDeviceInfo
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return out, false
	}
	walkLenovoInfo(m, &out)
	if out.Model == "" && out.Serial == "" && out.Firmware == "" && out.Hostname == "" {
		return out, false
	}
	return out, true
}

func walkLenovoInfo(m map[string]any, out *lenovoDeviceInfo) {
	for k, v := range m {
		key := strings.ToLower(strings.TrimSpace(k))
		switch vv := v.(type) {
		case string:
			s := strings.TrimSpace(vv)
			switch key {
			case "model", "model_name", "machinetype", "machinetypeandmodel", "mtm":
				if out.Model == "" {
					out.Model = s
				}
			case "serial", "serialnumber", "machine_serial_number":
				if out.Serial == "" {
					out.Serial = s
				}
			case "firmware", "fw", "firmwareversion", "buildid", "xccbuildversion":
				if out.Firmware == "" {
					out.Firmware = s
				}
			case "hostname", "systemname", "host_name":
				if out.Hostname == "" {
					out.Hostname = s
				}
			}
		case map[string]any:
			walkLenovoInfo(vv, out)
		case []any:
			for _, it := range vv {
				if mm, ok := it.(map[string]any); ok {
					walkLenovoInfo(mm, out)
				}
			}
		}
	}
}

// lenovoGetNonce issues the unauthenticated POST /api/providers/get_nonce and,
// when the distinctive JSON nonce envelope comes back on a 2xx, flags the
// deterministic pre-auth login nonce. A login page / 401 / 403 proves the
// endpoint is guarded and yields nothing.
func lenovoGetNonce(ctx context.Context, t *engine.Target) *engine.Finding {
	port := webPort(t)
	proto := webProto(t)
	if !webPortMaybeOpen(t, port) {
		return nil
	}
	client := insecureWebClient(min(t.Timeout, 6*time.Second))
	url := hostPortURL(proto, t.Host, port, "/api/providers/get_nonce")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader("{}"))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body := readLimited(resp.Body, 8*1024)
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	nonce, ok := parseXCCNonce(body)
	if !ok {
		return nil
	}
	return &engine.Finding{
		Check: "http.lenovo.xcc.nonce", Category: "exposure", Risk: "info",
		Port: port, Transport: "tcp", Protocol: proto,
		Fields: engine.F(
			"url", "/api/providers/get_nonce",
			"nonce", nonce,
			// The served token is the disclosure; the proof pins it to the endpoint
			// and status that returned it.
			"proof", proofKV(
				"url", "/api/providers/get_nonce",
				"status", strconv.Itoa(resp.StatusCode),
				"nonce", nonce,
			)),
	}
}

// parseXCCNonce extracts the nonce token from the get_nonce JSON envelope. The
// XCC handler returns {"nonce":"<uuid>"} (some builds wrap it, e.g.
// {"data":{"nonce":"..."}} or {"authnonce":"..."}); accept the common shapes and
// require a plausible token so a generic 200/HTML page is not mistaken for one.
func parseXCCNonce(body []byte) (string, bool) {
	b := strings.TrimSpace(string(body))
	if !strings.HasPrefix(b, "{") {
		return "", false
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal([]byte(b), &env); err != nil {
		return "", false
	}
	get := func(m map[string]json.RawMessage, key string) string {
		raw, ok := m[key]
		if !ok {
			return ""
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return strings.TrimSpace(s)
		}
		return ""
	}
	for _, k := range []string{"nonce", "authnonce", "loginNonce", "login_nonce"} {
		if v := get(env, k); v != "" {
			return v, true
		}
	}
	// Nested {"data":{"nonce":...}} form.
	if raw, ok := env["data"]; ok {
		var inner map[string]json.RawMessage
		if json.Unmarshal(raw, &inner) == nil {
			for _, k := range []string{"nonce", "authnonce"} {
				if v := get(inner, k); v != "" {
					return v, true
				}
			}
		}
	}
	return "", false
}

// lenovoSSDPLeak parses the XCC SSDP Server string for the four leaked
// identifiers. It reuses the SSDP reply identify already captured on 1900 when
// present, otherwise sends one unicast M-SEARCH.
func lenovoSSDPLeak(t *engine.Target) *engine.Finding {
	var r *ssdp.Result
	if v, ok := t.Evidenced("ssdp"); ok {
		switch res := v.(type) {
		case *ssdp.Result:
			r = res
		case ssdp.Result:
			r = &res
		}
	}
	if r == nil {
		if got, err := ssdp.UnicastSearch(t.Host, "upnp:rootdevice", min(t.Timeout, 4*time.Second)); err == nil && got != nil {
			r = got
			t.SetEvidence("ssdp", r)
		}
	}
	if r == nil || r.Server == "" {
		return nil
	}
	sysName, fw, mtm, serial, ok := parseXCCServerString(r.Server)
	if !ok {
		return nil
	}
	return &engine.Finding{
		Check: "ssdp.lenovo.xccLeak", Category: "exposure", Risk: "info",
		Port: 1900, Transport: "udp", Protocol: "ssdp",
		Fields: engine.F(
			"sysname", sysName,
			"firmware", fw,
			"mtm", mtm,
			"serial", serial,
			"server", r.Server,
			// The Server header is the leak itself, so mirror the raw string into
			// the proof rather than leaving the evidence under a key the audit does
			// not recognize.
			"proof", proofKV("ssdpServer", r.Server)),
	}
}

// parseXCCServerString parses the XCC SSDP Server header
// "<SysName>:<FirmwareVersion> UPnP/1.1 <MTM>:<SerialNumber>" into its four
// fields. It requires the "UPnP/" marker with a "<a>:<b>" token on either side so
// a generic UPnP Server string ("Linux/x UPnP/1.0 miniupnpd/1.0") does not match.
func parseXCCServerString(server string) (sysName, fw, mtm, serial string, ok bool) {
	idx := strings.Index(server, "UPnP/")
	if idx < 0 {
		return "", "", "", "", false
	}
	left := strings.TrimSpace(server[:idx])
	tail := strings.TrimSpace(server[idx:])
	// tail = "UPnP/1.1 <MTM>:<Serial>" -> drop the "UPnP/x.y" token.
	parts := strings.SplitN(tail, " ", 2)
	right := ""
	if len(parts) == 2 {
		right = strings.TrimSpace(parts[1])
	}
	sn, fwv, okL := strings.Cut(left, ":")
	m, ser, okR := strings.Cut(right, ":")
	if !okL || !okR {
		return "", "", "", "", false
	}
	sysName = strings.TrimSpace(sn)
	fw = strings.TrimSpace(fwv)
	mtm = strings.TrimSpace(m)
	serial = strings.TrimSpace(ser)
	if sysName == "" || mtm == "" || serial == "" {
		return "", "", "", "", false
	}
	return sysName, fw, mtm, serial, true
}

// readLimited reads at most limit bytes from an io.Reader that has a Close (the
// http.Response.Body), returning the bytes read. Kept local so the Lenovo/
// Opengear checks share one bounded reader without touching io imports at call
// sites.
func readLimited(r interface{ Read([]byte) (int, error) }, limit int) []byte {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 4096)
	for len(buf) < limit {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	if len(buf) > limit {
		buf = buf[:limit]
	}
	return buf
}

func init() {
	RegisterExplain("http.lenovo.xcc.nonce", explainLenovoXCCNonce)
	RegisterExplain("http.lenovo.xcc.nonceReplay", explainLenovoXCCNonceReplay)
	RegisterExplain("http.lenovo.xcc.deviceInfo", explainLenovoXCCDeviceInfo)
	RegisterExplain("http.lenovo.xcc.nonauthEdge", explainLenovoXCCNonauthEdge)
}

func explainLenovoXCCNonce(host string, f engine.Finding) string {
	nonce := explainField(f, "nonce")
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nLenovo XCC `/api/providers/get_nonce` returned a pre-auth nonce. The nonce\n")
	b.WriteString("is derived deterministically from a world-readable seed -- a weak login primitive.\n")
	if nonce != "" {
		b.WriteString(fmt.Sprintf("\n**Nonce:** `%s`\n", nonce))
	}
	b.WriteString("\n**Re-query:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf(`curl -sk -X POST %s/api/providers/get_nonce \`, baseURL),
		`  -H "Content-Type: application/json" -d '{}'`,
	))
	return b.String()
}

func explainLenovoXCCDeviceInfo(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nLenovo XCC returned device identity metadata from a pre-auth endpoint.\n")
	b.WriteString("\n**Validate the pre-auth metadata endpoints:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk %s/DeviceDescription.json", baseURL),
		fmt.Sprintf("curl -sk %s/api/providers/logoninfo", baseURL),
		fmt.Sprintf("curl -sk %s/api/providers/xccenvinfo", baseURL),
	))
	return b.String()
}

func explainLenovoXCCNonceReplay(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nLenovo XCC returned the same pre-auth login nonce across repeated requests,\n")
	b.WriteString("indicating deterministic replayable nonce generation.\n")
	b.WriteString("\n**Validate:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf(`curl -sk -X POST %s/api/providers/get_nonce -H 'Content-Type: application/json' -d '{}'`, baseURL),
		fmt.Sprintf(`curl -sk -X POST %s/api/providers/get_nonce -H 'Content-Type: application/json' -d '{}'`, baseURL),
	))
	return b.String()
}

func explainLenovoXCCNonauthEdge(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nLenovo XCC responded to GET requests for multiple `/nonauth/*` Edge-management routes.\n")
	b.WriteString("This proves route presence only; the check does not supply or bypass the network token,\n")
	b.WriteString("send state-changing POST requests, or demonstrate a configuration change.\n")
	b.WriteString("\n**Validate (GET-only):**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk %s/nonauth/lock_down", baseURL),
		fmt.Sprintf("curl -sk %s/nonauth/secmode", baseURL),
		fmt.Sprintf("curl -sk %s/nonauth/network_setting", baseURL),
	))
	return b.String()
}
