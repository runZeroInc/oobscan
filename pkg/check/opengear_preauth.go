package check

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// Opengear OM/CM/IM/ACM console servers expose REST endpoints without
// authentication (model_name, banner, local_password_policy -- see
// opengearEndpoints below) that disclose the device model and
// password-hardening policy. The model supports affected-firmware assessment;
// the policy shows how weak local credentials may be. Eaton OM2200/Gigamon
// and other Opengear-lineage stacks share this surface, so the check also
// runs on the serialConsole class, not just the opengear vendor slug. Each
// request is one benign GET.
func init() {
	Register(Check{
		Name:        "http.opengear.preAuthLeak",
		Description: "Opengear OM/CM pre-auth REST leak (model_name / banner / local_password_policy)",
		Category:    "exposure",
		Applies: Applicability{
			Vendors: []string{"opengear"},
			Classes: []engine.DeviceClass{engine.ClassSerialConsole},
		},
		Enabled: true,
		Run:     runOpengearPreauth,
	})
	Register(Check{
		Name:        "http.opengear.testStub",
		Description: "Opengear pre-auth /api/v*/test stub reachable",
		Category:    "exposure",
		Applies: Applicability{
			Vendors: []string{"opengear"},
			Classes: []engine.DeviceClass{engine.ClassSerialConsole},
		},
		Enabled: true,
		Run:     runOpengearTestStub,
	})
}

// opengearEndpoints are the unauth REST paths, tried across the API version
// prefixes Opengear has shipped (v1 on OM/CM, v2 on newer OM). The bare
// (prefix-less) forms cover firmware that mounts them without the /api/vN prefix.
var opengearEndpoints = []struct {
	key   string // finding field key
	paths []string
}{
	{"model_name", []string{"/api/v2/system/model_name", "/api/v1/system/model_name", "/system/model_name"}},
	{"banner", []string{"/api/v2/system/banner", "/api/v1/system/banner", "/system/banner"}},
	{"local_password_policy", []string{"/api/v2/local_password_policy", "/api/v1/local_password_policy", "/local_password_policy"}},
}

func runOpengearPreauth(ctx context.Context, t *engine.Target) []engine.Finding {
	port := webPort(t)
	proto := webProto(t)
	if !webPortMaybeOpen(t, port) {
		return nil
	}
	client := insecureWebClient(min(t.Timeout, 6*time.Second))

	fields := engine.Fields{}
	hits := 0
	var answered []string
	for _, ep := range opengearEndpoints {
		for _, p := range ep.paths {
			st, ct, body := httpProbe(ctx, client, hostPortURL(proto, t.Host, port, p), "")
			if st < 200 || st >= 300 {
				continue
			}
			// Require a JSON body (the REST API answers JSON); an HTML login page
			// with a 200 must not be mistaken for a leak.
			if !strings.Contains(ct, "json") && !looksLikeJSON(body) {
				continue
			}
			val := opengearExtract(ep.key, body)
			if val == "" {
				continue
			}
			fields = append(fields,
				engine.Field{Key: ep.key, Val: val},
				engine.Field{Key: ep.key + "_url", Val: p})
			answered = append(answered, fmt.Sprintf("%s=%d", p, st))
			hits++
			break // first matching prefix wins for this endpoint
		}
	}
	if hits == 0 {
		return nil
	}
	// Record which paths answered and with what status. Without this the finding
	// only carries evidence when the endpoint whose field key happens to be
	// spelled "banner" is among the ones that responded.
	fields = append(fields, engine.Field{Key: "proof", Val: proofKV(
		"endpoints", strings.Join(answered, " "),
		"leaked", strconv.Itoa(hits),
		"scheme", proto,
		"tcpPort", strconv.Itoa(port),
	)})
	return []engine.Finding{{
		Check: "http.opengear.preAuthLeak", Category: "exposure", Risk: "low",
		Port: port, Transport: "tcp", Protocol: proto,
		Fields: fields,
	}}
}

func runOpengearTestStub(ctx context.Context, t *engine.Target) []engine.Finding {
	port := webPort(t)
	proto := webProto(t)
	if !webPortMaybeOpen(t, port) {
		return nil
	}
	client := insecureWebClient(min(t.Timeout, 6*time.Second))
	for _, p := range []string{"/api/v2/test", "/api/v1/test"} {
		st, ct, body := opengearPostProbe(ctx, client, hostPortURL(proto, t.Host, port, p), []byte(`{}`))
		if st < 200 || st >= 300 {
			continue
		}
		if !strings.Contains(strings.ToLower(ct), "json") && !looksLikeJSON(body) {
			continue
		}
		if opengearErrorResponse(body) {
			continue
		}
		return []engine.Finding{{
			Check: "http.opengear.testStub", Category: "exposure", Risk: "info",
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

func opengearPostProbe(ctx context.Context, c *http.Client, rawURL string, body []byte) (status int, ctype string, out []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return 0, "", nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, resp.Header.Get("Content-Type"), b
}

// opengearExtract pulls a readable value out of the endpoint's JSON body. The
// REST envelopes vary by firmware ({"model_name":"OM2224-24E"} vs
// {"system":{"model_name":"..."}} vs a bare JSON string), so try the common
// shapes and fall back to a bounded snippet of the raw body for banner/policy.
func opengearExtract(key string, body []byte) string {
	b := strings.TrimSpace(string(body))
	if opengearErrorResponse(body) {
		return ""
	}
	// Bare JSON string, e.g. "OM2224-24E".
	var s string
	if json.Unmarshal([]byte(b), &s) == nil && strings.TrimSpace(s) != "" {
		return cleanSnippet(s)
	}
	var top map[string]json.RawMessage
	if json.Unmarshal([]byte(b), &top) == nil {
		if v := jsonStr(top, key); v != "" {
			return cleanSnippet(v)
		}
		// Nested under a wrapper object (e.g. {"system":{"model_name":...}}).
		for _, raw := range top {
			var inner map[string]json.RawMessage
			if json.Unmarshal(raw, &inner) == nil {
				if v := jsonStr(inner, key); v != "" {
					return cleanSnippet(v)
				}
			}
		}
		// A password-policy object is worth reporting even without a single value:
		// summarize the JSON keys so the disclosure is captured.
		if key == "local_password_policy" && len(top) > 0 {
			return cleanSnippet(b)
		}
	}
	// Banner is free-form text; capture a snippet when the body is non-empty.
	if key == "banner" && b != "" && b != "{}" {
		return cleanSnippet(b)
	}
	return ""
}

func opengearErrorResponse(body []byte) bool {
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil {
		return false
	}
	var ret string
	if raw, ok := top["ret"]; ok && json.Unmarshal(raw, &ret) == nil && strings.EqualFold(ret, "failed") {
		return true
	}
	if raw, ok := top["error"]; ok && len(raw) > 0 && string(raw) != "null" && string(raw) != "{}" {
		return true
	}
	return false
}

// jsonStr returns m[key] as a string when it is a JSON string value.
func jsonStr(m map[string]json.RawMessage, key string) string {
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

// looksLikeJSON reports whether a body begins with a JSON object/array/string,
// allowing REST responses that omit an application/json Content-Type.
func looksLikeJSON(body []byte) bool {
	b := strings.TrimSpace(string(body))
	return strings.HasPrefix(b, "{") || strings.HasPrefix(b, "[") || strings.HasPrefix(b, "\"")
}

func init() {
	RegisterExplain("http.opengear.preAuthLeak", explainOpengearPreauth)
	RegisterExplain("http.opengear.testStub", explainOpengearTestStub)
}

func explainOpengearPreauth(host string, f engine.Finding) string {
	model := explainField(f, "model_name")
	policy := explainField(f, "local_password_policy")
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nOpengear OM/CM/IM REST endpoints disclose device identity and password policy\n")
	b.WriteString("without authentication.\n")
	if model != "" {
		b.WriteString(fmt.Sprintf("\n**Model:** `%s`\n", model))
	}
	if policy != "" {
		b.WriteString(fmt.Sprintf("**Password policy:** `%s`\n", policy))
	}
	b.WriteString("\n**Retrieve the pre-auth endpoints:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk %s/api/v1/system/model_name", baseURL),
		fmt.Sprintf("curl -sk %s/api/v1/system/banner", baseURL),
		fmt.Sprintf("curl -sk %s/api/v1/local_password_policy", baseURL),
	))
	b.WriteString("\n\n**Impact:** Device model enables targeted attack selection; weak password\n")
	b.WriteString("policy informs brute-force strategy.\n")
	return b.String()
}

func explainOpengearTestStub(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nOpengear answered the undocumented `/api/v*/test` endpoint without\n")
	b.WriteString("authentication.\n")
	b.WriteString("\n**Validate the pre-auth test stub:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf(`curl -sk -X POST %s/api/v1/test -H 'Content-Type: application/json' -d '{}'`, baseURL),
		fmt.Sprintf(`curl -sk -X POST %s/api/v2/test -H 'Content-Type: application/json' -d '{}'`, baseURL),
	))
	return b.String()
}
