package check

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

func init() {
	Register(Check{
		Name:        "http.jetkvm.metricsUnauth",
		Description: "JetKVM unauthenticated Prometheus /metrics endpoint (device telemetry, no auth)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runJetKVMMetrics,
	})
	Register(Check{
		Name:        "http.nanokvm.universalKey",
		Description: "Sipeed NanoKVM universal content-encryption key + HTTP-only posture",
		Category:    "creds",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runNanoKVMUniversalKey,
	})
}

const nanoKVMUniversalKey = "nanokvm-sipeed-2024"

func runJetKVMMetrics(ctx context.Context, t *engine.Target) []engine.Finding {

	client := insecureWebClient(min(t.Timeout, 5*time.Second))
	tried := map[string]struct{}{}
	for _, ep := range []struct {
		scheme string
		port   int
	}{
		{webProto(t), webPort(t)},
		{"http", 80},
		{"https", httpsPort(t)},
	} {
		if ep.port <= 0 {
			continue
		}
		k := fmt.Sprintf("%s:%d", ep.scheme, ep.port)
		if _, ok := tried[k]; ok {
			continue
		}
		tried[k] = struct{}{}
		st, _, body := httpProbe(ctx, client, hostPortURL(ep.scheme, t.Host, ep.port, "/metrics"), "")
		if st == 200 && looksLikePrometheus(body) {
			t.MarkOpen(ep.port, "tcp", ep.scheme)
			proof := proofKV("path", "/metrics", "status", "200", "format", "prometheus")
			if m := firstPromMetric(body); m != "" {
				proof = proofKV("path", "/metrics", "status", "200", "metric", m)
			}
			return []engine.Finding{{
				Check: "http.jetkvm.metricsUnauth", Category: "exposure", Risk: "medium",
				Port: ep.port, Transport: "tcp", Protocol: ep.scheme,
				Fields: engine.F(
					"url", "/metrics",
					"proof", proof),
			}}
		}
	}
	return nil
}

func runNanoKVMUniversalKey(ctx context.Context, t *engine.Target) []engine.Finding {
	client := insecureWebClient(min(t.Timeout, 5*time.Second))
	port := webPort(t)
	httpOnly := false

	if st, _, _ := httpProbe(ctx, client, hostPortURL("http", t.Host, port, "/"), ""); st > 0 {
		httpOnly = true
	}

	tried := map[string]struct{}{}
	for _, ep := range []struct {
		scheme string
		port   int
	}{
		{webProto(t), webPort(t)},
		{"http", 80},
		{"https", httpsPort(t)},
	} {
		if ep.port <= 0 {
			continue
		}
		k := fmt.Sprintf("%s:%d", ep.scheme, ep.port)
		if _, ok := tried[k]; ok {
			continue
		}
		tried[k] = struct{}{}
		for _, path := range []string{"/", "/index.html"} {
			st, _, body := httpProbe(ctx, client, hostPortURL(ep.scheme, t.Host, ep.port, path), "")
			if st != 200 {
				continue
			}
			if strings.Contains(string(body), nanoKVMUniversalKey) {
				t.MarkOpen(ep.port, "tcp", ep.scheme)
				return []engine.Finding{{
					Check: "http.nanokvm.universalKey", Category: "creds", Risk: "high",
					Port: ep.port, Transport: "tcp", Protocol: ep.scheme,
					Fields: engine.F(
						"url", path,
						"universal_key", nanoKVMUniversalKey,
						"http_only", strconv.FormatBool(httpOnly)),
				}}
			}
			for _, asset := range extractScriptSrcs(body) {
				if !strings.HasPrefix(asset, "/") {
					continue
				}
				ast, _, abody := httpProbe(ctx, client, hostPortURL(ep.scheme, t.Host, ep.port, asset), "")
				if ast == 200 && strings.Contains(string(abody), nanoKVMUniversalKey) {
					t.MarkOpen(ep.port, "tcp", ep.scheme)
					return []engine.Finding{{
						Check: "http.nanokvm.universalKey", Category: "creds", Risk: "high",
						Port: ep.port, Transport: "tcp", Protocol: ep.scheme,
						Fields: engine.F(
							"url", asset,
							"universal_key", nanoKVMUniversalKey,
							"http_only", strconv.FormatBool(httpOnly)),
					}}
				}
			}
		}
	}
	return nil
}

var reScriptSrc = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)

func extractScriptSrcs(body []byte) []string {
	m := reScriptSrc.FindAllStringSubmatch(string(body), 16)
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	seen := map[string]struct{}{}
	for _, sm := range m {
		if len(sm) < 2 {
			continue
		}
		s := strings.TrimSpace(sm[1])
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func firstPromMetric(body []byte) string {
	for line := range strings.SplitSeq(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# HELP ") {
			if f := strings.Fields(line); len(f) >= 3 {
				return f[2]
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		name := line
		if i := strings.IndexAny(name, "{ "); i > 0 {
			name = name[:i]
		}
		return name
	}
	return ""
}

func looksLikePrometheus(body []byte) bool {
	s := string(body)
	return strings.Contains(s, "# HELP ") || strings.Contains(s, "# TYPE ") ||
		strings.Contains(s, "go_goroutines") || strings.Contains(s, "process_cpu_seconds_total")
}

func init() {
	RegisterExplain("http.jetkvm.metricsUnauth", explainJetKVMMetrics)
	RegisterExplain("http.nanokvm.universalKey", explainNanoKVMUniversalKey)
}

func explainJetKVMMetrics(host string, f engine.Finding) string {
	proof := explainField(f, "proof")
	port := explainPortOrDefault(f, 80)
	scheme := "http"
	if f.Protocol == "https" || port == 443 {
		scheme = "https"
	}
	baseURL := netaddr.URL(scheme, host, port, "")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nJetKVM exposes a Prometheus `/metrics` endpoint without authentication,\n")
	b.WriteString("leaking device telemetry (CPU, memory, sessions) pre-auth.\n")
	if proof != "" {
		b.WriteString(fmt.Sprintf("\n**Confirmed:** `%s`\n", proof))
	}
	b.WriteString("\n**Retrieve:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -s %s/metrics | head -40", baseURL),
		fmt.Sprintf("curl -s http://%s/metrics | head -40", host),
	))
	return b.String()
}

func explainNanoKVMUniversalKey(host string, f engine.Finding) string {
	key := explainField(f, "universal_key")
	httpOnly := explainField(f, "http_only") == "true"
	port := explainPortOrDefault(f, 80)
	scheme := "http"
	baseURL := netaddr.URL(scheme, host, port, "")
	if key == "" {
		key = "nanokvm-sipeed-2024"
	}
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nSipeed NanoKVM ships a universal content-encryption key (`%s`)\n", key))
	b.WriteString("fleet-wide in its web assets. Captured \"encrypted\" traffic is trivially decryptable.\n")
	if httpOnly {
		b.WriteString("\n> Device is serving over **plain HTTP** -- credentials transit in cleartext.\n")
	}
	b.WriteString("\n**Retrieve the key from the device:**\n")
	b.WriteString(explainSh(fmt.Sprintf("curl -sk %s/ | grep -o 'nanokvm[^\"]*'", baseURL)))
	b.WriteString("\n\n**Impact:** Known encryption key allows offline decryption of captured KVM sessions.\n")
	return b.String()
}
