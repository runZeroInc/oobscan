package redfish

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

type OEMEndpoint struct {
	Path string

	AuthRequired bool

	Status int

	AllowedMethods []string

	HasPOST  bool
	HasPATCH bool

	IsOEM bool

	Vendor string

	SampleData string
}

type OEMSurface struct {
	Host      string
	Endpoints []OEMEndpoint

	HighRisk []OEMEndpoint
}

var highRiskKeywords = []string{
	"update", "firmware", "accounts", "users", "session", "token",
	"kvm", "media", "virtual", "reset", "factory", "upload", "bios",
	"boot", "power", "certificate", "license",
}

type qitem struct {
	path  string
	depth int
}

func CrawlOEMSurface(host string, username, password string, timeout time.Duration, maxDepth, maxNodes int) (*OEMSurface, error) {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if maxDepth <= 0 {
		maxDepth = 6
	}
	if maxNodes <= 0 {
		maxNodes = 500
	}

	authedClient := httpx.Client(timeout)
	anonClient := httpx.Client(timeout)

	base := "https://" + netaddr.URLAuthority(host)
	surface := &OEMSurface{Host: host}

	visited := make(map[string]bool)
	queued := map[string]bool{"/redfish/v1/": true}
	queue := []qitem{{"/redfish/v1/", 0}}
	maxQueued := max(128, maxNodes*4)

	for len(queue) > 0 && len(surface.Endpoints) < maxNodes {
		item := queue[0]
		queue = queue[1:]

		if visited[item.path] {
			continue
		}
		visited[item.path] = true

		links, ep, err := crawlNode(authedClient, anonClient, base, item.path, username, password, timeout)
		if err != nil {
			continue
		}

		if ep != nil {
			surface.Endpoints = append(surface.Endpoints, *ep)
			if isHighRisk(ep) {
				surface.HighRisk = append(surface.HighRisk, *ep)
			}
		}

		if item.depth < maxDepth {
			for _, link := range links {
				queue = enqueueRedfishLink(queue, queued, visited, link, item.depth+1, maxQueued)
			}
		}
	}
	return surface, nil
}

func enqueueRedfishLink(queue []qitem, queued, visited map[string]bool, link string, depth, maxQueued int) []qitem {
	if !strings.HasPrefix(link, "/redfish/") {
		return queue
	}
	if visited[link] || queued[link] {
		return queue
	}
	if len(queue) >= maxQueued {
		return queue
	}
	queued[link] = true
	return append(queue, qitem{path: link, depth: depth})
}

func crawlNode(
	authed, anon *http.Client,
	base, path string,
	username, password string,
	timeout time.Duration,
) ([]string, *OEMEndpoint, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	authedReq, err := http.NewRequestWithContext(ctx, "GET", base+path, nil)
	if err != nil {
		return nil, nil, err
	}
	authedReq.Header.Set("Accept", "application/json")
	if username != "" {
		authedReq.SetBasicAuth(username, password)
	}
	authedResp, err := authed.Do(authedReq)
	if err != nil {
		return nil, nil, err
	}
	defer authedResp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(authedResp.Body, 65536))

	links := extractLinks(body, path)

	ep := &OEMEndpoint{
		Path:   path,
		IsOEM:  isOEMPath(path),
		Vendor: extractVendor(path, body),
	}

	anonCtx, anonCancel := context.WithTimeout(context.Background(), timeout)
	defer anonCancel()
	anonReq, err := http.NewRequestWithContext(anonCtx, "GET", base+path, nil)
	if err == nil {
		anonResp, aerr := anon.Do(anonReq)
		if aerr == nil {
			ep.Status = anonResp.StatusCode
			ep.AuthRequired = anonResp.StatusCode == 401 || anonResp.StatusCode == 403

			if allow := anonResp.Header.Get("Allow"); allow != "" {
				for m := range strings.SplitSeq(allow, ",") {
					m = strings.TrimSpace(strings.ToUpper(m))
					ep.AllowedMethods = append(ep.AllowedMethods, m)
					if m == "POST" {
						ep.HasPOST = true
					}
					if m == "PATCH" {
						ep.HasPATCH = true
					}
				}
			}
			anonBody, _ := io.ReadAll(io.LimitReader(anonResp.Body, 2048))
			anonResp.Body.Close()

			if anonResp.StatusCode == 200 && isUnauthLeak(anonBody) {
				ep.SampleData = string(anonBody)
			} else if anonResp.StatusCode == 200 && looksLikeLogin(anonBody) {
				ep.AuthRequired = true
			}
		}
	}

	if !ep.HasPOST && !ep.HasPATCH {
		optCtx, optCancel := context.WithTimeout(context.Background(), timeout)
		defer optCancel()
		optReq, err2 := http.NewRequestWithContext(optCtx, "OPTIONS", base+path, nil)
		if err2 == nil {
			if username != "" {
				optReq.SetBasicAuth(username, password)
			}
			optResp, oerr := authed.Do(optReq)
			if oerr == nil {
				if allow := optResp.Header.Get("Allow"); allow != "" {
					for m := range strings.SplitSeq(allow, ",") {
						m = strings.TrimSpace(strings.ToUpper(m))
						if m == "POST" {
							ep.HasPOST = true
						}
						if m == "PATCH" {
							ep.HasPATCH = true
						}
					}
				}
				optResp.Body.Close()
			}
		}
	}

	return links, ep, nil
}

const maxLinkWalkDepth = 64

func extractLinks(body []byte, currentPath string) []string {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var links []string

	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if depth > maxLinkWalkDepth {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			for k, child := range t {
				switch k {
				case "@odata.id":
					if s, ok := child.(string); ok && s != currentPath && !seen[s] {
						seen[s] = true
						links = append(links, s)
					}
				default:
					walk(child, depth+1)
				}
			}
		case []any:
			for _, item := range t {
				walk(item, depth+1)
			}
		}
	}
	walk(raw, 0)
	return links
}

func isOEMPath(path string) bool {
	low := strings.ToLower(path)
	return strings.Contains(low, "/oem/") ||
		strings.Contains(low, "/oem") ||
		strings.Contains(low, "dell") ||
		strings.Contains(low, "hpe") ||
		strings.Contains(low, "lenovo") ||
		strings.Contains(low, "supermicro") ||
		strings.Contains(low, "ami") ||
		strings.Contains(low, "megarac") ||
		strings.Contains(low, "nvidia") ||
		strings.Contains(low, "inspur") ||
		strings.Contains(low, "huawei")
}

func extractVendor(path string, body []byte) string {
	low := strings.ToLower(path) + " " + strings.ToLower(string(body[:min(len(body), 512)]))
	switch {
	case strings.Contains(low, "dell") || strings.Contains(low, "idrac"):
		return "Dell"
	case strings.Contains(low, "hpe") || strings.Contains(low, "ilo"):
		return "HPE"
	case strings.Contains(low, "lenovo") || strings.Contains(low, "xclarity"):
		return "Lenovo"
	case strings.Contains(low, "supermicro") || strings.Contains(low, "aten"):
		return "Supermicro"
	case strings.Contains(low, "ami") || strings.Contains(low, "megarac"):
		return "AMI"
	case strings.Contains(low, "openbmc") || strings.Contains(low, "bmcweb"):
		return "OpenBMC"
	case strings.Contains(low, "fujitsu") || strings.Contains(low, "irmc"):
		return "Fujitsu"
	case strings.Contains(low, "nvidia"):
		return "Nvidia"
	}
	return ""
}

func isUnauthLeak(b []byte) bool {
	return len(b) > 0 && looksLikeRedfish(b) && !looksLikeLogin(b)
}

func isHighRisk(ep *OEMEndpoint) bool {
	if ep == nil {
		return false
	}
	hasWrite := ep.HasPOST || ep.HasPATCH
	low := strings.ToLower(ep.Path)
	for _, kw := range highRiskKeywords {
		if strings.Contains(low, kw) {

			if !ep.AuthRequired && hasWrite {
				return true
			}

			if !ep.AuthRequired && ep.Status == 200 && ep.SampleData != "" {
				return true
			}
		}
	}
	return false
}

func (s *OEMSurface) OEMSurfaceMarkdown() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Redfish OEM Surface - %s\n\n", s.Host)
	fmt.Fprintf(&sb, "Total endpoints crawled: %d  High-risk: %d\n\n", len(s.Endpoints), len(s.HighRisk))
	fmt.Fprintln(&sb, "| Path | Vendor | AuthRequired | Status | POST | PATCH |")
	fmt.Fprintln(&sb, "|------|--------|-------------|--------|------|-------|")
	for i := range s.Endpoints {
		ep := &s.Endpoints[i]
		fmt.Fprintf(&sb, "| %s | %s | %v | %d | %v | %v |\n",
			ep.Path, ep.Vendor, ep.AuthRequired, ep.Status, ep.HasPOST, ep.HasPATCH)
	}
	if len(s.HighRisk) > 0 {
		fmt.Fprintln(&sb, "\n## [!] High-Risk Endpoints")
		for i := range s.HighRisk {
			ep := &s.HighRisk[i]
			fmt.Fprintf(&sb, "- `%s` auth=%v status=%d POST=%v PATCH=%v\n",
				ep.Path, ep.AuthRequired, ep.Status, ep.HasPOST, ep.HasPATCH)
		}
	}
	return sb.String()
}
