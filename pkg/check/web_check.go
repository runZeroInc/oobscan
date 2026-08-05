package check

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/bmcfp"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
	"github.com/runZeroInc/oobscan/pkg/sanitize"
)

func init() {
	Register(Check{
		Name:        "web.service",
		Description: "Per-port web-service identity: Server header, HTML title, favicon MD5",
		Category:    "http",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runWebService,
	})
}

type webPortSpec struct {
	port   int
	scheme string
}

func webCandidatePorts(t *engine.Target) []webPortSpec {
	seen := map[int]bool{}
	var out []webPortSpec
	add := func(port int, scheme string) {
		if port == 0 || seen[port] {
			return
		}
		seen[port] = true
		out = append(out, webPortSpec{port, scheme})
	}
	add(443, "https")
	add(80, "http")
	for _, p := range t.Ports {
		if p.Proto != engine.ProtoTCP {
			continue
		}
		switch p.Num {
		case 8443, 4443, 8834, 5000:
			add(p.Num, "https")
		case 8080, 8000, 8888:
			add(p.Num, "http")
		}
	}
	return out
}

func runWebService(ctx context.Context, t *engine.Target) []engine.Finding {
	per := min(t.Timeout, 2*time.Second)
	client := httpx.ClientWithRedirect(per, func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse })
	var out []engine.Finding
	done := map[int]bool{}

	if pp, pscheme, pserver, ptitle, okp := primaryWeb(t); okp {
		done[pp] = true
		fav, favMMH3, favVendor, favProduct, answered := webFavicon(ctx, client, t.Host, webPortSpec{pp, pscheme})
		source := "identify"
		if answered {
			source = ""
		}
		if f := webFinding(pp, pscheme, pserver, ptitle, fav, favMMH3, favVendor, favProduct, source); f != nil {
			out = append(out, *f)
		}
	}

	for _, wp := range webCandidatePorts(t) {
		if done[wp.port] || ctx.Err() != nil {
			continue
		}
		server, title, ok := webRoot(ctx, client, t.Host, wp)
		if !ok {
			continue
		}
		t.MarkOpen(wp.port, "tcp", wp.scheme)
		fav, favMMH3, favVendor, favProduct, _ := webFavicon(ctx, client, t.Host, wp)
		if f := webFinding(wp.port, wp.scheme, server, title, fav, favMMH3, favVendor, favProduct, ""); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

func primaryWeb(t *engine.Target) (port int, scheme, server, title string, ok bool) {
	if t.Identity == nil {
		return 0, "", "", "", false
	}
	p, err := strconv.Atoi(t.Identity.Attributes["web.port"])
	if err != nil || p == 0 {
		return 0, "", "", "", false
	}
	scheme = t.Identity.Attributes["web.scheme"]
	if scheme == "" {
		scheme = "https"
	}
	return p, scheme, t.Identity.Attributes["http.server"], t.Identity.Attributes["http.title"], true
}

func webFinding(port int, scheme, server, title, favicon, faviconMMH3, favVendor, favProduct, source string) *engine.Finding {
	if server == "" && title == "" && favicon == "" {
		return nil
	}
	fields := []string{"server", server, "title", title, "favicon", favicon}
	if faviconMMH3 != "" {
		fields = append(fields, "faviconMmh3", faviconMMH3)
	}
	if favVendor != "" {
		fields = append(fields, "faviconVendor", favVendor, "faviconProduct", favProduct)
	}
	if source != "" {
		fields = append(fields, "source", source)
	}
	return &engine.Finding{
		Check: "web.service", Category: "http", Risk: "info",
		Port: port, Transport: "tcp", Protocol: scheme,
		Fields: engine.F(fields...),
	}
}

func webRoot(ctx context.Context, c *http.Client, host string, wp webPortSpec) (server, title string, ok bool) {
	url := netaddr.URL(wp.scheme, host, wp.port, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", false
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.Header.Get("Server"), pageTitle(body), true
}

func webFavicon(ctx context.Context, c *http.Client, host string, wp webPortSpec) (md5hex, mmh3, vendor, product string, answered bool) {
	url := netaddr.URL(wp.scheme, host, wp.port, "/favicon.ico")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", "", "", false
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", "", "", "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", "", "", true
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if len(body) == 0 {
		return "", "", "", "", true
	}
	sum := md5.Sum(body)
	md5hex = hex.EncodeToString(sum[:])
	mmh3 = bmcfp.FaviconHashString(body)
	if v, p, ok := bmcfp.Match(bmcfp.FaviconMMH3, mmh3); ok {
		vendor, product = v, p
	}
	return md5hex, mmh3, vendor, product, true
}

func pageTitle(body []byte) string {
	s := string(sanitize.Bytes(body))
	low := strings.ToLower(s)
	i := strings.Index(low, "<title")
	if i < 0 {
		return ""
	}
	gt := strings.IndexByte(s[i:], '>')
	if gt < 0 {
		return ""
	}
	start := i + gt + 1
	end := strings.Index(low[start:], "</title>")
	if end < 0 {
		return ""
	}
	title := strings.Join(strings.Fields(s[start:start+end]), " ")
	title = strings.ReplaceAll(title, "\ufffd", "")
	title = strings.Join(strings.Fields(title), " ")
	return sanitize.TruncateString(title, 120)
}

func init() {
	RegisterExplain("web.service", explainWebService)
}

func explainWebService(host string, f engine.Finding) string {
	server := explainField(f, "server")
	title := explainField(f, "title")
	favicon := explainField(f, "faviconMd5")
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nWeb service fingerprint.\n")
	if server != "" {
		b.WriteString(fmt.Sprintf("**Server:** `%s`  ", server))
	}
	if title != "" {
		b.WriteString(fmt.Sprintf("**Title:** `%s`  ", title))
	}
	if favicon != "" {
		b.WriteString(fmt.Sprintf("**Favicon MD5:** `%s`", favicon))
	}
	b.WriteString("\n")
	b.WriteString("\n**Enumerate the service:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk %s/ -I", baseURL),
		fmt.Sprintf("curl -sk %s/redfish/v1/ 2>/dev/null | python3 -m json.tool", baseURL),
	))
	return b.String()
}
