package redfish

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

type GlobalLuaTablesResult struct {
	Host        string
	Port        int
	Scheme      string
	Path        string
	Status      int
	Available   bool
	MemberCount int
	ContentType string
	Snippet     string
	Error       string
}

func CheckGlobalLuaTables(host string, port int, scheme string, timeout time.Duration) GlobalLuaTablesResult {
	return CheckGlobalLuaTablesContext(context.Background(), host, port, scheme, timeout)
}

func CheckGlobalLuaTablesContext(ctx context.Context, host string, port int, scheme string, timeout time.Duration) GlobalLuaTablesResult {
	if port == 0 {
		port = 443
	}
	if scheme == "" {
		scheme = "https"
	}
	res := GlobalLuaTablesResult{Host: host, Port: port, Scheme: scheme, Path: "/redfish/v1/GlobalLuaTables"}
	client := httpx.ClientWithRedirect(timeout, func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	})
	url := netaddr.URL(scheme, host, port, res.Path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	rsp, err := client.Do(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	body, _ := io.ReadAll(io.LimitReader(rsp.Body, 64*1024))
	rsp.Body.Close()
	res.Status = rsp.StatusCode
	res.ContentType = rsp.Header.Get("Content-Type")
	res.Snippet = bypassSnippet(body)
	res.Available, res.MemberCount = parseGlobalLuaTablesBody(rsp.StatusCode, body)
	return res
}

func parseGlobalLuaTablesBody(status int, body []byte) (bool, int) {
	if status != http.StatusOK || len(body) < 32 {
		return false, 0
	}
	var resource struct {
		ODataID string            `json:"@odata.id"`
		Members []json.RawMessage `json:"Members"`
	}
	if err := json.Unmarshal(body, &resource); err != nil {
		return false, 0
	}
	if strings.EqualFold(strings.TrimSuffix(resource.ODataID, "/"), "/redfish/v1/GlobalLuaTables") {
		return true, len(resource.Members)
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err == nil {
		if raw, ok := object["GlobalLuaTables"]; ok && len(raw) > 0 && string(raw) != "null" {
			return true, -1
		}
	}
	return false, 0
}
