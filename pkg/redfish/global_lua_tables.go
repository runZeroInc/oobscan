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

// GlobalLuaTablesResult captures a probe of AMI's pre-auth GlobalLuaTables endpoint.
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

// CheckGlobalLuaTables performs a read-only pre-auth probe of
// /redfish/v1/GlobalLuaTables and confirms that the response belongs to the
// requested endpoint rather than a login page or generic error body.
func CheckGlobalLuaTables(host string, port int, scheme string, timeout time.Duration) GlobalLuaTablesResult {
	return CheckGlobalLuaTablesContext(context.Background(), host, port, scheme, timeout)
}

// CheckGlobalLuaTablesContext is CheckGlobalLuaTables with cancellation.
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

	// Older builds may return the table object directly instead of a Redfish
	// collection. Keep recognizing that distinct response shape as endpoint
	// presence, but do not infer sensitive disclosure from it.
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err == nil {
		if raw, ok := object["GlobalLuaTables"]; ok && len(raw) > 0 && string(raw) != "null" {
			return true, -1
		}
	}
	return false, 0
}
