package redfish

import (
	"bytes"
	"time"
)

// EventServiceInfo captures the unauthenticated Redfish EventService signals
// relevant to the Supermicro X14 (OpenBMC) `SubmitTestEvent` OEM command
// injection: whether the EventService resource is reachable and whether it
// advertises the SubmitTestEvent action. This is fingerprint-only -- it never
// POSTs the action (which would execute the vulnerable code path).
type EventServiceInfo struct {
	Status             int
	Reachable          bool // EventService resource answered (2xx, or auth-gated 401/403)
	HasSubmitTestEvent bool // Actions advertise #EventService.SubmitTestEvent (2xx body only)
}

// FetchEventService GETs /redfish/v1/EventService and reports the signals above.
// It sends only a GET; it does not authenticate and does not POST the action.
func FetchEventService(host string, port int, timeout time.Duration) EventServiceInfo {
	client := insecureClient(nil, timeout)
	url := baseURL(host, port) + "/redfish/v1/EventService"
	st, body, _, err := httpGet(client, url, timeout)
	if err != nil {
		return EventServiceInfo{}
	}
	info := EventServiceInfo{Status: st}
	// A 2xx means we can read the action set; 401/403 still proves the resource
	// exists (it is simply auth-gated) which, combined with an SMC+OpenBMC root,
	// is enough to flag the version-gated exposure.
	switch st {
	case 200, 401, 403:
		info.Reachable = true
	}
	if st == 200 && bytes.Contains(bytes.ToLower(body), []byte("submittestevent")) {
		info.HasSubmitTestEvent = true
	}
	return info
}
