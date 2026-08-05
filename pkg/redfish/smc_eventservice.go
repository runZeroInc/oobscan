package redfish

import (
	"bytes"
	"time"
)

type EventServiceInfo struct {
	Status             int
	Reachable          bool
	HasSubmitTestEvent bool
}

func FetchEventService(host string, port int, timeout time.Duration) EventServiceInfo {
	client := insecureClient(nil, timeout)
	url := baseURL(host, port) + "/redfish/v1/EventService"
	st, body, _, err := httpGet(client, url, timeout)
	if err != nil {
		return EventServiceInfo{}
	}
	info := EventServiceInfo{Status: st}

	switch st {
	case 200, 401, 403:
		info.Reachable = true
	}
	if st == 200 && bytes.Contains(bytes.ToLower(body), []byte("submittestevent")) {
		info.HasSubmitTestEvent = true
	}
	return info
}
