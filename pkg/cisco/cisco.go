// Package cisco implements Cisco CIMC-specific unauthenticated HTTP probes.
package cisco

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

// CIMCInfo is the device identity returned by the Cisco CIMC
// /api/cimcInfo.json endpoint. The endpoint answers without authentication,
// but only when the browser-style request headers set in FetchCIMCInfo are
// present (the web stack checks Origin/Referer against its own host and
// expects the browser Accept/Content-Type/User-Agent headers).
type CIMCInfo struct {
	Hostname     string `json:"hostname"`
	SerialNumber string `json:"serialNumber"`
	Banner       string `json:"banner"`
	SessionInfo  string `json:"sessionInfo"`
	SlotID       string `json:"SlotId"`
	Error        int    `json:"Error"`

	// Model is the model family derived from the hostname prefix
	// (e.g. "C225-WZP29029BE9" gives "C225"). Empty when it cannot be derived.
	Model string `json:"-"`
	// ChassisSerial is the serial derived from the hostname suffix when the
	// hostname follows the "MODEL-SERIAL" convention. Empty otherwise.
	ChassisSerial string `json:"-"`
}

// FetchCIMCInfo requests /api/cimcInfo.json with the header set the CIMC web
// server requires to answer, and returns the parsed identity plus true when the
// endpoint responds with a well-formed cimcInfo object.
func FetchCIMCInfo(host string, timeout time.Duration) (*CIMCInfo, bool) {
	client := httpx.Client(timeout)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	base := "https://" + netaddr.URLAuthority(host)
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/api/cimcInfo.json", nil)
	if err != nil {
		return nil, false
	}
	// The endpoint replies only when the request looks like it came from the
	// device's own single-page app. Omitting these headers yields no usable reply.
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.6")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Referer", base+"/index.html")

	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	return parseCIMCInfo(body)
}

// parseCIMCInfo decodes the cimcInfo.json body. Separated for testing.
func parseCIMCInfo(body []byte) (*CIMCInfo, bool) {
	var info CIMCInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, false
	}
	if info.Hostname == "" && info.SerialNumber == "" {
		return nil, false
	}
	info.deriveModel()
	return &info, true
}

// deriveModel splits a "MODEL-SERIAL" hostname (e.g. "C225-WZP29029BE9") into a
// model family and chassis serial, filling only the fields it can derive safely.
func (i *CIMCInfo) deriveModel() {
	h := strings.TrimSpace(i.Hostname)
	idx := strings.IndexByte(h, '-')
	if idx <= 0 || idx >= len(h)-1 {
		return
	}
	model, serial := h[:idx], h[idx+1:]
	// UCS model families begin with a letter and digits (C225, B200, S3260, E160).
	if len(model) >= 2 && strings.ContainsRune("CBSE", rune(model[0])) {
		i.Model = model
	}
	if i.ChassisSerial == "" && looksLikeSerial(serial) {
		i.ChassisSerial = serial
	}
}

// looksLikeSerial reports whether s resembles a Cisco alphanumeric serial.
func looksLikeSerial(s string) bool {
	if len(s) < 8 || len(s) > 16 {
		return false
	}
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
