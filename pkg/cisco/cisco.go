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

type CIMCInfo struct {
	Hostname     string `json:"hostname"`
	SerialNumber string `json:"serialNumber"`
	Banner       string `json:"banner"`
	SessionInfo  string `json:"sessionInfo"`
	SlotID       string `json:"SlotId"`
	Error        int    `json:"Error"`

	Model string `json:"-"`

	ChassisSerial string `json:"-"`
}

func FetchCIMCInfo(host string, timeout time.Duration) (*CIMCInfo, bool) {
	client := httpx.Client(timeout)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	base := "https://" + netaddr.URLAuthority(host)
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/api/cimcInfo.json", nil)
	if err != nil {
		return nil, false
	}

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

func (i *CIMCInfo) deriveModel() {
	h := strings.TrimSpace(i.Hostname)
	idx := strings.IndexByte(h, '-')
	if idx <= 0 || idx >= len(h)-1 {
		return
	}
	model, serial := h[:idx], h[idx+1:]

	if len(model) >= 2 && strings.ContainsRune("CBSE", rune(model[0])) {
		i.Model = model
	}
	if i.ChassisSerial == "" && looksLikeSerial(serial) {
		i.ChassisSerial = serial
	}
}

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
