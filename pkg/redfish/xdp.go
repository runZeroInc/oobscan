package redfish

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RemoteXDPManagerPath is the default Redfish NetworkProtocol resource that
// carries H3C's OEM RemoteXDP toggle. The OEM namespace vendor name is "Public".
const RemoteXDPManagerPath = "/redfish/v1/Managers/1/NetworkProtocol/"

// RemoteXDPResult reports the outcome of a SetRemoteXDP PATCH.
type RemoteXDPResult struct {
	Status int
	Body   []byte
	OK     bool
}

// RemoteXDPConfig is the settable subset of Oem.Public.Services.RemoteXDP. Only
// non-nil fields are sent in the PATCH, so callers can change one setting
// (e.g. just the TLS/secure port) without disturbing the rest.
type RemoteXDPConfig struct {
	CurrentState       *bool // master enable for the service
	NonsecurePortState *bool // plaintext listener on/off
	NonsecurePort      *int  // plaintext port (default 6868)
	SecurePortState    *bool // TLS listener on/off
	SecurePort         *int  // TLS port
	SessionTimeout     *int  // idle session timeout (seconds)
}

// Empty reports whether the config would send no fields.
func (c RemoteXDPConfig) Empty() bool {
	return c.CurrentState == nil && c.NonsecurePortState == nil && c.NonsecurePort == nil &&
		c.SecurePortState == nil && c.SecurePort == nil && c.SessionTimeout == nil
}

// SetRemoteXDP toggles/configures H3C's OEM RemoteXDP (At-Scale-Debug/JTAG)
// service via a Redfish PATCH to the Manager NetworkProtocol resource. It mirrors
// the cfgm keys under services.remote-xdp exposed as Oem.Public.Services.RemoteXDP.
// managerPath may be empty to use RemoteXDPManagerPath. headers must carry an
// authenticated principal (X-Auth-Token from OpenSession, or an
// Authorization: Basic header).
//
// This is a state-changing request; callers must gate it behind the
// authorized/online flag.
func SetRemoteXDP(client *http.Client, base, managerPath string, headers map[string]string, cfg RemoteXDPConfig, timeout time.Duration) (RemoteXDPResult, error) {
	if managerPath == "" {
		managerPath = RemoteXDPManagerPath
	}
	xdp := map[string]any{}
	if cfg.CurrentState != nil {
		xdp["CurrentState"] = *cfg.CurrentState
	}
	if cfg.NonsecurePortState != nil {
		xdp["NonsecurePortState"] = *cfg.NonsecurePortState
	}
	if cfg.NonsecurePort != nil {
		xdp["NonsecurePort"] = *cfg.NonsecurePort
	}
	if cfg.SecurePortState != nil {
		xdp["SecurePortState"] = *cfg.SecurePortState
	}
	if cfg.SecurePort != nil {
		xdp["SecurePort"] = *cfg.SecurePort
	}
	if cfg.SessionTimeout != nil {
		xdp["SessionTimeout"] = *cfg.SessionTimeout
	}
	payload := map[string]any{
		"Oem": map[string]any{
			"Public": map[string]any{
				"Services": map[string]any{
					"RemoteXDP": xdp,
				},
			},
		},
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return RemoteXDPResult{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, base+managerPath, bytes.NewReader(buf))
	if err != nil {
		return RemoteXDPResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return RemoteXDPResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 262144))
	return RemoteXDPResult{
		Status: resp.StatusCode,
		Body:   body,
		OK:     resp.StatusCode >= 200 && resp.StatusCode < 300,
	}, nil
}

// GetRemoteXDP reads the current RemoteXDP state from the Manager
// NetworkProtocol resource. It returns the decoded Oem.Public.Services.RemoteXDP
// object (or nil when absent) plus the raw body.
func GetRemoteXDP(client *http.Client, base, managerPath string, headers map[string]string, timeout time.Duration) (map[string]any, []byte, error) {
	if managerPath == "" {
		managerPath = RemoteXDPManagerPath
	}
	st, body := authGet(client, base+managerPath, headers, timeout)
	if st < 200 || st >= 300 {
		return nil, body, fmt.Errorf("GET NetworkProtocol returned status %d", st)
	}
	var doc struct {
		Oem struct {
			Public struct {
				Services struct {
					RemoteXDP map[string]any `json:"RemoteXDP"`
				} `json:"Services"`
			} `json:"Public"`
		} `json:"Oem"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, body, err
	}
	return doc.Oem.Public.Services.RemoteXDP, body, nil
}
