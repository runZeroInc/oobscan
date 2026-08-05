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

const RemoteXDPManagerPath = "/redfish/v1/Managers/1/NetworkProtocol/"

type RemoteXDPResult struct {
	Status int
	Body   []byte
	OK     bool
}

type RemoteXDPConfig struct {
	CurrentState       *bool
	NonsecurePortState *bool
	NonsecurePort      *int
	SecurePortState    *bool
	SecurePort         *int
	SessionTimeout     *int
}

func (c RemoteXDPConfig) Empty() bool {
	return c.CurrentState == nil && c.NonsecurePortState == nil && c.NonsecurePort == nil &&
		c.SecurePortState == nil && c.SecurePort == nil && c.SessionTimeout == nil
}

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
