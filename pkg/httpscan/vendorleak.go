package httpscan

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

// vendorleak.go holds dedicated pre-auth verifiers for firmware-derived exposures
// that the generic endpoint sweep only marks "reachable" - here we inspect the
// response for the specific leak signature and return a confirmed/not verdict.

// LeakResult is one vendor-specific pre-auth verifier outcome.
type LeakResult struct {
	Host    string   `json:"host"`
	Path    string   `json:"path"`
	Method  string   `json:"method"`
	Status  int      `json:"status"`
	Leaked  bool     `json:"leaked"`
	Matched []string `json:"matched,omitempty"`
	Snippet string   `json:"snippet,omitempty"`
	Error   string   `json:"error,omitempty"`
}

func leakClient(timeout time.Duration) *http.Client {
	return httpx.ClientWithRedirect(timeout, func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	})
}

func matchedSigs(body string, sigs []string) []string {
	low := strings.ToLower(body)
	var m []string
	for _, s := range sigs {
		if strings.Contains(low, strings.ToLower(s)) {
			m = append(m, s)
		}
	}
	return m
}

func looksLoginBody(body string) bool {
	low := strings.ToLower(body)
	return strings.Contains(low, "url=/") || strings.Contains(low, "login.html") ||
		strings.Contains(low, "<title>login") || strings.Contains(low, "http-equiv=\"refresh\"")
}

// CheckSMCConfigTftpd tests the Supermicro ATEN pre-auth U-Boot environment read
// via /cgi/config_tftpd.cgi (firmware: that CGI is fw_getenv/fw_setenv with no
// session check). Leaked = a 200 whose body carries >=2 U-Boot env-var
// signatures and is not a login redirect. Firmware-derived.
func CheckSMCConfigTftpd(host string, port int, timeout time.Duration) (*LeakResult, error) {
	if port == 0 {
		port = 443
	}
	scheme := "https"
	if port == 80 || port == 8080 {
		scheme = "http"
	}
	url := netaddr.URL(scheme, host, port, "/cgi/config_tftpd.cgi")
	r := &LeakResult{Host: host, Path: "/cgi/config_tftpd.cgi", Method: http.MethodGet}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		r.Error = err.Error()
		return r, err
	}
	resp, err := leakClient(timeout).Do(req)
	if err != nil {
		r.Error = err.Error()
		return r, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()
	bs := string(body)
	r.Status = resp.StatusCode
	r.Snippet = trimSnippet(body)
	sigs := []string{"ethaddr=", "ipaddr=", "bootcmd=", "bootargs=", "baudrate=", "stdin=", "stdout=", "bootdelay=", "BL_UNIQUE_PASSWORD"}
	r.Matched = matchedSigs(bs, sigs)
	r.Leaked = resp.StatusCode == http.StatusOK && len(r.Matched) >= 2 && !looksLoginBody(bs)
	return r, nil
}

// CheckFujitsuSCCI tests the Fujitsu iRMC SCCI "HP SIM" unauthenticated identity
// leak (firmware: FTS_WebServer EmitHpSimInfo, documented default-ON on S5/S6).
// It POSTs an unauthenticated SCCI ConfigSpace query and flags an identity-XML
// response. Firmware-derived; not live-validated (no Fujitsu hardware in lab).
func CheckFujitsuSCCI(host string, port int, timeout time.Duration) (*LeakResult, error) {
	if port == 0 {
		port = 443
	}
	url := netaddr.URL("https", host, port, "/nwsi/")
	scci := `<?xml version="1.0" encoding="UTF-8"?><CMDSEQ><CMD Context="SCCI" OC="ConfigSpace" OE="0" OI="0" Type="GET"></CMD></CMDSEQ>`
	r := &LeakResult{Host: host, Path: "/nwsi/", Method: http.MethodPost}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(scci))
	if err != nil {
		r.Error = err.Error()
		return r, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := leakClient(timeout).Do(req)
	if err != nil {
		r.Error = err.Error()
		return r, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()
	bs := string(body)
	r.Status = resp.StatusCode
	r.Snippet = trimSnippet(body)
	sigs := []string{"SerialNumber", "SystemName", "MACADDR", "PRODUCTID", "<CHASSIS", "<System", "<SCCI", "iRMC"}
	r.Matched = matchedSigs(bs, sigs)
	r.Leaked = resp.StatusCode == http.StatusOK && len(r.Matched) >= 2
	return r, nil
}
