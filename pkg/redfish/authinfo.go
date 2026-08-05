package redfish

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/excrypto/crypto/tls"
	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

type SystemInfo struct {
	Vendor          string `json:"vendor,omitempty"`
	Model           string `json:"model,omitempty"`
	FirmwareVersion string `json:"firmwareVersion,omitempty"`
	Product         string `json:"product,omitempty"`
	SerialNumber    string `json:"serialNumber,omitempty"`
	RedfishVersion  string `json:"redfishVersion,omitempty"`
	ServiceUUID     string `json:"serviceUuid,omitempty"`
	ManagerID       string `json:"managerId,omitempty"`
	SystemID        string `json:"systemId,omitempty"`
	BIOSVersion     string `json:"biosVersion,omitempty"`
	PowerState      string `json:"powerState,omitempty"`
	AccountRole     string `json:"accountRole,omitempty"`
	AccountEnabled  string `json:"accountEnabled,omitempty"`
}

func (s SystemInfo) Empty() bool {
	return s.Vendor == "" && s.Model == "" && s.FirmwareVersion == "" &&
		s.Product == "" && s.SerialNumber == "" && s.RedfishVersion == "" &&
		s.ServiceUUID == "" && s.ManagerID == "" && s.SystemID == "" &&
		s.BIOSVersion == "" && s.PowerState == "" && s.AccountRole == "" &&
		s.AccountEnabled == ""
}

func authGet(client *http.Client, url string, headers map[string]string, timeout time.Duration) (int, []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 262144))
	return resp.StatusCode, body
}

type managerDoc struct {
	ID              string `json:"Id"`
	Manufacturer    string `json:"Manufacturer"`
	Model           string `json:"Model"`
	FirmwareVersion string `json:"FirmwareVersion"`
}

type systemDoc struct {
	ID           string `json:"Id"`
	Manufacturer string `json:"Manufacturer"`
	Model        string `json:"Model"`
	SerialNumber string `json:"SerialNumber"`
	BIOSVersion  string `json:"BiosVersion"`
	PowerState   string `json:"PowerState"`
}

type accountDoc struct {
	UserName string `json:"UserName"`
	RoleID   string `json:"RoleId"`
	Enabled  *bool  `json:"Enabled"`
}

type collection struct {
	Members []struct {
		OdataID string `json:"@odata.id"`
	} `json:"Members"`
}

func AccountLockoutThreshold(client *http.Client, base string, timeout time.Duration) int {
	st, body := authGet(client, base+"/redfish/v1/AccountService", nil, timeout)
	if st != http.StatusOK {
		return 0
	}
	var doc struct {
		AccountLockoutThreshold *int `json:"AccountLockoutThreshold"`
	}
	if json.Unmarshal(body, &doc) != nil || doc.AccountLockoutThreshold == nil || *doc.AccountLockoutThreshold < 0 {
		return 0
	}
	return *doc.AccountLockoutThreshold
}

func PullSystemInfo(client *http.Client, base string, headers map[string]string, username string, timeout time.Duration) SystemInfo {
	var out SystemInfo

	if st, body := authGet(client, base+"/redfish/v1", headers, timeout); st == http.StatusOK {
		var sr ServiceRoot
		if json.Unmarshal(body, &sr) == nil {
			out.Vendor = firstNonEmpty(sr.Vendor, out.Vendor)
			out.Product = sr.Product
			out.RedfishVersion = firstNonEmpty(out.RedfishVersion, sr.RedfishVersion)
			out.ServiceUUID = firstNonEmpty(out.ServiceUUID, sr.UUID)
		}
	}

	if id := firstMember(client, base, "/redfish/v1/Managers", headers, timeout); id != "" {
		if st, body := authGet(client, base+id, headers, timeout); st == http.StatusOK {
			var m managerDoc
			if json.Unmarshal(body, &m) == nil {
				out.ManagerID = firstNonEmpty(out.ManagerID, m.ID)
				out.Vendor = firstNonEmpty(out.Vendor, m.Manufacturer)
				out.Model = firstNonEmpty(out.Model, m.Model)
				out.FirmwareVersion = firstNonEmpty(out.FirmwareVersion, m.FirmwareVersion)
			}
		}
	}

	if id := firstMember(client, base, "/redfish/v1/Systems", headers, timeout); id != "" {
		if st, body := authGet(client, base+id, headers, timeout); st == http.StatusOK {
			var s systemDoc
			if json.Unmarshal(body, &s) == nil {
				out.SystemID = firstNonEmpty(out.SystemID, s.ID)
				if s.Manufacturer != "" {
					out.Vendor = s.Manufacturer
				}
				if s.Model != "" {
					out.Model = s.Model
				}
				out.SerialNumber = firstNonEmpty(out.SerialNumber, s.SerialNumber)
				out.BIOSVersion = firstNonEmpty(out.BIOSVersion, s.BIOSVersion)
				out.PowerState = firstNonEmpty(out.PowerState, s.PowerState)
			}
		}
	}

	if role, enabled := pullAccountInfo(client, base, headers, username, timeout); role != "" || enabled != "" {
		out.AccountRole = firstNonEmpty(out.AccountRole, role)
		out.AccountEnabled = firstNonEmpty(out.AccountEnabled, enabled)
	}
	return out
}

func pullAccountInfo(client *http.Client, base string, headers map[string]string, username string, timeout time.Duration) (roleID, enabled string) {
	st, body := authGet(client, base+"/redfish/v1/AccountService/Accounts", headers, timeout)
	if st != http.StatusOK {
		return "", ""
	}
	var c collection
	if json.Unmarshal(body, &c) != nil || len(c.Members) == 0 {
		return "", ""
	}
	wantUser := strings.ToLower(strings.TrimSpace(username))
	const maxAccountReads = 8
	limit := min(len(c.Members), maxAccountReads)
	fallbackRole, fallbackEnabled := "", ""
	for i := range limit {
		id := strings.TrimPrefix(c.Members[i].OdataID, base)
		if id == "" {
			continue
		}
		st, body := authGet(client, base+id, headers, timeout)
		if st != http.StatusOK {
			continue
		}
		var a accountDoc
		if json.Unmarshal(body, &a) != nil {
			continue
		}
		curEnabled := ""
		if a.Enabled != nil {
			curEnabled = strconv.FormatBool(*a.Enabled)
		}
		if fallbackRole == "" && fallbackEnabled == "" {
			fallbackRole, fallbackEnabled = a.RoleID, curEnabled
		}
		if wantUser != "" && strings.EqualFold(strings.TrimSpace(a.UserName), wantUser) {
			return a.RoleID, curEnabled
		}
	}
	if wantUser == "" {
		return fallbackRole, fallbackEnabled
	}
	return "", ""
}

func firstMember(client *http.Client, base, collPath string, headers map[string]string, timeout time.Duration) string {
	st, body := authGet(client, base+collPath, headers, timeout)
	if st != http.StatusOK {
		return ""
	}
	var c collection
	if json.Unmarshal(body, &c) != nil || len(c.Members) == 0 {
		return ""
	}
	return strings.TrimPrefix(c.Members[0].OdataID, base)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func insecureClient(cert *tls.Certificate, timeout time.Duration) *http.Client {
	return httpx.NewClient(httpx.ClientOptions{
		Timeout: timeout,
		TLSCert: cert,

		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	})
}

func AuthedResource(client *http.Client, base string, headers map[string]string, timeout time.Duration) (bool, []byte) {

	for _, p := range []string{"/redfish/v1/AccountService/Accounts", "/redfish/v1/Managers"} {
		st, body := authGet(client, base+p, headers, timeout)
		if st >= 200 && st < 300 && looksLikeRedfish(body) && !looksLikeLogin(body) {
			return true, body
		}
	}
	return false, nil
}

type SessionResult struct {
	Authenticated bool
	Token         string
	SessionURI    string
	Via           string
	Status        int
}

type AuthPathStatus struct {
	Resource      string
	UnauthStatus  int
	BasicStatus   int
	SessionStatus int
	Challenge     string
}

func OpenSession(client *http.Client, base, username, password string, timeout time.Duration) SessionResult {

	if res, ok := postSession(client, base, username, password, timeout); ok {

		hdrs := map[string]string{"X-Auth-Token": res.Token}
		if authed, _ := AuthedResource(client, base, hdrs, timeout); authed {
			res.Authenticated = true
			return res
		}

		return res
	}

	hdrs := authHeaderForBestEffortChallenge(client, base, username, password, timeout)
	if authed, _ := AuthedResource(client, base, hdrs, timeout); authed {
		return SessionResult{Authenticated: true, Via: "basic", Status: http.StatusOK}
	}
	return SessionResult{}
}

func ProbeAuthPathStatus(client *http.Client, base, username, password string, timeout time.Duration) AuthPathStatus {
	out := AuthPathStatus{}

	for _, p := range []string{"/redfish/v1/Managers", "/redfish/v1/Systems", "/redfish/v1/AccountService/Accounts"} {
		st, hdr := authStatus(client, base+p, nil, timeout)
		if st == 0 {
			continue
		}
		if st == http.StatusNotFound || st == http.StatusMethodNotAllowed {
			continue
		}
		out.Resource = p
		out.UnauthStatus = st
		out.Challenge = hdr.Get("WWW-Authenticate")

		if bst, _ := authStatus(client, base+p, basicAuthHeader(username, password), timeout); bst != 0 {
			out.BasicStatus = bst
		}
		break
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	payload, _ := json.Marshal(map[string]string{"UserName": username, "Password": password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/redfish/v1/SessionService/Sessions", bytes.NewReader(payload))
	if err != nil {
		return out
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err == nil {
		out.SessionStatus = resp.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}
	return out
}

func IsAuthPathErrorPattern(st AuthPathStatus) bool {
	if st.UnauthStatus != http.StatusUnauthorized && st.UnauthStatus != http.StatusForbidden {
		return false
	}
	return st.BasicStatus >= 500 && st.SessionStatus >= 500
}

func VerifyCredential(client *http.Client, base, username, password string, timeout time.Duration) bool {
	for _, p := range []string{"/redfish/v1/Managers", "/redfish/v1/Systems", "/redfish/v1/AccountService/Accounts"} {
		ust, hdr := authStatus(client, base+p, nil, timeout)
		if ust != http.StatusUnauthorized && ust != http.StatusForbidden {
			continue
		}
		hdrs := authHeaderForChallenge(hdr.Get("WWW-Authenticate"), username, password)
		ast, _ := authStatus(client, base+p, hdrs, timeout)
		if ast >= 200 && ast < 300 {
			return true
		}
	}

	if username != "" {
		good := sessionLoginStatus(client, base, username, password, timeout)
		if good >= 500 {
			bad := sessionLoginStatus(client, base, username, invalidPasswordVariant(password), timeout)
			if bad == http.StatusUnauthorized || bad == http.StatusForbidden {
				return true
			}
		}
	}
	return false
}

func invalidPasswordVariant(password string) string {
	if password == "" {
		return "oobscan-invalid-password"
	}
	return password + "-oobscan-invalid"
}

func sessionLoginStatus(client *http.Client, base, username, password string, timeout time.Duration) int {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	payload, _ := json.Marshal(map[string]string{"UserName": username, "Password": password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/redfish/v1/SessionService/Sessions", bytes.NewReader(payload))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode
}

func authHeaderForBestEffortChallenge(client *http.Client, base, username, password string, timeout time.Duration) map[string]string {
	for _, p := range []string{"/redfish/v1/Managers", "/redfish/v1/Systems", "/redfish/v1/AccountService/Accounts"} {
		st, hdr := authStatus(client, base+p, nil, timeout)
		if st != http.StatusUnauthorized && st != http.StatusForbidden {
			continue
		}
		return authHeaderForChallenge(hdr.Get("WWW-Authenticate"), username, password)
	}
	return basicAuthHeader(username, password)
}

func authHeaderForChallenge(challenge, username, password string) map[string]string {
	if strings.Contains(strings.ToLower(challenge), "xbasic") {
		token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		return map[string]string{"Authorization": "xBasic " + token}
	}
	return basicAuthHeader(username, password)
}

func authStatus(client *http.Client, url string, headers map[string]string, timeout time.Duration) (int, http.Header) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
	return resp.StatusCode, resp.Header
}

func postSession(client *http.Client, base, username, password string, timeout time.Duration) (SessionResult, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	payload, _ := json.Marshal(map[string]string{"UserName": username, "Password": password})
	url := base + "/redfish/v1/SessionService/Sessions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return SessionResult{}, false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return SessionResult{}, false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	token := resp.Header.Get("X-Auth-Token")
	res := SessionResult{
		Token:      token,
		SessionURI: resp.Header.Get("Location"),
		Via:        "session",
		Status:     resp.StatusCode,
	}
	ok := (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated) && token != ""
	return res, ok
}

func DeleteSession(client *http.Client, base, sessionURI, token string, timeout time.Duration) {
	if sessionURI == "" || token == "" {
		return
	}
	uri := sessionURI
	if strings.HasPrefix(uri, "/") {
		uri = base + uri
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri, nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Auth-Token", token)
	if resp, err := client.Do(req); err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
	}
}

func InsecureClient(timeout time.Duration) *http.Client { return insecureClient(nil, timeout) }

func InsecureMTLSClient(cert tls.Certificate, timeout time.Duration) *http.Client {
	return insecureClient(&cert, timeout)
}

func basicAuthHeader(username, password string) map[string]string {
	req, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
	req.SetBasicAuth(username, password)
	return map[string]string{"Authorization": req.Header.Get("Authorization")}
}

func baseURL(host string, port int) string {
	return netaddr.URL("https", host, port, "")
}

func BaseURL(host string, port int) string { return baseURL(host, port) }

func ProbeAt(host string, port int, timeout time.Duration) (*Result, error) {
	if port == 0 || port == 443 {
		return Probe(host, timeout)
	}
	return Probe(netaddr.DialHostPort(host, port), timeout)
}
