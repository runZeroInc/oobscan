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

// SystemInfo is the vendor/model/firmware fingerprint pulled from an
// authenticated Redfish session. It proves real access (the fields come from
// resources a BMC gates behind auth) and enriches the host record. Empty fields
// are simply not reported by the callers (engine.F / kvPairs drop them).
type SystemInfo struct {
	Vendor          string `json:"vendor,omitempty"`          // Manager/System Manufacturer or service-root Vendor
	Model           string `json:"model,omitempty"`           // System Model (or Manager Model)
	FirmwareVersion string `json:"firmwareVersion,omitempty"` // Manager FirmwareVersion
	Product         string `json:"product,omitempty"`         // service-root Product string
	SerialNumber    string `json:"serialNumber,omitempty"`    // System SerialNumber, when present
	RedfishVersion  string `json:"redfishVersion,omitempty"`  // ServiceRoot RedfishVersion
	ServiceUUID     string `json:"serviceUuid,omitempty"`     // ServiceRoot UUID
	ManagerID       string `json:"managerId,omitempty"`       // Manager Id
	SystemID        string `json:"systemId,omitempty"`        // ComputerSystem Id
	BIOSVersion     string `json:"biosVersion,omitempty"`     // ComputerSystem BIOSVersion
	PowerState      string `json:"powerState,omitempty"`      // ComputerSystem PowerState
	AccountRole     string `json:"accountRole,omitempty"`     // Matched Account RoleId for authenticated user
	AccountEnabled  string `json:"accountEnabled,omitempty"`  // Matched Account Enabled ("true"/"false")
}

// Empty reports whether nothing useful was recovered.
func (s SystemInfo) Empty() bool {
	return s.Vendor == "" && s.Model == "" && s.FirmwareVersion == "" &&
		s.Product == "" && s.SerialNumber == "" && s.RedfishVersion == "" &&
		s.ServiceUUID == "" && s.ManagerID == "" && s.SystemID == "" &&
		s.BIOSVersion == "" && s.PowerState == "" && s.AccountRole == "" &&
		s.AccountEnabled == ""
}

// authGet performs a GET with the supplied client, returning status + a bounded
// body. Extra headers (e.g. an X-Auth-Token) are applied when non-nil.
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

// managerDoc / systemDoc / rootDoc are the small subsets of the Manager,
// ComputerSystem and ServiceRoot resources we read for the fingerprint.
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

// AccountLockoutThreshold reads AccountService.AccountLockoutThreshold from an
// unauthenticated GET (the AccountService resource is readable pre-auth on many
// BMCs). It returns the threshold (>0) when the BMC exposes it, or 0 when it is
// unknown or set to "never lock" (Redfish uses 0 to mean lockout is disabled).
// Callers use it to cap attempts; existing failures can still cause lockout.
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

// PullSystemInfo walks an authenticated Redfish session to recover the BMC /
// system vendor, model and firmware version. base is the scheme+host+port
// prefix (e.g. "https://10.0.0.1"); headers carry the session token when the
// caller authenticated via SessionService (nil for mTLS client-cert auth, where
// the transport carries the identity). username is optional and used to match
// the account metadata for the authenticated principal when available. It reads:
//
//	GET /redfish/v1               -> Vendor / Product
//	GET /redfish/v1/Managers/{id} -> Manufacturer / Model / FirmwareVersion
//	GET /redfish/v1/Systems/{id}  -> Manufacturer / Model / SerialNumber
//
// It is best-effort: any field that resolves is kept, and a fully empty result
// is returned rather than an error.
func PullSystemInfo(client *http.Client, base string, headers map[string]string, username string, timeout time.Duration) SystemInfo {
	var out SystemInfo

	// Read vendor/product strings from the service root using the session.
	if st, body := authGet(client, base+"/redfish/v1", headers, timeout); st == http.StatusOK {
		var sr ServiceRoot
		if json.Unmarshal(body, &sr) == nil {
			out.Vendor = firstNonEmpty(sr.Vendor, out.Vendor)
			out.Product = sr.Product
			out.RedfishVersion = firstNonEmpty(out.RedfishVersion, sr.RedfishVersion)
			out.ServiceUUID = firstNonEmpty(out.ServiceUUID, sr.UUID)
		}
	}

	// Manager (BMC) firmware + manufacturer/model.
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

	// ComputerSystem: prefer the host system's manufacturer/model (the branded
	// server, e.g. "ASRockRack X470D4U") over the BMC Manager's generic values,
	// and pick up a serial number when exposed.
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

// firstMember GETs a Redfish collection and returns the @odata.id of its first
// member (e.g. the sole Manager/System on a single-node BMC).
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

// insecureClient builds an HTTP client that trusts any TLS cert (BMCs ship
// self-signed leaves) and does not reuse connections, optionally presenting a
// client certificate for mutual-TLS auth.
func insecureClient(cert *tls.Certificate, timeout time.Duration) *http.Client {
	return httpx.NewClient(httpx.ClientOptions{
		Timeout: timeout,
		TLSCert: cert,
		// Do not follow a redirect to a login page as if it were success.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	})
}

// AuthedResource reports whether an authenticated GET to an admin-scoped Redfish
// resource succeeded: a 2xx that returns a genuine Redfish document (not an HTML
// login page). It is the success signal both the mTLS-bypass and default-cred
// checks assert on.
func AuthedResource(client *http.Client, base string, headers map[string]string, timeout time.Duration) (bool, []byte) {
	// AccountService/Accounts is admin-scoped on every compliant BMC; Managers is
	// the fallback (some builds gate Accounts differently but return Managers to
	// an authenticated principal).
	for _, p := range []string{"/redfish/v1/AccountService/Accounts", "/redfish/v1/Managers"} {
		st, body := authGet(client, base+p, headers, timeout)
		if st >= 200 && st < 300 && looksLikeRedfish(body) && !looksLikeLogin(body) {
			return true, body
		}
	}
	return false, nil
}

// SessionResult is the outcome of a Redfish SessionService login attempt.
type SessionResult struct {
	Authenticated bool
	Token         string // X-Auth-Token, when a session was minted
	SessionURI    string // Location of the created session, for cleanup
	Via           string // "session" | "basic"
	Status        int
}

// AuthPathStatus captures the HTTP status differential across key Redfish auth
// paths for one credential pair.
type AuthPathStatus struct {
	Resource      string // protected Redfish resource used for GET differential
	UnauthStatus  int    // GET Accounts with no Authorization
	BasicStatus   int    // GET Accounts with Basic Authorization
	SessionStatus int    // POST SessionService/Sessions
	Challenge     string // WWW-Authenticate from unauth probe
}

// OpenSession attempts a Redfish credential login against base
// (scheme+host+port). It first POSTs to /redfish/v1/SessionService/Sessions and,
// on failure, falls back to HTTP Basic against an admin-scoped resource. It
// returns the token + a verified-authenticated flag. This is a state-changing
// login (it mints a session and may count toward lockout); callers must gate it
// behind the authorized/online flag.
func OpenSession(client *http.Client, base, username, password string, timeout time.Duration) SessionResult {
	// 1. SessionService POST (preferred: no Basic-auth logging on the BMC side and
	// it exercises the real login path).
	if res, ok := postSession(client, base, username, password, timeout); ok {
		// Confirm the token actually reads an admin resource (some BMCs 201 a
		// session but scope it below admin; we only assert on a usable token).
		hdrs := map[string]string{"X-Auth-Token": res.Token}
		if authed, _ := AuthedResource(client, base, hdrs, timeout); authed {
			res.Authenticated = true
			return res
		}
		// Session minted but not admin-usable; still record the token for cleanup.
		return res
	}

	// 2. Basic-auth fallback against an admin-scoped resource.
	hdrs := authHeaderForBestEffortChallenge(client, base, username, password, timeout)
	if authed, _ := AuthedResource(client, base, hdrs, timeout); authed {
		return SessionResult{Authenticated: true, Via: "basic", Status: http.StatusOK}
	}
	return SessionResult{}
}

// ProbeAuthPathStatus samples the three key Redfish auth paths using one
// credential pair: unauthenticated Accounts GET, Basic-auth Accounts GET, and
// SessionService POST. It is used to detect auth-handler crash patterns where
// protected resources challenge correctly (401/403) but authenticated requests
// fail with 5xx.
func ProbeAuthPathStatus(client *http.Client, base, username, password string, timeout time.Duration) AuthPathStatus {
	out := AuthPathStatus{}

	// 1) Pick a protected admin resource and capture its unauth + basic status
	// differential on the same endpoint. AccountService/Accounts is not uniformly
	// implemented across vendors, so prefer Managers/Systems first.
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
		// Probe with RFC Basic explicitly: several broken BMC stacks advertise
		// xBasic but still crash with 5xx on Basic-authenticated requests. That
		// differential is exactly what authPathError is meant to detect.
		if bst, _ := authStatus(client, base+p, basicAuthHeader(username, password), timeout); bst != 0 {
			out.BasicStatus = bst
		}
		break
	}

	// 3) SessionService login attempt.
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

// IsAuthPathErrorPattern reports the Redfish auth-handler failure differential:
// admin resources are protected pre-auth (401/403), but authenticated paths
// return server errors (5xx).
func IsAuthPathErrorPattern(st AuthPathStatus) bool {
	if st.UnauthStatus != http.StatusUnauthorized && st.UnauthStatus != http.StatusForbidden {
		return false
	}
	return st.BasicStatus >= 500 && st.SessionStatus >= 500
}

// VerifyCredential confirms whether a credential authenticates to any protected
// Redfish admin resource using Basic auth. It does not mutate target state.
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

	// Some BMCs crash (5xx) on correct SessionService auth but still return
	// 401/403 when the password is intentionally wrong. Treat this differential
	// as evidence that the supplied credential is valid.
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

// authHeaderForBestEffortChallenge discovers one protected resource challenge
// and selects the matching Authorization scheme (xBasic vs Basic).
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

// authHeaderForChallenge builds an Authorization header matching the server's
// challenge when it advertises xBasic; otherwise it falls back to HTTP Basic.
func authHeaderForChallenge(challenge, username, password string) map[string]string {
	if strings.Contains(strings.ToLower(challenge), "xbasic") {
		token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		return map[string]string{"Authorization": "xBasic " + token}
	}
	return basicAuthHeader(username, password)
}

// authStatus performs a GET with optional headers and returns status + headers.
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

// postSession issues the SessionService POST and returns the token + location on
// a 200/201 with an X-Auth-Token.
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

// DeleteSession best-effort tears down a Redfish session created by OpenSession,
// leaving the BMC's session table clean. Failures are ignored.
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

// InsecureClient / InsecureMTLSClient expose the shared BMC HTTP client so
// callers in other packages (audit) reuse the same TLS posture.
func InsecureClient(timeout time.Duration) *http.Client { return insecureClient(nil, timeout) }

// InsecureMTLSClient builds a client that presents the given client certificate
// for mutual-TLS auth.
func InsecureMTLSClient(cert tls.Certificate, timeout time.Duration) *http.Client {
	return insecureClient(&cert, timeout)
}

// basicAuthHeader builds the Authorization header map for HTTP Basic.
func basicAuthHeader(username, password string) map[string]string {
	req, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
	req.SetBasicAuth(username, password)
	return map[string]string{"Authorization": req.Header.Get("Authorization")}
}

// baseURL builds the scheme+host+port prefix for a Redfish host. port 0 means
// the default 443.
func baseURL(host string, port int) string {
	return netaddr.URL("https", host, port, "")
}

// BaseURL is the exported form of baseURL for callers in other packages.
func BaseURL(host string, port int) string { return baseURL(host, port) }

// ProbeAt fingerprints the Redfish service on host:port. Probe hardcodes :443;
// this honors an alternate HTTPS port (8443/4443) that identify discovered, so
// callers reach BMCs that do not serve Redfish on 443. port 0 or 443 is the
// default port.
func ProbeAt(host string, port int, timeout time.Duration) (*Result, error) {
	if port == 0 || port == 443 {
		return Probe(host, timeout)
	}
	return Probe(netaddr.DialHostPort(host, port), timeout)
}
