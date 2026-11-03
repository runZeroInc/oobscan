// Package wsman performs WS-Management Identify requests. iLO, iDRAC, AMT,
// OpenBMC, and XClarity all implement WS-Man /wsman endpoints; Identify is
// unauthenticated and returns the product vendor + version.
package wsman

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

const identifyBody = `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <s:Header/>
  <s:Body><wsmid:Identify/></s:Body>
</s:Envelope>`

// Identity is the parsed Identify response.
type Identity struct {
	ProtocolVersion string
	ProductVendor   string
	ProductVersion  string
	SecurityProfile []string
	Raw             []byte
	URL             string
}

// LoginResult is one authenticated Identify attempt result.
type LoginResult struct {
	Authenticated bool
	URL           string
	Auth          string // "basic" | "digest"
	Authorization string
	Status        int
	Identity      *Identity
	SystemInfo    *SystemInfo
	Challenge     string
}

// SystemInfo is a compact authenticated WS-Man system snapshot recovered from
// a standard CIM_ComputerSystem enumeration.
type SystemInfo struct {
	Endpoint     string
	Manufacturer string
	Model        string
	Name         string
	ElementName  string
	UUID         string
	Raw          []byte
}

func (s *SystemInfo) HasProof() bool {
	if s == nil {
		return false
	}
	return strings.TrimSpace(s.Manufacturer) != "" ||
		strings.TrimSpace(s.Model) != "" ||
		strings.TrimSpace(s.Name) != "" ||
		strings.TrimSpace(s.ElementName) != "" ||
		strings.TrimSpace(s.UUID) != ""
}

const cimComputerSystemURI = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ComputerSystem"

// VendorSlug derives a vendor slug from ProductVendor and ProductVersion.
func (i *Identity) VendorSlug() string {
	low := strings.ToLower(i.ProductVendor + " " + i.ProductVersion)
	switch {
	case strings.Contains(low, "intel(r) amt"), strings.Contains(low, "intel amt"):
		return "intel-amt"
	case strings.Contains(low, "idrac"), strings.Contains(low, "dell"):
		return "dell"
	case strings.Contains(low, "ilo"), strings.Contains(low, "hpe"):
		return "hpe"
	case strings.Contains(low, "xclarity"), strings.Contains(low, "lenovo"), strings.Contains(low, "ibm"):
		return "lenovo"
	case strings.Contains(low, "openbmc"):
		return "openbmc"
	case strings.Contains(low, "supermicro"), strings.Contains(low, "aten"):
		return "supermicro"
	case strings.Contains(low, "megarac"), strings.Contains(low, "ami"):
		return "ami"
	case strings.Contains(low, "cisco"):
		return "cisco"
	}
	return ""
}

// HasFingerprint reports whether the Identify response contains useful product
// identity fields.
func (i *Identity) HasFingerprint() bool {
	if i == nil {
		return false
	}
	return strings.TrimSpace(i.ProductVendor) != "" ||
		strings.TrimSpace(i.ProductVersion) != "" ||
		strings.TrimSpace(i.ProtocolVersion) != ""
}

// Probe sends Identify to https://host:port/wsman and http://host:port/wsman.
// Most BMCs answer on 5986/tcp (https) and occasionally 5985/tcp (http).
// For AMT use 16993/tcp (TLS) or 16992/tcp (cleartext).
func Probe(host string, ports []int, timeout time.Duration) (*Identity, error) {
	return ProbeWithConnectTimeout(host, ports, timeout, timeout)
}

// ProbeWithConnectTimeout is Probe with the reachability test and the Identify request
// budgeted separately. The candidate list is a fixed set of six ports and a filtered
// port costs a full connect timeout each, easily more than identify's whole budget on a
// host with no WS-Man at all. A live endpoint is a local service and answers a connect
// promptly, so the reachability test can be short; the Identify request keeps the full
// budget for a slow TLS handshake on 5986.
func ProbeWithConnectTimeout(host string, ports []int, connectTimeout, requestTimeout time.Duration) (*Identity, error) {
	ports = normalizePorts(ports)
	client := httpx.Client(requestTimeout)
	if connectTimeout <= 0 {
		connectTimeout = requestTimeout
	}

	var lastErr error
	for _, p := range ports {
		if !tcpOpen(host, p, connectTimeout) {
			continue
		}
		timeout := requestTimeout
		for _, scheme := range schemesForPort(p) {
			url := netaddr.URL(scheme, host, p, "/wsman")
			id, err := doIdentify(client, url, timeout)
			if err == nil && id.HasFingerprint() {
				return id, nil
			}
			if err != nil {
				lastErr = err
			}
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no wsman endpoint responded on %s", host)
	}
	return nil, lastErr
}

// AuthenticateIdentify tries to authenticate to /wsman using Basic, then
// Digest (if challenged), returning the first successful Identify response.
func AuthenticateIdentify(host string, ports []int, timeout time.Duration, user, pass string) (*LoginResult, error) {
	if strings.TrimSpace(user) == "" {
		return nil, fmt.Errorf("username is required")
	}
	ports = normalizePorts(ports)
	client := httpx.Client(timeout)

	var lastErr error
	for _, p := range ports {
		if !tcpOpen(host, p, timeout) {
			continue
		}
		for _, scheme := range schemesForPort(p) {
			u := netaddr.URL(scheme, host, p, "/wsman")

			basic := basicAuth(user, pass)
			idBasic, statusBasic, challengeBasic, errBasic := identifyRequest(client, u, timeout, basic)
			if errBasic == nil && statusBasic == http.StatusOK && idBasic != nil && idBasic.HasFingerprint() {
				info, errInfo := systemInfoRequest(client, u, timeout, basic)
				if errInfo == nil && info != nil && info.HasProof() {
					return &LoginResult{Authenticated: true, URL: u, Auth: "basic", Authorization: basic, Status: statusBasic, Identity: idBasic, SystemInfo: info, Challenge: challengeBasic}, nil
				}
				if errInfo != nil {
					lastErr = errInfo
				}
			}
			if errBasic != nil {
				lastErr = errBasic
			}

			if strings.Contains(strings.ToLower(challengeBasic), "digest") {
				dig := digestAuthorization(challengeBasic, "POST", "/wsman", user, pass)
				if dig != "" {
					idDig, statusDig, _, errDig := identifyRequest(client, u, timeout, dig)
					if errDig == nil && statusDig == http.StatusOK && idDig != nil && idDig.HasFingerprint() {
						info, errInfo := systemInfoRequest(client, u, timeout, dig)
						if errInfo == nil && info != nil && info.HasProof() {
							return &LoginResult{Authenticated: true, URL: u, Auth: "digest", Authorization: dig, Status: statusDig, Identity: idDig, SystemInfo: info, Challenge: challengeBasic}, nil
						}
						if errInfo != nil {
							lastErr = errInfo
						}
					}
					if errDig != nil {
						lastErr = errDig
					}
				}
			}
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no wsman endpoint authenticated on %s", host)
	}
	return nil, lastErr
}

func schemesForPort(port int) []string {
	switch port {
	case 5986, 16993:
		return []string{"https", "http"}
	case 5985, 16992:
		return []string{"http", "https"}
	case 443:
		return []string{"https", "http"}
	default:
		return []string{"https", "http"}
	}
}

func doIdentify(client *http.Client, url string, timeout time.Duration) (*Identity, error) {
	id, status, _, err := identifyRequest(client, url, timeout, "")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("identify %s returned status %d", url, status)
	}
	if id == nil {
		return nil, fmt.Errorf("identify %s returned no parseable identity", url)
	}
	return id, nil
}

func identifyRequest(client *http.Client, endpoint string, timeout time.Duration, auth string) (*Identity, int, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(identifyBody))
	if err != nil {
		return nil, 0, "", err
	}
	req.Header.Set("Content-Type", `application/soap+xml;charset=UTF-8`)
	req.Header.Set("SOAPAction", `"http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity/Identify"`)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, resp.StatusCode, resp.Header.Get("WWW-Authenticate"), err
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, challenge, nil
	}
	var parsed struct {
		XMLName xml.Name
		Body    struct {
			IdentifyResponse struct {
				ProtocolVersion string   `xml:"ProtocolVersion"`
				ProductVendor   string   `xml:"ProductVendor"`
				ProductVersion  string   `xml:"ProductVersion"`
				SecurityProfile []string `xml:"SecurityProfileName"`
			} `xml:"IdentifyResponse"`
		} `xml:"Body"`
	}
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return nil, resp.StatusCode, challenge, err
	}
	id := &Identity{
		URL:             endpoint,
		ProtocolVersion: parsed.Body.IdentifyResponse.ProtocolVersion,
		ProductVendor:   parsed.Body.IdentifyResponse.ProductVendor,
		ProductVersion:  parsed.Body.IdentifyResponse.ProductVersion,
		SecurityProfile: parsed.Body.IdentifyResponse.SecurityProfile,
		Raw:             body,
	}
	return id, resp.StatusCode, challenge, nil
}

func systemInfoRequest(client *http.Client, endpoint string, timeout time.Duration, auth string) (*SystemInfo, error) {
	enumBody := wsmanEnumerateBody(endpoint, nextMessageID(), cimComputerSystemURI)
	enumResp, err := wsmanSOAPRequest(client, endpoint, timeout, auth, "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate", enumBody)
	if err != nil {
		return nil, err
	}
	parsedEnum, err := parseSystemEnvelope(enumResp)
	if err != nil {
		return nil, err
	}
	if info := parsedEnum.firstInfo(endpoint, enumResp); info != nil && info.HasProof() {
		return info, nil
	}
	if strings.TrimSpace(parsedEnum.Body.EnumerateResponse.EnumerationContext) == "" {
		return nil, fmt.Errorf("system info %s returned no CIM_ComputerSystem items", endpoint)
	}
	pullBody := wsmanPullBody(endpoint, nextMessageID(), cimComputerSystemURI, parsedEnum.Body.EnumerateResponse.EnumerationContext)
	pullResp, err := wsmanSOAPRequest(client, endpoint, timeout, auth, "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull", pullBody)
	if err != nil {
		return nil, err
	}
	parsedPull, err := parseSystemEnvelope(pullResp)
	if err != nil {
		return nil, err
	}
	if info := parsedPull.firstInfo(endpoint, pullResp); info != nil && info.HasProof() {
		return info, nil
	}
	return nil, fmt.Errorf("system info %s returned no CIM_ComputerSystem items", endpoint)
}

type systemEnvelope struct {
	Body struct {
		EnumerateResponse struct {
			EnumerationContext string      `xml:"EnumerationContext"`
			Items              systemItems `xml:"Items"`
		} `xml:"EnumerateResponse"`
		PullResponse struct {
			EnumerationContext string      `xml:"EnumerationContext"`
			Items              systemItems `xml:"Items"`
		} `xml:"PullResponse"`
	} `xml:"Body"`
}

type systemItems struct {
	ComputerSystem     []systemNode `xml:"CIM_ComputerSystem"`
	DCIMComputerSystem []systemNode `xml:"DCIM_ComputerSystem"`
}

type systemNode struct {
	Name                 string   `xml:"Name"`
	ElementName          string   `xml:"ElementName"`
	Manufacturer         string   `xml:"Manufacturer"`
	Model                string   `xml:"Model"`
	UUID                 string   `xml:"UUID"`
	OtherIdentifyingInfo []string `xml:"OtherIdentifyingInfo"`
}

func parseSystemEnvelope(body []byte) (*systemEnvelope, error) {
	var parsed systemEnvelope
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	return &parsed, nil
}

func (e *systemEnvelope) firstInfo(endpoint string, raw []byte) *SystemInfo {
	if e == nil {
		return nil
	}
	if info := e.Body.EnumerateResponse.Items.firstInfo(endpoint, raw); info != nil {
		return info
	}
	return e.Body.PullResponse.Items.firstInfo(endpoint, raw)
}

func (s systemItems) firstInfo(endpoint string, raw []byte) *SystemInfo {
	for _, item := range s.ComputerSystem {
		if info := item.toInfo(endpoint, raw); info != nil {
			return info
		}
	}
	for _, item := range s.DCIMComputerSystem {
		if info := item.toInfo(endpoint, raw); info != nil {
			return info
		}
	}
	return nil
}

func (n systemNode) toInfo(endpoint string, raw []byte) *SystemInfo {
	info := &SystemInfo{
		Endpoint:     endpoint,
		Manufacturer: strings.TrimSpace(n.Manufacturer),
		Model:        strings.TrimSpace(n.Model),
		Name:         strings.TrimSpace(n.Name),
		ElementName:  strings.TrimSpace(n.ElementName),
		UUID:         strings.TrimSpace(n.UUID),
		Raw:          raw,
	}
	if info.UUID == "" {
		for _, other := range n.OtherIdentifyingInfo {
			if looksLikeUUID(other) {
				info.UUID = strings.TrimSpace(other)
				break
			}
		}
	}
	if !info.HasProof() {
		return nil
	}
	return info
}

func looksLikeUUID(v string) bool {
	v = strings.TrimSpace(v)
	return len(v) == 36 && strings.Count(v, "-") == 4
}

func nextMessageID() string {
	return fmt.Sprintf("uuid:%d", time.Now().UnixNano())
}

func wsmanEnumerateBody(endpoint, messageID, resourceURI string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <wsa:To>%s</wsa:To>
    <wsa:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</wsa:Action>
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
      <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsman:ResourceURI s:mustUnderstand="true">%s</wsman:ResourceURI>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">153600</wsman:MaxEnvelopeSize>
    <wsman:OperationTimeout>PT5S</wsman:OperationTimeout>
  </s:Header>
  <s:Body>
    <wsen:Enumerate/>
  </s:Body>
</s:Envelope>`, endpoint, messageID, resourceURI)
}

func wsmanPullBody(endpoint, messageID, resourceURI, context string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <wsa:To>%s</wsa:To>
    <wsa:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull</wsa:Action>
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
      <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsman:ResourceURI s:mustUnderstand="true">%s</wsman:ResourceURI>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">153600</wsman:MaxEnvelopeSize>
    <wsman:OperationTimeout>PT5S</wsman:OperationTimeout>
  </s:Header>
  <s:Body>
    <wsen:Pull>
      <wsen:EnumerationContext>%s</wsen:EnumerationContext>
      <wsen:MaxElements>1</wsen:MaxElements>
    </wsen:Pull>
  </s:Body>
</s:Envelope>`, endpoint, messageID, resourceURI, context)
}

func wsmanSOAPRequest(client *http.Client, endpoint string, timeout time.Duration, auth, action, body string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `application/soap+xml;charset=UTF-8`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s"`, action))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 131072))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("system info %s action %s returned status %d", endpoint, action, resp.StatusCode)
	}
	return respBody, nil
}

func normalizePorts(in []int) []int {
	if len(in) == 0 {
		in = []int{443, 5986, 5985, 16993, 16992}
	}
	seen := map[int]struct{}{}
	out := make([]int, 0, len(in))
	for _, p := range in {
		if p <= 0 || p > 65535 {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		return wsmanPortPriority(out[i]) < wsmanPortPriority(out[j])
	})
	if len(out) == 0 {
		return []int{443, 5986, 5985, 16993, 16992}
	}
	return out
}

func wsmanPortPriority(p int) int {
	order := map[int]int{5986: 0, 5985: 1, 16993: 2, 16992: 3, 443: 4}
	if v, ok := order[p]; ok {
		return v
	}
	return 100 + p
}

func tcpOpen(host string, port int, timeout time.Duration) bool {
	to := timeout
	if to <= 0 {
		to = 4 * time.Second
	}
	if to > 1200*time.Millisecond {
		to = 1200 * time.Millisecond
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), to)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func basicAuth(user, pass string) string {
	req, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
	req.SetBasicAuth(user, pass)
	return req.Header.Get("Authorization")
}

func digestAuthorization(challenge, method, uri, user, pass string) string {
	return digestAuthorizationWithCnonce(challenge, method, uri, user, pass, rand.Text())
}

func digestAuthorizationWithCnonce(challenge, method, uri, user, pass, cnonce string) string {
	params := parseDigestChallenge(challenge)
	realm := params["realm"]
	nonce := params["nonce"]
	if realm == "" || nonce == "" {
		return ""
	}
	qop := ""
	if v := strings.ToLower(params["qop"]); strings.Contains(v, "auth") {
		qop = "auth"
	}
	alg := params["algorithm"]
	if alg == "" {
		alg = "MD5"
	}
	if !strings.EqualFold(alg, "MD5") {
		return ""
	}
	nc := "00000001"
	ha1 := md5Hex(user + ":" + realm + ":" + pass)
	ha2 := md5Hex(method + ":" + uri)
	resp := ""
	if qop != "" {
		resp = md5Hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
	} else {
		resp = md5Hex(ha1 + ":" + nonce + ":" + ha2)
	}
	parts := []string{
		`Digest username="` + escapeQuote(user) + `"`,
		`realm="` + escapeQuote(realm) + `"`,
		`nonce="` + escapeQuote(nonce) + `"`,
		`uri="` + escapeQuote(uri) + `"`,
		`response="` + resp + `"`,
		`algorithm=` + alg,
	}
	if opaque := params["opaque"]; opaque != "" {
		parts = append(parts, `opaque="`+escapeQuote(opaque)+`"`)
	}
	if qop != "" {
		parts = append(parts, `qop=`+qop, `nc=`+nc, `cnonce="`+cnonce+`"`)
	}
	return strings.Join(parts, ", ")
}

func parseDigestChallenge(challenge string) map[string]string {
	out := map[string]string{}
	s := strings.TrimSpace(challenge)
	if s == "" {
		return out
	}
	if i := strings.Index(strings.ToLower(s), "digest "); i >= 0 {
		s = s[i+len("digest "):]
	}
	for _, part := range splitCommaQuoted(s) {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := strings.TrimSpace(kv[1])
		v = strings.Trim(v, `"`)
		out[k] = v
	}
	return out
}

func splitCommaQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	esc := false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			cur.WriteRune(r)
			esc = true
		case r == '"':
			cur.WriteRune(r)
			inQuote = !inQuote
		case r == ',' && !inQuote:
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

func md5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func escapeQuote(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}

// ParseURL returns (scheme, host, port) for a wsman endpoint URL.
func ParseURL(raw string) (string, string, int) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", 0
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		if strings.EqualFold(u.Scheme, "http") {
			port = 80
		} else if strings.EqualFold(u.Scheme, "https") {
			port = 443
		}
	}
	return strings.ToLower(u.Scheme), u.Hostname(), port
}
