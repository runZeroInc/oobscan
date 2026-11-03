// Package redfish provides unauthenticated Redfish fingerprinting for BMCs.
// Every modern BMC answers at /redfish/v1/ without auth with vendor + model
// data. We also probe a handful of vendor-specific endpoints that must be
// auth-gated but are useful to check for pre-auth leakage.
package redfish

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/bmcfp"
	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

// ServiceRoot is the subset of /redfish/v1/ we parse.
type ServiceRoot struct {
	ID             string `json:"Id"`
	Name           string `json:"Name"`
	RedfishVersion string `json:"RedfishVersion"`
	UUID           string `json:"UUID"`
	Vendor         string `json:"Vendor"`
	Product        string `json:"Product"`
	// Oem is vendor-specific extension data. It preserves the typed sub-blocks
	// existing callers read and also captures every Oem key for OemVendor.
	Oem   OemBlock       `json:"Oem"`
	Links map[string]any `json:"Links"`
}

// OemBlock is the Redfish service-root Oem extension. It keeps the typed vendor
// sub-blocks callers depend on (Dell/HPE/Lenovo/Supermicro/Ami) and captures
// every Oem key (lower-cased) in Raw so OemVendor can attribute vendors we do
// not model as typed fields.
type OemBlock struct {
	Dell       map[string]any
	HPE        map[string]any
	Hpe        map[string]any
	Lenovo     map[string]any
	Supermicro map[string]any
	Ami        map[string]any
	// Raw holds every Oem key, lower-cased, for vendor attribution.
	Raw map[string]json.RawMessage
}

// UnmarshalJSON captures every Oem key generically while still populating the
// typed sub-blocks. It tolerates a malformed Oem object (leaves the block empty)
// rather than failing the whole service-root parse.
func (o *OemBlock) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil //nolint:nilerr // tolerate a malformed/oddly-typed Oem block
	}
	o.Raw = make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		lk := strings.ToLower(k)
		o.Raw[lk] = v
		switch lk {
		case "dell":
			_ = json.Unmarshal(v, &o.Dell)
		case "hpe", "hp":
			_ = json.Unmarshal(v, &o.HPE)
			o.Hpe = o.HPE
		case "lenovo":
			_ = json.Unmarshal(v, &o.Lenovo)
		case "supermicro":
			_ = json.Unmarshal(v, &o.Supermicro)
		case "ami":
			_ = json.Unmarshal(v, &o.Ami)
		}
	}
	return nil
}

// oemKeyVendor maps a lower-cased Redfish Oem extension key to a vendor slug and
// a default product label. The Oem key is the single most reliable vendor signal
// in a service root whose top-level Vendor/Product fields are blank.
var oemKeyVendor = map[string][2]string{
	"dell":            {"dell", "iDRAC"},
	"hpe":             {"hpe", "iLO"},
	"hp":              {"hpe", "iLO"},
	"lenovo":          {"lenovo", "XClarity"},
	"supermicro":      {"supermicro", "IPMI"},
	"ami":             {"ami", "MegaRAC"},
	"cisco":           {"cisco", "CIMC"},
	"fujitsu":         {"fujitsu", "iRMC"},
	"ts_fujitsu":      {"fujitsu", "iRMC"},
	"huawei":          {"huawei", "iBMC"},
	"intel":           {"intel", "BMC"},
	"intel_rackscale": {"intel", "BMC"},
	"inspur":          {"inspur", "BMC"},
	"oracle":          {"oracle", "ILOM"},
	"nvidia":          {"nvidia", "BMC"},
	"quanta":          {"quanta", "BMC"},
	"tyan":            {"tyan", "BMC"},
	"gigabyte":        {"gigabyte", "BMC"},
	"asus":            {"asus", "BMC"},
	"openbmc":         {"openbmc", "OpenBMC"},
}

// oemVendorPriority fixes the attribution order when a service root carries more
// than one recognized Oem key, so OemVendor is deterministic.
var oemVendorPriority = []string{
	"dell", "hpe", "hp", "lenovo", "supermicro", "cisco", "fujitsu", "ts_fujitsu",
	"huawei", "intel", "intel_rackscale", "inspur", "oracle", "nvidia", "quanta",
	"tyan", "gigabyte", "asus", "ami", "openbmc",
}

// OemVendor attributes a vendor from the service-root Oem extension keys, the
// most reliable signal on BMCs whose top-level Vendor/Product are blank.
func (sr *ServiceRoot) OemVendor() (vendor, product string) {
	if sr == nil || sr.Oem.Raw == nil {
		return "", ""
	}
	for _, k := range oemVendorPriority {
		if _, ok := sr.Oem.Raw[k]; ok {
			vp := oemKeyVendor[k]
			return vp[0], vp[1]
		}
	}
	return "", ""
}

// Result is the combined BMC fingerprint.
type Result struct {
	Host           string
	URL            string
	Status         int
	ServiceRoot    *ServiceRoot
	ServerHeader   string
	Vendor         string // guessed
	AMICVE         bool   // CVE-2024-54085 marker
	AMICVEPlain    int    // HTTP status of the plain (unspoofed) Managers/Self request
	AMICVESpoof    int    // HTTP status of the internal-IP-spoofed request
	DellFWVersion  string
	ILOGeneration  int
	RawRoot        []byte
	LeakyEndpoints []string
	// Manufacturer/Model are filled from an extra unauthenticated Manager/System
	// read when the service root itself did not self-identify the vendor.
	Manufacturer string
	Model        string
}

// IsRedfish reports whether the probe result is a genuine Redfish service root
// (a validated Redfish JSON body, not the HTML login/error page a WAF, VPN, or
// honeypot may return with a 200). It is the presence gate to assert before
// spending any credential login on a host.
func (r *Result) IsRedfish() bool {
	if r == nil || r.Status < 200 || r.Status >= 500 {
		return false
	}
	return looksLikeRedfish(r.RawRoot) && !looksLikeLogin(r.RawRoot)
}

// Probe fetches the service root and a few low-risk unauth endpoints.
func Probe(host string, timeout time.Duration) (*Result, error) {
	client := httpx.Client(timeout)
	base := "https://" + netaddr.URLAuthority(host)
	r := &Result{Host: host}

	// Service root
	status, body, hdr, err := httpGet(client, base+"/redfish/v1/", timeout)
	if err != nil {
		return r, err
	}
	r.URL = base + "/redfish/v1/"
	r.Status = status
	r.ServerHeader = hdr.Get("Server")
	r.RawRoot = body
	if status == 200 {
		var sr ServiceRoot
		_ = json.Unmarshal(body, &sr)
		r.ServiceRoot = &sr
		r.Vendor = guessVendor(&sr, r.ServerHeader)
	}

	// When the service root does not self-identify, spend one extra unauthenticated
	// hop reading the Manager/System Manufacturer. This only fires on a validated
	// Redfish endpoint, so it never touches a WAF/VPN/honeypot false positive.
	if r.Vendor == "" && r.IsRedfish() {
		if v, mfr, model := deepVendorUnauth(client, base, timeout); v != "" {
			r.Vendor = v
			r.Manufacturer = mfr
			r.Model = model
		}
	}

	// AMI MegaRAC CVE-2024-54085: unauth Redfish session via spoofed X-Auth.
	if r.Vendor == "ami" || strings.Contains(strings.ToLower(r.ServerHeader), "megarac") {
		r.AMICVE, r.AMICVEPlain, r.AMICVESpoof = probeAMI54085(client, base, timeout)
	}

	// Dell fw version via data?get=fwVersion (pre-auth on older iDRAC6/7).
	if r.Vendor == "dell" {
		if s, ok := probeDellFW(client, base, timeout); ok {
			r.DellFWVersion = s
			r.LeakyEndpoints = append(r.LeakyEndpoints, "/data?get=fwVersion")
		}
	}

	// iLO RIMP xmldata (handled by pkg/ilo; just count the endpoint here).
	if r.Vendor == "hpe" {
		st, _, _, _ := httpGet(client, base+"/xmldata?item=all", timeout)
		if st == 200 {
			r.LeakyEndpoints = append(r.LeakyEndpoints, "/xmldata?item=all")
		}
	}
	return r, nil
}

func httpGet(c *http.Client, url string, timeout time.Duration) (int, []byte, http.Header, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 262144))
	return resp.StatusCode, body, resp.Header, nil
}

func guessVendor(sr *ServiceRoot, server string) string {
	// The Oem extension key is the most reliable signal and covers vendors whose
	// top-level Vendor/Product fields are blank.
	if v, _ := sr.OemVendor(); v != "" {
		return v
	}
	// AMI MegaRAC (and its OEMs such as ASRock Rack) frequently advertise the
	// AMI key only inside the Oem block, and ASRock boxes brand the top-level
	// fields as "ASRock". Consult the AMI service-root markers so the
	// CVE-2024-54085 probe runs on those targets.
	if sr.Oem.Ami != nil || hasAMIServiceRootMarker(sr) {
		return "ami"
	}
	low := strings.ToLower(sr.Vendor + " " + sr.Product + " " + sr.Name + " " + sr.ID + " " + server)
	if v := vendorFromTokens(low); v != "" {
		return v
	}
	// The Redfish body did not self-identify. Fall back to the built-in BMC
	// fingerprints on the Server header.
	if v, _, ok := bmcfp.Match(bmcfp.HTTPServerHeader, server); ok {
		return v
	}
	return ""
}

// vendorFromTokens maps a lower-cased blob of identity tokens (service-root
// fields, Server header, or a Manager/System Manufacturer string) to a vendor
// slug. Shared by guessVendor and the unauthenticated Manufacturer fallback.
func vendorFromTokens(low string) string {
	switch {
	case strings.Contains(low, "dell"), strings.Contains(low, "idrac"):
		return "dell"
	case strings.Contains(low, "hpe"), strings.Contains(low, "ilo"), strings.Contains(low, "hewlett"), strings.Contains(low, "packard"):
		return "hpe"
	case strings.Contains(low, "lenovo"), strings.Contains(low, "xclarity"):
		return "lenovo"
	case strings.Contains(low, "supermicro"), strings.Contains(low, "aten"):
		return "supermicro"
	case strings.Contains(low, "megarac"), strings.Contains(low, "ami"), strings.Contains(low, "asrock"):
		return "ami"
	case strings.Contains(low, "openbmc"), strings.Contains(low, "bmcweb"):
		return "openbmc"
	case strings.Contains(low, "cisco"), strings.Contains(low, "cimc"):
		return "cisco"
	case strings.Contains(low, "fujitsu"), strings.Contains(low, "irmc"):
		return "fujitsu"
	case strings.Contains(low, "quanta"):
		return "quanta"
	case strings.Contains(low, "tyan"):
		return "tyan"
	case strings.Contains(low, "gigabyte"), strings.Contains(low, "giga computing"):
		return "gigabyte"
	case strings.Contains(low, "asus"):
		return "asus"
	case strings.Contains(low, "intel"):
		return "intel"
	case strings.Contains(low, "inspur"):
		return "inspur"
	case strings.Contains(low, "huawei"):
		return "huawei"
	case strings.Contains(low, "oracle"), strings.Contains(low, "ilom"), strings.Contains(low, "sun microsystems"):
		return "oracle"
	case strings.Contains(low, "nvidia"), strings.Contains(low, "bluefield"):
		return "nvidia"
	case strings.Contains(low, "ibm"):
		return "ibm"
	}
	return ""
}

// deepVendorUnauth performs up to two extra unauthenticated reads
// (Managers[0] then Systems[0]) to recover a vendor from the Manufacturer field
// when the service root itself was blank. Returns the vendor slug plus the raw
// manufacturer/model for enrichment.
func deepVendorUnauth(client *http.Client, base string, timeout time.Duration) (vendor, manufacturer, model string) {
	if id := firstMember(client, base, "/redfish/v1/Managers", nil, timeout); id != "" {
		if st, body := authGet(client, base+id, nil, timeout); st == http.StatusOK {
			var m managerDoc
			if json.Unmarshal(body, &m) == nil && m.Manufacturer != "" {
				manufacturer = m.Manufacturer
			}
		}
	}
	if manufacturer == "" {
		if id := firstMember(client, base, "/redfish/v1/Systems", nil, timeout); id != "" {
			if st, body := authGet(client, base+id, nil, timeout); st == http.StatusOK {
				var s systemDoc
				if json.Unmarshal(body, &s) == nil {
					manufacturer = s.Manufacturer
					model = s.Model
				}
			}
		}
	}
	return vendorFromTokens(strings.ToLower(manufacturer + " " + model)), manufacturer, model
}

// hasAMIServiceRootMarker reports whether the service root carries an AMI /
// MegaRAC / ASRock marker in its top-level identity fields.
func hasAMIServiceRootMarker(sr *ServiceRoot) bool {
	low := strings.ToLower(sr.Vendor + " " + sr.Product + " " + sr.Name + " " + sr.ID)
	return strings.Contains(low, "megarac") ||
		strings.Contains(low, "asrock") ||
		strings.Contains(low, "ami")
}

func probeAMI54085(c *http.Client, base string, timeout time.Duration) (vuln bool, plain, spoof int) {
	// CVE-2024-54085 is a Redfish spoofed-auth bypass. Mirror Eclypsium's
	// published detector exactly: compare GET /redfish/v1/Systems normally and
	// with only X-Server-Addr: 169.254.0.17: added. A bare 200 is not enough (a
	// patched BMC may serve some resources unauth or return a 200 login page), so
	// the spoofed response must also be a genuine Redfish body.
	const path = "/redfish/v1/Systems"

	plainStatus, _, _, err := httpGet(c, base+path, timeout)
	if err != nil {
		return false, 0, 0
	}

	spoofStatus, spoofBody := getWithHeaders(c, base+path, map[string]string{
		"X-Server-Addr": "169.254.0.17:",
	}, timeout)

	return ami54085Verdict(plainStatus, spoofStatus, spoofBody), plainStatus, spoofStatus
}

// CheckCVE202454085 runs the published CVE-2024-54085 differential against a
// specific Redfish HTTPS port. It is exported so the check runner can test a
// MegaRAC OEM identified by non-Redfish evidence even when the service root is
// OEM-branded rather than AMI-branded.
func CheckCVE202454085(host string, port int, timeout time.Duration) (vuln bool, plain, spoof int) {
	client := insecureClient(nil, timeout)
	return probeAMI54085(client, baseURL(host, port), timeout)
}

// ami54085Verdict implements the differential decision for CVE-2024-54085 and
// is separated out so it can be unit-tested without a live BMC.
//
// A vulnerable box denies the anonymous request (401/403, or any non-200) but
// serves a genuine Redfish resource once the spoofed host-trust headers are
// injected. A patched box denies both; a box that serves the resource unauth
// (plain 200) is not this bug; a spoofed 200 that returns a login page or a
// non-Redfish body is not a bypass either.
func ami54085Verdict(plainStatus, spoofStatus int, spoofBody []byte) bool {
	if plainStatus == 200 {
		return false
	}
	if spoofStatus != 200 {
		return false
	}
	return looksLikeRedfish(spoofBody) && !looksLikeLogin(spoofBody)
}

// getWithHeaders performs a GET with extra request headers and returns the
// status and (bounded) body.
func getWithHeaders(c *http.Client, url string, headers map[string]string, timeout time.Duration) (int, []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, nil
	}
	for k, v := range headers {
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

// looksLikeRedfish reports whether a body is a genuine Redfish resource rather
// than an HTML login/error page.
func looksLikeRedfish(b []byte) bool {
	return bytes.Contains(b, []byte("@odata.type")) ||
		bytes.Contains(b, []byte("@odata.id")) ||
		bytes.Contains(b, []byte("\"Members\""))
}

// looksLikeLogin reports whether a body is an HTML login/redirect page that a
// BMC may return with a 200 status in lieu of a 401.
func looksLikeLogin(b []byte) bool {
	l := bytes.ToLower(b)
	return bytes.Contains(l, []byte("<html")) ||
		bytes.Contains(l, []byte("<!doctype")) ||
		bytes.Contains(l, []byte("login"))
}

func probeDellFW(c *http.Client, base string, timeout time.Duration) (string, bool) {
	status, body, _, err := httpGet(c, base+"/data?get=fwVersion", timeout)
	if err != nil || status != 200 {
		return "", false
	}
	return extractDellFwVersion(string(body))
}

// extractDellFwVersion pulls the value out of <fwVersion>...</fwVersion>. The
// closing tag is searched relative to the opening tag: a global search for
// </fwVersion> returns the wrong span (or nothing, failing the b>a guard) when
// the response contains a stray leading </fwVersion> before the real value.
func extractDellFwVersion(s string) (string, bool) {
	i := strings.Index(s, "<fwVersion>")
	if i < 0 {
		return "", false
	}
	a := i + len("<fwVersion>")
	j := strings.Index(s[a:], "</fwVersion>")
	if j < 0 {
		return "", false
	}
	return s[a : a+j], true
}
