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

type ServiceRoot struct {
	ID             string `json:"Id"`
	Name           string `json:"Name"`
	RedfishVersion string `json:"RedfishVersion"`
	UUID           string `json:"UUID"`
	Vendor         string `json:"Vendor"`
	Product        string `json:"Product"`

	Oem   OemBlock       `json:"Oem"`
	Links map[string]any `json:"Links"`
}

type OemBlock struct {
	Dell       map[string]any
	HPE        map[string]any
	Hpe        map[string]any
	Lenovo     map[string]any
	Supermicro map[string]any
	Ami        map[string]any

	Raw map[string]json.RawMessage
}

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

var oemVendorPriority = []string{
	"dell", "hpe", "hp", "lenovo", "supermicro", "cisco", "fujitsu", "ts_fujitsu",
	"huawei", "intel", "intel_rackscale", "inspur", "oracle", "nvidia", "quanta",
	"tyan", "gigabyte", "asus", "ami", "openbmc",
}

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

type Result struct {
	Host           string
	URL            string
	Status         int
	ServiceRoot    *ServiceRoot
	ServerHeader   string
	Vendor         string
	AMICVE         bool
	AMICVEPlain    int
	AMICVESpoof    int
	DellFWVersion  string
	ILOGeneration  int
	RawRoot        []byte
	LeakyEndpoints []string

	Manufacturer string
	Model        string
}

func (r *Result) IsRedfish() bool {
	if r == nil || r.Status < 200 || r.Status >= 500 {
		return false
	}
	return looksLikeRedfish(r.RawRoot) && !looksLikeLogin(r.RawRoot)
}

func Probe(host string, timeout time.Duration) (*Result, error) {
	client := httpx.Client(timeout)
	base := "https://" + netaddr.URLAuthority(host)
	r := &Result{Host: host}

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

	if r.Vendor == "" && r.IsRedfish() {
		if v, mfr, model := deepVendorUnauth(client, base, timeout); v != "" {
			r.Vendor = v
			r.Manufacturer = mfr
			r.Model = model
		}
	}

	if r.Vendor == "ami" || strings.Contains(strings.ToLower(r.ServerHeader), "megarac") {
		r.AMICVE, r.AMICVEPlain, r.AMICVESpoof = probeAMI54085(client, base, timeout)
	}

	if r.Vendor == "dell" {
		if s, ok := probeDellFW(client, base, timeout); ok {
			r.DellFWVersion = s
			r.LeakyEndpoints = append(r.LeakyEndpoints, "/data?get=fwVersion")
		}
	}

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

	if v, _ := sr.OemVendor(); v != "" {
		return v
	}

	if sr.Oem.Ami != nil || hasAMIServiceRootMarker(sr) {
		return "ami"
	}
	low := strings.ToLower(sr.Vendor + " " + sr.Product + " " + sr.Name + " " + sr.ID + " " + server)
	if v := vendorFromTokens(low); v != "" {
		return v
	}

	if v, _, ok := bmcfp.Match(bmcfp.HTTPServerHeader, server); ok {
		return v
	}
	return ""
}

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

func hasAMIServiceRootMarker(sr *ServiceRoot) bool {
	low := strings.ToLower(sr.Vendor + " " + sr.Product + " " + sr.Name + " " + sr.ID)
	return strings.Contains(low, "megarac") ||
		strings.Contains(low, "asrock") ||
		strings.Contains(low, "ami")
}

func probeAMI54085(c *http.Client, base string, timeout time.Duration) (vuln bool, plain, spoof int) {

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

func CheckCVE202454085(host string, port int, timeout time.Duration) (vuln bool, plain, spoof int) {
	client := insecureClient(nil, timeout)
	return probeAMI54085(client, baseURL(host, port), timeout)
}

func ami54085Verdict(plainStatus, spoofStatus int, spoofBody []byte) bool {
	if plainStatus == 200 {
		return false
	}
	if spoofStatus != 200 {
		return false
	}
	return looksLikeRedfish(spoofBody) && !looksLikeLogin(spoofBody)
}

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

func looksLikeRedfish(b []byte) bool {
	return bytes.Contains(b, []byte("@odata.type")) ||
		bytes.Contains(b, []byte("@odata.id")) ||
		bytes.Contains(b, []byte("\"Members\""))
}

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
