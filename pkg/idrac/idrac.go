// Package idrac implements Dell-specific HTTP fingerprinting and a small set of
// unauthenticated endpoints that can expose device data.
package idrac

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

var (
	reAboutFW  = regexp.MustCompile(`var\s+fwVer\s*=\s*"([^"]+)"`)
	reAboutGen = regexp.MustCompile(`(?i)Integrated Dell Remote Access Controller\s*(\d+)`)
)

// Info captures pre-auth facts from an iDRAC.
type Info struct {
	Host           string
	Generation     int // 6,7,8,9,10 (best guess)
	Version        string
	FWVersion      string
	ServiceTag     string // from GUID decode or /sysmgmt leak
	Model          string
	Hostname       string
	OEMHostname    string
	SysDesc        string
	Status         string
	TitleBar       string
	License        string
	ServerGen      string
	SystemModel    string
	SystemLockdown string
	ADEnabled      string
	SSOEnabled     string
	TFAEnabled     string
	Name           string
	IsOEMBranded   string
	ServerBanner   string
	Endpoints      []string // endpoints that returned >0 bytes unauth
	// DefaultCredKnown is true when the non-intrusive default-cred detector
	// (/data?get=defaultCred_inplace) answered pre-auth. iDRAC6 lacks this
	// warning logic, so a false here does not prove the credential is changed.
	DefaultCredKnown bool
	// DefaultCredInPlace is true when the box still ships root:calvin (only
	// meaningful when DefaultCredKnown is true).
	DefaultCredInPlace bool
}

// Probe hits several Dell-specific endpoints.
func Probe(host string, timeout time.Duration) (*Info, error) {
	return ProbeAt(host, 443, timeout)
}

// ProbeAt hits several Dell-specific endpoints on the given web port.
func ProbeAt(host string, port int, timeout time.Duration) (*Info, error) {
	// IdentifyClient raises the per-phase handshake ceiling to the whole-request
	// timeout so a slow BMC RSA handshake completes; for the small check-battery
	// timeout it is identical to httpx.Client (ceiling clamps to timeout/2).
	client := httpx.IdentifyClient(timeout)
	info := &Info{Host: host}
	base := baseURL(host, port)

	// 1. / index -- banner carries "iDRAC" generation.
	if st, body, hdr, err := httpGet(client, base+"/", timeout); err == nil && st == 200 {
		info.ServerBanner = hdr.Get("Server")
		info.Generation = guessGen(hdr.Get("Server"), string(body))
	}
	// 1a. /public/about.html (legacy iDRAC6/7 page) leaks firmware+generation.
	if st, body, _, err := httpGet(client, base+"/public/about.html", timeout); err == nil && st == 200 {
		if fw, gen, ok := parseAboutPage(string(body)); ok {
			info.Endpoints = append(info.Endpoints, "/public/about.html")
			if info.FWVersion == "" {
				info.FWVersion = fw
			}
			if gen != "" {
				info.Version = gen
				if n, _ := strconv.Atoi(gen); n > 0 {
					info.Generation = n
				}
			}
		}
	}
	// 2. /data?get=fwVersion (iDRAC6/7 unauth leak).
	if st, body, _, err := httpGet(client, base+"/data?get=fwVersion", timeout); err == nil && st == 200 {
		info.FWVersion = extractTag(string(body), "fwVersion")
		info.Endpoints = append(info.Endpoints, "/data?get=fwVersion")
	}
	// 2a. /data?get=defaultCred_inplace -- sessionless allowlisted endpoint on
	// iDRAC7/8. Non-intrusive default-cred detector: reveals whether root:calvin
	// is still in place without a login.
	if st, body, _, err := httpGet(client, base+"/data?get=defaultCred_inplace", timeout); err == nil && st == 200 {
		info.Endpoints = append(info.Endpoints, "/data?get=defaultCred_inplace")
		if known, inplace := parseDefaultCredInPlace(string(body)); known {
			info.DefaultCredKnown = true
			info.DefaultCredInPlace = inplace
		}
	}
	// 2b. /session?aimGetProp=... -- sessionless iDRAC7-era metadata endpoint.
	if st, body, _, err := httpGet(client, base+"/session?aimGetProp=hostname,gui_str_title_bar,OEMHostName,fwVersion,sysDesc,status", timeout); err == nil && st == 200 {
		if aim, ok := parseAIMBody(body); ok {
			info.Endpoints = append(info.Endpoints, "/session?aimGetProp=hostname,gui_str_title_bar,OEMHostName,fwVersion,sysDesc,status")
			if info.TitleBar == "" {
				info.TitleBar = aim.GUITitleBar
			}
			if info.Hostname == "" {
				info.Hostname = aim.Hostname
			}
			if info.OEMHostname == "" {
				info.OEMHostname = aim.OEMHostname
			}
			if info.FWVersion == "" {
				info.FWVersion = aim.FWVersion
			}
			if info.SysDesc == "" {
				info.SysDesc = aim.SysDesc
			}
			if info.Status == "" {
				info.Status = aim.Status
			}
			if info.Generation == 0 {
				info.Generation = 7
			}
			if info.Version == "" {
				info.Version = "7"
			}
		}
	}
	// 3. /data/login -- iDRAC legacy login challenge (often leaks service tag).
	if st, body, _, err := httpGet(client, base+"/data/login", timeout); err == nil && st == 200 {
		info.Endpoints = append(info.Endpoints, "/data/login")
		if tag := extractTag(string(body), "smServiceTag"); tag != "" {
			info.ServiceTag = tag
		}
	}
	// 4. /sysmgmt/2015/bmc/info -- iDRAC9+ metadata endpoint (JSON on 200).
	if st, body, hdr, err := httpGet(client, base+"/sysmgmt/2015/bmc/info", timeout); err == nil {
		if st == 200 || st == 401 {
			info.Endpoints = append(info.Endpoints, "/sysmgmt/2015/bmc/info")
			if info.Model == "" {
				info.Model = hdr.Get("Dell-Product")
			}
			if st == 200 {
				if bmc, ok := parseBMCInfo(body); ok {
					if info.ADEnabled == "" {
						info.ADEnabled = bmc.ADEnabled
					}
					if info.TitleBar == "" {
						info.TitleBar = bmc.GUITitleBar
					}
					if info.FWVersion == "" {
						info.FWVersion = bmc.FwVersion
					}
					if info.IsOEMBranded == "" {
						info.IsOEMBranded = bmc.IsOEMBranded
					}
					if info.License == "" {
						info.License = bmc.License
					}
					if info.SSOEnabled == "" {
						info.SSOEnabled = bmc.SSOEnabled
					}
					if info.ServerGen == "" {
						info.ServerGen = bmc.ServerGen
					}
					if info.SystemLockdown == "" {
						info.SystemLockdown = bmc.SystemLockdown
					}
					if info.SystemModel == "" {
						info.SystemModel = bmc.SystemModelName
					}
					if info.TFAEnabled == "" {
						info.TFAEnabled = bmc.TFAEnabled
					}
					if info.Name == "" {
						info.Name = bmc.IDRACName
					}
					if info.Model == "" {
						info.Model = bmc.SystemModelName
					}
					if info.Generation == 0 {
						info.Generation = 9
					}
					if info.Version == "" {
						info.Version = "9"
					}
				}
			}
		}
	}
	// 5. /cgi-bin/login (very old iDRAC6/7) -- used by CVE-2018-1207 shellshock.
	if st, _, _, err := httpGet(client, base+"/cgi-bin/login", timeout); err == nil && st != 404 {
		info.Endpoints = append(info.Endpoints, "/cgi-bin/login")
	}
	// 6. Redfish SessionService typically returns product info even unauth.
	if st, body, _, err := httpGet(client, base+"/redfish/v1/Managers/iDRAC.Embedded.1", timeout); err == nil {
		if st == 200 || st == 401 {
			info.Endpoints = append(info.Endpoints, "/redfish/v1/Managers/iDRAC.Embedded.1")
			// Redfish + the iDRAC.Embedded.1 manager only proves iDRAC7 or newer
			// (iDRAC6 has no Redfish); iDRAC7/8/9 all expose this exact path, so we
			// cannot infer generation 9 from it. Leaving Generation at 0 (unknown)
			// rather than over-claiming "9" avoids mislabeling an iDRAC7/8 and, in
			// turn, attributing generation-9-specific CVEs to it. The reliable
			// generation signal is the Server-header banner parsed in guessGen().
			_ = body
		}
	}
	return info, nil
}

func baseURL(host string, port int) string {
	return netaddr.URL("https", host, port, "")
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	return resp.StatusCode, body, resp.Header, nil
}

func guessGen(server, body string) int {
	low := strings.ToLower(server + " " + body)
	switch {
	case strings.Contains(low, "idrac10"):
		return 10
	case strings.Contains(low, "idrac9"):
		return 9
	case strings.Contains(low, "idrac8"):
		return 8
	case strings.Contains(low, "idrac7"):
		return 7
	case strings.Contains(low, "idrac6"):
		return 6
	}
	return 0
}

func extractTag(s, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	a := strings.Index(s, open)
	if a < 0 {
		return ""
	}
	a += len(open)
	b := strings.Index(s[a:], close)
	if b < 0 {
		return ""
	}
	return s[a : a+b]
}

// parseDefaultCredInPlace interprets a /data?get=defaultCred_inplace response.
// The endpoint returns XML like <root><defaultCred_inplace>1</...></root>.
// known reports whether the tag was present; inplace reports whether the
// default root:calvin credential is still active.
func parseDefaultCredInPlace(body string) (known, inplace bool) {
	v := extractTag(body, "defaultCred_inplace")
	if v == "" {
		return false, false
	}
	v = strings.TrimSpace(strings.ToLower(v))
	return true, v == "1" || v == "true"
}

// parseAIMProp extracts a single property value from a /session?aimGetProp=<p>
// response, which is XML such as <aimGetProp><fwVersionFull>...</...>.
func parseAIMProp(body, prop string) string {
	if aim, ok := parseAIMBody([]byte(body)); ok {
		switch prop {
		case "fwVersionFull", "fwVersion":
			if aim.FWVersion != "" {
				return aim.FWVersion
			}
		case "hostname":
			return aim.Hostname
		case "OEMHostName":
			return aim.OEMHostname
		case "sysDesc":
			return aim.SysDesc
		case "status":
			return aim.Status
		case "gui_str_title_bar":
			return aim.GUITitleBar
		}
	}
	return strings.TrimSpace(extractTag(body, prop))
}

type aimFields struct {
	Hostname    string
	GUITitleBar string
	OEMHostname string
	FWVersion   string
	SysDesc     string
	Status      string
}

func parseAIMBody(body []byte) (aimFields, bool) {
	var jsonBody struct {
		AimGetProp struct {
			Hostname    string `json:"hostname"`
			GUITitleBar string `json:"gui_str_title_bar"`
			OEMHostname string `json:"OEMHostName"`
			FWVersion   string `json:"fwVersion"`
			FWVersion2  string `json:"fwVersionFull"`
			SysDesc     string `json:"sysDesc"`
			Status      string `json:"status"`
		} `json:"aimGetProp"`
	}
	if err := json.Unmarshal(body, &jsonBody); err == nil {
		fw := strings.TrimSpace(jsonBody.AimGetProp.FWVersion)
		if fw == "" {
			fw = strings.TrimSpace(jsonBody.AimGetProp.FWVersion2)
		}
		out := aimFields{
			Hostname:    strings.TrimSpace(jsonBody.AimGetProp.Hostname),
			GUITitleBar: strings.TrimSpace(jsonBody.AimGetProp.GUITitleBar),
			OEMHostname: strings.TrimSpace(jsonBody.AimGetProp.OEMHostname),
			FWVersion:   fw,
			SysDesc:     strings.TrimSpace(jsonBody.AimGetProp.SysDesc),
			Status:      strings.TrimSpace(jsonBody.AimGetProp.Status),
		}
		if out.Hostname != "" || out.GUITitleBar != "" || out.OEMHostname != "" || out.FWVersion != "" || out.SysDesc != "" || out.Status != "" {
			return out, true
		}
	}
	// Legacy XML fallback.
	out := aimFields{
		Hostname:    strings.TrimSpace(extractTag(string(body), "hostname")),
		GUITitleBar: strings.TrimSpace(extractTag(string(body), "gui_str_title_bar")),
		OEMHostname: strings.TrimSpace(extractTag(string(body), "OEMHostName")),
		FWVersion:   strings.TrimSpace(extractTag(string(body), "fwVersion")),
		SysDesc:     strings.TrimSpace(extractTag(string(body), "sysDesc")),
		Status:      strings.TrimSpace(extractTag(string(body), "status")),
	}
	if out.FWVersion == "" {
		out.FWVersion = strings.TrimSpace(extractTag(string(body), "fwVersionFull"))
	}
	if out.Hostname != "" || out.GUITitleBar != "" || out.OEMHostname != "" || out.FWVersion != "" || out.SysDesc != "" || out.Status != "" {
		return out, true
	}
	return aimFields{}, false
}

type bmcFields struct {
	ADEnabled       string `json:"ADEnabled"`
	GUITitleBar     string `json:"GUITitleBar"`
	FwVersion       string `json:"FwVer"`
	IsOEMBranded    string `json:"IsOEMBranded"`
	License         string `json:"License"`
	SSOEnabled      string `json:"SSOEnabled"`
	ServerGen       string `json:"ServerGen"`
	SystemLockdown  string `json:"SystemLockdown"`
	SystemModelName string `json:"SystemModelName"`
	TFAEnabled      string `json:"TFAEnabled"`
	IDRACName       string `json:"iDRACName"`
}

func parseBMCInfo(body []byte) (bmcFields, bool) {
	var doc struct {
		Attributes bmcFields `json:"Attributes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return bmcFields{}, false
	}
	b := doc.Attributes
	if b.ADEnabled != "" || b.GUITitleBar != "" || b.FwVersion != "" || b.IsOEMBranded != "" || b.License != "" || b.SSOEnabled != "" || b.ServerGen != "" || b.SystemLockdown != "" || b.SystemModelName != "" || b.TFAEnabled != "" || b.IDRACName != "" {
		return b, true
	}
	return bmcFields{}, false
}

func parseAboutPage(body string) (fwVersion, generation string, ok bool) {
	if m := reAboutFW.FindStringSubmatch(body); len(m) == 2 {
		fwVersion = strings.TrimSpace(m[1])
	}
	if m := reAboutGen.FindStringSubmatch(body); len(m) == 2 {
		generation = strings.TrimSpace(m[1])
	}
	return fwVersion, generation, fwVersion != "" || generation != ""
}

// ParseXMLData parses a Dell /data?get=... RackHMC-style response.
func ParseXMLData(body []byte) (map[string]string, error) {
	type elem struct {
		XMLName xml.Name
		Value   string `xml:",chardata"`
	}
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	out := map[string]string{}
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if se, ok := tok.(xml.StartElement); ok {
			var e elem
			if err := dec.DecodeElement(&e, &se); err == nil {
				out[se.Name.Local] = strings.TrimSpace(e.Value)
			}
		}
	}
	return out, nil
}
