package check

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/creds"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
	"github.com/runZeroInc/oobscan/pkg/snmp"
	"github.com/runZeroInc/oobscan/pkg/ssdp"
	"github.com/runZeroInc/oobscan/pkg/ssh"
)

func init() {
	Register(Check{
		Name:        "ssdp.libupnp",
		Description: "libupnp / UPnP SDK version disclosed via the SSDP Server header (informational)",
		Category:    "ssdp",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runLibUPnP,
	})
	Register(Check{
		Name:        "ssdp.redfishRest",
		Description: "Redfish REST service advertised over SSDP pre-auth",
		Category:    "ssdp",
		Applies:     Applicability{Classes: []engine.DeviceClass{engine.ClassBMC}},
		Enabled:     true,
		Run:         runSSDPRedfishRest,
	})
	Register(Check{
		Name:        "ssdp.hpe.federation",
		Description: "HPE iLO Federation SSDP service + pre-auth /upnp/BasicDevice.xml identity leak",
		Category:    "ssdp",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runHPEFederationSSDP,
	})
	Register(Check{
		Name:        "snmp",
		Description: "SNMP v1/v2c default communities + v3 engine discovery and factory-default USM credentials",
		Category:    "snmp",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runSNMP,
	})
	Register(Check{
		Name:        "ssh.exposure",
		Description: "SSH version/banner + weak-algorithm enumeration on every target (default-credential login when online)",
		Category:    "ssh",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runSSHExposure,
	})
	Register(Check{
		Name:        "http.smc.psBlock",
		Description: "Supermicro IPMI cleartext credential store on TCP/49152 (/PSBlock)",
		Category:    "creds",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runSMCPSBlock,
	})
}

func runLibUPnP(ctx context.Context, t *engine.Target) []engine.Finding {
	res, err := ssdp.UnicastSearch(t.Host, "upnp:rootdevice", t.Timeout)
	if err != nil || res == nil || res.Server == "" {
		return nil
	}
	t.SetEvidence("ssdp", res)
	sdk, ver := upnpSDK(res.Server)
	if sdk == "" {
		return nil
	}
	return []engine.Finding{{
		Check: "ssdp.libupnp", Category: "ssdp", Risk: "info",
		Port: 1900, Transport: "udp", Protocol: "ssdp",
		Fields: engine.F("sdk", sdk, "version", ver, "server", res.Server),
	}}
}

func runSSDPRedfishRest(ctx context.Context, t *engine.Target) []engine.Finding {
	res, err := ssdp.UnicastSearch(t.Host, "urn:dmtf-org:service:redfish-rest:1", t.Timeout)
	if err != nil || res == nil {
		return nil
	}
	if f, ok := ssdpRedfishFields(res); ok {
		t.SetEvidence("ssdp", res)
		return []engine.Finding{{
			Check: "ssdp.redfishRest", Category: "ssdp", Risk: "low",
			Port: 1900, Transport: "udp", Protocol: "ssdp",
			Fields: f,
		}}
	}
	return nil
}

func runHPEFederationSSDP(ctx context.Context, t *engine.Target) []engine.Finding {
	res, err := ssdp.UnicastSearch(t.Host, "urn:www-hp-com:service:Federation:2", t.Timeout)
	if err != nil || res == nil {
		return nil
	}
	if !strings.Contains(strings.ToLower(strings.TrimSpace(res.ST)), "urn:www-hp-com:service:federation:2") {
		return nil
	}
	loc := strings.TrimSpace(res.Location)
	if loc == "" {
		return nil
	}
	client := insecureWebClient(min(t.Timeout, 5*time.Second))
	reqURL := loc
	if u, e := url.Parse(loc); e == nil {
		if u.Host == "" {
			u.Host = t.Host
		}
		if u.Scheme == "" {
			u.Scheme = "http"
		}
		reqURL = u.String()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	bd, ok := parseHPEBasicDevice(body)
	if !ok {
		return nil
	}
	proof := proofKV("manufacturer", bd.Manufacturer, "model", bd.ModelDescription, "serialNumber", bd.SerialNumber)
	return []engine.Finding{{
		Check: "ssdp.hpe.federation", Category: "ssdp", Risk: "medium",
		Port: 1900, Transport: "udp", Protocol: "ssdp",
		Fields: engine.F(
			"st", res.ST,
			"location", loc,
			"server", res.Server,
			"manufacturer", bd.Manufacturer,
			"modelDescription", bd.ModelDescription,
			"modelNumber", bd.ModelNumber,
			"serial", bd.SerialNumber,
			"udn", bd.UDN,
			"proof", proof,
		),
	}}
}

type hpeBasicDevice struct {
	Manufacturer string `xml:"device>manufacturer"`
	ModelDesc    string `xml:"device>modelDescription"`
	ModelNum     string `xml:"device>modelNumber"`
	Serial       string `xml:"device>serialNumber"`
	UDNVal       string `xml:"device>UDN"`
	Services     []struct {
		Type string `xml:"serviceType"`
	} `xml:"device>serviceList>service"`
}

type hpeBasicDeviceView struct {
	Manufacturer     string
	ModelDescription string
	ModelNumber      string
	SerialNumber     string
	UDN              string
}

func parseHPEBasicDevice(body []byte) (hpeBasicDeviceView, bool) {
	var x hpeBasicDevice
	if err := xml.Unmarshal(body, &x); err != nil {
		return hpeBasicDeviceView{}, false
	}
	view := hpeBasicDeviceView{
		Manufacturer:     strings.TrimSpace(x.Manufacturer),
		ModelDescription: strings.TrimSpace(x.ModelDesc),
		ModelNumber:      strings.TrimSpace(x.ModelNum),
		SerialNumber:     strings.TrimSpace(x.Serial),
		UDN:              strings.TrimSpace(x.UDNVal),
	}
	if view.Manufacturer == "" && view.ModelDescription == "" && view.SerialNumber == "" {
		return hpeBasicDeviceView{}, false
	}
	if len(x.Services) > 0 {
		federation := false
		for _, service := range x.Services {
			if strings.Contains(strings.ToLower(strings.TrimSpace(service.Type)), "federation") {
				federation = true
				break
			}
		}
		if !federation {
			return hpeBasicDeviceView{}, false
		}
	}
	return view, true
}

func ssdpRedfishFields(res *ssdp.Result) (engine.Fields, bool) {
	if res == nil {
		return nil, false
	}
	st := strings.ToLower(strings.TrimSpace(res.ST))
	if !strings.Contains(st, "redfish-rest") {
		return nil, false
	}
	loc := strings.TrimSpace(res.Location)
	if loc == "" {
		return nil, false
	}
	return engine.F(
		"st", res.ST,
		"location", loc,
		"server", res.Server,
		"usn", res.USN), true
}

func runSNMP(ctx context.Context, t *engine.Target) []engine.Finding {
	const port = 161
	var out []engine.Finding

	if v, ok := t.Evidenced("snmp"); ok {
		if r, ok := v.(*snmp.Result); ok && r != nil {
			risk, access := "medium", "readOnly"
			proof := proofKV("operation", "read", "community", "public", "access", "readOnly")
			if !t.DisableLogins {
				if write, err := verifySNMPWrite(t.Host, port, "public", r.Version, min(t.Timeout, 1500*time.Millisecond)); err == nil && write != nil {
					risk, access = "high", "readWrite"
					proof = proofKV("operation", "setSameValue", "community", "public", "oid", write.OID, "access", "readWrite")
				}
			}
			out = append(out, engine.Finding{
				Check: "snmp.defaultCreds", Category: "creds", Risk: risk,
				Port: port, Transport: "udp", Protocol: "snmp",
				Fields: engine.F("version", snmpVerName(r.Version), "pass", "public",
					"access", access, "sysdescr", truncateStr(r.SysDescr, 120),
					"proof", proof),
			})
		}
	}

	if v, ok := t.Evidenced("snmp.hostinv"); ok {
		if inv, ok := v.(*snmp.HostInventory); ok && inv != nil && !inv.Empty() {
			risk := "medium"
			if len(inv.ManagedIPs) > 0 {
				risk = "high"
			}
			fields := engine.F("community", inv.Community,
				"version", snmpVerName(inv.Version),
				"arpEntries", fmt.Sprintf("%d", len(inv.ARP)),
				"serverNICs", fmt.Sprintf("%d", len(inv.ServerNICs)))
			if len(inv.ManagedIPs) > 0 {
				fields = append(fields, engine.F("managedIPs", strings.Join(inv.ManagedIPs, ","))...)
			}
			if inv.ServiceTag != "" {
				fields = append(fields, engine.F("serviceTag", inv.ServiceTag)...)
			}
			if inv.Model != "" {
				fields = append(fields, engine.F("model", inv.Model)...)
			}
			if inv.HostOS != "" {
				fields = append(fields, engine.F("hostOS", inv.HostOS)...)
			}
			fields = append(fields, engine.F("proof", proofKV(
				"operation", "read",
				"community", inv.Community,
				"arp", snmp.OIDIPNetToMediaPhys,
				"serverNICs", snmp.OIDDellNICMAC))...)
			out = append(out, engine.Finding{
				Check: "snmp.hostDisclosure", Category: "snmp", Risk: risk,
				Port: port, Transport: "udp", Protocol: "snmp",
				Fields: fields,
			})
		}
	}

	if v, ok := t.Evidenced("snmp.private"); ok {
		if r, ok := v.(*snmp.Result); ok && r != nil {
			risk, access := "medium", "readOnly"
			proof := proofKV("operation", "read", "community", "private", "access", "readOnly")
			if !t.DisableLogins {
				if write, err := verifySNMPWrite(t.Host, port, "private", r.Version, min(t.Timeout, 1500*time.Millisecond)); err == nil && write != nil {
					risk, access = "high", "readWrite"
					proof = proofKV("operation", "setSameValue", "community", "private", "oid", write.OID, "access", "readWrite")
				}
			}
			out = append(out, engine.Finding{
				Check: "snmp.defaultCreds", Category: "creds", Risk: risk,
				Port: port, Transport: "udp", Protocol: "snmp",
				Fields: engine.F("version", snmpVerName(r.Version), "pass", "private",
					"access", access, "sysdescr", truncateStr(r.SysDescr, 120),
					"proof", proof),
			})
		}
	}

	if v, ok := t.Evidenced("snmpv3"); ok {
		if v3, ok := v.(*snmp.Result); ok && v3 != nil {
			var hit *snmpV3Hit
			if !t.DisableLogins {
				creds := snmpV3Candidates(t)
				hit = tryV3CredsFn(ctx, t.Host, port, creds, min(t.Timeout, 1500*time.Millisecond))
			}
			v3Fields := engine.F(
				"engineId", v3.EngineID,
				"engineBoots", fmt.Sprintf("%d", v3.EngineBoots),
			)

			if info, derr := snmp.DecodeEngineIDHex(v3.EngineID); derr == nil && info.Enterprise != 0 {
				v3Fields = append(v3Fields, engine.Field{Key: "engineIdEnterprise", Val: fmt.Sprintf("%d", info.Enterprise)})
				if info.Vendor != "" {
					v3Fields = append(v3Fields, engine.Field{Key: "engineIdVendor", Val: info.Vendor})
				}
				if info.Suffix != "" {
					v3Fields = append(v3Fields, engine.Field{Key: "engineIdSuffix", Val: info.Suffix})
				}
			}
			if hit != nil {
				v3Fields = append(v3Fields,
					engine.Field{Key: "defaultCreds", Val: hit.cred.User + ":" + snmpV3Secret(hit.cred)},
					engine.Field{Key: "defaultCredentialProfile", Val: hit.cred.Name},
				)
			}
			out = append(out, engine.Finding{
				Check: "snmp.v3", Category: "snmp", Risk: "info",
				Port: port, Transport: "udp", Protocol: "snmp",
				Fields: v3Fields,
			})
			if hit != nil {

				risk, access := "medium", "readOnly"
				proof := proofKV("operation", "read", "username", hit.cred.User, "level", hit.res.V3Level, "access", "readOnly")
				if write, err := verifySNMPV3Write(t.Host, port, hit.cred, min(t.Timeout, 1500*time.Millisecond)); err == nil && write != nil {
					risk, access = "high", "readWrite"
					proof = proofKV("operation", "setSameValue", "username", hit.cred.User, "oid", write.OID, "access", "readWrite")
				}
				var cve []string
				if hit.cred.Name == "huawei-usm-customization" || hit.cred.Name == "huawei-usm-community" {
					cve = []string{"CVE-2026-65198"}
				}
				out = append(out, engine.Finding{
					Check: "snmp.v3.defaultCreds", Category: "creds", Risk: risk, CVE: cve,
					Port: port, Transport: "udp", Protocol: "snmp",
					Fields: engine.F("username", hit.cred.User, "password", snmpV3Secret(hit.cred), "profile", hit.cred.Name,
						"level", hit.res.V3Level, "access", access, "sysdescr", truncateStr(hit.res.SysDescr, 120),
						"proof", proof),
				})
			}
		}
	}

	if !t.DisableLogins {
		_, snmpUp := t.Evidenced("snmp")
		_, v3Up := t.Evidenced("snmpv3")
		if snmpUp || v3Up {
			vend := identityVendor(t)
			for _, dc := range snmp.DefaultCommunities {

				if dc.Vendor != "*" && !strings.EqualFold(dc.Vendor, vend) {
					continue
				}
				for _, ver := range []int{1, 0} {
					r, err := snmp.Probe(t.Host, port, dc.Community, ver, min(t.Timeout, 1500*time.Millisecond))
					if err != nil || r == nil || !r.Responded {
						continue
					}
					risk, access := "medium", "readOnly"
					proof := proofKV("operation", "read", "community", dc.Community, "access", "readOnly")
					if dc.Access == "rw" {
						if write, err := verifySNMPWrite(t.Host, port, dc.Community, r.Version, min(t.Timeout, 1500*time.Millisecond)); err == nil && write != nil {
							risk, access = "high", "readWrite"
							proof = proofKV("operation", "setSameValue", "community", dc.Community, "oid", write.OID, "access", "readWrite")
						}
					}
					vlabel := dc.Vendor
					if vlabel == "*" {
						if vlabel = vend; vlabel == "" {
							vlabel = "unknown"
						}
					}
					out = append(out, engine.Finding{
						Check: "snmp.vendorCommunity", Category: "creds", Risk: risk,
						Port: port, Transport: "udp", Protocol: "snmp",
						Fields: engine.F("version", snmpVerName(r.Version), "community", dc.Community,
							"vendor", vlabel, "access", access, "sysdescr", truncateStr(r.SysDescr, 120),
							"proof", proof),
					})
					break
				}
			}
		}
	}

	return out
}

var verifySNMPWrite = snmp.VerifyWrite

var verifySNMPV3Write = snmp.VerifyWriteV3

func snmpCredentialVendor(t *engine.Target) string {

	known := func(v string) bool {
		if v == "" {
			return false
		}
		for _, c := range snmp.DefaultV3Creds {
			if strings.EqualFold(c.Vendor, v) {
				return true
			}
		}
		for _, c := range snmp.LocalizedV3Creds {
			if strings.EqualFold(c.Vendor, v) {
				return true
			}
		}
		return false
	}
	if vendor := identityVendor(t); known(vendor) {
		return vendor
	}
	for _, evidence := range []string{"snmp", "snmp.private"} {
		if value, ok := t.Evidenced(evidence); ok {
			if result, ok := value.(*snmp.Result); ok && result != nil && known(result.VendorGuess) {
				return result.VendorGuess
			}
		}
	}
	return ""
}

type snmpV3Hit struct {
	cred snmp.V3Cred
	res  *snmp.Result
}

func snmpV3Candidates(t *engine.Target) []snmp.V3Cred {
	vendor := snmpCredentialVendor(t)
	creds := snmp.DefaultV3CredsWithLocalized(vendor)
	if c, ok := parseOperatorLocalizedKey(t.SNMPV3LocalizedKey); ok {
		creds = append([]snmp.V3Cred{c}, creds...)
	}
	return creds
}

func parseOperatorLocalizedKey(spec string) (snmp.V3Cred, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return snmp.V3Cred{}, false
	}
	parts := strings.Split(spec, ":")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return snmp.V3Cred{}, false
	}
	c := snmp.V3Cred{Name: "operator-localized", User: parts[0], AuthProto: "SHA256", AuthKeyHex: parts[1]}
	if len(parts) >= 3 && parts[2] != "" {
		c.PrivProto, c.PrivKeyHex = "AES", parts[2]
	}
	return c, true
}

func snmpV3Secret(c snmp.V3Cred) string {
	if c.AuthPass != "" {
		return c.AuthPass
	}
	if c.AuthKeyHex != "" {
		return "localizedKey=" + c.AuthKeyHex
	}
	return ""
}

var tryV3CredsFn = tryV3Creds

func tryV3Creds(ctx context.Context, host string, port int, creds []snmp.V3Cred, per time.Duration) *snmpV3Hit {
	for _, c := range creds {
		if ctx.Err() != nil {
			return nil
		}
		if r, ok := snmp.TryV3(host, port, c, per); ok {
			return &snmpV3Hit{cred: c, res: r}
		}
	}
	return nil
}

func snmpVerName(v int) string {
	switch v {
	case 0:
		return "v1"
	case 1:
		return "v2c"
	default:
		return "v3"
	}
}

var sshProbePorts = []int{22, 2222}

func runSSHExposure(ctx context.Context, t *engine.Target) []engine.Finding {
	banner := ""
	if v, ok := t.Evidenced("ssh.banner"); ok {
		banner, _ = v.(string)
	}

	sshPort := 22
	if v, ok := t.Evidenced("ssh.port"); ok {
		if p, ok2 := v.(int); ok2 && p > 0 {
			sshPort = p
		}
	}
	if banner == "" {
		for _, p := range sshProbePorts {
			if b, _ := ssh.Banner(t.Host, p, t.Timeout); b != "" {
				banner, sshPort = b, p
				break
			}
		}
	}
	if banner == "" {
		return nil
	}
	t.SetEvidence("ssh.banner", banner)

	product, _, _ := ssh.FingerprintBanner(banner)
	t.MarkOpen(sshPort, "tcp", "ssh")

	versionKV := []string{"product", sanitizeBanner(product), "banner", sanitizeBanner(banner)}
	var kexInfo *ssh.KexInfo
	if ki, err := ssh.Kex(t.Host, sshPort, t.Timeout); err == nil && ki != nil {
		kexInfo = ki
		if len(kexInfo.HostKeys) > 0 {
			versionKV = append(versionKV, "hostkeyTypes", strings.Join(kexInfo.HostKeys, ","))
		}
	}
	hostKeyTimeout := min(max(t.Timeout, 3*time.Second), 7*time.Second)
	cap, capErr := ssh.CaptureHostKeyEx(t.Host, sshPort, hostKeyTimeout)
	if capErr != nil {
		retryTimeout := max(hostKeyTimeout, 10*time.Second)
		cap, capErr = ssh.CaptureHostKeyEx(t.Host, sshPort, retryTimeout)
	}
	if capErr == nil {
		versionKV = append(versionKV,
			"hostkeyType", cap.KeyType,
			"hostkeyFingerprint", cap.Fingerprint,
			"bkhash", cap.BKHash,
		)
		if cap.BadKeyMatch {
			versionKV = append(versionKV,
				"bkKind", cap.BadKey.Kind,
				"bkVendor", cap.BadKey.Vendor,
				"bkProduct", cap.BadKey.Product,
			)
		}
	}

	var findings []engine.Finding
	findings = append(findings, engine.Finding{
		Check: "ssh.version", Category: "ssh", Risk: "info",
		Port: sshPort, Transport: "tcp", Protocol: "ssh",
		Fields: engine.F(versionKV...),
	})

	if kexInfo != nil {
		weak := kexInfo.WeakAlgos()
		var kv []string
		for _, cat := range []string{"kex", "cipher", "mac", "hostkey"} {
			if a := weak[cat]; len(a) > 0 {
				kv = append(kv, cat, strings.Join(a, ","))
			}
		}
		if len(kv) > 0 {
			findings = append(findings, engine.Finding{
				Check: "ssh.weakCrypto", Category: "ssh", Risk: "low",
				Fields: engine.F(kv...),
			})
		}
	}

	if !t.DisableLogins && isOOBDevice(t) {
		vendor := ""
		if t.Identity != nil {
			vendor = t.Identity.Vendor
		}
		pairs := credPairs(vendor, 6)
		if u, p, out, ok := ssh.TryDefaults(t.Host, sshPort, t.Timeout, pairs, len(pairs)); ok {
			findings = append(findings, engine.Finding{
				Check: "ssh.defaultCreds", Category: "creds", Risk: sshCredRisk(out),
				Fields: engine.F("user", u, "pass", p, "output", out, "access", sshAccessLevel(out)),
			})
		}
	}
	for i := range findings {
		if findings[i].Port == 0 {
			findings[i].Port, findings[i].Transport, findings[i].Protocol = sshPort, "tcp", "ssh"
		}
	}
	return findings
}

func isOOBDevice(t *engine.Target) bool {
	if t.Identity == nil {
		return false
	}
	return t.Identity.Vendor != "" || t.Identity.Class != engine.ClassUnknown
}

func runSMCPSBlock(ctx context.Context, t *engine.Target) []engine.Finding {
	client := httpx.Client(t.Timeout)
	for _, path := range []string{"/PSBlock", "/PSStore", "/IPMIdevicedesc.xml"} {
		url := netaddr.URL("http", t.Host, 49152, path)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if resp.StatusCode != 200 || len(body) == 0 {
			continue
		}
		if path == "/IPMIdevicedesc.xml" {
			fields, ok := smcDeviceDescFields(body)
			if !ok {
				continue
			}
			return []engine.Finding{{
				Check: "http.smc.deviceDesc", Category: "creds", Risk: "info",
				Port: 49152, Transport: "tcp", Protocol: "http",
				Fields: append(engine.F("path", path), fields...),
			}}
		}

		if !isPSBlockCredStore(body) {
			continue
		}

		fields := engine.F("path", path, "bytes", fmt.Sprintf("%d", len(body)),
			"sample", printablePrefix(body, 48))
		if creds := psblockStrings(body); creds != "" {
			fields = append(fields, engine.Field{Key: "recovered", Val: creds})
		}
		return []engine.Finding{{
			Check: "http.smc.psBlock", Category: "creds", Risk: "critical",
			Port: 49152, Transport: "tcp", Protocol: "http",
			Fields: append(fields, engine.Field{Key: "proof", Val: proofKV(
				"path", path,
				"bytes", fmt.Sprintf("%d", len(body)),
				"sample", printablePrefix(body, 48))}),
		}}
	}
	return nil
}

func isPSBlockCredStore(body []byte) bool {
	head := body
	if len(head) > 512 {
		head = head[:512]
	}
	low := strings.ToLower(string(head))
	if strings.Contains(low, "<html") || strings.Contains(low, "<head") ||
		strings.Contains(low, "not found") || strings.Contains(low, "<!doctype") {
		return false
	}

	return len(body) >= 256 && bytesContainsNUL(body)
}

func bytesContainsNUL(b []byte) bool { return strings.IndexByte(string(b), 0) >= 0 }

type smcDeviceDesc struct {
	XMLName xml.Name `xml:"root"`
	Spec    struct {
		Major string `xml:"major"`
		Minor string `xml:"minor"`
	} `xml:"specVersion"`
	Device struct {
		DeviceType       string `xml:"deviceType"`
		FriendlyName     string `xml:"friendlyName"`
		Manufacturer     string `xml:"manufacturer"`
		ManufacturerURL  string `xml:"manufacturerURL"`
		ModelDescription string `xml:"modelDescription"`
		ModelName        string `xml:"modelName"`
		ModelNumber      string `xml:"modelNumber"`
		ModelURL         string `xml:"modelURL"`
		SerialNumber     string `xml:"serialNumber"`
		UDN              string `xml:"UDN"`
		UPC              string `xml:"UPC"`
		PresentationURL  string `xml:"presentationURL"`
	} `xml:"device"`
}

func smcDeviceDescFields(body []byte) (engine.Fields, bool) {
	var desc smcDeviceDesc
	if err := xml.Unmarshal(body, &desc); err != nil {
		return nil, false
	}
	trim := strings.TrimSpace
	deviceType := trim(desc.Device.DeviceType)
	manufacturer := trim(desc.Device.Manufacturer)
	modelName := trim(desc.Device.ModelName)
	if deviceType == "" && manufacturer == "" && modelName == "" {
		return nil, false
	}
	major, minor := trim(desc.Spec.Major), trim(desc.Spec.Minor)
	specVersion := strings.Trim(strings.Join([]string{major, minor}, "."), ".")
	return engine.F(
		"specVersion", specVersion,
		"deviceType", deviceType,
		"friendlyName", trim(desc.Device.FriendlyName),
		"manufacturer", manufacturer,
		"manufacturerURL", trim(desc.Device.ManufacturerURL),
		"modelDescription", trim(desc.Device.ModelDescription),
		"modelName", modelName,
		"modelNumber", trim(desc.Device.ModelNumber),
		"modelURL", trim(desc.Device.ModelURL),
		"serialNumber", trim(desc.Device.SerialNumber),
		"udn", trim(desc.Device.UDN),
		"upc", trim(desc.Device.UPC),
		"presentationURL", trim(desc.Device.PresentationURL),
	), true
}

func psblockStrings(body []byte) string {
	var out []string
	var cur []byte
	flush := func() {
		if len(cur) >= 3 {
			out = append(out, string(cur))
		}
		cur = cur[:0]
	}
	for _, c := range body {
		if c >= 0x20 && c < 0x7f {
			cur = append(cur, c)
		} else {
			flush()
		}
	}
	flush()
	if len(out) > 8 {
		out = out[:8]
	}
	return strings.Join(out, ",")
}

func upnpSDK(server string) (name, version string) {
	for _, m := range []string{"Portable SDK for UPnP devices/", "Intel SDK for UPnP devices/"} {
		if _, after, ok := strings.Cut(server, m); ok {
			rest := after
			v := strings.FieldsFunc(rest, func(r rune) bool { return r == ' ' || r == ',' || r == '\r' || r == '\n' })
			if len(v) > 0 {
				return strings.TrimSuffix(m, "/"), v[0]
			}
			return strings.TrimSuffix(m, "/"), ""
		}
	}
	return "", ""
}

func versionLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var ai, bi int
		if i < len(as) {
			ai, _ = strconv.Atoi(strings.TrimRight(as[i], "abcdefghijklmnopqrstuvwxyz"))
		}
		if i < len(bs) {
			bi, _ = strconv.Atoi(bs[i])
		}
		if ai != bi {
			return ai < bi
		}
	}
	return false
}

func credPairs(vendor string, max int) [][2]string {
	seen := map[[2]string]bool{}
	var out [][2]string
	for _, c := range creds.CredsFor(vendor, creds.ClassSSH) {
		k := [2]string{c.Username, c.Password}
		if c.Username == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
		if len(out) >= max {
			break
		}
	}
	return out
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func printablePrefix(b []byte, n int) string {
	var sb strings.Builder
	for i := 0; i < len(b) && i < n; i++ {
		if b[i] >= 0x20 && b[i] < 0x7f {
			sb.WriteByte(b[i])
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

func init() {
	RegisterExplain("ssdp.libupnp", explainSSDPLibUPnP)
	RegisterExplain("snmp.defaultCreds", explainSNMPDefaultCreds)
	RegisterExplain("snmp.v3", explainSNMPV3Engine)
	RegisterExplain("snmp.v3.defaultCreds", explainSNMPV3DefaultCreds)
	RegisterExplain("ssh.exposure", explainSSHExposure)
	RegisterExplain("ssh.defaultCreds", explainSSHDefaultCreds)
	RegisterExplain("http.smc.psBlock", explainSMCPSBlock)
	RegisterExplain("ssdp.hpe.federation", explainHPEFederationSSDP)
}

func explainHPEFederationSSDP(host string, f engine.Finding) string {
	loc := explainField(f, "location")
	model := explainField(f, "modelDescription")
	serial := explainField(f, "serial")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nHPE iLO answered SSDP Federation service discovery and exposed pre-auth identity\n")
	b.WriteString("via `/upnp/BasicDevice.xml` (manufacturer/model/serial/UUID).\n")
	if model != "" || serial != "" {
		b.WriteString(fmt.Sprintf("\n**Model:** `%s`  **Serial:** `%s`\n", model, serial))
	}
	b.WriteString("\n**Validate:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("echo -ne 'M-SEARCH * HTTP/1.1\\r\\nHOST: %s:1900\\r\\nMAN: \"ssdp:discover\"\\r\\nMX: 2\\r\\nST: urn:www-hp-com:service:Federation:2\\r\\n\\r\\n' | nc -u -w2 %s 1900", host, host),
		fmt.Sprintf("curl -sk '%s'", loc),
	))
	return b.String()
}

func explainSSDPLibUPnP(host string, f engine.Finding) string {
	sdk := explainField(f, "sdk")
	ver := explainField(f, "version")
	server := explainField(f, "server")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nSSDP/UPnP Server header discloses the SDK name and version.\n")
	if sdk != "" {
		b.WriteString(fmt.Sprintf("\n**SDK:** `%s %s`  **Server string:** `%s`\n", sdk, ver, server))
	}
	b.WriteString("\n**Query via SSDP M-SEARCH:**\n")
	b.WriteString(explainSh(
		`echo -e "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n" | ` +
			fmt.Sprintf("nc -u -w2 %s 1900", host),
	))
	return b.String()
}

func explainSNMPDefaultCreds(host string, f engine.Finding) string {
	ver := explainField(f, "version")
	pass := explainField(f, "pass")
	access := explainField(f, "access")
	snmpVer := "2c"
	if ver == "v1" {
		snmpVer = "1"
	}
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nDevice accepts the default SNMP %s community `%s` (%s).\n", ver, pass, access))
	b.WriteString("\n**Enumerate the full MIB:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("snmpwalk -v%s -c %s %s system", snmpVer, pass, host),
		fmt.Sprintf("snmpwalk -v%s -c %s %s", snmpVer, pass, host),
	))
	b.WriteString(fmt.Sprintf("\n\n**Impact:** SNMP %s default community grants access to the full device MIB", ver))
	if access == "readWrite" {
		b.WriteString(" including write access (reconfiguration/reset)")
	}
	b.WriteString(".\n")
	return b.String()
}

func explainSNMPV3Engine(host string, f engine.Finding) string {
	engineID := explainField(f, "engineId")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nSNMPv3 engine discovered via unauthenticated engine-discovery probe.\n")
	if engineID != "" {
		b.WriteString(fmt.Sprintf("\n**Engine ID:** `%s`\n", engineID))
	}
	b.WriteString("\n**Test factory v3 credentials:**\n")
	b.WriteString(explainSh(fmt.Sprintf("oobscan scan --checks snmp %s", host)))
	return b.String()
}

func explainSNMPV3DefaultCreds(host string, f engine.Finding) string {
	user := explainField(f, "user")
	pass := explainField(f, "pass")
	level := explainField(f, "level")
	access := explainField(f, "access")
	if level == "" {
		level = "authPriv"
	}
	if access == "" {
		access = "readOnly"
	}
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nDevice accepted a factory-default SNMPv3 credential: user **%s**", user))
	if pass != "" {
		b.WriteString(fmt.Sprintf(", auth-password **%s**", pass))
	}
	b.WriteString(fmt.Sprintf(" (%s).\n", access))
	authArgs := fmt.Sprintf("-u %s", user)
	if pass != "" && strings.Contains(level, "auth") {
		authArgs += fmt.Sprintf(" -A %s -a MD5", pass)
	}
	if strings.Contains(level, "Priv") {
		authArgs += fmt.Sprintf(" -X %s -x DES", pass)
	}
	b.WriteString("\n**Validate:**\n")
	b.WriteString(explainSh(fmt.Sprintf("snmpwalk -v3 -l %s %s %s system", level, authArgs, host)))
	b.WriteString("\n\n**Impact:** Authenticated SNMPv3 access -- full device MIB")
	if access == "readWrite" {
		b.WriteString(", with confirmed write access (reconfiguration/reset)")
	}
	b.WriteString(".\n")
	return b.String()
}

func explainSSHExposure(host string, f engine.Finding) string {
	banner := explainField(f, "banner")
	product := explainField(f, "product")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	if product != "" {
		b.WriteString(fmt.Sprintf("\nSSH service identifies as **%s**.\n", product))
	}
	if banner != "" {
		b.WriteString(fmt.Sprintf("\n**Banner:** `%s`\n", banner))
	}
	b.WriteString("\n**Read the banner:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("ssh-keyscan -t rsa %s 2>&1", host),
		fmt.Sprintf("nc -w3 %s 22 </dev/null", host),
	))
	return b.String()
}

func explainSSHDefaultCreds(host string, f engine.Finding) string {
	user := explainField(f, "user")
	pass := explainField(f, "pass")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nSSH accepted the default credential **%s / %s**.\n", user, pass))
	b.WriteString("\n**Validate:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("ssh -o StrictHostKeyChecking=no %s@%s", user, host),
		fmt.Sprintf("# Password: %s", pass),
	))
	b.WriteString("\n\n**Impact:** Shell/CLI access to the device via SSH with a known credential.\n")
	return b.String()
}

func explainSMCPSBlock(host string, f engine.Finding) string {
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nSupermicro IPMI web interface exposes a cleartext credential store at\n")
	b.WriteString("`/PSBlock` on TCP/49152. All BMC user passwords in plaintext -- no auth required.\n")
	b.WriteString("\n**Retrieve the credential store:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -s http://%s:49152/PSBlock", host),
		fmt.Sprintf("wget -qO- http://%s:49152/PSBlock", host),
	))
	b.WriteString("\n\n**Impact:** All BMC user passwords exposed. Use any recovered credential for full BMC access.\n")
	return b.String()
}
