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

// These cover well-known older BMC exposures that the protocol pipeline would
// otherwise miss. They probe their own ports and run on identified BMCs, so
// they add no cost to non-BMC hosts.
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
		Applies:     Applicability{CrossVendor: true}, // identify probes SNMP on every target
		Enabled:     true,
		Run:         runSNMP,
	})
	Register(Check{
		Name:        "ssh.exposure",
		Description: "SSH version/banner + weak-algorithm enumeration on every target (default-credential login when online)",
		Category:    "ssh",
		Applies:     Applicability{CrossVendor: true}, // version + weak-crypto are useful on all targets
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

// runLibUPnP unicasts an SSDP M-SEARCH and reads the UPnP SDK (libupnp) name and
// version from the Server header. This reports the SDK version as a FACTUAL
// disclosure only. It does not flag CVE-2012-5958/5959: those are stack-overflow
// crashers with no safe non-destructive patched/unpatched differential, so the
// only remotely observable signal is the banner version -- which is disclosure,
// not a confirmed vulnerability.
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

// runSNMP renders the SNMP findings from the discovery the identify step already
// performed on every target (public/private v2c/v1 reads + v3 engine-ID
// discovery, stashed as "snmp"/"snmp.private"/"snmpv3" evidence), and adds the
// one active/credential step: testing documented factory SNMPv3 USM credentials.
// A default community read is a finding; a writable 'private' community is worse;
// a factory v3 credential that authenticates is a compromise.
func runSNMP(ctx context.Context, t *engine.Target) []engine.Finding {
	const port = 161
	var out []engine.Finding

	// Default 'public' community read (v1/v2c has no user; the community is the
	// shared secret, reported as pass= to match every other defaultCreds finding).
	// 'public' is conventionally read-only, but some devices ship it writable
	// (e.g. Advantech's `etc/snmpd.conf` template and IPv6 `rwcommunity6 public`);
	// a same-value SET tests write access so those are not mis-labelled RO.
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
	// Inventory of the machine the agent is attached to. The neighbour cache and
	// the managed-machine NIC list are served to the same community that answers
	// the system group, so a controller reachable with a default community
	// discloses which host it manages and who its neighbours are.
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
	// Writable 'private' community.
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
	// SNMPv3: engine already discovered by identify. When online, try the factory
	// v3 credentials; the outcome is recorded on the v3 finding so it is always
	// visible whether we tried.
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
			// Decode the RFC 3411 enterprise number/suffix baked into the engine
			// ID: many vendors (e.g. HPE iLO) embed a product/serial string in
			// the format-4/5 suffix, which is a useful pre-auth identifier
			// alongside the enterprise number itself.
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
				// Read is confirmed by the authenticated GET; confirm write with the
				// same idempotent same-value SET used for v1/v2c before lifting the
				// risk. A read-only v3 user (e.g. Lantronix snmprwuser vs snmpuser)
				// stays medium; a confirmed write goes high.
				risk, access := "medium", "readOnly"
				proof := proofKV("operation", "read", "username", hit.cred.User, "level", hit.res.V3Level, "access", "readOnly")
				if write, err := verifySNMPV3Write(t.Host, port, hit.cred, min(t.Timeout, 1500*time.Millisecond)); err == nil && write != nil {
					risk, access = "high", "readWrite"
					proof = proofKV("operation", "setSameValue", "username", hit.cred.User, "oid", write.OID, "access", "readWrite")
				}
				var cve []string
				if hit.cred.Name == "huawei-usm-customization" || hit.cred.Name == "huawei-usm-community" {
					cve = []string{"CVE-2026-65198"} // shared SNMPv3 USM key
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

	// Vendor-specific default communities beyond public/private (e.g. Intel
	// intel.public/intel.private). Only when SNMP is confirmed present - a public
	// read or a v3 engine-ID response, the latter catching devices like Intel
	// BMCs whose custom community hides the generic public read - and the host was
	// attributed to a vendor that ships a non-generic community. Active reads
	// confirm the community; documented-RW communities additionally require a
	// same-value SET before the finding reports write access.
	if !t.DisableLogins {
		_, snmpUp := t.Evidenced("snmp")
		_, v3Up := t.Evidenced("snmpv3")
		if snmpUp || v3Up {
			vend := identityVendor(t)
			for _, dc := range snmp.DefaultCommunities {
				// "*" is a firmware-level default (e.g. AMI) tried on any SNMP host;
				// everything else is gated to its own identify vendor slug.
				if dc.Vendor != "*" && !strings.EqualFold(dc.Vendor, vend) {
					continue
				}
				for _, ver := range []int{1, 0} { // v2c then v1
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
					vlabel := dc.Vendor // for "*" show the host's identified vendor, not the wildcard
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

// verifySNMPV3Write confirms a v3 credential's write access; injectable for tests.
var verifySNMPV3Write = snmp.VerifyWriteV3

func snmpCredentialVendor(t *engine.Target) string {
	// A vendor is "known to the v3 cred pool" if it has a vendor-specific
	// passphrase profile or raw-localized-key profile (e.g. Huawei, which ships
	// only a localized key). Recognizing it keeps the passphrase sweep
	// vendor-scoped instead of falling back to the whole cross-vendor list. This
	// checks vendor-specific membership directly so it is not perturbed by the
	// localized creds being tried broadly (regardless of vendor) in the default
	// sweep.
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

// snmpV3Hit is a factory v3 credential that authenticated.
type snmpV3Hit struct {
	cred snmp.V3Cred
	res  *snmp.Result
}

// snmpV3Candidates assembles the SNMPv3 credentials to try for a target: the
// documented passphrase-derived factory defaults, the built-in raw-localized-key
// credentials (Huawei openUBMC) -- now tried by default on any v3-responsive
// host regardless of vendor -- plus (when --snmp-v3-localized-key is set) an
// operator-supplied raw localized key.
func snmpV3Candidates(t *engine.Target) []snmp.V3Cred {
	vendor := snmpCredentialVendor(t)
	creds := snmp.DefaultV3CredsWithLocalized(vendor)
	if c, ok := parseOperatorLocalizedKey(t.SNMPV3LocalizedKey); ok {
		creds = append([]snmp.V3Cred{c}, creds...)
	}
	return creds
}

// parseOperatorLocalizedKey parses --snmp-v3-localized-key "user:authHex[:privHex]".
// The key(s) are raw pre-localized USM keys (hex); auth is assumed SHA-256 and
// privacy AES (Huawei's algorithms and the common modern default). Returns false
// when the flag is empty or malformed.
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

// snmpV3Secret renders the secret half of a v3 credential for reporting: the
// passphrase when passphrase-derived, or the raw localized key when the
// credential ships a pre-localized key (Huawei et al.).
func snmpV3Secret(c snmp.V3Cred) string {
	if c.AuthPass != "" {
		return c.AuthPass
	}
	if c.AuthKeyHex != "" {
		return "localizedKey=" + c.AuthKeyHex
	}
	return ""
}

// tryV3CredsFn is the v3 credential sweep; injectable for tests.
var tryV3CredsFn = tryV3Creds

// tryV3Creds tries each candidate SNMPv3 credential, returning the first that
// completes an authenticated GET (nil if none work).
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

// sshProbePorts are the TCP ports ssh.exposure fingerprints, in priority order.
// 22 is standard; 2222 is by far the most common alt-SSH port on OOB gear per the
// Shodan census (HPE iLO mpSSH and APC AOS cryptlib frequently listen there). SSH is
// probed here rather than via --ports because the web collectors would otherwise
// treat these ports as HTTP.
var sshProbePorts = []int{22, 2222}

// runSSHExposure fingerprints the SSH banner and, when online logins are
// permitted, tries a capped set of default credentials.
func runSSHExposure(ctx context.Context, t *engine.Target) []engine.Finding {
	banner := ""
	if v, ok := t.Evidenced("ssh.banner"); ok {
		banner, _ = v.(string)
	}
	// sshPort is the port the banner was observed on; drives every follow-up probe
	// (kex, host key, default creds) and the finding Port. When identify's
	// collectSSH already grabbed the banner it also stashed the port it used, so
	// honour that; otherwise default to 22.
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
	// Report the SSH product/banner as info only. Banner-version-inferred CVEs are
	// not asserted because distro/vendor backports patch them without bumping the
	// banner.
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

	// Enumerate the server's offered algorithms and flag weak KEX / cipher / MAC
	// / host-key choices (parity with Nessus/GreenBone SSH-hardening checks) as a
	// single finding, one key=val per weak category. These are weak defaults, not
	// directly exploitable, so they rate low.
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

	// Active default-credential login only on identified OOB devices, never on a
	// truly-unknown host - version/weak-crypto reporting runs everywhere, but we do
	// not credential-spray arbitrary SSH servers picked up by the all-targets sweep.
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

// isOOBDevice reports whether identify attributed the target to a known OOB class
// or vendor (not a bare unknown host), gating active credential attempts.
func isOOBDevice(t *engine.Target) bool {
	if t.Identity == nil {
		return false
	}
	return t.Identity.Vendor != "" || t.Identity.Class != engine.ClassUnknown
}

// runSMCPSBlock fetches the Supermicro IPMI credential store served (on affected
// firmware) from TCP/49152 as cleartext. The real /PSBlock (/PSStore) is a small
// binary blob carrying account names and cleartext/obfuscated passwords at fixed
// offsets. Some ATEN builds answer an unknown path with "200 OK" wrapping a 404
// HTML page, so a bare 200 is not sufficient; require the binary credential store
// before lifting recovered cleartext strings as evidence.
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
			if !ok { // reject malformed XML and 200-wrapped error pages
				continue
			}
			return []engine.Finding{{
				Check: "http.smc.deviceDesc", Category: "creds", Risk: "info",
				Port: 49152, Transport: "tcp", Protocol: "http",
				Fields: append(engine.F("path", path), fields...),
			}}
		}
		// Must be the binary credential store, not an HTML/error body served as 200.
		if !isPSBlockCredStore(body) {
			continue
		}
		// No CVE asserted: the Supermicro TCP/49152 plaintext credential-store
		// exposure (CARISIRT/Rapid7, 2014) has no accurate single CVE - CVE-2014-8272
		// is a Dell iDRAC6/7 session-ID bug, not this. The finding stands on its own
		// confirmed evidence (the cleartext store is actually served).
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

// isPSBlockCredStore reports whether a /PSBlock body is the genuine ATEN binary
// credential store rather than a 200-wrapped HTML/error page. The real store is a
// small binary blob with embedded NULs and no HTML markup.
func isPSBlockCredStore(body []byte) bool {
	head := body
	if len(head) > 512 {
		head = head[:512]
	}
	low := strings.ToLower(string(head))
	if strings.Contains(low, "<html") || strings.Contains(low, "<head") ||
		strings.Contains(low, "not found") || strings.Contains(low, "<!doctype") {
		return false // an HTML/error page served with 200
	}
	// The credential store is binary: it must contain NUL bytes (ATEN fixed-width
	// records) and be non-trivial in size.
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

// psblockStrings pulls the printable ASCII runs (>=3 chars) out of the binary
// credential store - these are the account names and cleartext passwords - and
// returns the first several, comma-joined, as recovered evidence.
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

// upnpSDK extracts the UPnP SDK name and version from an SSDP Server header.
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

// versionLess reports whether dotted numeric version a < b (e.g. "1.6.6" < "1.6.18").
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

// credPairs converts the credential knowledge base into ordered user:pass pairs
// (vendor-first) for a capped online spray.
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
