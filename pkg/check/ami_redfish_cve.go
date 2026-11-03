package check

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/redfish"
)

// CVE-2023-34329 is a Host-header spoofing bypass (the client sets Host to
// the trusted internal address 169.254.0.17), distinct from the
// X-Server-Addr-based CVE-2024-54085 handled elsewhere. The probe only flags
// a bypass on a differential -- plain GET denied, spoofed GET serves a real
// admin-scoped resource -- and never issues the account-creation POST, so it
// runs by default.
func init() {
	Register(Check{
		Name:        "http.redfish.ami.cve202334329",
		Description: "AMI MegaRAC Redfish auth-bypass via Host-header spoofing (CVE-2023-34329), pre-authentication response differential",
		Category:    "http",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runAMIRedfishCVE202334329,
	})
	Register(Check{
		Name:        "http.redfish.ami.cve202454085",
		Description: "AMI MegaRAC Redfish Host-Interface auth bypass (CVE-2024-54085), read-only differential confirmed on an admin-scoped resource",
		Category:    "http",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runRedfishAMICVE,
	})
	Register(Check{
		Name:        "http.redfish.ami.noXffBypass",
		Description: "AMI MegaRAC no-X-Forwarded-For auth bypass on port 9080 (pre-authentication read)",
		Category:    "http",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runAMINoXFFBypass,
	})
	Register(Check{
		Name:        "http.redfish.ami.globalLuaTables",
		Description: "AMI MegaRAC pre-auth /redfish/v1/GlobalLuaTables endpoint presence",
		Category:    "http",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runAMIGlobalLuaTables,
	})
}

func runAMIRedfishCVE202334329(ctx context.Context, t *engine.Target) []engine.Finding {
	// Only spend the differential on hosts that speak AMI/MegaRAC Redfish. Accept
	// known MegaRAC OEM identities as well as a live AMI service-root fingerprint.
	if !isAMIRedfish(t) {
		return nil
	}
	port := webPort(t)
	res := redfish.CheckCVE202334329(t.Host, port, t.Timeout)
	if !res.Vulnerable {
		return nil
	}
	return []engine.Finding{{
		Check: "http.redfish.ami.cve202334329", Category: "http", Risk: "critical",
		Port: port, Transport: "tcp", Protocol: "redfish",
		Fields: engine.F(
			"url", res.Path,
			"plain_status", fmt.Sprintf("%d", res.PlainStatus),
			"spoofed_status", fmt.Sprintf("%d", res.SpoofStatus),
			"spoof_header", "Host: 169.254.0.17",
			"proof", proofKV(
				"path", res.Path,
				"plainStatus", fmt.Sprintf("%d", res.PlainStatus),
				"spoofHost", "169.254.0.17",
				"spoofStatus", fmt.Sprintf("%d", res.SpoofStatus)),
			"response", res.Snippet),
		CVE: []string{"CVE-2023-34329"},
	}}
}

// runRedfishAMICVE confirms CVE-2024-54085: the Redfish routing layer trusts
// the internal USB0 address (169.254.0.17) but reads it from the
// caller-supplied X-Server-Addr header, so a spoofed request is served as the
// local host. Strong proof requires an admin-scoped resource denied
// anonymously but served once spoofed, backed by a real inventory read
// (GET-only, so it runs by default); otherwise it falls back to the published
// /redfish/v1/Systems differential with a weaker confirmation.
func runRedfishAMICVE(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	var res *redfish.Result
	if v, ok := t.Evidenced("redfish"); ok {
		res, _ = v.(*redfish.Result)
	}
	// Only spend the differential on AMI/MegaRAC Redfish. identify's own
	// published-detector hit counts as evidence of the stack even when the
	// OEM-branded service root never names AMI.
	flagged := res != nil && res.AMICVE
	if !flagged && !isAMIRedfish(t) {
		return nil
	}
	ports := amiRedfishPorts(t)
	port := ports[0]

	// Admin-scoped confirmation: denied anonymously, served with the header.
	for _, p := range ports {
		conf := redfish.CheckHostInterfaceBypass(t.Host, p, t.Timeout)
		if !conf.Confirmed {
			continue
		}
		port = p
		t.SetEvidence("redfish.postAuth", &redfish.PostAuthSnapshot{
			Method: "cve202454085",
			Via:    "hostInterfaceHeader",
			Source: "x-server-addr-spoof",
			Info:   conf.Info,
		})
		return []engine.Finding{{
			Check: "http.redfish.amiBypass", Category: "redfish", Risk: "critical",
			Port: port, Transport: "tcp", Protocol: "redfish",
			Fields: engine.F(
				"url", conf.Path,
				"plain_status", strconv.Itoa(conf.PlainStatus),
				"spoofed_status", strconv.Itoa(conf.SpoofStatus),
				"spoof_header", conf.Header(),
				"confirmation", "adminResource",
				"sessionAuthenticated", "true",
				"evidenceEndpoint", conf.Path,
				"vendor", conf.Info.Vendor,
				"model", conf.Info.Model,
				"firmwareVersion", conf.Info.FirmwareVersion,
				"redfishVersion", conf.Info.RedfishVersion,
				"serviceUuid", conf.Info.ServiceUUID,
				"product", conf.Info.Product,
				"serial", conf.Info.SerialNumber,
				"managerId", conf.Info.ManagerID,
				"systemId", conf.Info.SystemID,
				"biosVersion", conf.Info.BIOSVersion,
				"powerState", conf.Info.PowerState,
				"accountRole", conf.Info.AccountRole,
				"accountEnabled", conf.Info.AccountEnabled,
				"proof", proofKV(
					"path", conf.Path,
					"plainStatus", strconv.Itoa(conf.PlainStatus),
					"spoofHeader", conf.Header(),
					"spoofStatus", strconv.Itoa(conf.SpoofStatus)),
				"response", conf.Snippet),
			CVE: []string{"CVE-2024-54085"},
		}}
	}

	// Fall back to the published /redfish/v1/Systems differential. Re-run it when
	// identify did not (OEM-branded root, or a Redfish port identify skipped).
	if !flagged {
		for _, p := range ports {
			vuln, plain, spoof := redfish.CheckCVE202454085(t.Host, p, t.Timeout)
			if !vuln {
				continue
			}
			port = p
			// Re-read the evidence before writing: isAMIRedfish may have stored a
			// freshly probed service root above, and writing a bare Result over it
			// would drop the vendor/root fields later checks read.
			if v, ok := t.Evidenced("redfish"); ok {
				if r, ok := v.(*redfish.Result); ok && r != nil {
					res = r
				}
			}
			if res == nil {
				res = &redfish.Result{Host: t.Host}
			}
			res.AMICVE, res.AMICVEPlain, res.AMICVESpoof = vuln, plain, spoof
			t.SetEvidence("redfish", res)
			break
		}
	}
	if res == nil || !res.AMICVE {
		return nil
	}
	// Behavioral differential, not a fingerprint: the plain GET was denied while
	// the same GET carrying the published X-Server-Addr value returned a live
	// Redfish resource (not a login page). The admin-scoped read did not land,
	// so the finding records the weaker confirmation.
	return []engine.Finding{{
		Check: "http.redfish.amiBypass", Category: "redfish", Risk: "critical",
		Port: port, Transport: "tcp", Protocol: "redfish",
		Fields: engine.F(
			"url", "/redfish/v1/Systems",
			"plain_status", strconv.Itoa(res.AMICVEPlain),
			"spoofed_status", strconv.Itoa(res.AMICVESpoof),
			"spoof_header", "X-Server-Addr: 169.254.0.17:",
			"confirmation", "publishedDifferential",
			"proof", proofKV(
				"path", "/redfish/v1/Systems",
				"plainStatus", strconv.Itoa(res.AMICVEPlain),
				"spoofHeader", "X-Server-Addr: 169.254.0.17:",
				"spoofStatus", strconv.Itoa(res.AMICVESpoof))),
		CVE: []string{"CVE-2024-54085"},
	}}
}

// amiRedfishPorts lists the HTTPS ports the AMI Redfish differentials run
// against, identify's confirmed-responsive web port first. MegaRAC does not
// always serve the vulnerable Redfish listener on the web-UI port -- Eclypsium's
// published CVE-2024-54085 PoC targets :8443 -- so probing web.port alone (443
// on most boards, since identify prefers it) misses those hosts.
func amiRedfishPorts(t *engine.Target) []int {
	seen := map[int]bool{}
	var out []int
	add := func(p int) {
		if p <= 0 || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	add(webPort(t))
	for _, p := range t.Ports {
		if p.Proto != engine.ProtoTCP {
			continue
		}
		switch p.Num {
		case 443, 8443, 4443:
			add(p.Num)
		}
	}
	return out
}

// isAMIRedfish reports whether the target looks like an AMI/MegaRAC BMC exposing
// Redfish: the identity vendor is ami/asrockrack, or a live probe self-identifies
// the AMI service root.
func isAMIRedfish(t *engine.Target) bool {
	if amiVendor(t) {
		return true
	}
	// Fall back to a live fingerprint: identify may have set ClassBMC via IPMI
	// while leaving the vendor blank, so confirm AMI over Redfish before probing.
	if v, ok := t.Evidenced("redfish"); ok {
		if r, ok := v.(*redfish.Result); ok && r != nil && r.Vendor == "ami" {
			return true
		}
	}
	if r, err := redfish.ProbeAt(t.Host, webPort(t), t.Timeout); err == nil && r != nil {
		t.SetEvidence("redfish", r)
		return r.Vendor == "ami"
	}
	return false
}

func runAMINoXFFBypass(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	if !isAMIRedfish(t) {
		return nil
	}
	for _, scheme := range []string{"https", "http"} {
		res, err := redfish.CheckNoXFFBypass(t.Host, 9080, scheme, t.Timeout)
		if err != nil || len(res) == 0 {
			continue
		}
		for _, r := range res {
			if !r.Bypassed {
				continue
			}
			proof := proofKV(
				"path", r.Path,
				"noXffStatus", fmt.Sprintf("%d", r.Status),
				"xff", "1.2.3.4",
				"xffStatus", fmt.Sprintf("%d", r.XFFStatus))
			return []engine.Finding{{
				Check: "http.redfish.ami.noXffBypass", Category: "http", Risk: "critical",
				Port: 9080, Transport: "tcp", Protocol: scheme,
				Fields: engine.F(
					"scheme", scheme,
					"url", r.Path,
					"status", fmt.Sprintf("%d", r.Status),
					"xff_status", fmt.Sprintf("%d", r.XFFStatus),
					"proof", proof,
					"response", r.Snippet),
			}}
		}
	}
	return nil
}

func runAMIGlobalLuaTables(ctx context.Context, t *engine.Target) []engine.Finding {
	if !isAMIRedfish(t) {
		return nil
	}
	port := webPort(t)
	proto := webProto(t)
	res := redfish.CheckGlobalLuaTablesContext(ctx, t.Host, port, proto, t.Timeout)
	if !res.Available {
		return nil
	}
	memberCount := ""
	if res.MemberCount >= 0 {
		memberCount = fmt.Sprintf("%d", res.MemberCount)
	}
	proof := proofKV("path", res.Path, "status", fmt.Sprintf("%d", res.Status), "memberCount", memberCount)
	return []engine.Finding{{
		Check: "http.redfish.ami.globalLuaTables", Category: "http", Risk: "info",
		Port: port, Transport: "tcp", Protocol: proto,
		Fields: engine.F(
			"url", res.Path,
			"status", fmt.Sprintf("%d", res.Status),
			"content_type", res.ContentType,
			"member_count", memberCount,
			"proof", proof,
			"response", res.Snippet,
		),
	}}
}

func init() {
	RegisterExplain("http.redfish.ami.cve202334329", explainAMICVE202334329)
	// Registered under the FINDING name the 54085 check emits, not its check
	// name: GetExplainer keys on engine.Finding.Check.
	RegisterExplain("http.redfish.amiBypass", explainAMICVE202454085)
	RegisterExplain("http.redfish.ami.noXffBypass", explainAMINoXFFBypass)
	RegisterExplain("http.redfish.ami.globalLuaTables", explainAMIGlobalLuaTables)
}

func explainAMICVE202334329(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 443)
	path := explainField(f, "url")
	if path == "" {
		path = "/redfish/v1/Systems"
	}
	baseURL := explainBaseURL(host, f, port, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nAMI MegaRAC Redfish skips auth when the request replaces `Host` with the\n")
	b.WriteString("internal Host-Interface IP (`169.254.0.17`)\n")
	b.WriteString("(CVE-2023-34329). The bypass gives unauthenticated admin-scoped access.\n")
	b.WriteString("\n**Validate the bypass:**\n")
	b.WriteString(explainSh(
		"# Plain (should return 401/403):",
		fmt.Sprintf(`curl -sk %s%s -o /dev/null -w '%%{http_code}\n'`, baseURL, path),
		"",
		"# Spoofed internal-IP (should return 200 on a vulnerable host):",
		`curl -sk -H "Host: 169.254.0.17" \`,
		fmt.Sprintf(`  %s%s | python3 -m json.tool`, baseURL, path),
	))
	b.WriteString("\n\n**CVE:** CVE-2023-34329\n")
	return b.String()
}

func explainAMICVE202454085(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 443)
	path := explainField(f, "url")
	if path == "" {
		path = "/redfish/v1/Systems"
	}
	header := explainField(f, "spoof_header")
	if header == "" {
		header = "X-Server-Addr: 169.254.0.17:"
	}
	baseURL := explainBaseURL(host, f, port, "https")
	model := explainField(f, "model")
	fw := explainField(f, "firmwareVersion")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nAMI MegaRAC Redfish trusts the internal Host-Interface address (`169.254.0.17`,\n")
	b.WriteString("the USB0 link the host OS uses to reach its own BMC) but reads that address from\n")
	b.WriteString("a caller-supplied `X-Server-Addr` header, so any remote client that sets it is\n")
	b.WriteString("handled as the local host and skips authentication (CVE-2024-54085).\n")
	if explainField(f, "confirmation") == "adminResource" {
		b.WriteString("\nConfirmed on an **admin-scoped resource**: the request was denied anonymously and\n")
		b.WriteString("served once the header was added, and BMC inventory was read back over it.\n")
	}
	if model != "" || fw != "" {
		b.WriteString(fmt.Sprintf("\n**Device:** %s firmware %s\n", model, fw))
	}
	b.WriteString("\n**Validate the bypass (read-only):**\n")
	b.WriteString(explainSh(
		"# Plain (should return 401/403):",
		fmt.Sprintf(`curl -sk %s%s -o /dev/null -w '%%{http_code}\n'`, baseURL, path),
		"",
		"# Spoofed host-interface address (returns Redfish data on a vulnerable host):",
		fmt.Sprintf(`curl -sk -H '%s' \`, header),
		fmt.Sprintf(`  %s%s | python3 -m json.tool`, baseURL, path),
	))
	b.WriteString("\n\n**CVE:** CVE-2024-54085 -- AMI MegaRAC SPx (fixed in SPx 12.7 / 13.5; OEM rebuilds vary)\n")
	b.WriteString("\n**Evidence:** The check confirmed unauthorized read access to an admin-scoped resource; it did not create an account or exercise write operations.\n")
	b.WriteString("\n**Potential impact:** On affected firmware, the same trust bypass can allow creation of an Administrator account, exposing power control, virtual media, firmware updates, and console access.\n")
	b.WriteString("\n**Remediation:** Install the OEM firmware update for CVE-2024-54085 and restrict management-network access while updates are pending.\n")
	return b.String()
}

func explainAMINoXFFBypass(host string, f engine.Finding) string {
	path := explainField(f, "url")
	if path == "" {
		path = "/redfish/v1/AccountService/Accounts"
	}
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nAMI MegaRAC can expose a direct Redfish backend on :9080 where requests\n")
	b.WriteString("without `X-Forwarded-For` are treated as privileged. This check confirms\n")
	b.WriteString("the condition with a differential: no-XFF request succeeds while explicit XFF\n")
	b.WriteString("control does not.\n")
	b.WriteString("\n**Validate:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf(`curl -sk 'https://%s:9080%s' -o /dev/null -w '%%{http_code}\n'`, host, path),
		fmt.Sprintf(`curl -sk -H 'X-Forwarded-For: 1.2.3.4' 'https://%s:9080%s' -o /dev/null -w '%%{http_code}\n'`, host, path),
	))
	b.WriteString("\n\nIf no-XFF returns Redfish data but explicit XFF does not, the host is vulnerable.\n")
	return b.String()
}

func explainAMIGlobalLuaTables(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 443)
	baseURL := explainBaseURL(host, f, port, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nAMI MegaRAC exposed `/redfish/v1/GlobalLuaTables` without authentication.\n")
	b.WriteString("Observed responses are typically an empty collection or ordinary Redfish links;\n")
	b.WriteString("endpoint presence is an informational implementation fingerprint, not proof of\n")
	b.WriteString("an internal Lua-table disclosure.\n")
	b.WriteString("\n**Validate:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk %s/redfish/v1/GlobalLuaTables | python3 -m json.tool | head -n 40", baseURL),
	))
	return b.String()
}
