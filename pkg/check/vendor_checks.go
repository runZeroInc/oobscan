package check

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/idrac"
	"github.com/runZeroInc/oobscan/pkg/redfish"
	"github.com/runZeroInc/oobscan/pkg/ssh"
	"github.com/runZeroInc/oobscan/pkg/tlscert"
)

// These checks prefer probe results stashed by identify.

func init() {
	Register(Check{
		Name:        "http.idrac.defaultCreds",
		Description: "Dell iDRAC pre-auth default-credential (root:calvin) indicator",
		Category:    "creds",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runIDRACDefaultCreds,
	})
	Register(Check{
		Name:        "tls.cert",
		Description: "TLS certificate uses a known shipped/shared private key",
		Category:    "tls",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runTLSSharedKey,
	})
}

func runIDRACDefaultCreds(_ context.Context, t *engine.Target) []engine.Finding {
	var info *idrac.Info
	if v, ok := t.Evidenced("idrac"); ok {
		info, _ = v.(*idrac.Info)
	}
	if info == nil {
		if t.Identity == nil || (!strings.EqualFold(t.Identity.Vendor, "dell") &&
			!strings.Contains(strings.ToLower(t.Identity.Product+" "+t.Identity.Generation), "idrac")) {
			return nil
		}
		if got, err := idrac.Probe(t.Host, t.Timeout); err == nil && got != nil {
			info = got
			t.SetEvidence("idrac", info)
		}
	}
	if info == nil {
		return nil
	}
	if info.DefaultCredKnown && info.DefaultCredInPlace {
		// Indicator, not a confirmed login: the flag is a Dell self-report that can
		// be stale (root disabled/renamed while the flag still reads "in place"), so
		// rate it high rather than critical. Critical is reserved for the active path
		// below, which actually completes a root:calvin session.
		return []engine.Finding{{
			Check: "http.idrac.defaultCreds", Category: "creds", Risk: "high",
			Fields: engine.F(
				"username", "root",
				"password", "calvin",
				"via", "idrac.data.defaultCred_inplace",
				"evidenceEndpoint", "/data?get=defaultCred_inplace",
				"defaultCredInPlace", "true",
				"selfReported", "true",
			),
		}}
	}
	if info.DefaultCredKnown {
		return []engine.Finding{{
			Check: "http.idrac.defaultCreds", Category: "creds", Risk: "none",
			Fields: engine.F(
				"via", "idrac.data.defaultCred_inplace",
				"evidenceEndpoint", "/data?get=defaultCred_inplace",
				"result", "defaultCredReplaced",
			),
		}}
	}
	// Newer iDRACs may remove the passive default-credential indicator.
	if !t.DisableLogins && idracLooksDell(t, info) {
		if res, ok := activeIDRACDefaultCredCheck(t, info); ok {
			fields := engine.F(
				"username", "root",
				"password", "calvin",
				"via", res.Via,
				"evidenceEndpoint", loginEndpointForVia(res.Via),
			)
			if res.Info.Empty() {
				// SSH path (or a Redfish login that returned no readable inventory):
				// keep the bare boolean proof.
				fields = append(fields, engine.Field{Key: "sessionAuthenticated", Val: "true"})
			} else {
				// Redfish path: replace the bare boolean with the authenticated
				// inventory pulled from the live session.
				fields = append(fields, engine.Field{Key: "proof", Val: idracActiveProof(res)})
				t.SetEvidence("redfish.postAuth", &redfish.PostAuthSnapshot{
					Method: "idrac.defaultCreds",
					Via:    res.Via,
					User:   "root",
					Source: "redfish.active",
					Info:   res.Info,
				})
			}
			return []engine.Finding{{
				Check: "http.idrac.defaultCreds", Category: "creds", Risk: "critical",
				Fields: fields,
			}}
		}
	}
	return nil
}

// idracLooksDell reports whether the target is actually a Dell iDRAC, gating
// the active root:calvin login fallback so it never sprays a non-Dell host:
// idrac.ProbeAt always returns a non-nil *Info even when every Dell endpoint
// 404s, so an `info == nil` guard alone would not block a non-Dell target.
// This requires either an identify-side Dell attribution or a Dell-specific
// tell from the on-demand probe (iDRAC generation banner, pre-auth
// defaultCred flag, etc.).
func idracLooksDell(t *engine.Target, info *idrac.Info) bool {
	if t.Identity != nil && strings.EqualFold(strings.TrimSpace(t.Identity.Vendor), "dell") {
		return true
	}
	if info != nil {
		// Dell-specific tells recovered by the on-demand probe: a resolved iDRAC
		// generation (guessGen only fires on an "idrac<N>" marker), the pre-auth
		// default-cred flag, a populated Dell inventory field, or a Dell-only
		// endpoint that answered unauthenticated.
		if info.Generation != 0 || info.DefaultCredKnown {
			return true
		}
		if info.ServiceTag != "" || info.Model != "" || info.FWVersion != "" || info.ServerGen != "" {
			return true
		}
		if len(info.Endpoints) > 0 {
			return true
		}
	}
	return false
}

// idracActiveResult captures the outcome of a confirmed root:calvin login: how
// it authenticated plus the inventory recovered from the authenticated session
// (Redfish path only; the SSH fallback leaves Info empty).
type idracActiveResult struct {
	Via  string
	Info redfish.SystemInfo
}

func activeIDRACDefaultCredCheck(t *engine.Target, info *idrac.Info) (idracActiveResult, bool) {
	per := t.Timeout
	if per <= 0 {
		per = 4 * time.Second
	}
	client := redfish.InsecureClient(per)
	for _, port := range idracLoginPorts(t) {
		base := redfish.BaseURL(t.Host, port)
		res := redfish.OpenSession(client, base, "root", "calvin", per)
		if res.Authenticated {
			// Pull the authenticated fingerprint before deleting the session, so
			// the finding carries vendor/model/firmware, not just a boolean.
			hdrs := readHeaderFor(res, "root", "calvin")
			sysInfo := redfish.PullSystemInfo(client, base, hdrs, "root", per)
			redfish.DeleteSession(client, base, res.SessionURI, res.Token, per)
			info.DefaultCredKnown = true
			info.DefaultCredInPlace = true
			return idracActiveResult{
				Via:  fmt.Sprintf("redfish.%s:%d", res.Via, port),
				Info: sysInfo,
			}, true
		}
	}
	if tcpPortPresent(t, 22) {
		if user, pass, _, ok := ssh.TryDefaults(t.Host, 22, per, [][2]string{{"root", "calvin"}}, 1); ok {
			info.DefaultCredKnown = true
			info.DefaultCredInPlace = true
			return idracActiveResult{Via: "ssh.password(" + user + ":" + pass + ")"}, true
		}
	}
	return idracActiveResult{}, false
}

// idracActiveProof renders the authenticated-session inventory as the proof
// string for the active root:calvin finding (vendor/model/firmware/serial/etc.).
func idracActiveProof(res idracActiveResult) string {
	info := res.Info
	return proofKV(
		"sessionAuthenticated", "true",
		"vendor", info.Vendor,
		"model", info.Model,
		"firmwareVersion", info.FirmwareVersion,
		"product", info.Product,
		"serialNumber", info.SerialNumber,
		"redfishVersion", info.RedfishVersion,
		"serviceUuid", info.ServiceUUID,
		"managerId", info.ManagerID,
		"systemId", info.SystemID,
		"biosVersion", info.BIOSVersion,
		"powerState", info.PowerState,
		"accountRole", info.AccountRole,
		"accountEnabled", info.AccountEnabled,
	)
}

// loginEndpointForVia maps the "via" string returned by
// activeIDRACDefaultCredCheck into a human-readable endpoint description for
// the evidence_endpoint field on the finding.
func loginEndpointForVia(via string) string {
	switch {
	case strings.HasPrefix(via, "redfish."):
		return "/redfish/v1/SessionService/Sessions"
	case strings.HasPrefix(via, "ssh."):
		return "ssh://root@host"
	default:
		return via
	}
}

func idracLoginPorts(t *engine.Target) []int {
	seen := map[int]bool{}
	var out []int
	add := func(p int) {
		if p <= 0 || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	// Try canonical iDRAC HTTPS ports first.
	add(443)
	add(8443)
	add(4443)

	// If identify found a web port and scheme is HTTPS (or unknown), try it too.
	if t.Identity != nil && t.Identity.Attributes != nil {
		scheme := strings.ToLower(strings.TrimSpace(t.Identity.Attributes["web.scheme"]))
		if scheme != "http" {
			if s := strings.TrimSpace(t.Identity.Attributes["web.port"]); s != "" {
				if n, err := strconv.Atoi(s); err == nil {
					add(n)
				}
			}
		}
	}

	for _, p := range t.Ports {
		if p.Proto != engine.ProtoTCP {
			continue
		}
		if p.Num == 443 || p.Num == 8443 || p.Num == 4443 {
			add(p.Num)
		}
	}
	return out
}

func tcpPortPresent(t *engine.Target, num int) bool {
	for _, p := range t.Ports {
		if p.Proto == engine.ProtoTCP && p.Num == num {
			return true
		}
	}
	return false
}

// amiVendor reports whether the identified vendor is an AMI MegaRAC family board
// (AMI itself or an OEM that ships MegaRAC), so the CVE-2024-54085 differential is
// only actively probed where it could apply.
func amiVendor(t *engine.Target) bool {
	if t.Identity == nil {
		return false
	}
	switch t.Identity.Vendor {
	case "ami", "asrockrack", "asus", "tyan", "gigabyte", "quanta":
		return true
	}
	return strings.Contains(strings.ToLower(t.Identity.Product), "megarac")
}

func runTLSSharedKey(ctx context.Context, t *engine.Target) []engine.Finding {
	v, ok := t.Evidenced("tls")
	if !ok {
		return nil
	}
	ci, ok := v.(*tlscert.CertInfo)
	if !ok || ci == nil {
		return nil
	}
	var findings []engine.Finding
	switch {
	case ci.SharedKeyMatch != nil:
		findings = append(findings, engine.Finding{
			Check: "tls.sharedKey", Category: "tls", Risk: "low",
			Fields: engine.F("kind", "shipped-cert", "sha256", ci.SHA256,
				"match", "cert-sha256"),
		})
	case ci.SharedKeyBySPKI != nil:
		sk := ci.SharedKeyBySPKI
		findings = append(findings, engine.Finding{
			Check: "tls.sharedKey", Category: "tls", Risk: "low",
			// The impact narrative (sk.Note) is a fixed catalog sentence identical for
			// every host sharing a key; it lives in the explainer, not the finding
			// fields. The machine-actionable identity is spki/key/vendors.
			Fields: engine.F("kind", "shared-private-key-spki", "key", sk.Label,
				"vendors", strings.Join(sk.Vendors, ","), "spki", ci.SPKI256,
				"subject", ci.SubjectCN,
				"match", "spki"),
		})
	case ci.DefaultSubject != nil:
		findings = append(findings, engine.Finding{
			Check: "tls.defaultCert", Category: "tls", Risk: "low",
			Fields: engine.F("vendor", ci.DefaultSubject.Vendor, "product", ci.DefaultSubject.Product, "subject", ci.SubjectCN),
		})
	case ci.SelfSigned:
		findings = append(findings, engine.Finding{
			Check: "tls.selfSigned", Category: "tls", Risk: "low",
			Fields: engine.F("cn", ci.SubjectCN, "sha256", ci.SHA256),
		})
	}
	if ci.ClientCertRequested {
		findings = append(findings, engine.Finding{
			Check: "tls.clientCertRequested", Category: "tls", Risk: "info",
			Fields: engine.F("result", "serverRequestedClientCertificate", "subject", ci.SubjectCN),
		})
	}
	// The mutual-TLS shipped-CA bypass is handled by tls.mtls.ami.caBypass, which
	// models the trusted client CA and actively presents the shipped Administrator
	// cert.
	if ci.Expired {
		findings = append(findings, engine.Finding{
			Check: "tls.expired", Category: "tls", Risk: "low",
			Fields: engine.F("expired", ci.NotAfter.Format("2006-01-02")),
		})
	}
	for i := range findings {
		findings[i].Port, findings[i].Transport, findings[i].Protocol = 443, "tcp", "https"
	}
	return findings
}

func init() {
	RegisterExplain("http.idrac.defaultCreds", explainIDRACDefaultCreds)
	RegisterExplain("tls.cert", explainTLSSharedKey)
}

func explainIDRACDefaultCreds(host string, f engine.Finding) string {
	user := explainField(f, "user")
	pass := explainField(f, "pass")
	if user == "" {
		user = "root"
	}
	if pass == "" {
		pass = "calvin"
	}
	baseURL := explainBaseURL(host, f, 443, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\niDRAC pre-auth fingerprint indicates the factory default **%s / %s** is likely in place.\n", user, pass))
	b.WriteString("\n**Validate via Redfish:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf(`curl -sk -X POST %s/redfish/v1/SessionService/Sessions \`, baseURL),
		`  -H "Content-Type: application/json" \`,
		fmt.Sprintf(`  -d '{"UserName":"%s","Password":"%s"}'`, user, pass),
	))
	b.WriteString("\n\n**Validate via IPMI:**\n")
	b.WriteString(explainSh(fmt.Sprintf("ipmitool -I lanplus -H %s -p 623 -U '%s' -P '%s' lan print", host, user, pass)))
	b.WriteString("\n\n**Impact:** Full iDRAC access -- power control, virtual console, firmware update.\n")
	return b.String()
}

func explainTLSSharedKey(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 443)
	subject := explainField(f, "subject")
	serial := explainField(f, "serial")
	baseURL := explainBaseURL(host, f, port, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe TLS certificate uses a private key shared fleet-wide across this vendor's\n")
	b.WriteString("devices. The key has been extracted from firmware and is publicly known.\n")
	if subject != "" {
		b.WriteString(fmt.Sprintf("\n**Subject:** `%s`  **Serial:** `%s`\n", subject, serial))
	}
	b.WriteString("\n**Inspect the certificate:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("openssl s_client -connect %s:%d </dev/null 2>/dev/null | openssl x509 -noout -text", host, port),
		fmt.Sprintf("curl -vsk %s/ 2>&1 | grep -A5 'Server certificate'", baseURL),
	))
	b.WriteString("\n\n**Impact:** A known shared private key permits server impersonation. Recorded TLS traffic may be decrypted only when the negotiated key exchange lacks forward secrecy; the key alone does not decrypt ephemeral-key sessions.\n")
	b.WriteString("\n**Remediation:** Replace the shared key and certificate with a unique device identity, verify client trust, and restrict management-network access.\n")
	return b.String()
}
