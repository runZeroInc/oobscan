package check

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// udpProbeSink is a black-hole UDP socket that records whether anything was sent
// to it, so a check that opens an IPMI conversation can be observed on the wire
// rather than through internal state.
type udpProbeSink struct {
	port int
	got  chan int
}

func newUDPProbeSink(t *testing.T) *udpProbeSink {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	s := &udpProbeSink{port: pc.LocalAddr().(*net.UDPAddr).Port, got: make(chan int, 8)}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			select {
			case s.got <- n:
			default:
			}
		}
	}()
	return s
}

func relabelTargetOn(sink *udpProbeSink, vendor string) *engine.Target {
	tgt := &engine.Target{
		Host:     "127.0.0.1",
		Timeout:  200 * time.Millisecond,
		Ports:    []engine.Port{{Num: sink.port, Proto: engine.ProtoUDP}},
		Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: vendor},
	}
	tgt.MarkOpen(sink.port, "udp", "ipmi")
	return tgt
}

// The relabel check is device-specific, so ForIdentity schedules it ahead of the
// cross-vendor ipmi.defaultCreds on every BMC-class host. On a BMC that is not an
// OpenBMC derivative it must not gather its own evidence: the setup-state probe it
// needs is never produced there, so the credential battery would run twice per host.
func TestRelabelCheckSkipsCredentialBatteryOnNonOpenBMC(t *testing.T) {
	sink := newUDPProbeSink(t)
	tgt := relabelTargetOn(sink, "supermicro")

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	done := make(chan []engine.Finding, 1)
	go func() { done <- runOpenBMCRelabelCheck(ctx, tgt) }()

	select {
	case n := <-sink.got:
		t.Fatalf("relabel check sent a %d-byte IPMI packet to a supermicro BMC: it re-ran the full RAKP credential battery that ipmi.defaultCreds runs later, doubling RAKP traffic and duplicating every credential finding on BMC-class hosts", n)
	case f := <-done:
		if len(f) != 0 {
			t.Fatalf("expected no findings, got %d", len(f))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("relabel check did not return")
	}
}

// The counterpart: on an OpenBMC host the check must still gather its own evidence,
// otherwise the gate above would simply turn the check off everywhere.
func TestRelabelCheckGathersEvidenceOnOpenBMC(t *testing.T) {
	sink := newUDPProbeSink(t)
	tgt := relabelTargetOn(sink, "openbmc")

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	done := make(chan []engine.Finding, 1)
	go func() { done <- runOpenBMCRelabelCheck(ctx, tgt) }()

	select {
	case <-sink.got:
		cancel()
	case <-done:
		t.Fatal("relabel check returned without probing an OpenBMC host: it can no longer gather the setup-state evidence it depends on")
	case <-time.After(10 * time.Second):
		t.Fatal("relabel check never probed the OpenBMC host")
	}
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("relabel check did not unwind after cancellation")
	}
}

// mismatchedCAPool returns a cert pool holding one self-signed CA whose subject DN
// matches nothing in the shipped AMI client certificate chain. A TLS server
// configured with it advertises that DN in its CertificateRequest.
func mismatchedCAPool(t *testing.T) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated-test-ca.invalid"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool
}

// A BMC advertises the issuers it is willing to accept. Go filters
// tls.Config.Certificates against that list, so a BMC naming an issuer that does
// not byte-match the shipped leaf would receive no certificate at all and the
// bypass would be recorded as "not vulnerable" without ever being tested.
func TestAMIMTLSClientPresentsCertDespiteAcceptableCAMismatch(t *testing.T) {
	cert, ok := amiClientCert()
	if !ok {
		t.Fatal("embedded AMI client certificate does not parse")
	}
	var presented atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			presented.Store(int32(len(r.TLS.PeerCertificates)))
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &stdtls.Config{
		ClientAuth: stdtls.RequestClientCert,
		ClientCAs:  mismatchedCAPool(t),
		MinVersion: stdtls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	resp, err := amiMTLSClient(cert, 5*time.Second).Get(srv.URL + "/redfish/v1/AccountService/Accounts")
	if err != nil {
		t.Fatalf("mtls request: %v", err)
	}
	resp.Body.Close()
	if n := presented.Load(); n == 0 {
		t.Fatal("no client certificate reached the server: the acceptable-CA list it advertised suppressed the shipped AMI cert, so the bypass is reported as absent on hosts it was never presented to")
	}
}

// The check has to follow the HTTPS port identify settled on. A BMC whose
// management web tier answers on 8443 requests client certs there; inspecting 443
// instead measures nothing and reports a clean negative.
func TestAMIMTLSBypassProbesIdentityWebPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	var dialed atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dialed.Add(1)
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	tgt := &engine.Target{
		Host:    "127.0.0.1",
		Timeout: 2 * time.Second,
		Identity: &engine.Identity{
			Class:      engine.ClassBMC,
			Vendor:     "ami",
			Attributes: map[string]string{"web.port": strconv.Itoa(port)},
		},
	}
	if f := runAMIMTLSBypass(t.Context(), tgt); len(f) != 0 {
		t.Fatalf("expected no findings against a bare TCP listener, got %d", len(f))
	}
	if dialed.Load() == 0 {
		t.Fatalf("the mTLS check never connected to the identified HTTPS port %d: it is pinned to 443, so every BMC serving its web tier off-port is silently unmeasured", port)
	}
}

// A password this scan cracked out of a RAKP-2 hash is not an operator-supplied
// credential. Labelling it "cli" claims the operator handed it over and hides that
// the web login was reached from the scan's own IPMI recovery.
func TestMegaRACCandidatesLabelRecoveredCredentialProvenance(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.10", Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "ami"}}
	tgt.SetEvidence("ipmi.auth", &ipmi.AuthReport{
		Suite:   &ipmi.CipherAlgos{Suite: 17, Auth: ipmi.RAKPHMACSHA256},
		Cracked: []ipmi.CrackResult{{Username: "rzadmin", Password: "runZero26", Verified: true, PasswordType: "default"}},
	})

	var got string
	for _, c := range megaracWebCandidates(tgt, "ami") {
		if c.user == "rzadmin" {
			got = c.source
		}
	}
	if got == "" {
		t.Fatal("the RAKP-recovered credential is not a MegaRAC login candidate")
	}
	if got == "cli" {
		t.Fatal(`RAKP-recovered credential reported as source "cli": the finding would claim the operator supplied a password the scan itself cracked`)
	}
	if got != "ipmi.rakpCracked" {
		t.Fatalf("source = %q, want ipmi.rakpCracked", got)
	}
}

// The login route is POST-only, so its routed answer to the fingerprint GET is
// often 405 carrying the web server's HTML error page. Treating that document as
// the SPA catch-all discards the one status code that proves the route exists.
func TestMegaRACEndpointLiveAcceptsMethodNotAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte("<!DOCTYPE html>\n<html><body>405 - Method Not Allowed</body></html>"))
	}))
	defer srv.Close()

	if !megaracEndpointLive(t.Context(), srv.Client(), srv.URL+"/rpc/WEBSES/create.asp") {
		t.Fatal("a POST-only login route answering 405 was rejected as dead, so the check never posts credentials to a live MegaRAC endpoint")
	}
}

// The SPA catch-all must still be rejected: it answers 200 with the Angular index
// document for any unknown path, and posting credentials there proves nothing.
func TestMegaRACEndpointLiveRejectsSPACatchAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<!DOCTYPE html>\n<html><body><app-root></app-root></body></html>"))
	}))
	defer srv.Close()

	if megaracEndpointLive(t.Context(), srv.Client(), srv.URL+"/api/session") {
		t.Fatal("the SPA index document was accepted as a live login endpoint")
	}
}
