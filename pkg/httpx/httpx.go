// Package httpx centralizes the hardened HTTP client/transport oobscan uses to probe
// hostile, often-broken embedded management web servers. Every probe client in the
// tree should be built here so the scanner shares one set of safety bounds:
// per-connection dial, TLS-handshake and response-header timeouts so a slowloris
// tarpit fails fast rather than holding the socket for the whole request budget;
// keep-alives disabled, since embedded web tiers mishandle Go's connection reuse; TLS
// verification skipped, since BMCs ship self-signed certs; and a hard cap on body
// bytes read, enforced via ReadBody.
//
// The transport timeouts derive from the caller's per-probe timeout so no single
// phase outlives the caller's budget.
package httpx

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/runZeroInc/excrypto/crypto/tls"
)

// MaxBody is the default hard cap on response-body bytes any probe will read
// from a target. It is deliberately generous enough for the largest artifact
// oobscan fingerprints (a compressed Redfish schema archive) yet small enough
// that a hostile host streaming an endless body cannot exhaust memory. Callers
// that need a different cap pass it to ReadBody explicitly.
const MaxBody int64 = 1 << 20 // 1 MiB

// BrowserUserAgent is applied to every outbound request made by clients built
// in this package so scanner traffic matches common browser behavior.
const BrowserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"

const (
	defaultClientTimeout = 10 * time.Second
	defaultRedirectHops  = 8
)

// ClientOptions controls NewClient behavior.
type ClientOptions struct {
	Timeout       time.Duration
	CheckRedirect func(*http.Request, []*http.Request) error
	TLSCert       *tls.Certificate
	// PhaseCeiling caps each independently-bounded phase (dial, TLS handshake,
	// response-header). Zero uses the default 5s fast-fail ceiling. Identify
	// probes against slow embedded BMC web tiers (ATEN/Supermicro lighttpd doing
	// an RSA handshake on a weak SoC routinely needs >5s) raise this so the
	// handshake can complete; the whole-request Timeout still bounds the total.
	PhaseCeiling time.Duration
}

// defaultPhaseCeiling is the per-phase (dial / handshake / header) fast-fail cap
// applied to every scanner client unless a caller raises it via PhaseCeiling.
const defaultPhaseCeiling = 5 * time.Second

// Transport builds a hardened *http.Transport bounded by the supplied per-probe
// timeout. TLS verification is skipped (self-signed BMC certs) and keep-alives
// are disabled (embedded web tiers reuse connections unreliably). The dial,
// TLS-handshake, and response-header phases are each independently bounded so a
// host that stalls in any one phase fails fast rather than at the outer
// client.Timeout. A non-positive timeout falls back to a safe default.
func Transport(timeout time.Duration) *http.Transport {
	return transportWithTLS(timeout, nil, 0)
}

func transportWithTLS(timeout time.Duration, cert *tls.Certificate, phaseCeiling time.Duration) *http.Transport {
	if timeout <= 0 {
		timeout = defaultClientTimeout
	}
	if phaseCeiling <= 0 {
		phaseCeiling = defaultPhaseCeiling
	}
	dialTimeout := bounded(timeout/2, 500*time.Millisecond, phaseCeiling)
	handshakeTimeout := bounded(timeout/2, 500*time.Millisecond, phaseCeiling)
	headerTimeout := bounded(timeout/2, 500*time.Millisecond, phaseCeiling)
	netDialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: -1}
	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // BMCs ship self-signed certs; scanning, not trusting.
	if cert != nil {
		tlsCfg.Certificates = []tls.Certificate{*cert}
	}
	tlsDialer := &tls.Dialer{NetDialer: netDialer, Config: tlsCfg}
	return &http.Transport{
		DisableKeepAlives: true,
		DialContext:       netDialer.DialContext,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, dialTimeout+handshakeTimeout)
			defer cancel()
			return tlsDialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   handshakeTimeout,
		ResponseHeaderTimeout: headerTimeout,
		ExpectContinueTimeout: 500 * time.Millisecond,
		IdleConnTimeout:       0,
		MaxIdleConns:          0,
		MaxIdleConnsPerHost:   0,
		MaxConnsPerHost:       2,
	}
}

// Client builds a hardened *http.Client with the given whole-request timeout and
// a Transport bounded by the same value.
func Client(timeout time.Duration) *http.Client {
	return NewClient(ClientOptions{Timeout: timeout})
}

// ClientWithRedirect is Client with an explicit CheckRedirect policy (e.g. probes
// that treat the redirect target itself as the signal pass a policy returning
// http.ErrUseLastResponse). A nil policy uses Client's default.
func ClientWithRedirect(timeout time.Duration, redirect func(*http.Request, []*http.Request) error) *http.Client {
	return NewClient(ClientOptions{Timeout: timeout, CheckRedirect: redirect})
}

// IdentifyClient is a hardened client tuned for the fingerprint stage against
// slow embedded BMC web tiers: it raises the per-phase ceiling to the full
// whole-request timeout so a slow TLS handshake (weak-SoC RSA) can complete
// instead of tripping the 5s fast-fail cap that leaves the host ClassUnknown.
// It is not for the check battery, whose fast-fail bounds must stay tight.
func IdentifyClient(timeout time.Duration) *http.Client {
	return NewClient(ClientOptions{Timeout: timeout, PhaseCeiling: timeout})
}

// NewClient is the single constructor for scanner HTTP clients.
func NewClient(opts ClientOptions) *http.Client {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultClientTimeout
	}
	redirect := opts.CheckRedirect
	if redirect == nil {
		redirect = SameHostRedirectPolicy(defaultRedirectHops)
	}
	tr := transportWithTLS(timeout, opts.TLSCert, opts.PhaseCeiling)
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: redirect,
		Transport: &userAgentTransport{
			next: tr,
			ua:   BrowserUserAgent,
		},
	}
}

// AnyRedirectPolicy allows redirects to any location up to maxHops.
func AnyRedirectPolicy(maxHops int) func(*http.Request, []*http.Request) error {
	if maxHops <= 0 {
		maxHops = 1
	}
	return func(_ *http.Request, via []*http.Request) error {
		if len(via) >= maxHops {
			return http.ErrUseLastResponse
		}
		return nil
	}
}

type userAgentTransport struct {
	next http.RoundTripper
	ua   string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil || t.next == nil {
		return nil, fmt.Errorf("httpx: nil transport")
	}
	clone := req.Clone(req.Context())
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}
	clone.Header.Set("User-Agent", t.ua)
	return t.next.RoundTrip(clone)
}

// SameHostRedirectPolicy returns a redirect callback that allows at most maxHops
// redirects and only when every hop stays on the original target host. Port and
// scheme changes are allowed because management interfaces commonly redirect
// HTTP to HTTPS.
//
// This prevents a scanned target from pivoting the scanner via 30x responses to
// arbitrary internal/external URLs while still allowing common in-place login
// redirects on the same management interface.
func SameHostRedirectPolicy(maxHops int) func(*http.Request, []*http.Request) error {
	if maxHops <= 0 {
		maxHops = 1
	}
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxHops {
			return http.ErrUseLastResponse
		}
		if len(via) == 0 || via[0] == nil || via[0].URL == nil || req == nil || req.URL == nil {
			return nil
		}
		if !sameTargetHost(req.URL, via[0].URL) {
			return http.ErrUseLastResponse
		}
		return nil
	}
}

func sameTargetHost(next, original *url.URL) bool {
	return strings.EqualFold(next.Hostname(), original.Hostname())
}

func bounded(v, low, high time.Duration) time.Duration {
	if v < low {
		return low
	}
	if v > high {
		return high
	}
	return v
}

// ReadBody reads at most max bytes from r (falling back to MaxBody when max is
// non-positive). It always drains through the limit so a caller's deferred
// Body.Close can reuse or cleanly tear down the connection, and never returns
// more than max bytes, so a hostile unbounded body cannot exhaust memory.
func ReadBody(r io.Reader, max int64) []byte {
	if max <= 0 {
		max = MaxBody
	}
	b, _ := io.ReadAll(io.LimitReader(r, max))
	return b
}
