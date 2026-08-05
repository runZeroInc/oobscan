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

const MaxBody int64 = 1 << 20

const BrowserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"

const (
	defaultClientTimeout = 10 * time.Second
	defaultRedirectHops  = 8
)

type ClientOptions struct {
	Timeout       time.Duration
	CheckRedirect func(*http.Request, []*http.Request) error
	TLSCert       *tls.Certificate

	PhaseCeiling time.Duration
}

const defaultPhaseCeiling = 5 * time.Second

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

func Client(timeout time.Duration) *http.Client {
	return NewClient(ClientOptions{Timeout: timeout})
}

func ClientWithRedirect(timeout time.Duration, redirect func(*http.Request, []*http.Request) error) *http.Client {
	return NewClient(ClientOptions{Timeout: timeout, CheckRedirect: redirect})
}

func IdentifyClient(timeout time.Duration) *http.Client {
	return NewClient(ClientOptions{Timeout: timeout, PhaseCeiling: timeout})
}

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

func ReadBody(r io.Reader, max int64) []byte {
	if max <= 0 {
		max = MaxBody
	}
	b, _ := io.ReadAll(io.LimitReader(r, max))
	return b
}
