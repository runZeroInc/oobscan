package ipmi

// A minimal HTTP listener that gives the blind command-injection payloads a
// confirmation channel. Both CVE-2026-65213 and SMC-0022 execute asynchronously and
// return nothing that reflects the injected command, so the payload fetches a
// URL on this listener and the tool reports the hit (with the source address,
// which is the BMC) as proof.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SMCCallbackHit is one request the injected command made to the listener.
type SMCCallbackHit struct {
	When       time.Time `json:"when"`
	RemoteAddr string    `json:"remoteAddr"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	UserAgent  string    `json:"userAgent,omitempty"`
	Body       string    `json:"body,omitempty"`
}

// SMCCallbackServer is a single-purpose loopback-or-interface HTTP listener.
type SMCCallbackServer struct {
	ln    net.Listener
	srv   *http.Server
	token string
	port  int
	host  string

	mu   sync.Mutex
	all  []SMCCallbackHit
	hits chan SMCCallbackHit
}

// StartSMCCallbackServer binds a listener. addr is a host:port (":0" picks a
// free port); advertiseHost overrides the host used when rendering the URL for
// the target, which matters when the BMC reaches us over a specific interface.
// token, when set, is required as the last path element so an unrelated request
// to the same port is recorded but not treated as a confirmation.
func StartSMCCallbackServer(addr, advertiseHost, token string) (*SMCCallbackServer, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("callback listen address %q: %w", addr, err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("callback listener: %w", err)
	}
	_, actualPort, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		ln.Close()
		return nil, err
	}
	port, err := strconv.Atoi(actualPort)
	if err != nil {
		ln.Close()
		return nil, err
	}
	adv := strings.TrimSpace(advertiseHost)
	if adv == "" {
		adv = host
	}
	s := &SMCCallbackServer{
		ln:    ln,
		token: strings.TrimSpace(token),
		port:  port,
		host:  adv,
		hits:  make(chan SMCCallbackHit, 8),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
	}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

func (s *SMCCallbackServer) handle(w http.ResponseWriter, r *http.Request) {
	hit := SMCCallbackHit{
		When:       time.Now(),
		RemoteAddr: r.RemoteAddr,
		Method:     r.Method,
		Path:       r.URL.Path,
		UserAgent:  r.UserAgent(),
	}
	if body, err := io.ReadAll(io.LimitReader(r.Body, 2048)); err == nil {
		hit.Body = strings.TrimSpace(string(body))
	}
	s.mu.Lock()
	s.all = append(s.all, hit)
	s.mu.Unlock()
	// Answer 200 either way: a non-2xx would make a curl-based payload look like
	// a failure to the shell, which matters when the payload chains on success.
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, "ok\n")
	if !s.matches(r.URL.Path) {
		return
	}
	select {
	case s.hits <- hit:
	default:
	}
}

// matches reports whether a request path is the confirmation we planted. The
// token must be the FIRST path element, so a request for some other path on the
// same listener - a browser probing the port, or an unrelated service - is
// recorded in the activity log but is not mistaken for the injected command.
// With no token every request counts, which is the right default on a dedicated
// port.
func (s *SMCCallbackServer) matches(path string) bool {
	if s.token == "" {
		return true
	}
	first, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	return first == s.token
}

// URL renders the callback URL the payload should fetch.
func (s *SMCCallbackServer) URL() string {
	return s.baseURL() + s.Path()
}

// BaseURL renders the listener root with no token, for callers that need to
// describe the listener separately from the token path.
func (s *SMCCallbackServer) BaseURL() string {
	return s.baseURL()
}

// Path is the token path element, with a leading slash, or "/" when unset.
func (s *SMCCallbackServer) Path() string {
	if s.token == "" {
		return "/"
	}
	return "/" + s.token
}

func (s *SMCCallbackServer) baseURL() string {
	host := s.host
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("http://%s:%d", host, s.port)
}

// Addr is the bound listener address.
func (s *SMCCallbackServer) Addr() string { return s.ln.Addr().String() }

// Wait blocks up to d for a confirmation request from the target.
func (s *SMCCallbackServer) Wait(d time.Duration) (*SMCCallbackHit, bool) {
	if d <= 0 {
		d = 15 * time.Second
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case hit := <-s.hits:
		return &hit, true
	case <-timer.C:
		return nil, false
	}
}

// Activity reports every request seen, for a report that wants to show the
// listener was reached at all (even on a path other than the token).
func (s *SMCCallbackServer) Activity() []SMCCallbackHit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]SMCCallbackHit(nil), s.all...)
}

// Close stops the listener.
func (s *SMCCallbackServer) Close() error {
	if s == nil || s.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

// SMCAdvertisedHostForTarget guesses the local address a target can reach us on,
// which is the local end of the route toward it. It is best-effort: a routed
// target on a remote network still needs --callback-host, because the local
// interface address is what carried the probe, not necessarily an address the
// BMC routes back to.
func SMCAdvertisedHostForTarget(target string, port int) string {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, "623"), 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || la.IP == nil {
		return ""
	}
	_ = port
	return la.IP.String()
}
