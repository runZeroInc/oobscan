package apc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

type Client struct {
	base string
	hc   *http.Client
}

var (
	reNMCPath = regexp.MustCompile(`/NMC/[^/]+/`)
	reAuthed  = regexp.MustCompile(`^/NMC/[^/]+/$`)
)

func New(host string, port int, timeout time.Duration) *Client {
	return NewWithScheme(netaddr.DefaultScheme(port), host, port, timeout)
}

func NewWithScheme(scheme, host string, port int, timeout time.Duration) *Client {
	if scheme != "http" && scheme != "https" {
		scheme = "https"
	}
	return newClient(netaddr.URL(scheme, host, port, ""), timeout)
}

func newClient(base string, timeout time.Duration) *Client {
	return &Client{
		base: base,

		hc: httpx.ClientWithRedirect(timeout, func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }),
	}
}

type resp struct {
	status  int
	locPath string
	body    string
}

func (c *Client) do(ctx context.Context, method, path, body string) (resp, error) {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return resp{}, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r, err := c.hc.Do(req)
	if err != nil {
		return resp{}, err
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
	out := resp{status: r.StatusCode, body: string(b)}
	if loc := r.Header.Get("Location"); loc != "" {
		if u, perr := url.Parse(loc); perr == nil {
			out.locPath = u.Path
		}
	}
	return out, nil
}

func (c *Client) tokenPath(ctx context.Context) string {
	r, err := c.do(ctx, http.MethodGet, "/home.htm", "")
	if err != nil {
		return ""
	}
	if m := reNMCPath.FindString(r.locPath); m != "" {
		return m
	}

	return reNMCPath.FindString(r.locPath)
}

func (c *Client) Login(ctx context.Context, user, pass string) (ok bool, proof string, err error) {
	tok := c.tokenPath(ctx)
	if tok == "" {
		return false, "", fmt.Errorf("no NMC session token (not an APC NMC login flow)")
	}
	form := url.Values{
		"prefLanguage":   {"00000000"},
		"login_username": {user},
		"login_password": {pass},
		"submit":         {"Log On"},
	}.Encode()
	r, err := c.do(ctx, http.MethodPost, tok+"Forms/login1", form)
	if err != nil {
		return false, "", err
	}

	if r.status < 300 || r.status >= 400 || !reAuthed.MatchString(r.locPath) {
		return false, "", nil
	}
	h, herr := c.do(ctx, http.MethodGet, r.locPath+"home.htm", "")
	if herr != nil {
		return false, "", nil
	}

	defer func() { _, _ = c.do(ctx, http.MethodGet, r.locPath+"logout.htm", "") }()
	if h.status < 200 || h.status >= 300 || !looksLikeAuthedNMC(h.body) {

		return false, "", nil
	}
	proof = fmt.Sprintf("authedPath=%s status=%d %s", r.locPath+"home.htm", h.status, apcProof(h.body))
	return true, proof, nil
}

func looksLikeAuthedNMC(body string) bool {
	low := strings.ToLower(body)
	if strings.Contains(low, "login_password") || strings.Contains(low, "login_username") {
		return false
	}
	return reModelFW.MatchString(body) ||
		strings.Contains(low, "logout") ||
		strings.Contains(low, "network management card")
}

func apcProof(body string) string {
	if m := reModelFW.FindString(body); m != "" {
		return fmt.Sprintf("modelFw=%q", snippet(m))
	}
	low := strings.ToLower(body)
	if i := strings.Index(low, "<title"); i >= 0 {
		if gt := strings.IndexByte(body[i:], '>'); gt >= 0 {
			start := i + gt + 1
			if end := strings.Index(strings.ToLower(body[start:]), "</title>"); end >= 0 {
				return fmt.Sprintf("title=%q", snippet(body[start:start+end]))
			}
		}
	}
	if strings.Contains(low, "logout") {
		return "logout=true"
	}
	return "nmcMarker=true"
}

var reModelFW = regexp.MustCompile(`(?i)(AP\d{4}[A-Z0-9]*|v\d+\.\d+\.\d+[^"<\r\n]{0,40})`)

func (c *Client) LimitedStatusOpen(ctx context.Context) (bool, string, error) {
	r, err := c.do(ctx, http.MethodGet, "/limstat.htm", "")
	if err != nil {
		return false, "", err
	}
	if r.status >= 200 && r.status < 300 && looksLikeLimitedStatus(r.body) {
		return true, snippet(r.body), nil
	}
	return false, "", nil
}

type MacontrolInfo struct {
	MV string
	PC string
	DT string
	TM string
	SR string
	SU string
	RD string
	CI string
	CS string
	MD string
}

func (c *Client) MacontrolExempt(ctx context.Context) (info *MacontrolInfo, snip string, err error) {
	r, err := c.do(ctx, http.MethodGet, "/macontrol.htm", "")
	if err != nil {
		return nil, "", err
	}
	if r.status < 200 || r.status >= 300 {
		return nil, "", nil
	}
	info, ok := parseMacontrol(r.body)
	if !ok {
		return nil, "", nil
	}
	return info, snippet(r.body), nil
}

func (c *Client) MacontrolPostAuthExempt(ctx context.Context) (exempt bool, status int, snip string, err error) {
	r, err := c.do(ctx, http.MethodHead, "/Forms/macontrol1", "")
	if err != nil {
		return false, 0, "", err
	}
	if strings.Contains(strings.ToLower(r.locPath), "logon") {
		return false, r.status, snippet(r.body), nil
	}
	if r.status == http.StatusUnauthorized || r.status == http.StatusForbidden || r.status == http.StatusNotFound {
		return false, r.status, snippet(r.body), nil
	}
	return true, r.status, snippet(r.body), nil
}

func looksLikeLimitedStatus(body string) bool {
	low := strings.ToLower(body)
	if bodyStart := strings.Index(low, "<body"); bodyStart >= 0 {
		if bodyOpenEnd := strings.IndexByte(low[bodyStart:], '>'); bodyOpenEnd >= 0 {
			low = low[bodyStart+bodyOpenEnd+1:]
			if end := strings.Index(low, "</body>"); end >= 0 {
				low = low[:end]
			}
		}
	}
	tokens := make(map[string]struct{})
	for _, token := range reLimitedStatusToken.FindAllString(low, -1) {
		tokens[token] = struct{}{}
	}
	branded := strings.Contains(low, "apc") || strings.Contains(low, "schneider")
	return len(tokens) >= 2 || branded && len(tokens) >= 1
}

var reLimitedStatusToken = regexp.MustCompile(`\b(?:ups|pdu|battery|runtime|outlets?|load|voltage|current|phase)\b`)

var (
	reMacontrolTitle = regexp.MustCompile(`(?is)<title[^>]*>\s*macontrol\s*</title>`)
	reMacontrolField = regexp.MustCompile(`(?m)(?:^|[\s>])([A-Z]{2})=([^\s<]+)`)
)

func parseMacontrol(body string) (*MacontrolInfo, bool) {
	if !reMacontrolTitle.MatchString(body) {
		return nil, false
	}
	values := make(map[string]string)
	for _, match := range reMacontrolField.FindAllStringSubmatch(body, -1) {
		values[match[1]] = match[2]
	}
	if values["MV"] == "" || values["PC"] == "" || len(values) < 4 {
		return nil, false
	}
	return &MacontrolInfo{
		MV: values["MV"], PC: values["PC"], DT: values["DT"], TM: values["TM"],
		SR: values["SR"], SU: values["SU"], RD: values["RD"], CI: values["CI"],
		CS: values["CS"], MD: values["MD"],
	}, true
}

func (c *Client) DemoLogin(ctx context.Context) (ok bool, proof string, err error) {
	return c.Login(ctx, DemoUser, DemoPassword)
}

const (
	DemoUser     = "apc"
	DemoPassword = "jmm627"
)

func snippet(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\n' || c == '\r' || c == '\t':
			b = append(b, ' ')
		case c >= 0x20 && c < 0x7f:
			b = append(b, c)
		}
	}
	out := strings.Join(strings.Fields(string(b)), " ")
	if len(out) > 120 {
		out = out[:120]
	}
	return out
}
