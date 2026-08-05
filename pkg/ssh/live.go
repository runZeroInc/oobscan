package ssh

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	xssh "github.com/runZeroInc/excrypto/x/crypto/ssh"
)

func Banner(host string, port int, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 255)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return "", err
	}

	for ln := range strings.SplitSeq(string(buf[:n]), "\n") {
		if ln = strings.TrimRight(ln, "\r"); strings.HasPrefix(ln, "SSH-") {
			return ln, nil
		}
	}
	return "", fmt.Errorf("not an SSH banner")
}

func SoftwareVersion(banner string) string {
	rest, ok := strings.CutPrefix(banner, "SSH-")
	if !ok {
		return banner
	}

	_, sw, ok := strings.Cut(rest, "-")
	if !ok {
		return banner
	}
	return sw
}

func FingerprintBanner(banner string) (product, vendor string, cves []string) {
	b := strings.ToLower(banner)
	switch {
	case strings.Contains(b, "mpssh"):

		return "mpSSH (HPE iLO)", "hpe", nil
	case strings.Contains(b, "dropbear"):

		return "Dropbear " + afterUnderscore(banner), "", nil
	case strings.Contains(b, "openssh"):
		return "OpenSSH " + afterUnderscore(banner), "", nil
	case strings.Contains(b, "cryptlib"):

		return "cryptlib", "apc", nil
	case strings.Contains(b, "lancom"), strings.Contains(b, "racssh"):
		return banner, "", nil
	}
	return banner, "", nil
}

func TryDefaults(host string, port int, timeout time.Duration, pairs [][2]string, max int) (user, pass, output string, ok bool) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	deadline := time.Now().Add(timeout * 3)
	for i, p := range pairs {
		if i >= max || time.Now().After(deadline) {
			break
		}
		cfg := &xssh.ClientConfig{
			User:            p[0],
			Auth:            []xssh.AuthMethod{xssh.Password(p[1]), keyboardInteractive(p[1])},
			HostKeyCallback: xssh.InsecureIgnoreHostKey(),
			Timeout:         timeout,
		}

		cfg.Ciphers = append(cfg.Ciphers, "aes128-cbc", "3des-cbc", "aes128-ctr")
		if u, pw, out, ok := tryOne(addr, timeout, cfg, p); ok {
			return u, pw, out, ok
		}
	}
	return "", "", "", false
}

func tryOne(addr string, timeout time.Duration, cfg *xssh.ClientConfig, p [2]string) (user, pass, output string, ok bool) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", "", "", false
	}

	watchdog := time.AfterFunc(2*timeout+time.Second, func() { _ = conn.Close() })
	defer watchdog.Stop()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	cc, chans, reqs, err := xssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return "", "", "", false
	}
	_ = conn.SetDeadline(time.Time{})
	c := xssh.NewClient(cc, chans, reqs)
	out := sessionProof(c, timeout)
	_ = c.Close()
	return p[0], p[1], out, true
}

func sessionProof(c *xssh.Client, timeout time.Duration) string {
	sess, err := c.NewSession()
	if err != nil {
		return "authenticated (session refused)"
	}
	defer sess.Close()
	done := make(chan string, 1)
	go func() {
		out, _ := sess.CombinedOutput("id 2>/dev/null; uname -a 2>/dev/null; hostname 2>/dev/null")
		done <- string(out)
	}()
	select {
	case out := <-done:
		if s := firstNonEmptyLine(string(out)); s != "" {
			return s
		}
		return "authenticated (no command output)"
	case <-time.After(timeout):
		return "authenticated (session timed out)"
	}
}

func firstNonEmptyLine(s string) string {
	for ln := range strings.SplitSeq(s, "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			if len(ln) > 160 {
				ln = ln[:160]
			}
			return ln
		}
	}
	return ""
}

func keyboardInteractive(password string) xssh.AuthMethod {
	return xssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		ans := make([]string, len(questions))
		for i := range ans {
			ans[i] = password
		}
		return ans, nil
	})
}

func afterUnderscore(s string) string {
	if _, v, ok := strings.Cut(s, "_"); ok {
		return strings.TrimSpace(v)
	}
	return ""
}
