package ssh

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	xssh "github.com/runZeroInc/excrypto/x/crypto/ssh"
)

// Banner connects to an SSH port and returns the server identification string
// (e.g. "SSH-2.0-OpenSSH_7.4", "SSH-2.0-dropbear_2016.74", "SSH-2.0-mpSSH_0.0.1").
// It reads only the banner line and closes; no key exchange occurs.
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
	// RFC 4253 §4.2: the server identification string begins "SSH-". A server MAY
	// send other lines before it, so scan lines rather than trusting the first.
	// A response with no "SSH-" line is not an SSH banner (HTTP-proxy replies,
	// binary services, and sshd overload messages must not be reported as ssh.version
	// or fed to SSHBanner fingerprinting), so reject it rather than returning garbage.
	for ln := range strings.SplitSeq(string(buf[:n]), "\n") {
		if ln = strings.TrimRight(ln, "\r"); strings.HasPrefix(ln, "SSH-") {
			return ln, nil
		}
	}
	return "", fmt.Errorf("not an SSH banner")
}

// SoftwareVersion returns the softwareversion field of an RFC 4253 §4.2 server
// identification string: "SSH-2.0-mpSSH_0.2.1" -> "mpSSH_0.2.1". Any trailing
// SP-separated comment is kept, since some fingerprints key off it (Oracle ILOM
// identifies as "OpenSSH_7.4p1 +ILOM.1").
//
// The bmcfp SSHBanner rules are anchored to this field, not to the whole line,
// so every value fed to bmcfp.SSHBanner must pass through here first. Feeding
// the raw line instead silently kills every ^-anchored rule.
func SoftwareVersion(banner string) string {
	rest, ok := strings.CutPrefix(banner, "SSH-")
	if !ok {
		return banner
	}
	// rest is "protoversion-softwareversion[ comments]"; the protoversion may
	// not itself contain a '-', so the first '-' ends it.
	_, sw, ok := strings.Cut(rest, "-")
	if !ok {
		return banner
	}
	return sw
}

// FingerprintBanner maps an SSH banner to a short product label, a vendor slug
// (for bmcfp / identify), and any associated CVEs for known-weak BMC SSH stacks.
func FingerprintBanner(banner string) (product, vendor string, cves []string) {
	b := strings.ToLower(banner)
	switch {
	case strings.Contains(b, "mpssh"):
		// HPE iLO Management Processor SSH ("mpSSH_<ver>"): the iLO daemon's own
		// banner, present only on HPE iLO (iLO4/iLO5). The version token is
		// invariant across firmware builds so it carries no version signal, and
		// it is not shared with any other vendor (ATEN/Supermicro ship dropbear).
		return "mpSSH (HPE iLO)", "hpe", nil
	case strings.Contains(b, "dropbear"):
		// Report the build but no CVEs: banner-version-inferred SSH CVEs
		// (Dropbear/OpenSSH) are too noisy and rarely reflect the actual patch
		// level, so we surface the version and leave CVE attribution to a
		// version-gated advisory step, not the banner.
		return "Dropbear " + afterUnderscore(banner), "", nil
	case strings.Contains(b, "openssh"):
		return "OpenSSH " + afterUnderscore(banner), "", nil
	case strings.Contains(b, "cryptlib"):
		// cryptlib is an embedded SSH library, not a vendor stack: APC AOS ships it,
		// and so did HP iLO2. Attributing it to iLO contradicts the bmcfp rule, which
		// maps cryptlib to apc/NMC, and the corroborating signals on cryptlib
		// responders are almost entirely APC. The banner alone cannot separate APC
		// from a surviving iLO2, so the product label stays neutral and the vendor
		// matches bmcfp; identity comes from the fold of other signals.
		return "cryptlib", "apc", nil
	case strings.Contains(b, "lancom"), strings.Contains(b, "racssh"):
		return banner, "", nil
	}
	return banner, "", nil
}

// TryDefaults attempts a capped, ordered set of user:pass pairs over SSH and
// returns the first that authenticates, along with a short capture from the
// authenticated session (proof). It is an active login (lockout risk); callers
// gate it behind --disable-logins. Weak host keys are accepted since BMCs ship
// self-signed keys.
func TryDefaults(host string, port int, timeout time.Duration, pairs [][2]string, max int) (user, pass, output string, ok bool) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	// Overall budget across all attempts: a slow/rate-limiting BMC SSH daemon
	// (e.g. ATEN dropbear or iLO mpSSH) can stall each handshake for tens of
	// seconds, so cap the
	// whole spray to keep the check bounded even with several pairs.
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
		// Keep library-default KEX list (modern + compatible) and broaden ciphers
		// with a small legacy set for older BMC daemons.
		cfg.Ciphers = append(cfg.Ciphers, "aes128-cbc", "3des-cbc", "aes128-ctr")
		if u, pw, out, ok := tryOne(addr, timeout, cfg, p); ok {
			return u, pw, out, ok
		}
	}
	return "", "", "", false
}

// tryOne runs a single authenticated-login attempt with a deadline covering the
// SSH handshake and auth. This is essential: xssh.ClientConfig.Timeout bounds
// Only the TCP dial, not NewClientConn (version exchange + KEX + auth), so a
// daemon that accepts the connection then stalls during auth would otherwise
// hang with no timeout at all.
func tryOne(addr string, timeout time.Duration, cfg *xssh.ClientConfig, p [2]string) (user, pass, output string, ok bool) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", "", "", false
	}
	// Hard watchdog: force the underlying socket closed after a fixed budget
	// covering the handshake (NewClientConn) plus the session-proof command.
	// x/crypto/ssh drives all its I/O over conn, so closing conn unblocks any
	// read/write that stalled past the deadline (a rate-limiting or malicious
	// BMC that stops responding mid-KEX would otherwise wedge this goroutine
	// even though ClientConfig.Timeout only bounds the TCP dial). Stopped on the
	// normal path so a healthy session is never truncated early.
	watchdog := time.AfterFunc(2*timeout+time.Second, func() { _ = conn.Close() })
	defer watchdog.Stop()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	cc, chans, reqs, err := xssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return "", "", "", false
	}
	_ = conn.SetDeadline(time.Time{}) // clear the handshake deadline for the live session
	c := xssh.NewClient(cc, chans, reqs)
	out := sessionProof(c, timeout)
	_ = c.Close()
	return p[0], p[1], out, true
}

// sessionProof opens a session on an authenticated client and captures a short
// proof of access: the output of a benign identity command, or the interactive
// shell/CLI banner if the BMC's restricted shell rejects exec.
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

// keyboardInteractive answers every prompt with the password (BMC SSH often
// uses keyboard-interactive rather than the password method).
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
