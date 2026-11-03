package ipmi

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// SMCShellExec connects to a deployed smc-restore-shell (stunnel client-authenticated root
// shell) on host:port using the pinned client identity, runs script as root, and
// returns its combined output. It is the oobscan-native, non-interactive
// counterpart of the generated connect.sh.
//
// This is the transport behind `mem ... via=shell`: it reaches the BMC's own
// /dev/mem (arbitrary physical memory) and /proc/<pid>/mem (process virtual
// memory) directly, which is a full bypass of the IPMI 0x30/0x70/0xC0 read
// allowlist and of a firmware with no physical-write primitive at all. Deploy the
// service first with `ipmi ... smc-restore-shell --apply`.
func SMCShellExec(host string, port int, cert *SMCShellClientCert, script string, timeout time.Duration) (string, error) {
	if cert == nil {
		return "", errors.New("smcshell: no pinned client cert; deploy the service with 'ipmi ... smc-restore-shell --apply' and reuse ~/.cache/oobscan/smcrestore-shell.pem")
	}
	if len(cert.CertPEM) == 0 || len(cert.KeyPEM) == 0 {
		return "", errors.New("smcshell: client cert is missing its certificate or key half")
	}
	tlsCert, err := tls.X509KeyPair(cert.CertPEM, cert.KeyPEM)
	if err != nil {
		return "", fmt.Errorf("smcshell: load pinned client key pair: %w", err)
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	// The board presents a self-signed Supermicro cert; trust is anchored the other
	// way (stunnel verify=4 pins our byte-identical client cert), so server-name
	// verification is intentionally skipped. OpenSSL 1.0.1 / stunnel 4.56 on-board
	// needs a low TLS floor.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp",
		fmt.Sprintf("%s:%d", host, port), &tls.Config{
			Certificates:       []tls.Certificate{tlsCert},
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		})
	if err != nil {
		return "", fmt.Errorf("smcshell: connect %s:%d (is the service deployed and the BMC booted?): %w", host, port, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// The service runs a root shell reading commands from the socket. Send the
	// script, a trailing marker, then exit so the shell closes and we read to EOF.
	// With pty=yes the terminal echoes the `echo <marker>` input too, so the
	// marker is recognized only when the shell prints it as its own output line.
	const marker = "__OOBSCAN_SHELL_DONE__"
	if _, err := io.WriteString(conn, script+"\necho "+marker+"\nexit\n"); err != nil {
		return "", fmt.Errorf("smcshell: write script: %w", err)
	}
	var sb strings.Builder
	buf := make([]byte, 8192)
	for {
		n, rerr := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if rerr != nil {
			if rerr != io.EOF && !strings.Contains(rerr.Error(), "closed") && sb.Len() == 0 {
				return "", fmt.Errorf("smcshell: read: %w", rerr)
			}
			break
		}
		if _, found := smcShellOutputBeforeMarker(sb.String(), marker); found {
			break
		}
	}
	out, _ := smcShellOutputBeforeMarker(sb.String(), marker)
	return out, nil
}

// smcShellOutputBeforeMarker returns output before a marker that occupies an
// entire terminal line. A PTY echoes `echo <marker>` as a command line, which
// must not be mistaken for the shell's marker output.
func smcShellOutputBeforeMarker(out, marker string) (string, bool) {
	start := 0
	for _, line := range strings.SplitAfter(out, "\n") {
		trimmed := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if trimmed == marker {
			return out[:start], true
		}
		start += len(line)
	}
	return out, false
}
