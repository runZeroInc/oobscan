package cmd

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// smcShellDefaultPort matches the smc-restore-shell --shell-port default.
const smcShellDefaultPort = 4444

var smcShellCmd = &cobra.Command{
	Use:   "smc-shell <host> [port]",
	Short: "Connect to a deployed stunnel root shell for authorized break-glass investigation.",
	Long: `smc-shell opens an interactive TLS session to the certificate-authenticated root shell that
smc-restore-shell deploys on Supermicro/ATEN BMCs, using the pinned client
certificate from that deploy. No IPMI session is opened; the stunnel service is
the transport.

The client identity is loaded from --cert-path (default
~/.cache/oobscan/smcrestore-shell.pem, the same file smc-restore-shell generates
and reuses across deploys). Deploy the service first:

	oobscan smc-restore-shell -u ADMIN -P ADMIN <host> --apply

Then connect (port defaults to 4444, the smc-restore-shell default):

	oobscan smc-shell 10.0.0.10
	oobscan smc-shell 10.0.0.10 2223
	oobscan smc-shell 10.0.0.10 4444 --cert-path /path/to/client.pem

The BMC shell runs as uid 0 in a pseudo-terminal. This is full administrative
access, not a read-only diagnostic session. The client does not verify the BMC's
server certificate and allows legacy TLS; use a trusted, restricted management
path. Remove the deployed service after the investigation and verify cleanup.

End the session with "exit",
or press ^C/^D to close the connection locally. When stdin is not a terminal the
session is a plain pipe (an "exit" is sent automatically on stdin EOF), so
commands can be scripted exactly like the generated connect.sh:

	printf 'uname -a; cat /proc/mtd\n' | oobscan smc-shell 10.0.0.10`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runSMCShell,
}

func init() {
	registerSMCCertPathFlag(smcShellCmd)
	rootCmd.AddCommand(smcShellCmd)
}

func runSMCShell(cmd *cobra.Command, args []string) error {
	host := strings.TrimSpace(args[0])
	if host == "" {
		return fmt.Errorf("smc-shell: a host is required")
	}
	port, err := parseSMCShellPort(args)
	if err != nil {
		return err
	}

	certPath := resolveSMCShellCertPath(smcCertPath)
	cert, err := readSMCShellClientCert(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("smc-shell: no client cert at %s (deploy the service first with 'oobscan smc-restore-shell ... --apply', or pass --cert-path)", certPath)
		}
		return fmt.Errorf("smc-shell: %w", err)
	}
	tlsCert, err := tls.X509KeyPair(cert.CertPEM, cert.KeyPEM)
	if err != nil {
		return fmt.Errorf("smc-shell: load client key pair from %s: %w", certPath, err)
	}

	// Same trust model as ipmi.SMCShellExec: the board presents a self-signed
	// cert and stunnel verify=4 pins our byte-identical client cert, so server
	// verification is intentionally skipped and the TLS floor stays low for the
	// on-board OpenSSL 1.0.1 / stunnel 4.56.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp",
		net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{
			Certificates:       []tls.Certificate{tlsCert},
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		})
	if err != nil {
		return fmt.Errorf("smc-shell: connect %s:%d: %w", host, port, err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	fmt.Fprintf(os.Stderr, "smc-shell: connected to %s (TLS %s, client cert %s)\n",
		conn.RemoteAddr(), tlsVersionName(state.Version), certPath)
	fmt.Fprintf(os.Stderr, "smc-shell: session ready; type 'exit' or press ^C/^D to quit\n")
	return runSMCShellSession(conn)
}

// parseSMCShellPort resolves the optional [port] argument, defaulting to the
// smc-restore-shell service port.
func parseSMCShellPort(args []string) (int, error) {
	if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
		return smcShellDefaultPort, nil
	}
	p, err := strconv.Atoi(strings.TrimSpace(args[1]))
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("smc-shell: invalid port %q", args[1])
	}
	return p, nil
}

// runSMCShellSession wires the TLS connection to stdin/stdout. On a terminal it
// switches to raw mode and adapts line endings both ways: the local terminal
// sends CR for Enter while the BMC shell splits commands on LF, and the shell's
// bare-LF output needs CRLF for a raw terminal. Piped stdin/stdout pass through
// unchanged so scripted use matches the generated connect.sh.
func runSMCShellSession(conn net.Conn) error {
	stdinFD := int(os.Stdin.Fd())
	stdoutFD := int(os.Stdout.Fd())
	interactive := term.IsTerminal(stdinFD) && term.IsTerminal(stdoutFD)

	if interactive {
		oldState, err := term.MakeRaw(stdinFD)
		if err == nil {
			defer func() { _ = term.Restore(stdinFD, oldState) }()
		} else {
			interactive = false
		}
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := os.Stdin.Read(buf)
			if n > 0 {
				if interactive {
					// stunnel allocates a PTY but the firmware does not grant it as
					// the shell's controlling terminal, so terminate these locally.
					for i := 0; i < n; i++ {
						if buf[i] == 3 || buf[i] == 4 { // ^C / ^D
							fmt.Fprintf(os.Stderr, "\r\nsmc-shell: session closed\r\n")
							_ = conn.Close()
							os.Exit(0)
						}
					}
					// Enter arrives as CR; the BMC shell wants LF.
					for i := 0; i < n; i++ {
						if buf[i] == '\r' {
							buf[i] = '\n'
						}
					}
				}
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				// stdin closed (e.g. a pipe ran dry): end the remote shell so
				// the connection unwinds instead of hanging half-open.
				_, _ = conn.Write([]byte("exit\n"))
				return
			}
		}
	}()

	var w io.Writer = os.Stdout
	if interactive {
		w = &crlfWriter{w: os.Stdout}
	}
	_, _ = io.Copy(w, conn)
	// The remote shell exited and closed its side. Close ours too so a stdin
	// writer still blocked on the next keystroke errors out instead of hanging
	// the exit; the process terminates without waiting for it.
	_ = conn.Close()
	return nil
}

// tlsVersionName renders a TLS version for the connection banner.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// crlfWriter expands bare LF into CRLF for a terminal in raw mode, leaving
// CRLF pairs the remote already sent untouched.
type crlfWriter struct {
	w      io.Writer
	lastCR bool
}

func (c *crlfWriter) Write(p []byte) (int, error) {
	var out []byte
	for _, b := range p {
		if b == '\n' && !c.lastCR {
			out = append(out, '\r')
		}
		out = append(out, b)
		c.lastCR = b == '\r'
	}
	if len(out) == 0 {
		return len(p), nil
	}
	if _, err := c.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}
