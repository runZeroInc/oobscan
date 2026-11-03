package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/runZeroInc/oobscan/pkg/redfish"
)

var (
	redfishUser        string
	redfishPassword    string
	redfishPort        int
	redfishTimeout     time.Duration
	redfishManagerPath string

	// RemoteXDP service-config overrides
	redfishXDPSecurePort     int
	redfishXDPTLS            bool
	redfishXDPNonsecure      bool
	redfishXDPSessionTimeout int
)

var redfishCmd = &cobra.Command{
	Use:   "redfish [flags] <command> ...",
	Short: "Run authenticated Redfish OEM operations against a BMC.",
	Long: `redfish drives authenticated Redfish operations (via oobscan's Redfish stack)
for triage and remediation. Authentication uses the Redfish SessionService with
an HTTP Basic fallback; TLS certificate verification is disabled for the typical
self-signed BMC leaf. Use a trusted, restricted management path and only targets
you are authorized to administer. State-changing operations execute immediately;
there is no general dry-run mode.`,
}

var redfishXDPCmd = &cobra.Command{
	Use:   "xdp <enable|disable> [port]",
	Short: "Enable or disable H3C OEM RemoteXDP (At-Scale-Debug/JTAG) via Redfish.",
	Long: `xdp toggles H3C's OEM RemoteXDP service (Intel At-Scale-Debug over JTAG,
served on tcp/6868 by default) by PATCHing the Manager NetworkProtocol resource
Oem.Public.Services.RemoteXDP.

	redfish --user admin --password '...' <host> xdp enable [port]
	redfish --user admin --password '...' <host> xdp disable

Beyond the on/off state you can set the full service config:

	--secure-port N        TLS listener port
	--tls                  enable the TLS/secure listener (SecurePortState)
	--nonsecure            enable the plaintext listener (NonsecurePortState)
	--session-timeout N    idle session timeout (seconds)

Only flags you pass are sent, so you can change one field (e.g. --tls) without
disturbing the rest. This is a state-changing operation; only run it against
systems you are authorized to modify.`,
	Args: cobra.RangeArgs(2, 3),
	RunE: func(cmd *cobra.Command, args []string) error {
		host := args[0]
		action := args[1]
		var enable bool
		switch action {
		case "enable":
			enable = true
		case "disable":
			enable = false
		default:
			return fmt.Errorf("unsupported xdp action %q (want enable|disable)", action)
		}
		port := 6868
		portSet := false
		if len(args) == 3 {
			p, err := strconv.Atoi(args[2])
			if err != nil {
				return fmt.Errorf("invalid port %q", args[2])
			}
			port = p
			portSet = true
		}
		return runRedfishXDP(cmd, host, enable, port, portSet)
	},
}

func runRedfishXDP(cmd *cobra.Command, host string, enable bool, port int, portSet bool) error {
	if redfishUser == "" {
		return fmt.Errorf("--user is required")
	}
	timeout := redfishTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	client := redfish.InsecureClient(timeout)
	base := redfish.BaseURL(host, redfishPort)

	res := redfish.OpenSession(client, base, redfishUser, redfishPassword, timeout)
	if !res.Authenticated && res.Token == "" {
		return fmt.Errorf("redfish authentication failed for %s@%s", redfishUser, host)
	}
	headers := map[string]string{}
	if res.Token != "" {
		headers["X-Auth-Token"] = res.Token
		defer redfish.DeleteSession(client, base, res.SessionURI, res.Token, timeout)
	} else {
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(redfishUser+":"+redfishPassword))
	}
	log().Infof("redfish: authenticated via %s", firstNonEmptyStr(res.Via, "session"))

	action := "disable"
	if enable {
		action = "enable"
	}

	// Build the config: CurrentState always tracks enable/disable. On enable the
	// nonsecure listener defaults on; other fields are only sent when the caller
	// specifies them (or provides an explicit positional port).
	cfg := redfish.RemoteXDPConfig{CurrentState: &enable}
	if enable {
		ns := true
		cfg.NonsecurePortState = &ns
		cfg.NonsecurePort = &port
	} else if portSet {
		cfg.NonsecurePort = &port
	}
	f := cmd.Flags()
	if f.Changed("nonsecure") {
		v := redfishXDPNonsecure
		cfg.NonsecurePortState = &v
	}
	if f.Changed("secure-port") {
		v := redfishXDPSecurePort
		cfg.SecurePort = &v
	}
	if f.Changed("tls") {
		v := redfishXDPTLS
		cfg.SecurePortState = &v
	}
	if f.Changed("session-timeout") {
		v := redfishXDPSessionTimeout
		cfg.SessionTimeout = &v
	}

	patch, err := redfish.SetRemoteXDP(client, base, redfishManagerPath, headers, cfg, timeout)
	if err != nil {
		return fmt.Errorf("set RemoteXDP: %w", err)
	}

	out := map[string]any{
		"action":     "xdp " + action,
		"host":       host,
		"port":       port,
		"httpStatus": patch.Status,
		"ok":         patch.OK,
	}
	// Best-effort read-back of the resulting state.
	if state, _, gerr := redfish.GetRemoteXDP(client, base, redfishManagerPath, headers, timeout); gerr == nil && state != nil {
		out["state"] = state
	}
	printJSON(out)
	if !patch.OK {
		return fmt.Errorf("RemoteXDP PATCH returned HTTP %d", patch.Status)
	}
	return nil
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func init() {
	pf := redfishCmd.PersistentFlags()
	pf.StringVarP(&redfishUser, "user", "u", "", "Redfish username")
	pf.StringVarP(&redfishPassword, "password", "p", "", "Redfish password")
	pf.IntVar(&redfishPort, "port", 0, "HTTPS port (0 or 443 = default)")
	pf.DurationVar(&redfishTimeout, "timeout", 15*time.Second, "request timeout")
	pf.StringVar(&redfishManagerPath, "manager-path", redfish.RemoteXDPManagerPath, "Manager NetworkProtocol resource path")

	xf := redfishXDPCmd.Flags()
	xf.IntVar(&redfishXDPSecurePort, "secure-port", 0, "RemoteXDP TLS/secure listener port")
	xf.BoolVar(&redfishXDPTLS, "tls", false, "enable the TLS/secure listener (SecurePortState)")
	xf.BoolVar(&redfishXDPNonsecure, "nonsecure", true, "enable the plaintext listener (NonsecurePortState)")
	xf.IntVar(&redfishXDPSessionTimeout, "session-timeout", 0, "idle session timeout in seconds")

	redfishCmd.AddCommand(redfishXDPCmd)
	rootCmd.AddCommand(redfishCmd)
}
