package check

// explain_helpers.go contains the small utility functions shared by every
// per-check explainer. Keeping them here (rather than in the explain package)
// means check files only need to import what they already import; the helpers
// reference only engine.Finding and standard library types.

import (
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

// explainHeading returns the level-2 markdown heading for a finding section:
//
//	## [CRITICAL] 192.0.2.1 623/udp ipmi -- ipmi.v15.authNoneSession
func explainHeading(host string, f engine.Finding) string {
	loc := ""
	if f.Port != 0 {
		loc = fmt.Sprintf(" %d/%s", f.Port, f.Transport)
	}
	if f.Protocol != "" {
		loc += " " + f.Protocol
	}
	return fmt.Sprintf("## [%s] %s%s -- %s\n", strings.ToUpper(f.Risk), host, loc, f.Check)
}

// explainField returns the value of the named field from f, or "".
func explainField(f engine.Finding, key string) string {
	want := engine.CanonicalFieldKey(key)
	for _, fld := range f.Fields {
		if engine.CanonicalFieldKey(fld.Key) == want {
			return fld.Val
		}
	}
	return ""
}

// explainSh wraps one or more shell commands in a fenced ```sh block.
func explainSh(cmds ...string) string {
	return "```sh\n" + strings.Join(cmds, "\n") + "\n```"
}

// explainPortOrDefault returns f.Port when non-zero, else def.
func explainPortOrDefault(f engine.Finding, def int) int {
	if f.Port != 0 {
		return f.Port
	}
	return def
}

// explainBaseURL constructs a base URL from the finding port and protocol,
// falling back to defaultPort and defaultScheme. No trailing slash.
func explainBaseURL(host string, f engine.Finding, defaultPort int, defaultScheme string) string {
	port := explainPortOrDefault(f, defaultPort)
	scheme := defaultScheme
	if f.Protocol == "http" || port == 80 {
		scheme = "http"
	} else if f.Protocol == "https" || f.Protocol == "redfish" || port == 443 {
		scheme = "https"
	}
	return netaddr.URL(scheme, host, port, "")
}

// explainIPMIPriv maps an IPMI privilege-level name to the ipmitool -L flag value.
func explainIPMIPriv(priv string) string {
	switch strings.ToLower(priv) {
	case "administrator", "admin":
		return "ADMINISTRATOR"
	case "operator":
		return "OPERATOR"
	case "user":
		return "USER"
	case "callback":
		return "CALLBACK"
	default:
		return "ADMINISTRATOR"
	}
}

// explainDisplayUser returns the username safe for embedding in a shell
// command: an empty string for the anonymous account, the username otherwise.
func explainDisplayUser(u string) string {
	if u == "" || u == "(null)" {
		return ""
	}
	return u
}
