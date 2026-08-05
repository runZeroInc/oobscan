package check

import (
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

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

func explainField(f engine.Finding, key string) string {
	want := engine.CanonicalFieldKey(key)
	for _, fld := range f.Fields {
		if engine.CanonicalFieldKey(fld.Key) == want {
			return fld.Val
		}
	}
	return ""
}

func explainSh(cmds ...string) string {
	return "```sh\n" + strings.Join(cmds, "\n") + "\n```"
}

func explainPortOrDefault(f engine.Finding, def int) int {
	if f.Port != 0 {
		return f.Port
	}
	return def
}

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

func explainDisplayUser(u string) string {
	if u == "" || u == "(null)" {
		return ""
	}
	return u
}
