package check

import (
	"context"
	"strconv"

	"github.com/runZeroInc/oobscan/pkg/cim"
	"github.com/runZeroInc/oobscan/pkg/creds"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

// http.cim.defaultCreds confirms a default credential on the CIM-XML (WBEM)
// surface, which is separate from web/IPMI and can retain a shipped default
// after those are rotated. Because CIM Basic auth usually maps to a real
// OS/PAM account, it is conservative: gated on a confirmed CIMOM and
// !DisableLogins, tries ordered candidates (operator creds, vendor defaults,
// else the documented BMC set) capped and stopping at first success, using
// the read-only EnumerateClassNames intrinsic.
func init() {
	Register(Check{
		Name:        "http.cim.defaultCreds",
		Description: "Active CIM-XML/WBEM default-credential login (5988/5989): confirms a default kept on the separate WBEM surface after the web/IPMI password changed, or when only WBEM is reachable; vendor-targeted, capped, online only",
		Category:    "creds",
		Applies:     Applicability{CrossVendor: true}, // self-gated on a confirmed CIMOM below
		Enabled:     true,
		Run:         runCIMDefaultCreds,
	})
}

// maxCIMAttempts caps CIM Basic-auth logins per host. CIM auth typically maps to
// a real OS/PAM account, so this stays well under any lockout threshold.
const maxCIMAttempts = 4

// cimNegControlUser/Pass is a deliberately-invalid credential tested as a
// negative control before crediting any real default: a genuinely
// authenticating CIMOM must reject it (401/403), while one that accepts it is
// anonymous or accept-any, making any "default" success there a false
// positive -- as seen with an OpenPegasus CIMOM that 200s every request, and
// a CIMOM that 401s only with no Authorization header but 200s for any
// credential. The username is non-existent, so it never trips a real lockout.
const (
	cimNegControlUser = "oobscan-nouser-9f3a2c7b1e"
	cimNegControlPass = "oobscan-nopass-4e1d8a6f52"
)

func runCIMDefaultCreds(ctx context.Context, t *engine.Target) []engine.Finding {
	if t.DisableLogins {
		return nil // active login; skipped under --disable-logins
	}
	// Self-gate: only proceed against a CIMOM identify already confirmed.
	ev, ok := t.Evidenced("cim")
	if !ok {
		return nil
	}
	res, _ := ev.(*cim.Result)
	if res == nil || res.Port <= 0 {
		return nil
	}
	scheme := res.Scheme
	if scheme == "" {
		scheme = "https"
	}
	hostPort := netaddr.URLHostPort(t.Host, res.Port)

	cands := cimCandidates(t)
	if len(cands) == 0 {
		return nil
	}
	client := httpx.Client(t.Timeout)

	// Negative control first: prove the WBEM surface actually validates
	// credentials before crediting any default. If a definitely-invalid credential
	// is accepted, the CIMOM is anonymous / accept-any, so no specific default can
	// be attributed -- skip rather than emit a false positive.
	if okCtrl, _ := cim.AuthenticateContext(ctx, client, scheme, hostPort, cimNegControlUser, cimNegControlPass); okCtrl {
		return nil
	}

	attempts := 0
	for _, c := range cands {
		if ctx.Err() != nil || attempts >= maxCIMAttempts {
			break
		}
		attempts++
		okAuth, evidence := cim.AuthenticateContext(ctx, client, scheme, hostPort, c.user, c.pass)
		if !okAuth {
			continue
		}
		if evidence == nil {
			evidence = &cim.AuthEvidence{}
		}
		t.MarkOpen(res.Port, "tcp", "cim-xml")
		return []engine.Finding{{
			Check:     "http.cim.defaultCreds",
			Category:  "creds",
			Risk:      "critical",
			Port:      res.Port,
			Transport: "tcp",
			Protocol:  "cim-xml",
			Fields: engine.F(
				"username", c.user,
				"password", c.pass,
				"scheme", scheme,
				"source", c.src,
				"sessionAuthenticated", "true",
				"namespace", "root/cimv2",
				"authProbe", "EnumerateClassNames",
				"classCount", strconv.Itoa(evidence.ClassCount),
				"negativeControl", "rejected",
				"systemClass", evidence.System.ClassName,
				"systemName", evidence.System.Name,
				"elementName", evidence.System.ElementName,
				"caption", evidence.System.Caption,
				"description", evidence.System.Description,
				"manufacturer", evidence.System.Manufacturer,
				"model", evidence.System.Model,
				"serialNumber", evidence.System.SerialNumber,
				"uuid", evidence.System.UUID,
				"proof", proofKV(
					"username", c.user,
					"sessionAuthenticated", "true",
					"authProbe", "EnumerateClassNames",
					"classCount", strconv.Itoa(evidence.ClassCount),
					"negativeControl", "rejected"),
			),
		}}
	}
	return nil
}

type cimCred struct{ user, pass, src string }

// cimCandidates assembles the small, ordered credential set: operator --creds
// first (verify a specific/rotated password), then the identified vendor's
// documented defaults; only when the vendor is unknown (WBEM is the sole
// surface) does it fall back to the documented BMC set -- never the broad spray.
func cimCandidates(t *engine.Target) []cimCred {
	seen := map[[2]string]bool{}
	var out []cimCred
	add := func(u, p, src string) {
		if u == "" || seen[[2]string{u, p}] {
			return
		}
		seen[[2]string{u, p}] = true
		out = append(out, cimCred{u, p, src})
	}
	for _, c := range suppliedCreds(t) {
		add(c.User, c.Pass, "cli")
	}
	if vendor := identityVendor(t); vendor != "" {
		for _, c := range creds.VendorCredsFor(vendor, creds.ClassHTTP) {
			add(c.Username, c.Password, c.Source)
		}
	} else {
		for _, c := range creds.DocumentedDefaults(creds.ClassHTTP) {
			add(c.Username, c.Password, c.Source)
		}
	}
	return out
}
