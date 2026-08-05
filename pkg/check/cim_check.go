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

func init() {
	Register(Check{
		Name:        "http.cim.defaultCreds",
		Description: "Active CIM-XML/WBEM default-credential login (5988/5989): confirms a default kept on the separate WBEM surface after the web/IPMI password changed, or when only WBEM is reachable; vendor-targeted, capped, online only",
		Category:    "creds",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runCIMDefaultCreds,
	})
}

const maxCIMAttempts = 4

const (
	cimNegControlUser = "oobscan-nouser-9f3a2c7b1e"
	cimNegControlPass = "oobscan-nopass-4e1d8a6f52"
)

func runCIMDefaultCreds(ctx context.Context, t *engine.Target) []engine.Finding {
	if t.DisableLogins {
		return nil
	}

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
