package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// TestSMC0021CommandShape locks the registration and the flags that make the
// command safe: it opens an authenticated session, it carries the confirmation
// channel, and it does not carry the config-archive crypto group.
func TestSMC0021CommandShape(t *testing.T) {
	c := findRootCommand("smc-x14-cmdinj")
	if c == nil {
		t.Fatal("smc-x14-cmdinj is not registered as a top-level command")
	}
	for _, f := range []string{"user", "password", "callback-host", "callback-port", "callback-wait", "marker", "mac", "probe-only", "apply"} {
		if c.Flags().Lookup(f) == nil {
			t.Errorf("smc-x14-cmdinj is missing --%s", f)
		}
	}
	if c.Flags().Lookup("config-key") != nil {
		t.Error("smc-x14-cmdinj should not carry the config-archive crypto flags")
	}
	// The X14-only gate is a documented precondition, so the help must say so.
	if !strings.Contains(c.Long, "X14") {
		t.Error("smc-x14-cmdinj help must state the X14-only scope")
	}
}

// TestSMC0022CommandShape locks the registration and the sink selector.
func TestSMC0022CommandShape(t *testing.T) {
	c := findRootCommand("smc-alert-cmdinj")
	if c == nil {
		t.Fatal("smc-alert-cmdinj is not registered as a top-level command")
	}
	for _, f := range []string{"user", "password", "sink", "smtp-fields", "pef-channel", "pef-destination", "web-user", "web-pass", "callback-host", "marker", "apply"} {
		if c.Flags().Lookup(f) == nil {
			t.Errorf("smc-alert-cmdinj is missing --%s", f)
		}
	}
	if c.Flags().Lookup("config-key") != nil {
		t.Error("smc-alert-cmdinj should not carry the config-archive crypto flags")
	}
}

// TestParseSMC0022Sink locks the sink selector, including the default.
func TestParseSMC0022Sink(t *testing.T) {
	for in, want := range map[string]string{"": "both", "both": "both", "smtp": "smtp", "SNMP": "snmp", " smtp ": "smtp"} {
		got, err := parseSMC0022Sink(in)
		if err != nil || got != want {
			t.Errorf("parseSMC0022Sink(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := parseSMC0022Sink("carrier-pigeon"); err == nil {
		t.Error("an unknown sink must be refused")
	}
}

// TestParseSMC0022Fields locks the SMTP field selector and its default. The
// default is the server field because it is the only one injectable on every
// affected generation.
func TestParseSMC0022Fields(t *testing.T) {
	got, err := parseSMC0022Fields("")
	if err != nil || len(got) != 1 || got[0] != 0x01 {
		t.Fatalf("default fields = %v, %v; want [0x01]", got, err)
	}
	got, err = parseSMC0022Fields("server,user,password,sender")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x01, 0x03, 0x04, 0x05}
	if len(got) != len(want) {
		t.Fatalf("fields = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("fields = %v, want %v", got, want)
		}
	}
	if _, err := parseSMC0022Fields("bcc"); err == nil {
		t.Error("an unknown SMTP field must be refused")
	}
}

// TestParseSMCWebCSRFToken covers both SmcCsrfInsert spellings the generations
// use, plus the hidden-field fallback.
func TestParseSMCWebCSRFToken(t *testing.T) {
	cases := map[string]string{
		`<script>SmcCsrfInsert("CSRF-TOKEN", "abc123");</script>`: "abc123",
		`<script>SmcCsrfInsert("CSRF_TOKEN", "def456");</script>`: "def456",
		`<input type="hidden" name="csrf_token" value="ghi789">`:  "ghi789",
		`<html>no token here</html>`:                              "",
		`<script>SmcCsrfInsert("CSRF-TOKEN", "");</script>`:       "",
	}
	for body, want := range cases {
		if got := parseSMCWebCSRFToken(body); got != want {
			t.Errorf("parseSMCWebCSRFToken(%q) = %q, want %q", body, got, want)
		}
	}
}

// TestSMC0022ReportJSON locks the JSON shape and the honesty of the verdict
// fields: an unconfirmed run must not read as a confirmed one.
func TestSMC0022ReportJSON(t *testing.T) {
	prev := ipmiOutputFormat
	ipmiOutputFormat = "json"
	defer func() { ipmiOutputFormat = prev }()

	rep := newSMC0022Report("192.0.2.10")
	rep.Generation = "X10"
	rep.Sink = "smtp"
	rep.InjectedValue = "x;id>/tmp/oobscan_marker;#"
	rep.Fields = []smc0022FieldResult{{Sink: "smtp", Field: "server", FieldID: "0x01", SetCC: "0x00", Stored: true}}
	rep.Verdict = "NOT CONFIRMED: no callback arrived"

	var buf bytes.Buffer
	if err := printIPMISMCReport(nil, &buf, rep); err != nil {
		t.Fatalf("print: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid json: %v\n%s", err, buf.String())
	}
	if decoded["finding"] != "SMC-0022" {
		t.Errorf("finding = %v", decoded["finding"])
	}
	if decoded["confirmed"] != false {
		t.Errorf("confirmed = %v, want false", decoded["confirmed"])
	}
	if got, _ := decoded["verdict"].(string); !strings.Contains(got, "NOT CONFIRMED") {
		t.Errorf("verdict = %q", got)
	}
}

// TestSMC0021ReportJSON locks the JSON shape and that the impact statement
// names root execution.
func TestSMC0021ReportJSON(t *testing.T) {
	prev := ipmiOutputFormat
	ipmiOutputFormat = "json"
	defer func() { ipmiOutputFormat = prev }()

	rep := newSMC0021Report("192.0.2.10")
	rep.Generation = "X14"
	rep.MAC = "ac:1f:6b:5b:46:ce"
	rep.MACSource = "--mac"
	rep.Verdict = "CONFIRMED: the injected command ran as root and called back"
	rep.Confirmed = true

	var buf bytes.Buffer
	if err := printIPMISMCReport(nil, &buf, rep); err != nil {
		t.Fatalf("print: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid json: %v\n%s", err, buf.String())
	}
	if decoded["finding"] != "CVE-2026-65213" {
		t.Errorf("finding = %v", decoded["finding"])
	}
	if got, _ := decoded["impact"].(string); !strings.Contains(got, "root") {
		t.Errorf("impact must name root execution, got %q", got)
	}
}

// TestPrintSMC0021TableShowsSafetyContract checks the operator-facing table
// names the MAC that is written back and the confirmation channel, which are the
// two things a reader must be able to audit after a run.
func TestPrintSMC0021TableShowsSafetyContract(t *testing.T) {
	rep := newSMC0021Report("192.0.2.10")
	rep.Generation = "X14"
	rep.MAC = "ac:1f:6b:5b:46:ce"
	rep.MACSource = "Get LAN Configuration Parameters param 5"
	rep.CallbackURL = "http://10.0.0.5:8080/tok"
	rep.MarkerPath = "/tmp/oob_marker"
	rep.PayloadBytes = 512
	rep.Verdict = "NOT CONFIRMED: no callback arrived"

	var buf bytes.Buffer
	if err := printSMC0021Table(&buf, rep); err != nil {
		t.Fatalf("print: %v", err)
	}
	got := buf.String()
	for _, want := range []string{"ac:1f:6b:5b:46:ce", "Get LAN Configuration Parameters param 5", "http://10.0.0.5:8080/tok", "/tmp/oob_marker", "NOT CONFIRMED"} {
		if !strings.Contains(got, want) {
			t.Errorf("table output missing %q:\n%s", want, got)
		}
	}
}

// TestPrintSMC0022TableShowsStoreSide checks the table distinguishes a stored
// value from a rejected one, which is the whole point of the readback.
func TestPrintSMC0022TableShowsStoreSide(t *testing.T) {
	rep := newSMC0022Report("192.0.2.10")
	rep.Generation = "X11"
	rep.Sink = "smtp"
	rep.Apply = true
	rep.InjectedValue = "x;id>/tmp/oobscan_marker;#"
	rep.Fields = []smc0022FieldResult{
		{Sink: "smtp", Field: "server", FieldID: "0x01", SetCC: "0xcc", Stored: false, Note: "rejected with 0xcc"},
	}
	rep.Verdict = "NOT CONFIRMED: no callback arrived"

	var buf bytes.Buffer
	if err := printSMC0022Table(&buf, rep); err != nil {
		t.Fatalf("print: %v", err)
	}
	got := buf.String()
	for _, want := range []string{"0xcc", "rejected with 0xcc", "NOT CONFIRMED", "X11"} {
		if !strings.Contains(got, want) {
			t.Errorf("table output missing %q:\n%s", want, got)
		}
	}
}

// TestSMC0022GenerationGates locks the applicability gates the command relies
// on: X14 is a different stack, X9 has no reachable setter, and the SNMP sink is
// absent on X10.
func TestSMC0022GenerationGates(t *testing.T) {
	for _, gen := range []string{"X10", "X11", "X12", "X13", "H13"} {
		if !ipmi.SMCCmdInj0022Generation(gen) {
			t.Errorf("%s should be on the SMC-0022 surface", gen)
		}
	}
	for _, gen := range []string{"X14", "X9", ""} {
		if ipmi.SMCCmdInj0022Generation(gen) {
			t.Errorf("%s should not be on the SMC-0022 surface", gen)
		}
	}
	for _, gen := range []string{"X11", "X12", "X13", "H13"} {
		if !ipmi.SMCCmdInj0022SNMPSink(gen) {
			t.Errorf("%s should have the SNMPv3 trap sink", gen)
		}
	}
	if ipmi.SMCCmdInj0022SNMPSink("X10") {
		t.Error("X10 has no snmptrap execution and must not report the SNMP sink")
	}
}

// TestSMC0021GenerationGate locks the X14-only scope.
func TestSMC0021GenerationGate(t *testing.T) {
	if ipmi.SMCX14FileChainGeneration != "X14" {
		t.Errorf("the RestorePSOOBBFile handler is X14-only, got %q", ipmi.SMCX14FileChainGeneration)
	}
}
