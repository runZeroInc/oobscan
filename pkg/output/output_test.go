package output

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ilo"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/redfish"
	"github.com/runZeroInc/oobscan/pkg/tlscert"
)

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestTTYEmitterReportsBufferedWriteError(t *testing.T) {
	emitter := newTTYEmitterTo(io.Discard, io.Discard, errorWriter{}, true, false)
	emitter.Emit(sampleTarget())
	if err := emitter.Close(); err == nil {
		t.Fatal("Close returned nil after the records writer failed")
	}
}

func TestOutputTruncationPreservesUTF8(t *testing.T) {
	ttyValue := strings.Repeat("a", 179) + "\u00e9" + strings.Repeat("z", 20)
	if got := trimTTYField("raw", ttyValue); !utf8.ValidString(got) {
		t.Fatalf("TTY truncation produced invalid UTF-8: %q", got)
	}
	jsonValue := strings.Repeat("a", ndjsonRawFieldMax-1) + "\u00e9" + strings.Repeat("z", 20)
	fields := capJSONLargeFields(engine.F("raw", jsonValue))
	if !utf8.ValidString(fields[0].Val) {
		t.Fatalf("NDJSON truncation produced invalid UTF-8: %q", fields[0].Val)
	}
}

// TestCapJSONLargeFieldsUniversalCeiling locks the universal per-field ceiling:
// every field is bounded at 4 KiB except `response` (16 KiB, raw payloads) and
// `hash` (exempt -- crackable RAKP material must stay byte-complete).
func TestCapJSONLargeFieldsUniversalCeiling(t *testing.T) {
	big := strings.Repeat("x", 20<<10) // 20 KiB
	fields := capJSONLargeFields(engine.F(
		"server", big, // arbitrary non-response field -> 4 KiB
		"response", big, // raw payload -> 16 KiB
		"hash", big, // crackable material -> uncapped
	))
	byKey := map[string]string{}
	for _, f := range fields {
		byKey[f.Key] = f.Val
	}
	if got := len(byKey["server"]); got > ndjsonFieldMax {
		t.Errorf("server field len=%d, want <= %d", got, ndjsonFieldMax)
	}
	if got := len(byKey["response"]); got > ndjsonRawFieldMax || got <= ndjsonFieldMax {
		t.Errorf("response field len=%d, want in (%d, %d]", got, ndjsonFieldMax, ndjsonRawFieldMax)
	}
	if got := len(byKey["hash"]); got != len(big) {
		t.Errorf("hash field len=%d, want %d (uncapped)", got, len(big))
	}
}

func TestDisplayFieldsOmitsEmptyValues(t *testing.T) {
	fields := engine.Fields{
		{Key: "ilo.fw", Val: ""},
		{Key: "vendor", Val: "hpe"},
	}
	if got := displayFields(fields); got != "vendor=hpe" {
		t.Fatalf("displayFields() = %q, want vendor=hpe", got)
	}
}

func sampleTarget() *engine.Target {
	t := &engine.Target{
		Host:     "10.0.0.5",
		Ports:    []engine.Port{{Num: 623, Proto: engine.ProtoUDP}},
		Open:     engine.OpenPorts{"623/udp": "ipmi"},
		Identity: &engine.Identity{Class: engine.ClassBMC, Vendor: "dell", Product: "iDRAC9", Confidence: engine.ConfHigh},
		Findings: []engine.Finding{
			{Check: "ipmi.v20.defaultCreds", Category: "creds", Risk: "critical", Port: 623, Transport: "udp", Protocol: "ipmi", Fields: engine.F("user", "root", "pass", "calvin")},
			{Check: "ipmi.v20.rakpHash", Category: "rakp", Risk: "critical", Port: 623, Transport: "udp", Protocol: "ipmi", Fields: engine.F("user", "root", "hash", "abcd:1234")},
		},
	}
	return t
}

// TestTTYStreamsAreSeparate confirms the three output streams stay independent:
// the records file is pure NDJSON, findings render on the fancy (stdout)
// stream, and neither leaks into the other.
func TestTTYStreamsAreSeparate(t *testing.T) {
	var fancy, errw, records bytes.Buffer
	e := newTTYEmitterTo(&fancy, &errw, &records, true /*noColor*/, true /*verbose*/)
	e.Start("10.0.0.5")
	e.Emit(sampleTarget())
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	// The JSON file is one valid JSON object per line, zero ANSI bytes.
	assertCleanNDJSON(t, records.Bytes(), 1)
	// The fancy stream carries the findings...
	if !strings.Contains(fancy.String(), "ipmi.v20.defaultCreds") {
		t.Errorf("fancy stream missing finding line:\n%s", fancy.String())
	}
	// ...and with --no-color it carries no color SGR sequences.
	for _, seq := range []string{"38;5;", "\x1b[0m", "\x1b[1m"} {
		if strings.Contains(fancy.String(), seq) {
			t.Errorf("no-color fancy stream contains color sequence %q: %q", seq, fancy.String())
		}
	}
	// The JSON file must never contain a rendered finding line.
	if strings.Contains(records.String(), "CRITICAL") {
		t.Errorf("records file leaked a fancy finding line: %q", records.String())
	}
}

func TestTTYActivityEmitsProgress(t *testing.T) {
	var fancy, errw bytes.Buffer
	e := newTTYEmitterTo(&fancy, &errw, nil, true /*noColor*/, true /*verbose*/)
	e.Activity("10.0.0.5", "ipmi.fullWalk: pre-session sweep 1/1207")
	if !strings.Contains(errw.String(), "10.0.0.5") || !strings.Contains(errw.String(), "pre-session sweep") {
		t.Fatalf("activity was not rendered to stderr: %q", errw.String())
	}
}

func TestTTYPostAuthActivityAlwaysInfo(t *testing.T) {
	var fancy, errw bytes.Buffer
	e := newTTYEmitterTo(&fancy, &errw, nil, true /*noColor*/, false /*verbose*/)
	e.Activity("10.0.0.5", "post-auth ipmi start proto=ipmi port=623 flow=2.0/cred user=ADMIN source=ipmi.auth.defaultCreds")
	out := errw.String()
	if !strings.Contains(out, "INFO") || !strings.Contains(strings.ToLower(out), "post-auth ipmi start") {
		t.Fatalf("post-auth activity was not rendered as info: %q", out)
	}
}

func TestTTYStatusListsActiveHosts(t *testing.T) {
	var fancy, errw bytes.Buffer
	e := newTTYEmitterTo(&fancy, &errw, nil, true /*noColor*/, false /*verbose*/)
	e.Start("10.0.0.5")
	e.Activity("10.0.0.5", "check ipmi.defaultCreds")
	e.Checks("10.0.0.5", 3, 5)
	e.Emit(&engine.Target{Host: "10.0.0.6", Findings: []engine.Finding{
		{Check: "ipmi.v20.defaultCreds", Risk: "critical"},
		{Check: "http.redfish.authPathError", Risk: "high"},
		{Check: "ipmi.v15.authMethods", Risk: "low"},
	}})
	e.Status(2, 8, true)
	out := errw.String()
	for _, want := range []string{"Scan status", "hosts=2/8", "checks=3/5", "active=1", "critical=1", "high=1", "medium=0", "low=1", "current=\"10.0.0.5 check ipmi.defaultCreds (3/5 checks)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output %q missing %q", out, want)
		}
	}
}

func TestTTYStatusDetailedAggregatesRunningChecks(t *testing.T) {
	var fancy, errw bytes.Buffer
	e := newTTYEmitterTo(&fancy, &errw, nil, true /*noColor*/, false /*verbose*/)
	// Two hosts running the same check plus a distinct one: the shared check must
	// collapse to a single aggregated line (hosts=2), not one line per host.
	e.Start("10.0.0.5")
	e.Start("10.0.0.6")
	e.CheckStart("10.0.0.5", "ipmi.defaultCreds")
	e.CheckStart("10.0.0.6", "ipmi.defaultCreds")
	e.CheckStart("10.0.0.5", "http.idrac.defaultCreds")
	e.StatusDetailed(1, 8)
	out := errw.String()
	for _, want := range []string{
		"Scan status detail", "runningChecks=3", "checks=2",
		"Check in progress", "check=http.idrac.defaultCreds",
		"Oldest check", "host=10.0.0.", "elapsed=",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("detailed status output %q missing %q", out, want)
		}
	}
	// The shared check must collapse to a single aggregate line with hosts=2 (not
	// one line per host, and not confusable with the header's activeHosts count).
	foundAgg := false
	for ln := range strings.SplitSeq(out, "\n") {
		if strings.Contains(ln, "Check in progress") && strings.Contains(ln, "check=ipmi.defaultCreds") {
			if !strings.Contains(ln, "hosts=2") {
				t.Fatalf("aggregate line missing hosts=2: %q", ln)
			}
			foundAgg = true
		}
	}
	if !foundAgg {
		t.Fatalf("no aggregated 'Check in progress' line for ipmi.defaultCreds: %q", out)
	}
	// The old per-(host,check) flood label must be gone.
	if strings.Contains(out, "Running check") {
		t.Fatalf("expected aggregated output, still emits per-host 'Running check': %q", out)
	}
}

func TestResultJSONUsesCvesAndTimestamps(t *testing.T) {
	tgt := &engine.Target{
		Host: "10.0.0.9",
		Findings: []engine.Finding{{
			Check: "ipmi.v20.rakpHash",
			Risk:  "critical",
			CVE:   []string{"CVE-2013-4786"},
		}},
	}

	r := resultFrom(tgt)
	if r.TS == 0 {
		t.Fatal("expected host ts to be set")
	}
	if len(r.Findings) != 1 || r.Findings[0].TS == 0 {
		t.Fatalf("expected finding ts to be set, got %+v", r.Findings)
	}

	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"timestamp":`) {
		t.Fatalf("expected timestamp in json: %s", s)
	}
	if !strings.Contains(s, `"cves":"CVE-2013-4786"`) {
		t.Fatalf("expected cves field in json: %s", s)
	}
	if strings.Contains(s, `"cve":`) {
		t.Fatalf("unexpected legacy cve field in json: %s", s)
	}
}

func TestEmitterOmitsNonResponsiveTargetRecord(t *testing.T) {
	var records bytes.Buffer
	e := newTTYEmitterTo(io.Discard, io.Discard, &records, true, false)
	tgt := &engine.Target{
		Host: "192.0.2.10",
		Identity: &engine.Identity{
			Class:      engine.ClassUnknown,
			Confidence: engine.ConfLow,
		},
		Findings: []engine.Finding{{Check: "ipmi.v20.defaultCreds", Risk: "none"}},
	}

	e.Emit(tgt)
	if records.Len() != 0 {
		t.Fatalf("non-responsive target produced NDJSON: %s", records.String())
	}
}

func TestEmitterKeepsResponsiveCleanTargetRecord(t *testing.T) {
	var records bytes.Buffer
	e := newTTYEmitterTo(io.Discard, io.Discard, &records, true, false)
	tgt := &engine.Target{
		Host:     "192.0.2.11",
		Open:     engine.OpenPorts{"443/tcp": "https"},
		Findings: []engine.Finding{{Check: "http.web.defaultCreds", Risk: "none"}},
	}

	e.Emit(tgt)
	if !strings.Contains(records.String(), `"host":"192.0.2.11"`) {
		t.Fatalf("responsive clean target missing from NDJSON: %s", records.String())
	}
}

func TestResultJSONIncludesRedfishPostAuthEvidence(t *testing.T) {
	tgt := &engine.Target{Host: "10.0.0.19", Evidence: map[string]any{}}
	tgt.SetEvidence("redfish.postAuth", &redfish.PostAuthSnapshot{
		Method: "providedCreds",
		Via:    "session",
		User:   "root",
		Source: "cli",
		Info: redfish.SystemInfo{
			Vendor:          "OpenBMC",
			Model:           "X470D4U",
			FirmwareVersion: "2.14.0",
		},
	})
	r := resultFrom(tgt)
	if r.RFPost == nil || r.RFPost.User != "root" {
		t.Fatalf("expected redfish postauth evidence, got %+v", r.RFPost)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if !strings.Contains(string(b), `"redfishPostAuth"`) {
		t.Fatalf("expected redfishPostAuth in json: %s", string(b))
	}
}

func TestResultJSONKeysAreCamelCaseAndCSVSorted(t *testing.T) {
	tgt := &engine.Target{
		Host: "10.0.0.20",
		Open: engine.OpenPorts{"443/tcp": "redfish,https"},
		Identity: &engine.Identity{
			Class:      engine.ClassBMC,
			Vendor:     "dell",
			Product:    "iDRAC9",
			Confidence: engine.ConfHigh,
			Attributes: map[string]string{
				"dell.service_tag": "ABC1234",
				"http.server":      "Apache",
				"idrac.fw":         "7.00.00.00",
			},
		},
		Final: &engine.Final{
			Class:      engine.ClassBMC,
			Vendor:     "dell",
			Product:    "iDRAC9",
			Confidence: engine.ConfHigh,
			Flags:      map[string]string{"defaultCreds": "critical", "rakpHash": "critical"},
			Findings:   1,
			TopRisk:    "critical",
		},
		Findings: []engine.Finding{
			{Check: "z.clean", Risk: "none"},
			{Check: "a.clean", Risk: "none"},
			{
				Check: "http.idrac.defaultCreds", Category: "creds", Risk: "critical",
				Fields: engine.F(
					"username", "root",
					"password", "calvin",
					"evidenceEndpoint", "/redfish/v1/SessionService/Sessions",
					"match", "zeta,alpha",
				),
				CVE: []string{"CVE-2024-2", "CVE-2023-1"},
			},
		},
		Evidence: map[string]any{},
	}
	tgt.SetEvidence("ipmi.postAuth", &ipmi.PostAuthCollection{
		LAN: map[string]string{
			"community_string":   "public",
			"default_gateway_ip": "192.0.2.1",
		},
		Error:        "before fru: context deadline exceeded",
		Completed:    []string{"mcInfo", "lan"},
		IncompleteAt: "fru",
	})
	tgt.SetEvidence("redfish.postAuth", &redfish.PostAuthSnapshot{User: "root"})

	b, err := json.Marshal(resultFrom(tgt))
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	s := string(b)
	for _, want := range []string{
		`"attemptedChecks":"a.clean,z.clean"`,
		`"finalIdentity"`,
		`"ipmiPostAuth"`,
		`"redfishPostAuth"`,
		`"defaultCreds":"critical"`,
		`"rakpHash":"critical"`,
		`"dellServiceTag":"ABC1234"`,
		`"idracFirmwareVersion":"7.00.00.00"`,
		`"username":"root"`,
		`"password":"calvin"`,
		`"evidenceEndpoint":"/redfish/v1/SessionService/Sessions"`,
		`"match":"alpha,zeta"`,
		`"cves":"CVE-2023-1,CVE-2024-2"`,
		`"communityString":"public"`,
		`"defaultGatewayIp":"192.0.2.1"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("expected %s in json: %s", want, s)
		}
	}
	// "context deadline exceeded" stays out: a scan-side transport error is not device
	// evidence. `completed`/`incompleteAt` are no longer excluded -- they are the
	// coverage record, and without them an empty-but-attempted section is
	// indistinguishable from one never attempted. See
	// TestPostAuthCollectionOmitsOperationalStatusFromJSON.
	for _, legacy := range []string{"attempted_checks", "id.final", "ipmi_postauth", "redfish_postauth", "evidence_endpoint", "community_string", `"user":`, `"pass":`, "context deadline exceeded"} {
		if strings.Contains(s, legacy) {
			t.Fatalf("unexpected legacy key %q in json: %s", legacy, s)
		}
	}

	var decoded any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	assertNoSnakeOrDottedKeys(t, decoded, "$", false)
}

func assertNoSnakeOrDottedKeys(t *testing.T, v any, path string, inPorts bool) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if !inPorts && (strings.Contains(k, "_") || strings.Contains(k, ".")) {
				t.Fatalf("non-camelCase key at %s: %q", path, k)
			}
			assertNoSnakeOrDottedKeys(t, child, path+"."+k, k == "ports")
		}
	case []any:
		for i, child := range x {
			assertNoSnakeOrDottedKeys(t, child, fmt.Sprintf("%s[%d]", path, i), inPorts)
		}
	}
}

func TestTTYStaticArchiveExposureDisplaySummary(t *testing.T) {
	var fancy, errw, records bytes.Buffer
	e := newTTYEmitterTo(&fancy, &errw, &records, true /*noColor*/, true /*verbose*/)

	fullArchive := strings.Join([]string{
		"$metadata",
		"ActivateLicense_v1.xml",
		"ClearLicense_v1.xml",
		"DeviceUpdate_v1.xml",
		"DumpCollection_v1.xml",
		"DumpService_v1.xml",
		"Dump_v1.xml",
		"FanMode_v1.xml",
		"FilterRuleCollection_v1.xml",
		"FilterRule_v1.xml",
	}, ", ")

	target := &engine.Target{
		Host: "192.0.2.41",
		Findings: []engine.Finding{{
			Check:     "http.exposure",
			Category:  "http",
			Risk:      "low",
			Port:      443,
			Transport: "tcp",
			Protocol:  "https",
			Fields: engine.F(
				"url", "https://192.0.2.41/Metadata.tar.xz",
				"method", "GET",
				"httpStatus", "200",
				"match", "preAuthReadable,staticDisclosure",
				"response", `7zXZF!t/R]Hwd A[gO+f08RO z+d_jJt{9U-yFKVi;WhhV~A'NBbmfU/v>`,
				"fingerprint", "xz redfish-metadata tar (68 files, supermicro)",
				"archiveCount", "68",
				"archiveContents", fullArchive,
			),
		}},
	}

	e.Emit(target)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	fancyOut := fancy.String()
	if strings.Contains(fancyOut, "response=") {
		t.Fatalf("fancy output should omit compressed response for static archive disclosure: %q", fancyOut)
	}
	if !strings.Contains(fancyOut, "archiveCount=68") {
		t.Fatalf("fancy output missing archiveCount proof: %q", fancyOut)
	}
	if !strings.Contains(fancyOut, `archiveContents=$metadata,ActivateLicense_v1.xml,ClearLicense_v1.xml,DeviceUpdate_v1.xml,DumpCollection_v1.xml,DumpService_v1.xml,Dump_v1.xml,...`) {
		t.Fatalf("fancy output should summarize archiveContents: %q", fancyOut)
	}

	lines := strings.Split(strings.TrimSpace(records.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one NDJSON record, got %d", len(lines))
	}
	var rec Result
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("invalid NDJSON: %v", err)
	}
	if len(rec.Findings) != 1 {
		t.Fatalf("expected one finding in NDJSON, got %d", len(rec.Findings))
	}
	gotFull := ""
	gotResponse := ""
	for _, f := range rec.Findings[0].Fields {
		switch f.Key {
		case "archiveContents":
			gotFull = f.Val
		case "response":
			gotResponse = f.Val
		}
	}
	if wantFull := engine.SortedCSVString(fullArchive); gotFull != wantFull {
		t.Fatalf("NDJSON archiveContents should stay full, got=%q want=%q", gotFull, wantFull)
	}
	if gotResponse == "" {
		t.Fatalf("NDJSON should retain raw response field")
	}
}

func TestTTYTrimsFullResponseFieldAndCapsNDJSONRaw(t *testing.T) {
	var fancy, errw, records bytes.Buffer
	e := newTTYEmitterTo(&fancy, &errw, &records, true /*noColor*/, true /*verbose*/)
	long := strings.Repeat("X", ndjsonRawFieldMax+1024)
	target := &engine.Target{
		Host: "10.0.0.10",
		Findings: []engine.Finding{{
			Check:     "tcp.digi.realportBanner",
			Category:  "exposure",
			Risk:      "medium",
			Port:      771,
			Transport: "tcp",
			Protocol:  "digi-realport",
			Fields: engine.F(
				"serialPort", "1",
				"raw", long,
			),
		}},
	}
	e.Emit(target)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fancy.String(), long) {
		t.Fatalf("terminal output should trim raw, got full payload")
	}
	if !strings.Contains(fancy.String(), "response=") || !strings.Contains(fancy.String(), "...") {
		t.Fatalf("terminal output missing trimmed raw marker: %q", fancy.String())
	}

	lines := strings.Split(strings.TrimSpace(records.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one NDJSON record, got %d", len(lines))
	}
	var rec Result
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("invalid NDJSON: %v", err)
	}
	if len(rec.Findings) != 1 {
		t.Fatalf("expected one finding in NDJSON, got %d", len(rec.Findings))
	}
	got := ""
	for _, f := range rec.Findings[0].Fields {
		if f.Key == "response" {
			got = f.Val
			break
		}
	}
	if len(got) != ndjsonRawFieldMax {
		t.Fatalf("expected raw capped in NDJSON, got len=%d want=%d", len(got), ndjsonRawFieldMax)
	}
	if got != long[:ndjsonRawFieldMax] {
		t.Fatalf("expected NDJSON raw to keep first %d bytes", ndjsonRawFieldMax)
	}
}

func TestNDJSONCapsResponseField(t *testing.T) {
	var fancy, errw, records bytes.Buffer
	e := newTTYEmitterTo(&fancy, &errw, &records, true /*noColor*/, true /*verbose*/)
	long := strings.Repeat("R", ndjsonRawFieldMax+2048)
	target := &engine.Target{
		Host: "10.0.0.20",
		Findings: []engine.Finding{{
			Check:     "http.exposure",
			Category:  "http",
			Risk:      "low",
			Port:      443,
			Transport: "tcp",
			Protocol:  "https",
			Fields: engine.F(
				"url", "https://10.0.0.20/redfish/v1/",
				"response", long,
			),
		}},
	}
	e.Emit(target)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(records.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one NDJSON record, got %d", len(lines))
	}
	var rec Result
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("invalid NDJSON: %v", err)
	}
	if len(rec.Findings) != 1 {
		t.Fatalf("expected one finding in NDJSON, got %d", len(rec.Findings))
	}
	got := ""
	for _, f := range rec.Findings[0].Fields {
		if f.Key == "response" {
			got = f.Val
			break
		}
	}
	if len(got) != ndjsonRawFieldMax {
		t.Fatalf("expected response capped in NDJSON, got len=%d want=%d", len(got), ndjsonRawFieldMax)
	}
	if got != long[:ndjsonRawFieldMax] {
		t.Fatalf("expected NDJSON response to keep first %d bytes", ndjsonRawFieldMax)
	}
}

func assertCleanNDJSON(t *testing.T, b []byte, wantLines int) {
	t.Helper()
	if bytes.ContainsRune(b, '\x1b') {
		t.Fatalf("output contains ANSI escape byte: %q", b)
	}
	lines := 0
	for line := range strings.SplitSeq(strings.TrimRight(string(b), "\n"), "\n") {
		if line == "" {
			continue
		}
		var r Result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("line is not valid JSON: %v\n%s", err, line)
		}
		if r.Host == "" {
			t.Errorf("record missing host: %s", line)
		}
		lines++
	}
	if lines != wantLines {
		t.Errorf("got %d NDJSON records, want %d", lines, wantLines)
	}
}

// TestResultJSONIncludesServicesAndTLSAttributes locks the lossless raw-field
// preservation contract: the emitted record carries a per-service attribute bag
// projected from the discovered open surface plus the stashed TLS leaf evidence,
// most importantly tls.fp.bkhash (the shared/default-key detection input), and a
// host-level attribute map derived from the resolved identity.
func TestResultJSONIncludesServicesAndTLSAttributes(t *testing.T) {
	tgt := &engine.Target{
		Host:     "10.0.0.30",
		Open:     engine.OpenPorts{"443/tcp": "https,tls", "623/udp": "ipmi"},
		Evidence: map[string]any{},
		Final: &engine.Final{
			Class:   engine.ClassBMC,
			Vendor:  "supermicro",
			Product: "IPMI",
			Version: "1.2.3",
		},
	}
	tgt.SetEvidence("tls", &tlscert.CertInfo{
		Port:       443,
		BadKeyHash: "cp6xENLjreef8s5DbYfx",
		SHA256:     "deadbeef",
		SubjectCN:  "IPMI",
		SelfSigned: true,
		KeyBits:    2048,
	})

	r := resultFrom(tgt)

	var tlsSvc *ServiceRecord
	for i := range r.Services {
		if r.Services[i].Port == 443 {
			tlsSvc = &r.Services[i]
		}
	}
	if tlsSvc == nil {
		t.Fatalf("expected a service record for port 443, got %+v", r.Services)
	}
	if got := tlsSvc.Attributes["tls.fp.bkhash"]; got != "cp6xENLjreef8s5DbYfx" {
		t.Fatalf("tls.fp.bkhash = %q, want cp6xENLjreef8s5DbYfx", got)
	}
	if got := tlsSvc.Attributes["tls.selfSigned"]; got != "true" {
		t.Fatalf("tls.selfSigned = %q, want true", got)
	}
	if r.Attributes["vendor"] != "supermicro" || r.Attributes["product"] != "IPMI" {
		t.Fatalf("host attributes missing vendor/product: %+v", r.Attributes)
	}

	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if !strings.Contains(string(b), `"tls.fp.bkhash":"cp6xENLjreef8s5DbYfx"`) {
		t.Fatalf("expected tls.fp.bkhash in json: %s", string(b))
	}
}

// TestResultILOSerializesRIMPFields pins that the pre-auth RIMP doc reaches the
// NDJSON record with lowerCamel keys. It was previously evidence-only, so MP.PN
// and MP.ST -- the only two inputs to Generation() -- never reached the output
// and a generation fall-through could not be diagnosed without a re-scan.
func TestResultILOSerializesRIMPFields(t *testing.T) {
	var x ilo.XMLData
	raw := `<?xml version="1.0"?>
<RIMP>
 <HSI><SPN>ProLiant DL360 Gen9</SPN><PRODUCTID>755258-B21</PRODUCTID>
  <SBSN>CZ3447HTCW</SBSN><UUID>ILO755258CZ3447HTCW</UUID>
  <NICS><NIC><PORT>1</PORT><MACADDR>00:11:22:33:44:55</MACADDR><IPADDR>192.0.2.10</IPADDR></NIC></NICS></HSI>
 <MP><PN>Integrated Lights-Out 4</PN><ST>7</ST><FWRI>2.77</FWRI><SN>ILOCZ3447HTCW</SN></MP>
</RIMP>`
	if err := xml.Unmarshal([]byte(raw), &x); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	b, err := json.Marshal(Result{Host: "192.0.2.1", ILO: &x})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	root, ok := got["ilo"].(map[string]any)
	if !ok {
		t.Fatalf("no lowerCamel \"ilo\" object in record: %s", b)
	}
	if _, bad := root["XMLName"]; bad {
		t.Error("XMLName leaked into the record; it is an xml artifact, not device data")
	}
	mp, ok := root["mp"].(map[string]any)
	if !ok {
		t.Fatalf("no \"mp\" object: %s", b)
	}
	// The two fields Generation() reads must both be present.
	if mp["product"] != "Integrated Lights-Out 4" {
		t.Errorf("mp.product = %v, want the MP.PN string", mp["product"])
	}
	if mp["family"] != "7" {
		t.Errorf("mp.family = %v, want MP.ST \"7\"", mp["family"])
	}
	hsi, ok := root["hsi"].(map[string]any)
	if !ok {
		t.Fatalf("no \"hsi\" object: %s", b)
	}
	if hsi["serverModel"] != "ProLiant DL360 Gen9" {
		t.Errorf("hsi.serverModel = %v", hsi["serverModel"])
	}
	if hsi["productId"] != "755258-B21" {
		t.Errorf("hsi.productId = %v", hsi["productId"])
	}
	// The pre-auth NIC inventory is unique to this doc; it must survive too.
	nics, ok := hsi["nics"].(map[string]any)
	if !ok {
		t.Fatalf("no hsi.nics: %s", b)
	}
	list, ok := nics["nic"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("hsi.nics.nic = %v", nics["nic"])
	}
	n0 := list[0].(map[string]any)
	if n0["macAddress"] != "00:11:22:33:44:55" || n0["ipAddress"] != "192.0.2.10" {
		t.Errorf("nic entry = %v", n0)
	}
}

// TestResultILOOmittedWhenAbsent keeps non-iLO records unchanged.
func TestResultILOOmittedWhenAbsent(t *testing.T) {
	b, err := json.Marshal(Result{Host: "192.0.2.1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), `"ilo"`) {
		t.Errorf("empty record carries an ilo key: %s", b)
	}
}

// TestResultFromWiresILOEvidence covers the collector->record hop specifically:
// resultFrom must pull the RIMP doc out of the "ilo" evidence handle. A unit
// test on Result alone would still pass if that wiring were dropped.
func TestResultFromWiresILOEvidence(t *testing.T) {
	var x ilo.XMLData
	raw := `<RIMP><HSI><SPN>ProLiant DL380 Gen10</SPN></HSI>` +
		`<MP><PN>Integrated Lights-Out 5</PN><ST>8</ST><FWRI>2.82</FWRI></MP></RIMP>`
	if err := xml.Unmarshal([]byte(raw), &x); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tgt := &engine.Target{Host: "192.0.2.1"}
	tgt.SetEvidence("ilo", &x)

	got := resultFrom(tgt)
	if got.ILO == nil {
		t.Fatal("resultFrom dropped the ilo evidence")
	}
	if got.ILO.MP.PN != "Integrated Lights-Out 5" || got.ILO.MP.ST != "8" {
		t.Errorf("MP.PN=%q MP.ST=%q, want the generation inputs preserved",
			got.ILO.MP.PN, got.ILO.MP.ST)
	}
	if got.ILO.Generation() != "iLO5" {
		t.Errorf("Generation() = %q, want iLO5", got.ILO.Generation())
	}
}
