package convert

import (
	"bytes"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

// replayOne runs the per-record tally over one record and returns the counters and
// field slots, so a test can assert on the rules without touching a corpus file.
func replayOne(recs ...*scanfile.Record) (map[string]*ReplayCounter, map[string]*FieldSlot) {
	counters := map[string]*ReplayCounter{}
	fields := map[string]*fieldTally{}
	bump := func(key, host string) {
		c := counters[key]
		if c == nil {
			c = &ReplayCounter{}
			counters[key] = c
		}
		c.add(host)
	}
	for _, rec := range recs {
		replayRecord(rec, ReplayOptions{}, bump, fields, map[string]int{})
	}
	out := map[string]*FieldSlot{}
	for k, ft := range fields {
		ft.slot.Key = k
		ft.slot.Hosts = len(ft.hosts)
		ft.slot.Distinct = len(ft.digest)
		ft.slot.Saturated = ft.slot.Distinct >= replayDistinctCap
		ft.slot.Constant = ft.slot.Distinct == 1 && !ft.slot.Saturated
		slot := ft.slot
		out[k] = &slot
	}
	return counters, out
}

func unreachableAt(port int) engine.Finding {
	return engine.Finding{
		Check: "http.surfaceUnreachable", Category: "http", Risk: "info",
		Port: port, Transport: "tcp", Protocol: "https",
	}
}

// A record that contradicts itself on two ports is two pairs, not one. Counting
// per record instead of per pair is the natural mistake and it understates the
// reach of the rule, which is the whole reason the harness exists.
func TestReplayCountsEveryContradictionPair(t *testing.T) {
	rec := &scanfile.Record{
		Host: "192.0.2.10",
		Findings: []engine.Finding{
			unreachableAt(443),
			unreachableAt(80),
			{Check: "http.ilo.xmlData", Category: "http", Risk: "low", Port: 443, Protocol: "https"},
			{Check: "http.ilo.licenseKey", Category: "http", Risk: "low", Port: 80, Protocol: "http"},
		},
	}
	counters, _ := replayOne(rec)
	got := counters["contradiction"]
	if got == nil || got.Events != 2 {
		n := 0
		if got != nil {
			n = got.Events
		}
		t.Fatalf("contradiction events = %d, want 2: one host contradicting itself on two ports is two pairs", n)
	}
	if got.Hosts != 1 {
		t.Errorf("contradiction hosts = %d, want 1", got.Hosts)
	}
	// The per-signature rows are what a diff between two builds actually reads.
	for _, want := range []string{
		"contradiction/http.surfaceUnreachable|http.ilo.xmlData|443",
		"contradiction/http.surfaceUnreachable|http.ilo.licenseKey|80",
	} {
		if counters[want] == nil {
			t.Errorf("missing per-signature row %q", want)
		}
	}
}

// A field holding one value across many findings is what the ConstantEvidence rule
// exists to catch, and the harness has to be able to say so per slot.
func TestReplayDetectsConstantAndVaryingFields(t *testing.T) {
	var recs []*scanfile.Record
	for _, h := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		recs = append(recs, &scanfile.Record{
			Host: h,
			Findings: []engine.Finding{{
				Check: "kvm.usbAnywhere", Category: "exposure", Risk: "high",
				Fields: engine.F(
					"serverBytes", "0", // identical on every host
					"proof", "tcpPort=5900 banner="+h, // differs per host
				),
			}},
		})
	}
	_, fields := replayOne(recs...)

	constant := fields["kvm.usbAnywhere.serverBytes"]
	if constant == nil || !constant.Constant {
		t.Fatalf("serverBytes slot = %+v, want Constant=true: it is the same value on every host", constant)
	}
	if constant.Findings != 3 || constant.Hosts != 3 {
		t.Errorf("serverBytes findings=%d hosts=%d, want 3/3", constant.Findings, constant.Hosts)
	}
	varying := fields["kvm.usbAnywhere.proof"]
	if varying == nil || varying.Constant {
		t.Fatalf("proof slot = %+v, want Constant=false: it differs per host", varying)
	}
	if varying.Distinct != 3 {
		t.Errorf("proof distinct = %d, want 3", varying.Distinct)
	}
}

// Keys embed device-supplied text. A tab or newline in one would split a row and
// silently corrupt a diff of two tables, which is the one failure mode that would
// make the harness quietly lie.
func TestReplayKeysCannotSplitARow(t *testing.T) {
	rec := &scanfile.Record{
		Host: "192.0.2.20",
		Findings: []engine.Finding{{
			Check: "http.exposure\tboot\nnext", Category: "http", Risk: "low",
			Port: 443, Protocol: "https",
		}},
	}
	counters, _ := replayOne(rec)
	for k := range counters {
		if strings.ContainsAny(k, "\t\n\r") {
			t.Fatalf("counter key %q carries a control byte; a diff of two tables would misalign", k)
		}
	}

	res := &ReplayResult{Rows: counters, Fields: map[string]*FieldSlot{}}
	var buf bytes.Buffer
	if err := WriteReplay(&buf, res); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if n := len(strings.Split(line, "\t")); n != 4 {
			t.Errorf("count row has %d columns, want 4: %q", n, line)
		}
	}
}

// The proof predicate is shared with the audit; the harness reports how far it
// reaches, which the audit's capped example list cannot.
func TestReplaySeparatesProofPresentFromMissing(t *testing.T) {
	rec := &scanfile.Record{
		Host: "192.0.2.30",
		Findings: []engine.Finding{
			{Check: "kvm.vnc", Category: "exposure", Risk: "high",
				Fields: engine.F("proof", "rfb=003.008 host=192.0.2.30")},
			{Check: "kvm.usbAnywhere", Category: "exposure", Risk: "high",
				Fields: engine.F("vendor", "supermicro")},
		},
	}
	counters, _ := replayOne(rec)
	if c := counters["proof.present"]; c == nil || c.Events != 1 {
		t.Errorf("proof.present = %v, want 1", c)
	}
	if c := counters["proof.missing"]; c == nil || c.Events != 1 {
		t.Errorf("proof.missing = %v, want 1", c)
	}
	if counters["proof.missing/kvm.usbAnywhere"] == nil {
		t.Error("missing the per-check proof.missing row that names which check to fix")
	}
}

// Output ordering has to be stable or a diff between two builds reports noise.
func TestReplayOutputIsDeterministic(t *testing.T) {
	rec := &scanfile.Record{
		Host: "192.0.2.40",
		Findings: []engine.Finding{
			{Check: "b.check", Category: "http", Risk: "info", Fields: engine.F("z", "1", "a", "2")},
			{Check: "a.check", Category: "http", Risk: "info", Fields: engine.F("m", "3")},
		},
	}
	var first string
	for range 5 {
		counters, fields := replayOne(rec)
		var buf bytes.Buffer
		if err := WriteReplay(&buf, &ReplayResult{Rows: counters, Fields: fields}); err != nil {
			t.Fatalf("write: %v", err)
		}
		if first == "" {
			first = buf.String()
			continue
		}
		if buf.String() != first {
			t.Fatal("replay output varies between runs on identical input; a build-to-build diff would be unreadable")
		}
	}
}
