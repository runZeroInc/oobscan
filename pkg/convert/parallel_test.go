package convert

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bigRZSQL writes a many-asset runZero SQL export so the parallel and serial
// paths both process a non-trivial batch. Addresses are in 192.168/16 so that,
// when redacted, they renumber into the 10/8 target range and the source form
// is unambiguously gone from the output.
func bigRZSQL(t *testing.T, n int) string {
	t.Helper()
	var b strings.Builder
	for i := range n {
		ip := fmt.Sprintf("192.168.%d.%d", i/256, i%256)
		// Two cracked accounts so the (formerly map-ordered) defaultCreds findings
		// exercise the deterministic-ordering fix.
		fmt.Fprintf(&b, `{"asset":{"type":"BMC","hw_vendor":"Super Micro Computer","addresses":[%q]},`+
			`"services":[{"port":623,"transport":"udp","protocols":["ipmi"],"service_data":{`+
			`"ipmi.rakp.hashes":"ADMIN:1$<redacted>\troot:1$<redacted>",`+
			`"ipmi.rakp.cracked":"root:default\tADMIN:default",`+
			`"ipmi.connVersions":"ipmi-2.0","redfish.version":"1.0","http.body":"redfish here"}}]}`+"\n", ip)
	}
	path := filepath.Join(t.TempDir(), "big.jsonl")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func convertToFile(t *testing.T, opts Options) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out.jsonl")
	opts.Output = out
	if _, err := Run(opts); err != nil {
		t.Fatalf("Run(workers=%d): %v", opts.Workers, err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// TestParallelMatchesSerial is the core guarantee of the worker pool: for a
// deterministic conversion (no redaction), the parallel output is byte-identical
// to the serial output -- records stay in input order and the projection is
// order-independent.
func TestParallelMatchesSerial(t *testing.T) {
	in := bigRZSQL(t, 500)
	serial := convertToFile(t, Options{Format: FormatRZSQL, Input: in, Workers: 1})
	parallel := convertToFile(t, Options{Format: FormatRZSQL, Input: in, Workers: 8})
	if serial != parallel {
		// Locate the first differing line for a useful failure.
		sl, pl := strings.Split(serial, "\n"), strings.Split(parallel, "\n")
		for i := range sl {
			if i >= len(pl) || sl[i] != pl[i] {
				t.Fatalf("parallel output diverges at line %d:\n serial:   %.180s\n parallel: %.180s", i+1, sl[i], safeIdx(pl, i))
			}
		}
		t.Fatal("parallel output differs from serial")
	}
}

// TestConversionIsDeterministic pins the projection: repeated serial runs are
// byte-identical. It guards the map-iteration-order fixes (redfish key choice,
// cracked-account ordering) that a converted corpus is otherwise sensitive to.
func TestConversionIsDeterministic(t *testing.T) {
	in := bigRZSQL(t, 300)
	first := convertToFile(t, Options{Format: FormatRZSQL, Input: in, Workers: 1})
	second := convertToFile(t, Options{Format: FormatRZSQL, Input: in, Workers: 1})
	if first != second {
		t.Fatal("two serial conversions of the same input differ (projection is non-deterministic)")
	}
}

// TestParallelRedactionEquivalent checks that redaction under the parallel path
// covers exactly what the serial path does (identical stats) and leaks nothing,
// even though the arbitrary pseudonym numbering differs by processing order.
func TestParallelRedactionEquivalent(t *testing.T) {
	in := bigRZSQL(t, 400)
	serialOut := filepath.Join(t.TempDir(), "s.jsonl")
	parOut := filepath.Join(t.TempDir(), "p.jsonl")

	ss, err := Run(Options{Format: FormatRZSQL, Input: in, Output: serialOut, Redact: true, Workers: 1})
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	ps, err := Run(Options{Format: FormatRZSQL, Input: in, Output: parOut, Redact: true, Workers: 8})
	if err != nil {
		t.Fatalf("parallel: %v", err)
	}
	if *ss.Redaction != *ps.Redaction {
		t.Errorf("redaction stats differ:\n serial:   %+v\n parallel: %+v", *ss.Redaction, *ps.Redaction)
	}
	if ss.Written != ps.Written || ss.Written != 400 {
		t.Errorf("written serial=%d parallel=%d, want 400 each", ss.Written, ps.Written)
	}
	body, err := os.ReadFile(parOut)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "192.168.") {
		t.Error("parallel redaction leaked a source 192.168.x address")
	}
}

func safeIdx(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return "<missing>"
}
