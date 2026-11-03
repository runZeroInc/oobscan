package convert

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/output"
	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

// convertToRecords runs a conversion and decodes the output back.
func convertToRecords(t *testing.T, format Format, input string) []scanfile.Record {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out.jsonl")
	if _, err := Run(Options{Format: format, Input: input, Output: out}); err != nil {
		t.Fatalf("Run(%s): %v", format, err)
	}
	r, err := scanfile.Open(out)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer r.Close()
	var recs []scanfile.Record
	for r.Next() {
		recs = append(recs, *r.Record())
	}
	if err := r.Err(); err != nil {
		t.Fatalf("read output: %v", err)
	}
	return recs
}

// TestRZSQLProjection covers the SQL export end to end: the raw service_data
// and asset attributes are preserved verbatim, and the oobscan view (ports,
// identity, findings) is derived on top of them.
func TestRZSQLProjection(t *testing.T) {
	line := `{"asset":{"id":"a1","type":"BMC","os":"Supermicro IPMI","hw_vendor":"Super Micro Computer",` +
		`"hw_product":"X10SLM","os_version":"3.88","addresses":["192.0.2.10"],"names":["bmc-01"],` +
		`"macs":["0c:c4:7a:11:22:33"],"attributes":{"custom.owner":"lab"},` +
		`"unindexed_attributes":{"big.blob":"kept"}},` +
		`"services":[{"port":623,"transport":"udp","address":"192.0.2.10","protocols":["ipmi"],` +
		`"service_data":{"ipmi.connVersions":"ipmi-1.5\tipmi-2.0","ipmi.cipherZero":"enabled",` +
		`"ipmi.passAuth":"null-user\tanonymous","ipmi.ciphers":"0\t1\t3","fp.recog.blob":"opaque"}},` +
		`{"port":443,"transport":"tcp","address":"192.0.2.10","protocols":["tls","http"],` +
		`"summary":"HTTPS","service_data":{"tls.selfSigned":"true","tls.subject":"bmc-01"}}]}`

	recs := convertToRecords(t, FormatRZSQL, writeLines(t, "sql.jsonl", line))
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	rec := recs[0]

	if rec.Host != "192.0.2.10" {
		t.Errorf("host = %q, want 192.0.2.10", rec.Host)
	}
	if got := rec.Ports["623/udp"]; got != "ipmi" {
		t.Errorf("ports[623/udp] = %q, want ipmi", got)
	}
	if len(rec.Services) != 2 {
		t.Fatalf("services = %d, want 2", len(rec.Services))
	}

	// Nothing from service_data is dropped, including the recog blob.
	ipmiSvc := serviceOnPort(t, rec, 623)
	for _, k := range []string{"ipmi.connVersions", "ipmi.cipherZero", "fp.recog.blob"} {
		if ipmiSvc.Attributes[k] == "" {
			t.Errorf("service attribute %q was dropped", k)
		}
	}
	// Both asset attribute bags survive alongside the typed columns.
	for k, want := range map[string]string{
		"custom.owner": "lab",
		"big.blob":     "kept",
		"type":         "BMC",
		"hw_product":   "X10SLM",
		"class":        "bmc",
		"vendor":       "supermicro",
		"version":      "3.88",
	} {
		if got := rec.Attributes[k]; got != want {
			t.Errorf("attributes[%q] = %q, want %q", k, got, want)
		}
	}

	if rec.Identity == nil || rec.Identity.Class != engine.ClassBMC {
		t.Fatalf("identity = %+v, want class bmc", rec.Identity)
	}
	if rec.Identity.Confidence != engine.ConfHigh {
		t.Errorf("confidence = %q, want high (runZero typed it a BMC)", rec.Identity.Confidence)
	}

	got := findingChecks(rec.Findings)
	for _, want := range []string{
		"ipmi.rmcpPing", "ipmi.versions", "ipmi.ciphers", "ipmi.v20.cipherZero",
		"ipmi.authNull", "ipmi.authAnon", "tls.selfSigned",
	} {
		if !got[want] {
			t.Errorf("missing derived finding %q (got %v)", want, keys(got))
		}
	}
	if rec.Final == nil || rec.Final.TopRisk != "critical" {
		t.Errorf("final = %+v, want topRisk critical (cipher zero)", rec.Final)
	}
	// Every derived finding names the observation it came from.
	for _, f := range rec.Findings {
		if findingField(f, "proof") == "" {
			t.Errorf("derived finding %q carries no proof", f.Check)
		}
	}
}

// TestRZServicesGroupsByAsset covers the services export, whose rows are one
// service each and are not grouped -- or even sorted -- by asset.
func TestRZServicesGroupsByAsset(t *testing.T) {
	const asset = `"service_asset_id":"a1","id":"a1","type":"BMC","hw_vendor":"Dell","addresses":["192.0.2.20"]`
	const other = `"service_asset_id":"a2","id":"a2","type":"Server","addresses":["192.0.2.21"]`
	recs := convertToRecords(t, FormatRZServices, writeLines(t, "svc.jsonl",
		`{`+asset+`,"service_port":623,"service_transport":"udp","service_protocol":["ipmi"],"service_data":{"ipmi.channel":"1"}}`,
		`{`+other+`,"service_port":22,"service_transport":"tcp","service_protocol":["ssh"],"service_data":{}}`,
		// Back to the first asset: the export interleaves, so grouping cannot
		// assume contiguous runs.
		`{`+asset+`,"service_port":443,"service_transport":"tcp","service_protocol":["tls"],"service_data":{}}`,
	))
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2 (one per asset)", len(recs))
	}
	if len(recs[0].Services) != 2 {
		t.Errorf("first asset services = %d, want 2 merged rows", len(recs[0].Services))
	}
	if recs[0].Host != "192.0.2.20" || recs[1].Host != "192.0.2.21" {
		t.Errorf("hosts = %q / %q, want first-seen order", recs[0].Host, recs[1].Host)
	}
	if recs[0].Identity.Class != engine.ClassBMC {
		t.Errorf("first asset class = %q, want bmc", recs[0].Identity.Class)
	}
}

// TestRZRAKPRoundTrip verifies the RAKP projection: runZero
// stores the exchange collapsed into one salt string, and a converted record
// has to decompose it back into the session ids, nonces and GUID oobscan's own
// cracking tools expect.
func TestRZRAKPRoundTrip(t *testing.T) {
	want := &ipmi.RAKPResult{
		Username:   "ADMIN",
		AuthAlgo:   ipmi.RAKPHMACSHA1,
		ClientSID:  0xa0a2a3a4,
		BMCSID:     0x0007fb0f,
		ClientRand: mustBytes(t, "000102030405060708090a0b0c0d0e0f"),
		BMCRand:    mustBytes(t, "101112131415161718191a1b1c1d1e1f"),
		BMCGUID:    mustBytes(t, "202122232425262728292a2b2c2d2e2f"),
		RAKPHash:   mustBytes(t, "0123456789abcdef0123456789abcdef01234567"),
	}
	entry := "ADMIN:1$" + hex.EncodeToString(want.Salt()) + ":" + hex.EncodeToString(want.RAKPHash)

	line := `{"asset":{"type":"BMC","addresses":["192.0.2.30"]},"services":[{"port":623,"transport":"udp",` +
		`"protocols":["ipmi"],"service_data":{"ipmi.rakp.hashes":` + jsonString(entry) +
		`,"ipmi.rakp.cracked":"ADMIN:default","ipmi.rakp.passwords":"ADMIN:ADMIN"}}]}`

	recs := convertToRecords(t, FormatRZSQL, writeLines(t, "rakp.jsonl", line))
	if len(recs) != 1 || len(recs[0].RAKP) != 1 {
		t.Fatalf("rakp rows = %v, want exactly 1", recs)
	}
	got := recs[0].RAKP[0]
	if got.Username != want.Username || got.AuthAlgo != want.AuthAlgo {
		t.Errorf("username/algo = %q/%d, want %q/%d", got.Username, got.AuthAlgo, want.Username, want.AuthAlgo)
	}
	if got.ClientSID != want.ClientSID || got.BMCSID != want.BMCSID {
		t.Errorf("session ids = %x/%x, want %x/%x", got.ClientSID, got.BMCSID, want.ClientSID, want.BMCSID)
	}
	if got.ClientRand != hex.EncodeToString(want.ClientRand) ||
		got.BMCRand != hex.EncodeToString(want.BMCRand) ||
		got.BMCGUID != hex.EncodeToString(want.BMCGUID) {
		t.Errorf("nonces/guid did not round-trip: %+v", got)
	}
	if got.Hashcat != want.Hashcat() {
		t.Errorf("hashcat line = %q, want %q", got.Hashcat, want.Hashcat())
	}
	if got.Cracked != "ADMIN" {
		t.Errorf("cracked = %q, want the recovered password", got.Cracked)
	}
}

// TestRZRAKPRedactedBySource covers the common case for exports taken from the
// console, which withhold the hash material: the row still has to say that the
// account leaked one.
func TestRZRAKPRedactedBySource(t *testing.T) {
	line := `{"asset":{"type":"BMC","addresses":["192.0.2.31"]},"services":[{"port":623,"transport":"udp",` +
		`"protocols":["ipmi"],"service_data":{"ipmi.rakp.hashes":"ADMIN:1$<redacted>",` +
		`"ipmi.rakp.cracked":"ADMIN:default","ipmi.rakp.passwords":"ADMIN:<redacted>"}}]}`

	recs := convertToRecords(t, FormatRZSQL, writeLines(t, "redacted.jsonl", line))
	if len(recs) != 1 || len(recs[0].RAKP) != 1 {
		t.Fatalf("rakp rows = %v, want exactly 1", recs)
	}
	got := recs[0].RAKP[0]
	if !got.Redacted {
		t.Error("row is not flagged Redacted")
	}
	if got.Username != "ADMIN" || got.AuthAlgo != ipmi.RAKPHMACSHA1 {
		t.Errorf("username/algo = %q/%d, want ADMIN/1 from the cipher id", got.Username, got.AuthAlgo)
	}
	if got.RAKPHash != "" {
		t.Errorf("rakpHash = %q, want empty", got.RAKPHash)
	}
	// The password itself was withheld, so the classification stands in for it.
	if got.Cracked != "default" {
		t.Errorf("cracked = %q, want the default marker", got.Cracked)
	}
	if !findingChecks(recs[0].Findings)["ipmi.v20.defaultCreds"] {
		t.Error("a cracked default account did not produce ipmi.v20.defaultCreds")
	}
}

// TestRZUnknownTypeInfersFromServices checks the fallback path: a host runZero
// did not type as out-of-band gear is still classed from what it exposes.
func TestRZUnknownTypeInfersFromServices(t *testing.T) {
	recs := convertToRecords(t, FormatRZSQL, writeLines(t, "infer.jsonl",
		`{"asset":{"type":"Server","addresses":["192.0.2.40"]},"services":[{"port":16992,"transport":"tcp","service_data":{}}]}`,
	))
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	if recs[0].Identity.Class != engine.ClassAMT {
		t.Errorf("class = %q, want amt (inferred from tcp/16992)", recs[0].Identity.Class)
	}
	if recs[0].Identity.Confidence != engine.ConfMedium {
		t.Errorf("confidence = %q, want medium for an inferred class", recs[0].Identity.Confidence)
	}
}

// TestConvertGzipRoundTrip checks that compression is handled on both ends.
func TestConvertGzipRoundTrip(t *testing.T) {
	in := writeLines(t, "in.jsonl", `{"host":"192.0.2.50","ports":{"623/udp":"ipmi"}}`)
	out := filepath.Join(t.TempDir(), "out.jsonl.gz")
	if _, err := Run(Options{Format: FormatOOBScan, Input: in, Output: out}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		t.Fatalf("output is not gzipped: % x", raw[:min(4, len(raw))])
	}
	recs := convertToRecords(t, FormatOOBScan, out)
	if len(recs) != 1 || recs[0].Host != "192.0.2.50" {
		t.Errorf("gzip round trip lost the record: %+v", recs)
	}
}

func serviceOnPort(t *testing.T, rec scanfile.Record, port int) output.ServiceRecord {
	t.Helper()
	for _, s := range rec.Services {
		if s.Port == port {
			return s
		}
	}
	t.Fatalf("no service on port %d: %+v", port, rec.Services)
	return output.ServiceRecord{}
}

func findingChecks(fs []engine.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range fs {
		out[f.Check] = true
	}
	return out
}

func findingField(f engine.Finding, key string) string {
	for _, fd := range f.Fields {
		if engine.CanonicalFieldKey(fd.Key) == engine.CanonicalFieldKey(key) {
			return fd.Val
		}
	}
	return ""
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func mustBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
