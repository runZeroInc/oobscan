package check

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/creds"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

// webloginReplayFixture is an anonymized, in-tree corpus (RFC 5737 TEST-NET
// addresses, generic lab hostnames, product-only fingerprints) that exercises
// the web-login targeting gates hermetically. It intentionally includes the
// UDP-discovery false positives (Cradlepoint / TEXECOM / D-Link mislabelled as
// lantronix/moxa/eaton) and honeypot/BMC/unknown-vendor records so the fingerprint
// gate and the safety invariants are actually tested -- not just the happy path.
const webloginReplayFixture = "testdata/weblogin_replay.jsonl"

// replayRecord is the subset of a scan record the replay needs.
type replayRecord struct {
	Ports    map[string]string `json:"ports"`
	Identity struct {
		Vendor string `json:"vendor"`
	} `json:"identity"`
	FinalIdentity struct {
		Class string `json:"class"`
	} `json:"finalIdentity"`
	Findings []struct {
		Check  string            `json:"check"`
		Fields map[string]string `json:"fields"`
	} `json:"findings"`
}

// webLoginAppliedClasses mirrors the http.web.defaultCreds check's Applies.Classes.
var webLoginAppliedClasses = map[string]bool{
	string(engine.ClassPDU):           true,
	string(engine.ClassSerialConsole): true,
	string(engine.ClassKVM):           true,
}

// replayVStat is per-vendor engagement accounting.
type replayVStat struct {
	engaged  int
	fpPass   int // would pass the live vendor-fingerprint gate (login attempted)
	fpReject int // filtered as misID / no corroborating signal
	honeypot int // honeypot that slipped past the class gate (must stay 0)
	servers  map[string]int
	titles   map[string]int
}

// replayScan runs the web-login targeting gates over a record stream and returns
// per-vendor stats. It performs no network I/O -- only the pure predicates the
// live check uses (class gate, vendor-has-documented-default gate, skip-vendor
// gate, and the fingerprint gate applied to the recorded server/title).
func replayScan(t *testing.T, r io.Reader) (total, engaged int, stats map[string]*replayVStat) {
	t.Helper()
	stats = map[string]*replayVStat{}
	stat := func(v string) *replayVStat {
		s := stats[v]
		if s == nil {
			s = &replayVStat{servers: map[string]int{}, titles: map[string]int{}}
			stats[v] = s
		}
		return s
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec replayRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		total++

		vendor := strings.ToLower(strings.TrimSpace(rec.Identity.Vendor))
		class := rec.FinalIdentity.Class

		if !webLoginAppliedClasses[class] {
			continue // class gate (excludes bmc/honeypot/unknown)
		}
		if vendor == "" || webBasicSkipVendors[vendor] {
			continue // vendor gate
		}
		if len(creds.VendorCredsFor(vendor, creds.ClassHTTP)) == 0 {
			continue // no documented default -> never engaged
		}

		engaged++
		s := stat(vendor)
		s.engaged++
		if class == string(engine.ClassHoneypot) {
			s.honeypot++ // impossible given the class gate; tracked as a tripwire
		}
		var server, title string
		for _, fnd := range rec.Findings {
			if fnd.Check == "web.service" || fnd.Check == "http.surface" {
				if v := fnd.Fields["server"]; v != "" {
					s.servers[v]++
					if server == "" {
						server = v
					}
				}
				if v := fnd.Fields["title"]; v != "" {
					s.titles[v]++
					if title == "" {
						title = v
					}
				}
			}
		}
		if confirmVendorWeb(server, title, vendor) {
			s.fpPass++
		} else {
			s.fpReject++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return total, engaged, stats
}

func sumStats(stats map[string]*replayVStat) (engaged, pass, reject, honeypot int) {
	for _, s := range stats {
		engaged += s.engaged
		pass += s.fpPass
		reject += s.fpReject
		honeypot += s.honeypot
	}
	return
}

// TestWebLoginReplayFixtures is the hermetic regression: it replays the in-tree
// anonymized corpus and asserts the exact targeting outcome, including the
// safety invariants (no honeypot engaged, every engaged host has a documented
// credential) and the fingerprint gate filtering the UDP-collision false
// positives.
func TestWebLoginReplayFixtures(t *testing.T) {
	f, err := os.Open(webloginReplayFixture)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	total, engaged, stats := replayScan(t, f)
	_, pass, reject, honeypot := sumStats(stats)

	// --- safety invariants ---
	if honeypot != 0 {
		t.Errorf("SAFETY: %d honeypot hosts engaged (must be 0)", honeypot)
	}
	for v, s := range stats {
		if len(creds.VendorCredsFor(v, creds.ClassHTTP)) == 0 && s.engaged > 0 {
			t.Errorf("SAFETY: engaged vendor %q has no documented default", v)
		}
	}

	// --- exact fixture accounting (update alongside the fixture) ---
	if total != 16 {
		t.Errorf("total records = %d, want 16", total)
	}
	if engaged != 13 {
		t.Errorf("engaged = %d, want 13 (3 excluded: honeypot, bmc, unknown-vendor)", engaged)
	}
	if pass != 9 {
		t.Errorf("fpPass = %d, want 9", pass)
	}
	if reject != 4 {
		t.Errorf("fpReject = %d, want 4 (moxa/D-Link, lantronix/Cradlepoint, lantronix/TEXECOM, eaton/Cradlepoint)", reject)
	}

	// per-vendor spot checks on the mistargeting the fingerprint gate removes
	if s := stats["lantronix"]; s == nil || s.engaged != 3 || s.fpPass != 1 || s.fpReject != 2 {
		t.Errorf("lantronix = %+v, want engaged=3 fpPass=1 fpReject=2", s)
	}
	if s := stats["moxa"]; s == nil || s.fpPass != 1 || s.fpReject != 1 {
		t.Errorf("moxa = %+v, want fpPass=1 fpReject=1", s)
	}
	if s := stats["eaton"]; s == nil || s.fpPass != 1 || s.fpReject != 1 {
		t.Errorf("eaton = %+v, want fpPass=1 fpReject=1", s)
	}
	// raritan is not fingerprint-gated -> always passes on the bare 401 page
	if s := stats["raritan"]; s == nil || s.fpPass != 1 {
		t.Errorf("raritan = %+v, want fpPass=1 (no FP gate)", s)
	}
}

// TestWebLoginReplayCorpus is the opt-in measurement against a private
// internet-scan corpus. It is skipped unless OOBSCAN_REPLAY_CORPUS points at a
// .jsonl(.gz) file, so no third-party scan data is hardcoded or committed. It
// only reports (and enforces the safety invariants); it does not assert
// population counts, which vary by corpus.
func TestWebLoginReplayCorpus(t *testing.T) {
	path := os.Getenv("OOBSCAN_REPLAY_CORPUS")
	if path == "" {
		t.Skip("set OOBSCAN_REPLAY_CORPUS=/path/to/scan.jsonl[.gz] to run the corpus measurement")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			t.Fatalf("gzip: %v", err)
		}
		defer gz.Close()
		r = gz
	}

	total, engaged, stats := replayScan(t, r)
	_, pass, reject, honeypot := sumStats(stats)
	if honeypot != 0 {
		t.Errorf("SAFETY: %d honeypot hosts engaged (must be 0)", honeypot)
	}
	t.Logf("corpus %s: %d records; class+vendor gate selects %d; fingerprint gate attempts ~%d, filters ~%d",
		path, total, engaged, pass, reject)
	vendors := make([]string, 0, len(stats))
	for v := range stats {
		vendors = append(vendors, v)
	}
	sort.Slice(vendors, func(i, j int) bool { return stats[vendors[i]].engaged > stats[vendors[j]].engaged })
	for _, v := range vendors {
		s := stats[v]
		t.Logf("  %-11s engaged=%-5d fpPass=%-5d fpReject=%-5d mechanism=%s", v, s.engaged, s.fpPass, s.fpReject, webLoginMechanismFor(v))
	}
}

// webLoginMechanismFor labels the login mechanism the check will use for a
// vendor: a bespoke form/JSON adapter when registered, else the generic
// self-scoping HTTP Basic path.
func webLoginMechanismFor(vendor string) string {
	if a, ok := webLoginAdapters[vendor]; ok {
		return a.mechanism()
	}
	return "http.basic (self-scoping)"
}
