package check

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/amt"
)

func TestAMTDetectedFindingVersionlessIncludesProof(t *testing.T) {
	f := amtDetectedFinding(&amt.Result{
		HTTPStatus:      401,
		ServerHdr:       "Intel(R) Active Management Technology",
		DetectionSource: "http_server",
		Fingerprint:     "Intel(R) Active Management Technology",
	}, amt.CleartextPort)

	want := map[string]string{
		"httpStatus":      "401",
		"server":          "Intel(R) Active Management Technology",
		"detectionSource": "http_server",
		"fingerprint":     "Intel(R) Active Management Technology",
	}
	for key, value := range want {
		if got := findingField(f, key); got != value {
			t.Errorf("field %s = %q, want %q", key, got, value)
		}
	}
	if got := findingField(f, "version"); got != "" {
		t.Errorf("version = %q, want omitted", got)
	}
	if len(f.CVE) != 0 {
		t.Errorf("unknown version should not carry CVE metadata: %v", f.CVE)
	}
}

func TestAMTDetectedFindingInRangeUsesCVEMetadata(t *testing.T) {
	f := amtDetectedFinding(&amt.Result{
		Version:         "9.1.45",
		VersionSource:   "http_server",
		VersionInRange:  true,
		HTTPStatus:      200,
		DetectionSource: "http_server",
		Fingerprint:     "Intel(R) Active Management Technology",
	}, amt.CleartextPort)

	if len(f.CVE) != 1 || f.CVE[0] != "CVE-2017-5689" {
		t.Fatalf("CVE metadata = %v", f.CVE)
	}
	if got := findingField(f, "cve20175689VersionRange"); got != "" {
		t.Errorf("legacy range field still emitted: %q", got)
	}
}
