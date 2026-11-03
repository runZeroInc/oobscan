package convert

import (
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

// A `proof` that is byte-identical on every host proves nothing host-specific, and a
// prose-length field that never varies is per-check documentation stored per host.
func TestQualityFlagsConstantEvidence(t *testing.T) {
	a := newQualityAuditor()
	const caveat = "a rejected forge counts toward a time-limited lock on user record 0 on X11/X12/X13/H13, and past the threshold a CORRECT key answers 0x08 too"
	for i := range constantEvidenceMinFindings {
		a.observe(&scanfile.Record{
			Host: "192.0.2." + string(rune('0'+i%10)),
			Findings: []engine.Finding{{
				Check: "ipmi.smc.rakpUnordered", Risk: "medium",
				Fields: engine.F(
					"detectionCaveat", caveat, // never varies -> flagged
					"proof", "rakp4Status=0x08", // never varies -> flagged
					"rakp4Status", "0x08"), // short label -> not flagged
			}},
		}, nil)
	}
	q := a.report()
	if got := q.ConstantEvidence["ipmi.smc.rakpUnordered.detectionCaveat"]; got != constantEvidenceMinFindings {
		t.Errorf("constant prose field not flagged (got %d)", got)
	}
	if got := q.ConstantEvidence["ipmi.smc.rakpUnordered.proof"]; got != constantEvidenceMinFindings {
		t.Errorf("constant proof field not flagged (got %d)", got)
	}
	// A short stable label like "0x08" is legitimately constant and must not be noise.
	if _, flagged := q.ConstantEvidence["ipmi.smc.rakpUnordered.rakp4Status"]; flagged {
		t.Error("a short stable label was flagged; only proof and prose-length fields should be")
	}
	if !q.Dirty() {
		t.Error("constant evidence should make the report dirty")
	}
}

// A field that varies is fine, however long it is.
func TestQualityAllowsVaryingEvidence(t *testing.T) {
	a := newQualityAuditor()
	for i := range constantEvidenceMinFindings {
		a.observe(&scanfile.Record{
			Host:     "192.0.2.1",
			Findings: []engine.Finding{{Check: "ipmi.v20.cipherZero", Fields: engine.F("proof", "bmcSessionId=0x"+strings.Repeat("a", i%8+1))}},
		}, nil)
	}
	if got := a.report().ConstantEvidence; len(got) != 0 {
		t.Errorf("varying proof was flagged constant: %v", got)
	}
}

// An adjudicated label (tls.sharedKey.key names which shared key matched) is
// legitimately constant and is allowlisted with a reason.
func TestQualityAllowlistsAdjudicatedConstant(t *testing.T) {
	a := newQualityAuditor()
	for range constantEvidenceMinFindings {
		a.observe(&scanfile.Record{
			Host: "192.0.2.1",
			Findings: []engine.Finding{{Check: "tls.sharedKey", Fields: engine.F(
				"key", "Sierra AirLink ALEOS ACEmanager fleet key (CN=*.sierrawireless.com)")}},
		}, nil)
	}
	if _, flagged := a.report().ConstantEvidence["tls.sharedKey.key"]; flagged {
		t.Error("allowlisted constant was flagged")
	}
	if _, ok := constantEvidenceAllowed["tls.sharedKey.key"]; !ok {
		t.Error("the allowlist entry must carry a reason")
	}
}

// These are the strings as stored: by the time a value reaches a field it has been
// sanitized (NULs and invalid UTF-8 removed), so the surviving-ASCII husk -- not the raw
// container -- is what the audit sees.
func TestQualityFlagsBinaryEvidence(t *testing.T) {
	a := newQualityAuditor()
	a.observe(&scanfile.Record{
		Host: "192.0.2.1",
		Findings: []engine.Finding{
			{Check: "http.exposure", Fields: engine.F("response", `7zXZF!t/'n]9H>6"H6,;!Nq(Uqe#1{c_3Cls-T r^i1,s!zZWEo5o#5H:uPXRgYZ`)},
			{Check: "http.endpoint", Fields: engine.F("response", "PKrTEUkhc@META-INF/MANIFEST.MFI8?xAUP=F4 ~})3O*%L9VEI")},
			{Check: "http.endpoint", Fields: engine.F("response", `{"@odata.id":"/redfish/v1/"}`)},
		},
	}, nil)
	q := a.report()
	if len(q.BinaryEvidence) != 2 {
		t.Errorf("BinaryEvidence = %v, want the xz and the jar flagged (and the JSON not)", q.BinaryEvidence)
	}
	if _, ok := q.BinaryEvidence["http.exposure.response"]; !ok {
		t.Error("xz body not flagged")
	}
}

// An unreachable-surface claim is wrong when a vendor probe succeeded on that same
// port in the same pass.
func TestQualityFlagsContradiction(t *testing.T) {
	a := newQualityAuditor()
	a.observe(&scanfile.Record{
		Host: "66.207.205.136",
		Findings: []engine.Finding{
			{Check: "http.surfaceUnreachable", Port: 443, Fields: engine.F("endpointsTested", "5")},
			{Check: "http.ilo.xmlData", Port: 443, Fields: engine.F("url", "/xmldata?item=all")},
			// A different port says nothing about the claim and must not be flagged.
			{Check: "http.endpoint", Port: 80, Fields: engine.F("url", "/")},
			// Nor does a non-HTTP finding.
			{Check: "ipmi.guid", Port: 623, Fields: engine.F("guid", "abc")},
		},
	}, nil)
	q := a.report()
	if _, ok := q.Contradiction["http.surfaceUnreachable|http.ilo.xmlData"]; !ok {
		t.Errorf("same-port contradiction not flagged: %v", q.Contradiction)
	}
	if len(q.Contradiction) != 1 {
		t.Errorf("Contradiction = %v, want only the same-port pair", q.Contradiction)
	}
}

// Partial post-auth inventory that claims nothing about the gap reads as a complete
// measurement.
func TestQualityFlagsSilentPartialPostAuth(t *testing.T) {
	// Missing chassis/users/lan/fru and no marker -> flagged.
	a := newQualityAuditor()
	a.observe(&scanfile.Record{
		Host:     "23.95.82.194",
		IPMIPost: []byte(`{"flow":"2.0/cred","mcInfo":{"x":1}}`),
		Findings: []engine.Finding{{Check: "ipmi.postAuthEnum", Fields: engine.F("flow", "2.0/cred")}},
	}, nil)
	if len(a.report().SilentPartial) == 0 {
		t.Error("partial post-auth with no coverage marker was not flagged")
	}

	// Same gaps, but declared -> not flagged.
	b := newQualityAuditor()
	b.observe(&scanfile.Record{
		Host:     "23.95.82.194",
		IPMIPost: []byte(`{"flow":"2.0/cred","mcInfo":{"x":1}}`),
		Findings: []engine.Finding{{Check: "ipmi.postAuthEnum", Fields: engine.F(
			"flow", "2.0/cred",
			"coverage", "partial",
			"missingSections", "chassis,users,lan,fru")}},
	}, nil)
	if got := b.report().SilentPartial; len(got) != 0 {
		t.Errorf("a declared partial run was flagged: %v", got)
	}
}

// check.panic's absence is the healthy state, so listing it as dark would train the
// reader to ignore the dark list.
func TestPanicCheckIsNeverDark(t *testing.T) {
	for _, id := range darkChecks(map[string]bool{"check.panic": true, "ipmi.fullWalk": true}, map[string]int{}) {
		if id == "check.panic" {
			t.Fatal("check.panic listed as dark on a clean run")
		}
	}
}
