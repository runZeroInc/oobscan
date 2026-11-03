package check

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/tlscert"
)

func TestDeriveGenerationDellIgnoresBareIDRACProduct(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.50"}
	tgt.SetEvidence("tls", &tlscert.CertInfo{SubjectCN: "idrac-2X52333", Product: "iDRAC"})
	id := &engine.Identity{Vendor: "dell", Product: "iDRAC", Attributes: map[string]string{"http.server": "Apache"}}

	if got := deriveGeneration(tgt, id); got != "iDRAC7/8/9" {
		t.Fatalf("deriveGeneration(lowercase cn) = %q, want iDRAC7/8/9", got)
	}

	tgt.SetEvidence("tls", &tlscert.CertInfo{SubjectCN: "iDRAC-1SL5H03", Product: "iDRAC"})
	if got := deriveGeneration(tgt, id); got != "iDRAC9/10" {
		t.Fatalf("deriveGeneration(uppercase cn) = %q, want iDRAC9/10", got)
	}
}
