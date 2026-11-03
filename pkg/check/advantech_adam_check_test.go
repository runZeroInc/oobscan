package check

import (
	"context"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/advantech"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

func TestRunAdvantechADAMReadIsInformational(t *testing.T) {
	target := &engine.Target{Host: "192.0.2.20"}
	target.SetEvidence("advantech.adam", &advantech.Response{
		Transport: "udp",
		Opcode:    0x4102,
		MagicOK:   true,
		MAC:       "00:00:6a:52:df:45",
		Raw:       []byte("ADAM"),
	})

	got := runAdvantechADAM(context.Background(), target)
	finding := hasFinding(got, "udp.advantech.adamConfig")
	if finding == nil {
		t.Fatalf("expected udp.advantech.adamConfig finding, got %+v", got)
	}
	if finding.Risk != "info" {
		t.Errorf("risk = %s, want info", finding.Risk)
	}
	if finding.Category != "discovery" {
		t.Errorf("category = %s, want discovery", finding.Category)
	}
	if got := findingField(*finding, "opcode"); got != "0x4102-networkRead" {
		t.Errorf("opcode = %q, want 0x4102-networkRead", got)
	}
}
