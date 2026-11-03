package ipmi

import "testing"

// TestILORAKPNoneWireFormat locks the exact Open Session algorithm records that
// drive the iLO4 RAKP-none payload-type-confusion bypass.
func TestILORAKPNoneWireFormat(t *testing.T) {
	if got := iloRAKPNoneAuthRecord; got != [8]byte{0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00} {
		t.Fatalf("type-confused auth record changed: %v", got)
	}
	if got := iloNormalAlgoZeroRecord; got != [8]byte{0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00} {
		t.Fatalf("control (normal algo-0) record changed: %v", got)
	}
	// Only the declared payload-type byte differs.
	if iloRAKPNoneAuthRecord[3] != iloNormalAlgoZeroRecord[3] || iloRAKPNoneAuthRecord[4] != iloNormalAlgoZeroRecord[4] {
		t.Fatal("records must differ only in the declared type byte")
	}
	if iloRAKPNoneAuthRecord[0] == iloNormalAlgoZeroRecord[0] {
		t.Fatal("type byte must differ between exploit and control")
	}
}
