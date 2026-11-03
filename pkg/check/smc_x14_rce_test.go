package check

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/redfish"
)

func TestSMCX14CheckIsNonDestructive(t *testing.T) {
	for _, registered := range All() {
		if registered.Name != "http.redfish.smc.x14.submitTestEvent" {
			continue
		}
		if registered.Destructive {
			t.Fatal("bounded sleep-based SubmitTestEvent check must not require --destructive")
		}
		return
	}
	t.Fatal("SubmitTestEvent check is not registered")
}

func TestClassifySMCOpenBMC(t *testing.T) {
	mk := func(root string) *redfish.Result { return &redfish.Result{RawRoot: []byte(root)} }

	cases := []struct {
		name         string
		root         string
		vendor       string
		wantSMC      bool
		wantOpenBMC  bool
		shouldReport bool // both true = fire the check
	}{
		{
			name:         "SMC OpenBMC X14 (vulnerable fork)",
			root:         `{"Name":"Root Service","Vendor":"Supermicro","Oem":{"Supermicro":{}},"Links":{"Managers":[{"@odata.id":"/redfish/v1/Managers/bmc"}]}}`,
			vendor:       "supermicro",
			wantSMC:      true,
			wantOpenBMC:  true,
			shouldReport: true,
		},
		{
			name:         "generic OpenBMC (upstream, NOT vulnerable) - excluded",
			root:         `{"Name":"Root Service","Oem":{},"Links":{"ManagerProvidingService":{"@odata.id":"/redfish/v1/Managers/bmc"}}}`,
			vendor:       "openbmc",
			wantSMC:      false,
			wantOpenBMC:  true,
			shouldReport: false,
		},
		{
			name:         "ATEN-era Supermicro (no OpenBMC) - excluded",
			root:         `{"Name":"Supermicro Service Root","Vendor":"Supermicro","Oem":{"Supermicro":{}}}`,
			vendor:       "supermicro",
			wantSMC:      true,
			wantOpenBMC:  false,
			shouldReport: false,
		},
		{
			name:         "Dell iDRAC - neither",
			root:         `{"Name":"Root Service","Vendor":"Dell","Oem":{"Dell":{}}}`,
			vendor:       "dell",
			wantSMC:      false,
			wantOpenBMC:  false,
			shouldReport: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			smc, ob := classifySMCOpenBMC(mk(c.root), c.vendor)
			if smc != c.wantSMC || ob != c.wantOpenBMC {
				t.Errorf("classify = (smc=%v, openbmc=%v), want (smc=%v, openbmc=%v)", smc, ob, c.wantSMC, c.wantOpenBMC)
			}
			if got := smc && ob; got != c.shouldReport {
				t.Errorf("shouldReport = %v, want %v", got, c.shouldReport)
			}
		})
	}
}
