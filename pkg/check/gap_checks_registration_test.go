package check

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func TestParseHPEBasicDeviceFindsFederationAmongServices(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<root><device>
  <manufacturer>Hewlett-Packard</manufacturer>
  <modelDescription>Integrated Lights-Out 5</modelDescription>
  <serialNumber>ILO123</serialNumber>
  <serviceList>
    <service><serviceType>urn:www-hp-com:service:Federation:2</serviceType></service>
    <service><serviceType>urn:schemas-upnp-org:service:Basic:1</serviceType></service>
  </serviceList>
</device></root>`)
	got, ok := parseHPEBasicDevice(body)
	if !ok {
		t.Fatal("parseHPEBasicDevice rejected a multi-service document containing Federation")
	}
	if got.SerialNumber != "ILO123" {
		t.Fatalf("serial = %q, want ILO123", got.SerialNumber)
	}
}

// TestGapChecksRegistered confirms the detection-gap checks are registered and
// select for the intended identities (and not for unrelated ones), so the
// pipeline actually runs them.
func TestGapChecksRegistered(t *testing.T) {
	byName := map[string]Check{}
	for _, c := range All() {
		byName[c.Name] = c
	}
	for _, name := range []string{
		"http.redfish.ami.noXffBypass",
		"http.redfish.ami.globalLuaTables",
		"http.ami.preAuthRouteRead",
		"http.lenovo.xcc.preAuth",
		"http.lenovo.xcc.nonceReplay",
		"http.lenovo.xcc.nonauthEdge",
		"ssdp.hpe.federation",
		"http.lantronix.ntcRootPassOracle",
		"http.opengear.preAuthLeak",
		"telnet.perleDiag",
	} {
		if _, ok := byName[name]; !ok {
			t.Errorf("check %q not registered", name)
		}
	}

	selects := func(id *engine.Identity, name string) bool {
		for _, c := range ForIdentity(id, Selector{}) {
			if c.Name == name {
				return true
			}
		}
		return false
	}

	// Positive selections.
	if !selects(&engine.Identity{Class: engine.ClassBMC, Vendor: "ami"}, "http.redfish.ami.noXffBypass") {
		t.Error("http.redfish.ami.noXffBypass should select for an AMI BMC")
	}
	if !selects(&engine.Identity{Class: engine.ClassBMC, Vendor: "tyan"}, "http.redfish.ami.noXffBypass") {
		t.Error("http.redfish.ami.noXffBypass should select for a TYAN AMI-OEM BMC")
	}
	if !selects(&engine.Identity{Class: engine.ClassBMC, Vendor: "ami"}, "http.redfish.ami.globalLuaTables") {
		t.Error("http.redfish.ami.globalLuaTables should select for an AMI BMC")
	}
	if !selects(&engine.Identity{Class: engine.ClassBMC, Vendor: "asrockrack"}, "http.ami.preAuthRouteRead") {
		t.Error("http.ami.preAuthRouteRead should select for an ASRockRack AMI-OEM BMC")
	}
	if !selects(&engine.Identity{Class: engine.ClassBMC, Vendor: "lenovo"}, "http.lenovo.xcc.preAuth") {
		t.Error("http.lenovo.xcc.preAuth should select for a Lenovo BMC")
	}
	if !selects(&engine.Identity{Class: engine.ClassBMC, Vendor: "lenovo"}, "http.lenovo.xcc.nonceReplay") {
		t.Error("http.lenovo.xcc.nonceReplay should select for a Lenovo BMC")
	}
	if !selects(&engine.Identity{Class: engine.ClassBMC, Vendor: "lenovo"}, "http.lenovo.xcc.nonauthEdge") {
		t.Error("http.lenovo.xcc.nonauthEdge should select for a Lenovo BMC")
	}
	if !selects(&engine.Identity{Class: engine.ClassBMC, Vendor: "hpe"}, "ssdp.hpe.federation") {
		t.Error("ssdp.hpe.federation should select for an HPE BMC")
	}
	if !selects(&engine.Identity{Class: engine.ClassBMC, Vendor: "lantronix"}, "http.lantronix.ntcRootPassOracle") {
		t.Error("http.lantronix.ntcRootPassOracle should select for a Lantronix target")
	}
	if !selects(&engine.Identity{Class: engine.ClassSerialConsole, Vendor: "opengear"}, "http.opengear.preAuthLeak") {
		t.Error("http.opengear.preAuthLeak should select for an Opengear console server")
	}
	if !selects(&engine.Identity{Class: engine.ClassSerialConsole, Vendor: "perle"}, "telnet.perleDiag") {
		t.Error("telnet.perleDiag should select for a Perle console server")
	}

	// None of these active/version checks are Authenticated or Destructive
	// (they are pre-auth reads / TCP connects), so they run in the default set.
	for _, name := range []string{"http.redfish.ami.noXffBypass", "http.redfish.ami.globalLuaTables", "http.ami.preAuthRouteRead", "http.lenovo.xcc.preAuth", "http.lenovo.xcc.nonceReplay", "http.lenovo.xcc.nonauthEdge", "ssdp.hpe.federation", "http.lantronix.ntcRootPassOracle", "http.opengear.preAuthLeak", "telnet.perleDiag"} {
		c := byName[name]
		if c.Authenticated {
			t.Errorf("%s is marked Authenticated; these are pre-auth checks", name)
		}
		if c.Destructive {
			t.Errorf("%s is marked Destructive; these are safe reads/connects", name)
		}
		if !c.Enabled {
			t.Errorf("%s should be enabled in the default set", name)
		}
	}

	// Negative: a Dell BMC must not select the Perle/Opengear console checks.
	dell := &engine.Identity{Class: engine.ClassBMC, Vendor: "dell"}
	for _, name := range []string{"telnet.perleDiag", "http.opengear.preAuthLeak", "http.lantronix.ntcRootPassOracle", "http.lenovo.xcc.nonauthEdge"} {
		if selects(dell, name) {
			t.Errorf("%s should not select for a Dell BMC", name)
		}
	}
}
