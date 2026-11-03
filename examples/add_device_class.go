package examples

import (
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/oob"
)

// AddDeviceRow shows how to teach oobscan about a new product. pkg/oob is
// the single source of truth for the device inventory: appending a row to
// oob.Registry (in pkg/oob/registry.go) makes the product show up in
// `oobscan coverage`, seeds the credential wordlist, and -- via its Category --
// determines the runtime DeviceClass the check pipeline switches on.
//
// The Fingerprints slice holds short on-the-wire strings (HTTP Server header,
// TLS cert CN, SSH banner, SNMP sysDescr) that identify uses to attribute the
// device.
func AddDeviceRow() oob.Device {
	return oob.Device{
		Vendor:       "example",
		Product:      "ExampleBMC 1",
		Category:     oob.CatBMC, // -> engine.ClassBMC at runtime
		IPMI:         true,
		Redfish:      true,
		WebUI:        true,
		SSH:          true,
		Fingerprints: []string{"ExampleBMC", "Server: examplebmc-httpd"},
		DefaultCreds: [][2]string{{"ADMIN", "example-default"}},
		Notes:        "illustrative row; append the literal to oob.Registry",
	}
}

// ExampleCategoryToClass documents the category -> DeviceClass relationship that
// pkg/identify/class.go implements. A new Category const in pkg/oob
// needs a matching case there so the pipeline can select device-specific checks
// for it. This map mirrors the stable cases.
func ExampleCategoryToClass() map[oob.Category]engine.DeviceClass {
	return map[oob.Category]engine.DeviceClass{
		oob.CatBMC:     engine.ClassBMC,
		oob.CatIPKVM:   engine.ClassKVM,
		oob.CatPDU:     engine.ClassPDU,
		oob.CatSerial:  engine.ClassSerialConsole,
		oob.CatConsole: engine.ClassSerialConsole,
		oob.CatAMT:     engine.ClassAMT,
	}
}
