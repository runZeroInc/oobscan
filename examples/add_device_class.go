package examples

import (
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/oob"
)

func AddDeviceRow() oob.Device {
	return oob.Device{
		Vendor:       "example",
		Product:      "ExampleBMC 1",
		Category:     oob.CatBMC,
		IPMI:         true,
		Redfish:      true,
		WebUI:        true,
		SSH:          true,
		Fingerprints: []string{"ExampleBMC", "Server: examplebmc-httpd"},
		DefaultCreds: [][2]string{{"ADMIN", "example-default"}},
		Notes:        "illustrative row; append the literal to oob.Registry",
	}
}

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
