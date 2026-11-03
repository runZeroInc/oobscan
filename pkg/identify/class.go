package identify

import (
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/oob"
)

// classForCategory translates an pkg/oob category into the runtime
// DeviceClass the pipeline switches on. pkg/oob stays the single source of
// truth for which product belongs to which class.
func classForCategory(c oob.Category) engine.DeviceClass {
	switch c {
	case oob.CatBMC:
		return engine.ClassBMC
	case oob.CatIPKVM, oob.CatKVMOverIP:
		return engine.ClassKVM
	case oob.CatSerial, oob.CatConsole:
		return engine.ClassSerialConsole
	case oob.CatPDU:
		return engine.ClassPDU
	case oob.CatAMT:
		return engine.ClassAMT
	case oob.CatFirmware:
		return engine.ClassFirmware
	default:
		return engine.ClassUnknown
	}
}

// classForVendorProduct resolves a device class from a vendor slug and optional
// product string by consulting the oob registry: an exact product match wins,
// otherwise the vendor's first registered device supplies the class.
func classForVendorProduct(vendor, product string) (engine.DeviceClass, bool) {
	vendor = strings.ToLower(vendor)
	if vendor == "" {
		return engine.ClassUnknown, false
	}
	var vendorHit bool
	for _, d := range oob.Registry {
		if !strings.EqualFold(d.Vendor, vendor) {
			continue
		}
		vendorHit = true
		if product != "" && strings.EqualFold(d.Product, product) {
			return classForCategory(d.Category), true
		}
	}
	if vendorHit {
		for _, d := range oob.Registry {
			if strings.EqualFold(d.Vendor, vendor) {
				return classForCategory(d.Category), true
			}
		}
	}
	return engine.ClassUnknown, false
}
