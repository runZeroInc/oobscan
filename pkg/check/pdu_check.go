package check

import (
	"context"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// The PDU check covers the networked-power device class (APC NMC / AP79xx-89xx,
// Raritan PX/Xerus, Eaton ePDU + Network-M2/M3, ServerTech Sentry, CyberPower
// RMCARD, Tripp Lite, Vertiv/Geist/Liebert). It fires on ClassPDU and, exactly
// like the serialConsole check, fingerprints the appliance and surfaces the
// vulndb PDU candidates. Non-destructive: no login or state-changing (power
// on/off/cycle) request is ever sent.
func init() {
	Register(Check{
		Name:        "pdu.exposure",
		Description: "Managed-PDU exposure and fingerprinting (APC/Raritan PX/Eaton/ServerTech/CyberPower)",
		Category:    "exposure",
		Applies:     Applicability{Classes: []engine.DeviceClass{engine.ClassPDU}},
		Enabled:     true,
		Run:         runPDUExposure,
	})
}

func runPDUExposure(ctx context.Context, t *engine.Target) []engine.Finding {
	return oobDeviceExposure(ctx, t, "pdu")
}
