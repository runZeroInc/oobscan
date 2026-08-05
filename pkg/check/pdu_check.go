package check

import (
	"context"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

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
