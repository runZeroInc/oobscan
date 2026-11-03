package check

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func init() {
	Register(Check{
		Name:        "http.ami.upnpDescriptor",
		Description: "AMI MegaRAC Redfish UPnP descriptor exposed pre-auth",
		Category:    "http",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runAMIUPnPDescriptor,
	})
}

func runAMIUPnPDescriptor(ctx context.Context, t *engine.Target) []engine.Finding {
	vendor := identityVendor(t)
	if vendor != "ami" && vendor != "asrockrack" && vendor != "tyan" && vendor != "gigabyte" {
		return nil
	}
	port := webPort(t)
	proto := webProto(t)
	if !webPortMaybeOpen(t, port) {
		return nil
	}
	client := insecureWebClient(min(t.Timeout, 6*time.Second))
	for _, p := range []string{"/redfishSCPD.xml", "/upnp/desc/desc.xml", "/desc.xml"} {
		st, ct, body := httpProbe(ctx, client, hostPortURL(proto, t.Host, port, p), "")
		if st < 200 || st >= 300 {
			continue
		}
		bl := strings.ToLower(string(body))
		if !strings.Contains(ct, "xml") && !strings.HasPrefix(strings.TrimSpace(bl), "<") {
			continue
		}
		if !strings.Contains(bl, "redfish-rest") && !strings.Contains(bl, "redfishscpd") && !strings.Contains(bl, "american megatrends") && !strings.Contains(bl, "ami") {
			continue
		}
		return []engine.Finding{{
			Check: "http.ami.upnpDescriptor", Category: "http", Risk: "low",
			Port: port, Transport: "tcp", Protocol: proto,
			Fields: engine.F(
				"url", p,
				"status", fmt.Sprintf("%d", st),
				"response", cleanSnippet(string(body))),
		}}
	}
	return nil
}
