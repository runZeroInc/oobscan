package examples

import (
	"context"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/check"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

func RegisterCustomCheck() {
	check.Register(check.Check{
		Name:        "example.bannerMarker",
		Description: "Flags an example vendor banner marker (illustrative only)",
		Category:    "http",

		Applies: check.Applicability{Vendors: []string{"example"}},
		Enabled: true,
		Run:     runExampleBannerMarker,
	})
}

func runExampleBannerMarker(ctx context.Context, t *engine.Target) []engine.Finding {

	var server string
	if t.Identity != nil {
		server = t.Identity.Attributes["http.server"]
	}
	if !strings.Contains(strings.ToLower(server), "examplebmc") {

		return []engine.Finding{{
			Check:    "example.bannerMarker",
			Category: "http",
			Fields:   engine.F("detail", "marker not present"),
		}}
	}
	return []engine.Finding{{
		Check:    "example.bannerMarker",
		Category: "http",
		Risk:     "info",
		Protocol: "http",
		Fields:   engine.F("server", server),
	}}
}
