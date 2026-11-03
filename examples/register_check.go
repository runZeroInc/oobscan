// Package examples contains small, compiling snippets that show how to extend
// oobscan as a library: registering a security check, adding a device-class
// mapping, and adding a default-credential row. They are illustrative -- the
// functions are exported so `go build ./examples/...` and `go vet` keep them
// checked by the compiler, but nothing here is wired into the scanner.
package examples

import (
	"context"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/check"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

// RegisterCustomCheck shows the shape of a new security check. In a real
// contribution this call lives in an init() inside pkg/check so the check
// registers itself at program start; the pipeline then selects it by
// Applicability with no other wiring.
//
// The house rule: a check asserts a finding only when it has proof (a served
// key, a reflected payload, a working login, a behavioral differential), never
// on a version/banner guess. Findings default to Risk "none" when a check runs
// clean, which the interactive view hides.
func RegisterCustomCheck() {
	check.Register(check.Check{
		Name:        "example.bannerMarker",
		Description: "Flags an example vendor banner marker (illustrative only)",
		Category:    "http",
		// Fire only for the "example" vendor. Use CrossVendor:true for a check
		// that should run against every identified device.
		Applies: check.Applicability{Vendors: []string{"example"}},
		Enabled: true, // in the default set; false = opt-in via --checks
		Run:     runExampleBannerMarker,
	})
}

// runExampleBannerMarker is a Run func: it inspects the already-collected
// evidence on the Target (never re-probing when identify already has the data)
// and returns zero or more findings.
func runExampleBannerMarker(ctx context.Context, t *engine.Target) []engine.Finding {
	// Reuse evidence gathered during identify rather than opening a new
	// connection. Here we look at the HTTP server banner the web probe stored.
	var server string
	if t.Identity != nil {
		server = t.Identity.Attributes["http.server"]
	}
	if !strings.Contains(strings.ToLower(server), "examplebmc") {
		// Clean result: risk defaults to "none" and is hidden in the TUI.
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
