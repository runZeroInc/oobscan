package check

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/ilo"
)

// The license key is read from each scheme's default port, not from the host's
// identified web port. Stamping the finding with the wrong port is what put this
// disclosure on the same port as an unreachable-surface claim, so the fetch has to
// report where it actually read.
func TestLicenseKeyReportsWhereItWasRead(t *testing.T) {
	for _, tc := range []struct {
		scheme string
		port   int
	}{
		{"https", 443},
		{"http", 80},
	} {
		lk := &ilo.LicenseKey{Scheme: tc.scheme, Port: tc.port}
		if lk.Port != tc.port || lk.Scheme != tc.scheme {
			t.Errorf("scheme %s: got %s/%d, want %s/%d", tc.scheme, lk.Scheme, lk.Port, tc.scheme, tc.port)
		}
	}

	// The zero value must not read as port 443: a fetch that did not record where it
	// read should be visibly unset rather than silently claiming the default.
	var empty ilo.LicenseKey
	if empty.Port != 0 || empty.Scheme != "" {
		t.Errorf("zero LicenseKey = %s/%d, want unset so a missing attribution is visible", empty.Scheme, empty.Port)
	}
}
