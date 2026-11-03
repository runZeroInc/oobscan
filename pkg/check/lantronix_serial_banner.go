package check

import (
	"context"
	"encoding/hex"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/lantronix"
)

func init() {
	Register(Check{
		Name:        "tcp.lantronix.setupBanner",
		Description: "Lantronix setup service banner capture on TCP/9999",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runLantronixSetupBanner,
	})
}

func runLantronixSetupBanner(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	if t.DisableLogins {
		return nil
	}
	banner := ""
	if v, ok := t.Evidenced("lantronix.telnet"); ok {
		if s, ok := v.(string); ok {
			banner = s
		}
	}
	iacSummary := ""
	if banner == "" {
		got, iac, looksLantronix, err := lantronix.ProbeSetupTelnet(t.Host, t.Timeout)
		// Require a positive Lantronix signature (XPort/UDS/"setup mode" banner),
		// mirroring the identify collector: without this gate, any 9999 banner --
		// proxies ("ProxyServer is ready"), Moxa HTTP servers, SSH daemons -- would
		// be misattributed as a Lantronix setup exposure.
		if err != nil || got == "" || !looksLantronix {
			return nil
		}
		banner = got
		iacSummary = iac
		t.SetEvidence("lantronix.telnet", banner)
	}
	// Defense in depth: never report an SSH identification string as a Lantronix
	// setup banner. Some devices run sshd on 9999/tcp, and the identify-time
	// evidence path can carry that banner here without the looksLantronix gate.
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(banner)), "SSH-") {
		return nil
	}
	t.MarkOpen(lantronix.SetupTelnetPort, "tcp", "telnet")
	bannerClean := sanitizeBanner(banner)
	printable := countPrintableRunes(banner)
	risk := "info"
	var noBannerReason string
	switch {
	case len(banner) == 0:
		noBannerReason = "empty_read"
	case printable < 2:
		noBannerReason = "non_printable_only"
	default:
		risk = "medium"
		if looksLikeAuthPrompt(bannerClean) {
			risk = "high"
		}
	}
	fields := []string{
		"banner", cleanSnippet(bannerClean),
	}
	if iacSummary != "" {
		fields = append(fields, "telnetIAC", iacSummary)
	}
	if len(banner) > 0 {
		fields = append(fields, "raw", hex.EncodeToString([]byte(banner)))
	}
	if noBannerReason != "" {
		fields = append(fields, "noBannerReason", noBannerReason)
	}
	return []engine.Finding{{
		Check:     "tcp.lantronix.setupBanner",
		Category:  "exposure",
		Risk:      risk,
		Port:      lantronix.SetupTelnetPort,
		Transport: "tcp",
		Protocol:  "telnet",
		Fields:    engine.F(fields...),
	}}
}
