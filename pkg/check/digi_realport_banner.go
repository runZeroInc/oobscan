package check

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/digi"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

func init() {
	Register(Check{
		Name:        "tcp.digi.realportBanner",
		Description: "Digi RealPort serial-line banner scan (per-port handshake + read-only banner capture)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runDigiRealPortBanner,
	})
	RegisterExplain("tcp.digi.realportBanner", explainDigiRealPortBanner)
}

func runDigiRealPortBanner(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	if t.DisableLogins {
		return nil
	}
	v, ok := t.Evidenced("digi.realport")
	if !ok {
		return nil
	}
	ri, ok := v.(*digi.RealPortInfo)
	if !ok || ri == nil {
		return nil
	}
	if ri.PortCount <= 0 {
		return nil
	}
	if t.Progress != nil {
		t.Progress(fmt.Sprintf("realport banner scan (%d serial ports)", ri.PortCount))
	}
	bannerTimeout := min(t.Timeout, 5*time.Second)
	scan, err := digi.ScanRealPortBanners(t.Host, ri.Port, ri.TLS, min(t.Timeout, 6*time.Second), bannerTimeout, nil, nil, 512)
	if err != nil || scan == nil {
		return nil
	}
	t.MarkOpen(ri.Port, "tcp", "digi-realport-line")
	if len(scan.Banners) == 0 {
		return []engine.Finding{digiRealPortNoBannerFinding(ri)}
	}
	t.SetEvidence("digi.realport.banners", scan.Banners)

	out := make([]engine.Finding, 0, len(scan.Banners))
	for _, b := range scan.Banners {
		out = append(out, digiRealPortBannerFinding(ri, b))
	}
	return out
}

func digiRealPortNoBannerFinding(ri *digi.RealPortInfo) engine.Finding {
	return engine.Finding{
		Check:     "tcp.digi.realportBanner",
		Category:  "exposure",
		Risk:      "info",
		Port:      ri.Port,
		Transport: "tcp",
		Protocol:  "digi-realport",
		Fields: engine.F(
			"serialPort", "0",
			"baud", "0",
			"realportName", strings.TrimSpace(ri.Name),
			"realportPorts", strconv.Itoa(ri.PortCount),

			"noBannerReason", "emptyRead",
			"proof", proofKV(
				"realportName", strings.TrimSpace(ri.Name),
				"realportPorts", strconv.Itoa(ri.PortCount),
				"tcpPort", strconv.Itoa(ri.Port),
				"linesWithBanner", "0",
			),
		),
	}
}

func digiRealPortBannerFinding(ri *digi.RealPortInfo, b digi.RealPortBanner) engine.Finding {
	bannerClean := sanitizeBanner(b.Banner)
	risk := "info"
	var noBannerReason string
	switch {
	case len(b.Banner) == 0:
		noBannerReason = "emptyRead"
	case !isMeaningfulSerialBanner(b.Banner, bannerClean):
		noBannerReason = "lowQualityBanner"
	default:
		risk = "medium"
		if looksLikeAuthPrompt(bannerClean) {
			risk = "high"
		}
	}
	fields := []string{
		"serialPort", strconv.Itoa(b.SerialPort),
		"baud", strconv.Itoa(b.Baud),
		"banner", cleanSnippet(bannerClean),
		"proof", proofKV(
			"realportName", strings.TrimSpace(ri.Name),
			"realportPorts", strconv.Itoa(ri.PortCount),
			"serialLine", strconv.Itoa(b.SerialPort),
			"baud", strconv.Itoa(b.Baud),
			"bytesRead", strconv.Itoa(len(b.Banner)),
		),
	}
	if len(b.Banner) > 0 {
		fields = append(fields, "raw", hex.EncodeToString([]byte(b.Banner)))
	}
	if noBannerReason != "" {
		fields = append(fields, "no_banner_reason", noBannerReason)
	}
	return engine.Finding{
		Check:     "tcp.digi.realportBanner",
		Category:  "exposure",
		Risk:      risk,
		Port:      ri.Port,
		Transport: "tcp",
		Protocol:  "digi-realport",
		Fields:    engine.F(fields...),
	}
}

func isMeaningfulSerialBanner(raw, clean string) bool {
	printable := countPrintableRunes(raw)
	if printable < 4 || printable*4 < len(raw)*3 {
		return false
	}
	distinct := make(map[byte]struct{})
	for i := 0; i < len(clean); i++ {
		c := clean[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			distinct[c] = struct{}{}
		}
	}
	return len(distinct) >= 3
}

func looksLikeAuthPrompt(banner string) bool {
	s := strings.ToLower(banner)
	for _, tok := range []string{"login:", "username:", "password:", "console", "router", "junos", "ios", "#", ">"} {
		if strings.Contains(s, tok) {
			return true
		}
	}
	return false
}

func explainDigiRealPortBanner(host string, f engine.Finding) string {
	line := explainField(f, "serialPort")
	baud := explainField(f, "baud")
	banner := explainField(f, "banner")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nDigi RealPort accepted a serial-line open and returned banner data pre-auth.\n")
	if line != "" || baud != "" {
		b.WriteString(fmt.Sprintf("\n**Serial line:** `%s`  **Baud:** `%s`\n", line, baud))
	}
	if banner != "" {
		b.WriteString(fmt.Sprintf("\n**Banner:** `%s`\n", banner))
	}
	b.WriteString("\n**Reproduce:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("oobscan scan --checks tcp.digi.realportBanner %s", host),
	))
	b.WriteString("\n\n**Impact:** Attached console lines are reachable over the network and may expose login prompts or device metadata pre-auth.\n")
	return b.String()
}
