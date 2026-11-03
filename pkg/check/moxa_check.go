package check

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/moxa"
)

const moxaSerialBasePort = 4001

func init() {
	Register(Check{
		Name:        "udp.moxa.deviceSearch",
		Description: "Moxa DeviceSearch UDP/4800 pre-auth disclosure (model/firmware/MAC/IP/serial)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runMoxaDeviceSearch,
	})
	Register(Check{
		Name:        "tcp.moxa.serialBanner",
		Description: "Moxa serial line banner capture over raw TCP serial ports (4001+N)",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runMoxaSerialBanner,
	})
}

func runMoxaDeviceSearch(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	var r *moxa.Response
	if v, ok := t.Evidenced("moxa"); ok {
		if rr, ok := v.(*moxa.Response); ok && rr != nil {
			r = rr
		}
	}
	if r == nil {
		got, err := moxa.Query(t.Host, t.Timeout)
		if err != nil || got == nil {
			return nil
		}
		r = got
		t.SetEvidence("moxa", r)
	}
	if r.Model == "" && r.MAC == "" && r.Firmware == "" && r.Hostname == "" && r.IP == "" && r.Serial == "" {
		return nil
	}
	t.MarkOpen(moxa.DiscoveryPort, "udp", "moxa")
	return []engine.Finding{{
		Check: "udp.moxa.deviceSearch", Category: "exposure", Risk: "medium",
		Port: moxa.DiscoveryPort, Transport: "udp", Protocol: "moxa-devicesearch",
		Fields: engine.F(
			"model", strings.TrimSpace(r.Model),
			"firmware", strings.TrimSpace(r.Firmware),
			"authStatus", strings.TrimSpace(r.Auth),
			"hostname", strings.TrimSpace(r.Hostname),
			"mac", r.MAC,
			"ip", r.IP,
			"serial", r.Serial,
			"serialPorts", strconv.Itoa(r.Ports),
			"raw", hex.EncodeToString(r.Raw),
		),
	}}
}

func runMoxaSerialBanner(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	if t.DisableLogins {
		return nil
	}
	var r *moxa.Response
	if v, ok := t.Evidenced("moxa"); ok {
		if rr, ok := v.(*moxa.Response); ok && rr != nil {
			r = rr
		}
	}
	if r == nil {
		return nil
	}
	ports := r.Ports
	if ports <= 0 {
		ports = 1
	}
	if ports > 16 {
		ports = 16
	}
	if t.Progress != nil {
		t.Progress(fmt.Sprintf("moxa serial banner scan (%d ports)", ports))
	}
	per := min(t.Timeout, 2*time.Second)
	out := make([]engine.Finding, 0, ports)
	for i := 0; i < ports; i++ {
		p := moxaSerialBasePort + i
		open, rawBytes := probeMoxaSerialLine(t.Host, p, per)
		if !open {
			continue
		}
		t.MarkOpen(p, "tcp", "moxa-serial")
		out = append(out, moxaSerialBannerFinding(i+1, p, rawBytes))
	}
	return out
}

// moxaSerialBannerFinding reports one raw serial line. Risk gating: empty or
// non-printable reads stay info, printable banners are medium, and a likely
// auth prompt is high.
//
// The proof is built on every arm, not only where a banner arrived: a line that
// stays silent is still a measurement, and evidence attached solely to the
// silent arm would carry one identical value across every host that reaches it.
func moxaSerialBannerFinding(serialLine, tcpPort int, rawBytes []byte) engine.Finding {
	bannerClean := sanitizeBanner(string(rawBytes))
	printable := countPrintableRunes(string(rawBytes))
	risk := "info"
	var noBannerReason string
	switch {
	case len(rawBytes) == 0:
		noBannerReason = "emptyRead"
	case printable < 2:
		noBannerReason = "nonPrintableOnly"
	default:
		risk = "medium"
		if looksLikeAuthPrompt(bannerClean) {
			risk = "high"
		}
	}
	fields := []string{
		"serialPort", strconv.Itoa(serialLine),
		"tcpPort", strconv.Itoa(tcpPort),
		"banner", cleanSnippet(bannerClean),
		"proof", proofKV(
			"tcpPort", strconv.Itoa(tcpPort),
			"serialLine", strconv.Itoa(serialLine),
			"bytesRead", strconv.Itoa(len(rawBytes)),
			"printableRunes", strconv.Itoa(printable),
		),
	}
	if len(rawBytes) > 0 {
		fields = append(fields, "raw", hex.EncodeToString(rawBytes))
	}
	if noBannerReason != "" {
		fields = append(fields, "noBannerReason", noBannerReason)
	}
	return engine.Finding{
		Check:     "tcp.moxa.serialBanner",
		Category:  "exposure",
		Risk:      risk,
		Port:      tcpPort,
		Transport: "tcp",
		Protocol:  "moxa-serial",
		Fields:    engine.F(fields...),
	}
}

func probeMoxaSerialLine(host string, port int, timeout time.Duration) (bool, []byte) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false, nil
	}
	defer c.Close()
	// First read: whatever the serial line already had queued.
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, _ := c.Read(buf)
	if n > 0 {
		return true, append([]byte(nil), buf[:n]...)
	}
	// Silent raw serial-over-IP passthrough line. Do not send a CRLF wake-up:
	// port 4001+N is transparent to the ATTACHED device console, so an injected
	// "\r\n" could wake a pager or confirm a pending [y/N] on that downstream
	// device (router/switch/PLC/UPS). Report the open line with no banner rather
	// than injecting input.
	return true, nil
}
