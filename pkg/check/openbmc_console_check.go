package check

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func init() {
	Register(Check{
		Name:        "net.openbmc.obmcConsole2200",
		Description: "OpenBMC obmc-console SSH listener exposed on TCP/2200",
		Category:    "exposure",
		Applies: Applicability{
			Classes: []engine.DeviceClass{engine.ClassBMC},
		},
		Enabled: true,
		Run:     runOpenBMCConsole2200,
	})
}

func runOpenBMCConsole2200(ctx context.Context, t *engine.Target) []engine.Finding {
	if !portInScan(t, 2200) {
		return nil
	}
	deadline := min(t.Timeout, 4*time.Second)
	banner, ok := readTCPBanner(ctx, t.Host, 2200, deadline)
	if !ok {
		return nil
	}
	if !strings.HasPrefix(strings.TrimSpace(banner), "SSH-2.0-") {
		return nil
	}
	return []engine.Finding{{
		Check: "net.openbmc.obmcConsole2200", Category: "exposure", Risk: "low",
		Port: 2200, Transport: "tcp", Protocol: "ssh",
		Fields: engine.F(
			"banner", cleanSnippet(banner)),
	}}
}

func readTCPBanner(ctx context.Context, host string, port int, timeout time.Duration) (string, bool) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		return "", false
	}
	return strings.TrimSpace(line), true
}
