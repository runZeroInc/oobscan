package check

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/asd"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

// xdpPorts covers the H3C remap and Intel ASD default.
var xdpPorts = []int{asd.DefaultPort, 5123}

func init() {
	Register(Check{
		Name:        "xdp.exposed",
		Description: "Intel At-Scale-Debug (ASD) / H3C RemoteXDP JTAG-over-network service is reachable and answering the ASD handshake",
		Category:    "exposure",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runXDPExposed,
	})
	RegisterExplain("xdp.exposed", explainXDPExposed)
}

// runXDPExposed confirms ASD over plain TCP or TLS and tries supplied PAM creds.
func runXDPExposed(ctx context.Context, t *engine.Target) []engine.Finding {
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	// Collect all supplied credentials for the PAM login path.
	var credList []engine.Cred
	if t.Cred.User != "" {
		credList = append(credList, t.Cred)
	}
	credList = append(credList, t.Creds...)
	var findings []engine.Finding
	for _, port := range xdpPorts {
		if ctx.Err() != nil {
			break
		}
		// Try plain TCP first (the `asd -u` authnone path), then TLS (the
		// default `asd` posture). The ASD version query is the liveness probe:
		// it requires a genuine ASD server to frame a valid response, so a bare
		// TCP accept (e.g. slirp hostfwd) returns EOF and is not reported.
		if f := probeXDP(t.Host, port, false, timeout, credList); f != nil {
			findings = append(findings, *f)
			continue // one finding per port; prefer the working transport
		}
		if f := probeXDP(t.Host, port, true, timeout, credList); f != nil {
			findings = append(findings, *f)
		}
	}
	return dedupeXDPExposures(findings)
}

// dedupeXDPExposures collapses the per-port auth-prompted exposure findings
// (Intel ASD default port + the H3C RemoteXDP remap) into a single finding per
// host, since both report the same "listening, PAM-enforcing" exposure and
// neither carries port-distinct evidence. Findings that prove a usable service
// (version query) are kept distinct per port.
func dedupeXDPExposures(in []engine.Finding) []engine.Finding {
	if len(in) < 2 {
		return in
	}
	var usable, prompted []engine.Finding
	for _, f := range in {
		if f.Risk == "critical" {
			usable = append(usable, f)
		} else {
			prompted = append(prompted, f)
		}
	}
	if len(prompted) < 2 {
		return in
	}
	// Merge the auth-prompted exposures into one, noting every port it fired on.
	merged := prompted[0]
	ports := make([]string, 0, len(prompted))
	for _, f := range prompted {
		ports = append(ports, fmt.Sprintf("%d", f.Port))
	}
	merged.Fields = append(merged.Fields,
		engine.Field{Key: "ports", Val: strings.Join(ports, ",")},
		engine.Field{Key: "portCount", Val: fmt.Sprintf("%d", len(prompted))},
	)
	return append(usable, merged)
}

// probeXDP dials one port/transport, runs the ASD handshake, and returns a
// finding if a valid ASD service answered. Returns nil for a closed port, a
// non-ASD listener, or an auth-required service we couldn't log in to (the
// presence of the auth prompt is still recorded as a lower-severity finding).
func probeXDP(host string, port int, useTLS bool, timeout time.Duration, creds []engine.Cred) *engine.Finding {
	transport := "tcp"
	if useTLS {
		transport = "tls"
	}
	// Try with the first credential pair (if any). If auth fails, the Dial
	// returns a connection with Authenticated=false; we then retry with the
	// remaining credentials below.
	var pamUser, pamPass string
	if len(creds) > 0 {
		pamUser, pamPass = creds[0].User, creds[0].Pass
	}
	opts := asd.Options{Timeout: timeout, TLS: useTLS, PAMUser: pamUser, PAMPass: pamPass}
	conn, err := asd.Dial(host, port, opts)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	// If auth was prompted but the first credential pair failed (or no creds
	// were supplied), retry with the remaining credentials before reporting.
	// Each retry needs a fresh connection because the server closes on auth
	// failure.
	if conn.AuthPrompted && !conn.Authenticated && len(creds) > 1 {
		for _, c := range creds[1:] {
			_ = conn.Close()
			opts = asd.Options{Timeout: timeout, TLS: useTLS, PAMUser: c.User, PAMPass: c.Pass}
			conn, err = asd.Dial(host, port, opts)
			if err != nil {
				return nil
			}
			if !conn.AuthPrompted || conn.Authenticated {
				break // auth-none or auth succeeded
			}
		}
	}

	// An auth-prompted service we can't log into is a hardened (auth-enforcing)
	// ASD daemon: it is reachable and confirmed to speak ASD (the authpam prompt
	// proves the protocol), but it requires PAM authentication, so there is no
	// unauthenticated primitive to flag. That is an exposure note, not a high --
	// report it low. The confirmed, usable service (version query below) stays
	// critical.
	if conn.AuthPrompted && !conn.Authenticated {
		return &engine.Finding{
			Check:     "xdp.exposed",
			Category:  "exposure",
			Risk:      "low",
			Port:      port,
			Transport: transport,
			Protocol:  "asd",
			Fields: engine.F(
				"service", "Intel ASD / H3C RemoteXDP",
				"authPrompted", "true",
				"note", "ASD daemon is listening and requires PAM authentication; protocol confirmed by the authpam prompt",
				"promptHex", fmt.Sprintf("%x", conn.PromptBytes),
				"proof", proofKV(
					"service", "intel-asd-h3c-remotexdp",
					"authPrompted", "true",
					"authenticated", "false",
					"promptHex", fmt.Sprintf("%x", conn.PromptBytes)),
			),
		}
	}

	// The version query is the definitive ASD protocol probe: only a real ASD
	// server frames a valid agent-control response. A bare TCP listener (slirp
	// hostfwd, a proxy) returns EOF here and is not reported.
	version, vErr := conn.Version()
	if vErr != nil {
		// Version failed; try loopback as a secondary liveness probe.
		if _, lbErr := conn.Loopback([]byte{0x01, 0x02, 0x03, 0x04}); lbErr != nil {
			return nil // not an ASD service (or auth-blocked without prompt)
		}
		// Loopback succeeded: still a confirmed ASD service.
		version = ""
	}

	// Build the finding fields. engine.F takes alternating key,value strings and
	// drops empty values, so we collect them into one slice.
	kv := []string{
		"service", "Intel ASD / H3C RemoteXDP",
		"transport", conn.Transport,
	}
	if version != "" {
		kv = append(kv, "version", version)
	}
	if conn.AuthPrompted {
		kv = append(kv, "authPrompted", "true", "authenticated", fmt.Sprintf("%v", conn.Authenticated))
	}
	// Enrich with the negotiated session parameters when available (best-effort;
	// a server that closes after the version query will error here).
	if n, err := conn.MaxDataSizeReported(); err == nil {
		kv = append(kv, "maxDataSize", fmt.Sprintf("%d", n))
	}
	if n, err := conn.NumInFlight(); err == nil {
		kv = append(kv, "numInFlight", fmt.Sprintf("%d", n))
	}
	if n, err := conn.SupportedJTAGChains(); err == nil {
		kv = append(kv, "supportedJTAGChains", fmt.Sprintf("%d", n))
	}
	// Read the device IDCODE (best-effort; on locked/emulated silicon this is
	// hardware-blocked, which is still a confirmed ASD service).
	if id, res, err := conn.IDCODE(); err == nil {
		if res.Blocked {
			kv = append(kv, "idcode", "hardware-blocked (no target on JTAG chain)")
		} else {
			kv = append(kv, "idcode", fmt.Sprintf("0x%08x", id))
		}
	}

	proof := proofKV("versionQuery", "ok")
	if version != "" {
		proof = proofKV("versionQuery", "ok", "version", version)
	}
	kv = append(kv, "proof", proof)

	return &engine.Finding{
		Check:     "xdp.exposed",
		Category:  "exposure",
		Risk:      "critical",
		Port:      port,
		Transport: transport,
		Protocol:  "asd",
		Fields:    engine.F(kv...),
	}
}

func explainXDPExposed(host string, f engine.Finding) string {
	fieldVal := func(key string) (string, bool) {
		for _, fld := range f.Fields {
			if fld.Key == key {
				return fld.Val, true
			}
		}
		return "", false
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("An Intel At-Scale-Debug (ASD) / H3C RemoteXDP JTAG-over-network service is reachable on %s:%d", host, f.Port))
	if v, ok := fieldVal("version"); ok && v != "" {
		b.WriteString(fmt.Sprintf(" (version %s)", v))
	}
	if t, ok := fieldVal("transport"); ok {
		b.WriteString(fmt.Sprintf(" over %s", t))
	}
	b.WriteString(". ASD exposes raw JTAG and host CPU run-control. An unlocked debug TAP can allow memory, register, and halt access. Restrict ASD to the management network and disable it when unused.")
	return b.String()
}
