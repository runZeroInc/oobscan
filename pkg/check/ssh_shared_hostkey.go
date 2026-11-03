package check

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ssh"
)

// ssh.sharedHostKey captures SSH host keys from every discovered SSH service
// and asserts when the key is known fleet-wide/shared (or badkeys FW/SSH),
// independent of device class attribution.
func init() {
	Register(Check{
		Name:        "ssh.sharedHostKey",
		Description: "SSH host key matches a known shared/fleet-wide firmware key",
		Category:    "creds",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runSSHSharedHostKey,
	})
	RegisterExplain("ssh.sharedHostKey", explainSharedSSHHostKey)
}

func runSSHSharedHostKey(ctx context.Context, t *engine.Target) []engine.Finding {
	_ = ctx
	ports := sshPorts(t)
	if len(ports) == 0 {
		return nil
	}
	deadline := min(t.Timeout, 5*time.Second)
	if deadline <= 0 {
		deadline = 5 * time.Second
	}
	var out []engine.Finding
	captures := make(map[int]ssh.HostKeyCapture)
	for _, port := range ports {
		cap, err := ssh.CaptureHostKeyEx(t.Host, port, deadline)
		if err != nil {
			continue
		}
		// Stash every captured host key (not just matches) so the output layer
		// can emit ssh.hostKey.bkhash per service for downstream shared/default
		// key detection without re-probing.
		if cap.BKHash != "" || cap.Fingerprint != "" {
			captures[port] = cap
		}
		if cap.SharedMatch {
			shk := cap.SharedKey
			out = append(out, engine.Finding{
				Check: "ssh.sharedHostKey", Category: "creds", Risk: "low",
				Port: port, Transport: "tcp", Protocol: "ssh",
				Fields: engine.F(
					"vendor", shk.Vendor,
					"product", shk.Product,
					"fingerprint", shk.Fingerprint,
					"keyType", shk.KeyType,
					"source", "shared-key-corpus"),
			})
			continue
		}
		if cap.BadKeyMatch && cap.BadKey.Kind == "FW/SSH" {
			out = append(out, engine.Finding{
				Check: "ssh.sharedHostKey", Category: "creds", Risk: "low",
				Port: port, Transport: "tcp", Protocol: "ssh",
				Fields: engine.F(
					"vendor", cap.BadKey.Vendor,
					"product", cap.BadKey.Product,
					"fingerprint", cap.Fingerprint,
					"keyType", cap.KeyType,
					"bkhash", cap.BKHash,
					"source", "badkeys-fw-ssh"),
			})
		}
	}
	if len(captures) > 0 {
		t.SetEvidence("ssh.hostKeys", captures)
	}
	return out
}

func sshPorts(t *engine.Target) []int {
	seen := map[int]struct{}{}
	for _, p := range t.Ports {
		if p.Proto == engine.ProtoTCP && p.Num == 22 {
			seen[p.Num] = struct{}{}
		}
	}
	for k, protos := range t.OpenSnapshot() {
		if !strings.HasSuffix(k, "/tcp") {
			continue
		}
		n := strings.TrimSuffix(k, "/tcp")
		port, err := strconv.Atoi(n)
		if err != nil || port <= 0 {
			continue
		}
		if port == 22 || strings.Contains(strings.ToLower(protos), "ssh") {
			seen[port] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}
