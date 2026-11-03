package check

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func TestSSHPorts(t *testing.T) {
	tgt := &engine.Target{
		Ports: []engine.Port{{Num: 22, Proto: engine.ProtoTCP}},
		Open:  engine.OpenPorts{"2222/tcp": "ssh", "443/tcp": "https", "123/udp": "snmp"},
	}
	got := sshPorts(tgt)
	if len(got) != 2 || got[0] != 22 || got[1] != 2222 {
		t.Fatalf("sshPorts=%v, want [22 2222]", got)
	}
}

func TestSSHPortsNone(t *testing.T) {
	tgt := &engine.Target{Open: engine.OpenPorts{"443/tcp": "https"}}
	if got := sshPorts(tgt); len(got) != 0 {
		t.Fatalf("sshPorts=%v, want empty", got)
	}
}
