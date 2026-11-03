package moxa

import (
	"time"

	"github.com/runZeroInc/oobscan/pkg/wire"
)

// DSCI is Moxa's device-configuration utility protocol (distinct from the
// DeviceSearch discovery in discover.go). Its UDP dispatcher reads a 1-byte
// opcode and dispatches with no authentication check; a set of read opcodes
// return device and network state pre-auth. The exact header/length framing
// and the UDP port were read from the NPort 6000 application dispatcher but
// not confirmed against live hardware, so this probe is best-effort: it emits
// the bare read opcodes and reports every field the reply carries, flagged as
// heuristic framing. It sends only read opcodes - never 0x79 sub-command 3
// (the network-config setter) or the 0x7a write sub-command.
//
// Read opcodes: 0x7a model/firmware, 0x04 IP/netmask/gateway/DNS,
// 0x19 MAC, 0x1f hostname/serial, 0x16 network-config field.

// DSCIPort is the candidate UDP port for the DSCI dispatcher. The KB records
// the exact port as unconfirmed; 4800 is the Moxa management UDP plane and is
// used as the default probe target.
const DSCIPort = 4800

// dsciReadOpcodes are the pre-auth, read-only opcodes, most-identifying first.
var dsciReadOpcodes = []struct {
	op   byte
	name string
}{
	{0x7a, "0x7a-modelFirmware"},
	{0x04, "0x04-ipConfig"},
	{0x19, "0x19-mac"},
	{0x1f, "0x1f-hostnameSerial"},
	{0x16, "0x16-networkField"},
}

// DSCIResponse is one decoded DSCI reply.
type DSCIResponse struct {
	From    string
	Opcode  byte
	OpName  string
	MAC     string
	IPv4    []string
	Strings []string
	Raw     []byte
}

// DSCIQuery probes the DSCI read opcodes over UDP and returns the first reply
// that decodes to any field. Read-only.
func DSCIQuery(host string, timeout time.Duration) *DSCIResponse {
	per := min(timeout, time.Second)
	for _, o := range dsciReadOpcodes {
		raw, err := wire.UDPQuery(host, DSCIPort, []byte{o.op}, per)
		if err != nil || len(raw) == 0 {
			continue
		}
		// Ignore a structured DeviceSearch reply (type/opcode/len header)
		// echoed back on this port; that is handled by discover.go.
		if len(raw) >= 4 && raw[0] == 0x01 && raw[1] == 0x81 {
			continue
		}
		r := &DSCIResponse{From: host, Opcode: o.op, OpName: o.name, Raw: append([]byte(nil), raw...)}
		r.Strings = wire.Printable(raw)
		r.IPv4 = wire.IPv4s(raw)
		if m := wire.MACs(raw); len(m) > 0 {
			r.MAC = m[0]
		}
		if r.MAC == "" && len(r.IPv4) == 0 && len(r.Strings) == 0 {
			continue
		}
		return r
	}
	return nil
}
