package moxa

import (
	"time"

	"github.com/runZeroInc/oobscan/pkg/wire"
)

const DSCIPort = 4800

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

type DSCIResponse struct {
	From    string
	Opcode  byte
	OpName  string
	MAC     string
	IPv4    []string
	Strings []string
	Raw     []byte
}

func DSCIQuery(host string, timeout time.Duration) *DSCIResponse {
	per := min(timeout, time.Second)
	for _, o := range dsciReadOpcodes {
		raw, err := wire.UDPQuery(host, DSCIPort, []byte{o.op}, per)
		if err != nil || len(raw) == 0 {
			continue
		}

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
