package vertiv

import (
	"time"

	"github.com/runZeroInc/oobscan/pkg/wire"
)

var DiscoveryPorts = []int{5555, 5556}

const MulticastGroup = "225.1.1.1"

type Response struct {
	From    string
	Port    int
	MAC     string
	IPv4    []string
	Strings []string
	Raw     []byte
}

func Query(host string, timeout time.Duration) *Response {
	per := min(timeout, time.Second)
	for _, p := range DiscoveryPorts {
		raw, err := wire.UDPQuery(host, p, []byte{}, per)
		if err != nil || len(raw) == 0 {
			continue
		}
		r := &Response{From: host, Port: p, Raw: append([]byte(nil), raw...)}
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
