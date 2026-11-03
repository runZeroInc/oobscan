// Package vertiv implements a best-effort probe for the Vertiv
// Velocity/IntelliSlot discovery scheme used by IntelliSlot Unity / Liebert
// monitoring cards. The card participates on IPv4 multicast 225.1.1.1, UDP
// ports 5555-5556, with no observed authentication. It is a LAN-segment
// enumeration/announcement channel; multicast is not routed to the internet,
// so this is a LAN-scan signal only.
//
// The datagram layout was not reverse-engineered, so this probe cannot craft a
// meaningful query. It sends an empty datagram to the target on each discovery
// port and reports every field found in any announcement the card volunteers,
// with the raw hex retained. Framing is flagged unknown.
package vertiv

import (
	"time"

	"github.com/runZeroInc/oobscan/pkg/wire"
)

// DiscoveryPorts are the Velocity/IntelliSlot discovery UDP ports.
var DiscoveryPorts = []int{5555, 5556}

// MulticastGroup is the discovery multicast group (recorded for reference; the
// per-host probe targets the unicast address the scanner is iterating).
const MulticastGroup = "225.1.1.1"

// Response records a Velocity discovery reply.
type Response struct {
	From    string
	Port    int
	MAC     string
	IPv4    []string
	Strings []string
	Raw     []byte
}

// Query sends an empty datagram to each discovery port and returns the first
// reply that decodes to any field. Read-only.
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
