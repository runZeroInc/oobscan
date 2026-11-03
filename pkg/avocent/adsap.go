// Package avocent implements a reachability/banner probe for the Avocent DSView
// Access Protocol served by adsap2d on TCP/3502, the transport a DSView management
// server uses to reach an Avocent/Vertiv console server. The factory default is
// nonsecure mode, in which the daemon accepts and logs the credentials presented over
// the channel.
//
// The probe is read-only: it connects, captures whatever the daemon volunteers, and
// reports the fields found. It presents no credential.
//
// The sibling UDP appliance-discovery responder answers pre-session, but its port and
// datagram layout were not recovered in the firmware review, so no active probe is
// issued for it.
package avocent

import (
	"strconv"
	"time"

	"github.com/runZeroInc/oobscan/pkg/wire"
)

// ADSAPPort is the Avocent DSView access-protocol TCP port.
const ADSAPPort = 3502

// Response records adsap2d reachability and any connect banner.
type Response struct {
	From   string
	Open   bool
	Banner []byte
}

// Query connects to adsap2d and captures the connect banner. Read-only.
func Query(host string, timeout time.Duration) *Response {
	open, banner, err := wire.TCPQuery(host, ADSAPPort, nil, timeout)
	if err != nil || !open {
		return nil
	}
	return &Response{From: host, Open: true, Banner: banner}
}

// Fields renders the decoded response as engine field key/value pairs.
func (r *Response) Fields() []string {
	f := []string{
		"service", "adsap2d",
		"port", strconv.Itoa(ADSAPPort),
		"defaultMode", "nonsecure",
	}
	if len(r.Banner) > 0 {
		f = append(f,
			"bannerStrings", wire.Join(wire.Printable(r.Banner)),
			"bannerIPv4", wire.Join(wire.IPv4s(r.Banner)),
			"bannerMAC", wire.Join(wire.MACs(r.Banner)),
		)
	}
	return f
}
