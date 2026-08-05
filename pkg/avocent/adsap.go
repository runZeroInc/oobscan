package avocent

import (
	"strconv"
	"time"

	"github.com/runZeroInc/oobscan/pkg/wire"
)

const ADSAPPort = 3502

type Response struct {
	From   string
	Open   bool
	Banner []byte
}

func Query(host string, timeout time.Duration) *Response {
	open, banner, err := wire.TCPQuery(host, ADSAPPort, nil, timeout)
	if err != nil || !open {
		return nil
	}
	return &Response{From: host, Open: true, Banner: banner}
}

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
