// Package mdns implements a read-only unicast mDNS / DNS-SD probe on
// UDP 5353. It sends one PTR query for the DNS-SD meta-service
// (_services._dns-sd._udp.local) and parses the advertised service types. It is
// unicast (not multicast) so it works against a single scan target; many
// responders answer a unicast query. Read-only: it never registers or updates a
// record.
package mdns

import (
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/wire"
	"golang.org/x/net/dns/dnsmessage"
)

// Port is the mDNS UDP port.
const Port = 5353

// dnssdMeta is the DNS-SD service-type enumeration name.
const dnssdMeta = "_services._dns-sd._udp.local."

// Result records advertised service types and a best-effort vendor hint.
type Result struct {
	From     string
	Services []string // e.g. "_http._tcp.local", "_ipmi._udp.local"
	Vendor   string   // OOB vendor slug guessed from service names, or ""
}

// Query sends the unicast DNS-SD enumeration query and returns advertised
// service types, or nil when nothing usable comes back.
func Query(host string, timeout time.Duration) *Result {
	q, err := buildQuery(dnssdMeta)
	if err != nil {
		return nil
	}
	raw, err := wire.UDPQuery(host, Port, q, timeout)
	if err != nil || len(raw) == 0 {
		return nil
	}
	return parse(host, raw)
}

func buildQuery(name string) ([]byte, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}},
	}
	return msg.Pack()
}

func parse(host string, raw []byte) *Result {
	var p dnsmessage.Parser
	if _, err := p.Start(raw); err != nil {
		return nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil
	}
	r := &Result{From: host}
	seen := map[string]bool{}
	for {
		h, err := p.AnswerHeader()
		if err != nil { // ErrSectionDone or malformed -> stop
			break
		}
		if h.Type == dnsmessage.TypePTR {
			ptr, perr := p.PTRResource()
			if perr != nil {
				break
			}
			name := strings.TrimSuffix(ptr.PTR.String(), ".")
			if name != "" && !seen[name] {
				seen[name] = true
				r.Services = append(r.Services, name)
			}
			continue
		}
		if _, err := p.UnknownResource(); err != nil {
			break
		}
	}
	if len(r.Services) == 0 {
		return nil
	}
	r.Vendor = vendorFromServices(r.Services)
	return r
}

// vendorFromServices maps a distinctive OOB/KVM mDNS service name to a vendor
// slug (best effort; "" when only generic _http/_ssh services are advertised).
func vendorFromServices(services []string) string {
	joined := strings.ToLower(strings.Join(services, " "))
	switch {
	case strings.Contains(joined, "pikvm"):
		return "pikvm"
	case strings.Contains(joined, "nanokvm"):
		return "nanokvm"
	case strings.Contains(joined, "jetkvm"):
		return "jetkvm"
	case strings.Contains(joined, "_ipmi"), strings.Contains(joined, "redfish"):
		return "" // OOB service present but vendor-agnostic; caller records the service
	}
	return ""
}
