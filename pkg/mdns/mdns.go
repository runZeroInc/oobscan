package mdns

import (
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/wire"
	"golang.org/x/net/dns/dnsmessage"
)

const Port = 5353

const dnssdMeta = "_services._dns-sd._udp.local."

type Result struct {
	From     string
	Services []string
	Vendor   string
}

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
		if err != nil {
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
		return ""
	}
	return ""
}
