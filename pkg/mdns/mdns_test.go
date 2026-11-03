package mdns

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestParsePTRServices(t *testing.T) {
	name := func(s string) dnsmessage.Name {
		n, err := dnsmessage.NewName(s)
		if err != nil {
			t.Fatalf("name %q: %v", s, err)
		}
		return n
	}
	meta := name(dnssdMeta)
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{{Name: meta, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: meta, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET},
				Body: &dnsmessage.PTRResource{PTR: name("_http._tcp.local.")}},
			{Header: dnsmessage.ResourceHeader{Name: meta, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET},
				Body: &dnsmessage.PTRResource{PTR: name("_pikvm._tcp.local.")}},
		},
	}
	raw, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	r := parse("192.0.2.9", raw)
	if r == nil {
		t.Fatal("parse returned nil for a valid DNS-SD response")
	}
	if len(r.Services) != 2 {
		t.Fatalf("services=%v, want 2", r.Services)
	}
	if r.Vendor != "pikvm" {
		t.Fatalf("vendor=%q, want pikvm", r.Vendor)
	}
}

func TestParseEmpty(t *testing.T) {
	if r := parse("192.0.2.9", []byte("not a dns packet")); r != nil {
		t.Fatalf("parse should reject non-DNS bytes, got %+v", r)
	}
}
