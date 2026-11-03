package wsdiscovery

import "testing"

func TestParseProbeMatch(t *testing.T) {
	// A representative ProbeMatch (namespace-prefixed, like an ONVIF/appliance reply).
	resp := `<s:Envelope><s:Body><d:ProbeMatches><d:ProbeMatch>` +
		`<d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>` +
		`<d:XAddrs>http://192.0.2.5/onvif/device_service https://192.0.2.5/svc</d:XAddrs>` +
		`</d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>`
	r := parse("192.0.2.5", resp)
	if r == nil {
		t.Fatal("parse returned nil for a valid ProbeMatch")
	}
	if len(r.Types) != 2 || r.Types[0] != "dn:NetworkVideoTransmitter" {
		t.Fatalf("Types=%v, want [dn:NetworkVideoTransmitter tds:Device]", r.Types)
	}
	if len(r.XAddrs) != 2 || r.XAddrs[0] != "http://192.0.2.5/onvif/device_service" {
		t.Fatalf("XAddrs=%v", r.XAddrs)
	}
}

func TestParseNonWSD(t *testing.T) {
	if r := parse("192.0.2.5", "GARBAGE udp datagram"); r != nil {
		t.Fatalf("parse should reject a non-WS-Discovery datagram, got %+v", r)
	}
}
