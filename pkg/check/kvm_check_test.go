package check

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// TestKVMChecksRegistered confirms the KVM redirection-channel checks are
// registered, enabled in the default set, safe (not Authenticated/Destructive),
// and selected independent of identity. The Run bodies self-gate by bounded TCP
// connects, so weak identify must not suppress these port probes.
func TestKVMChecksRegistered(t *testing.T) {
	names := []string{
		"kvm.avocent.aps",
		"kvm.ami.redirect",
		"kvm.ami.vmedia",
		"kvm.hpe.irc",
		"kvm.cisco.vkvm",
		"kvm.usbAnywhere",
		"kvm.vnc",
	}

	byName := map[string]Check{}
	for _, c := range All() {
		byName[c.Name] = c
	}
	for _, name := range names {
		c, ok := byName[name]
		if !ok {
			t.Errorf("check %q not registered", name)
			continue
		}
		if !c.Enabled {
			t.Errorf("%s should be enabled in the default set", name)
		}
		if c.Authenticated {
			t.Errorf("%s is marked Authenticated; these are pre-auth TCP/TLS probes", name)
		}
		if c.Destructive {
			t.Errorf("%s is marked Destructive; these are safe connects", name)
		}
		if c.Category != "exposure" {
			t.Errorf("%s Category = %q, want %q", name, c.Category, "exposure")
		}
	}

	selects := func(id *engine.Identity, name string) bool {
		for _, c := range ForIdentity(id, Selector{}) {
			if c.Name == name {
				return true
			}
		}
		return false
	}

	// Every KVM check selects for BMC and non-BMC identities; the probe itself
	// decides whether the target actually exposes the channel.
	bmc := &engine.Identity{Class: engine.ClassBMC, Vendor: "supermicro"}
	serial := &engine.Identity{Class: engine.ClassSerialConsole, Vendor: "moxa"}
	for _, name := range names {
		if !selects(bmc, name) {
			t.Errorf("%s should select for a ClassBMC identity", name)
		}
		if !selects(serial, name) {
			t.Errorf("%s should select even when identify reports a non-BMC identity", name)
		}
	}
}

// TestUSBAnywhereLooksLikeATEN guards the kvm.usbAnywhere fallback against the
// large population of non-ATEN services (proxies, mail relays, honeypot/anti-
// spam tarpits) that also answer on TCP/623. The genuine ATEN vmedia listener
// is stunnel-wrapped and never speaks first, so a plain-TCP peer that sends an
// unsolicited banner must be rejected. The reject cases are real banners
// captured on 623 during a scan (hex-encoded first bytes).
func TestUSBAnywhereLooksLikeATEN(t *testing.T) {
	accept := []struct {
		name string
		st   kvmChannelState
	}{
		{"tls handshake (X13+ stunnel verify=0)", kvmChannelState{open: true, proto: "tls", cn: "IPMI"}},
		{"tls handshake even with post-handshake bytes", kvmChannelState{open: true, proto: "tls", handshakeHex: "deadbeef"}},
		{"plain tcp, silent (X10 cert-expired stunnel)", kvmChannelState{open: true, proto: "tcp"}},
	}
	for _, tc := range accept {
		if !usbAnywhereLooksLikeATEN(tc.st) {
			t.Errorf("accept %q: usbAnywhereLooksLikeATEN=false, want true", tc.name)
		}
	}

	// Foreign-service banners observed on TCP/623 in the wild. None of these may
	// produce a kvm.usbAnywhere finding.
	rejectBanners := map[string]string{
		"ELM Enterprise Manager": "454c4d20456e7465727072697365204d616e61676572205f6c0d0a436f7079726967687420c2a92031383636383531312d39323836343139323020544e542053",
		"honeypot ptr-noise":     "005b67c2954e7f0000",
		"tarpit rand-1":          "6b6a6e6b6a61626862616e633238337562637362686463373200000002",
		"CUPS lpd reject":        "6c7064205b40426f796b5d3a205072696e742d736572766963657320617265206e6f7420617661696c61626c6520746f20796f757220686f7374202861463271",
		"PowerDNS Recursor":      "210776657273696f6e0462696e643720747b52506f776572444e53205265637572736f7220343130",
		"stat uptime tarpit":     "535441542070696420313636300a5354415420757074696d652032383838340a535441542074696d6520313634313239303337370a535441542076657273696f",
		"all-zero pad":           "00000000000000000000",
		"HTTP 400 error page":    "3c48544d4c3e3c484541443e3c5449544c453e4572726f723c2f5449544c453e3c2f484541443e3c424f44593e3c48313e4572726f723c2f48313e4261642072",
		"binary tarpit-2":        "0f00020005000d0000000000010000000a3000",
		"ceph v2":                "636570682076320a100001000000000000000000000a0000000000",
		"IMAP CAPABILITY":        "2a204f4b205b4341504142494c4954592061322c4d5c5d206e4277586b3270505020494d415034726576312032307178206174",
		"ircd dircproxy":         "3a6469726370726f7879204e4f544943452041555448203a4c6f6f6b696e6720757020796f757220686f73746e616d652e2e2e0d0a3a6469726370726f787920",
		"xml declaration":        "3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d2249534f2d383835392d3122207374616e64616c6f6e653d22796573223f3e0a413c21",
		"VMware auth daemon":     "32323020564d776172652041757468656e7469636174696f6e204461656d6f6e2056657273696f6e20312e31303a2053534c2052657175697265642c2053650a",
		"OpenSSH 7.4":            "5353482d322e302d4f70656e5353485f372e34",
		"Microsoft FTP":          "323230204d6963726f736f6674204654502053657276696365",
		"ZooKeeper 3.7":          "5a6f6f6b65657065722076657273696f6e3a20332e372e302d653337303462333930613636393762666466346230626566373965336461376134663662616334",
		"RFB 003.008":            "524642203030332e303038",
		"squid HTTP 400":         "485454502f312e31203430302042616420526571756573740d0a5365727665723a2073717569642f332e352e380d0a4d696d652d56657273696f6e3a20312e30",
		"corpease anti-spam":     "32323020636f7270656173652e6e657420416e74692d7370616d20475420666f7220436f72656d61696c2053797374656d202869636d686f7374696e675b320a",
		"binary tarpit-3":        "02090001000000000000",
	}
	for name, hex := range rejectBanners {
		st := kvmChannelState{open: true, proto: "tcp", handshakeHex: hex}
		if usbAnywhereLooksLikeATEN(st) {
			t.Errorf("reject %q: usbAnywhereLooksLikeATEN=true, want false (foreign banner on 623)", name)
		}
	}

	// A closed port is never ATEN.
	if usbAnywhereLooksLikeATEN(kvmChannelState{}) {
		t.Error("closed channel: usbAnywhereLooksLikeATEN=true, want false")
	}
}
