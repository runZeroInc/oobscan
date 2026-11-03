package identify

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/guid"
	"github.com/runZeroInc/oobscan/pkg/tlscert"
)

// withTLS returns a Target carrying a TLS cert-info evidence record with the
// given default-subject product label and subject CN, mirroring collectTLS.
func withTLS(product, cn string) *engine.Target {
	t := &engine.Target{Host: "192.0.2.1"}
	ci := &tlscert.CertInfo{SubjectCN: cn, Product: product}
	if product != "" {
		ci.DefaultSubject = &tlscert.KnownDefault{Vendor: "supermicro", Product: product, SubjectCN: cn}
	}
	t.SetEvidence("tls", ci)
	return t
}

func TestSupermicroGeneration(t *testing.T) {
	cases := []struct {
		name        string
		product     string // TLS default-cert product label
		cn          string
		modelPrefix string // Supermicro GUID board-code prefix
		server      string
		ciphers     []int
		redfish     bool
		want        string
	}{
		// The shared "X10 ATEN" default cert names the cert template, not the
		// board, so it must not drive generation (it ships across X10..H13).
		{"cert X10 ATEN ignored", "X10 ATEN", "IPMI", "", "", nil, false, ""},
		{"cert product ignored entirely", "X11", "IPMI", "", "", nil, false, ""},
		// GUID board-code prefix is the primary pre-auth signal.
		{"guid 7001MS = X10", "X10 ATEN", "IPMI", "7001MS", "", nil, false, "X10"},
		{"guid 4101MS = X11", "X10 ATEN", "IPMI", "4101MS", "", nil, false, "X11"},
		{"guid F401MS = H13 (beats shared cert)", "X10 ATEN", "IPMI", "F401MS", "", nil, false, "H13"},
		{"guid C001MS = X10 (SSG-6028R)", "", "", "C001MS", "", nil, false, "X10"},
		// Uncatalogued board-code but the smc-board-serial GUID family proves an
		// AST-era ATEN board -> X10+ floor (not blank, not a false exact X10).
		{"guid unknown code = X10+ floor", "", "", "9Z9ZMS", "", nil, false, "X10+"},
		// Non-GUID sessionless tells still apply when no board code is present.
		{"lighttpd 1.4.23 = X9", "", "", "", "lighttpd/1.4.23", nil, false, "X9"},
		{"lighttpd 1.4.35 = X10", "", "", "", "lighttpd/1.4.35", nil, false, "X10"},
		{"lighttpd 1.4.32 = X10", "", "", "", "lighttpd/1.4.32", nil, false, "X10"},
		{"wpcm450 = X9", "", "", "", "Linux/2.6.17.WB_WPCM450.1.3", nil, false, "X9"},
		{"redfish only = X10+", "", "", "", "", nil, true, "X10+"},
		{"cipher17 = X10+", "", "", "", "", []int{3, 17}, false, "X10+"},
		// No usable signal: empty (do not default to X9 -- ATEN X10/X11 advertise
		// only suites 0-14 and would be mislabelled X9).
		{"bare ipmi = unknown", "", "", "", "", nil, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tgt := withTLS(c.product, c.cn)
			if c.modelPrefix != "" {
				tgt.SetEvidence("guid", &guid.Result{
					Family: "smc-board-serial", Vendor: "supermicro",
					Fields: map[string]string{"model_prefix": c.modelPrefix},
				})
			}
			if len(c.ciphers) > 0 {
				tgt.SetEvidence("ipmi.ciphers", c.ciphers)
			}
			if c.redfish {
				tgt.SetEvidence("redfish", struct{}{})
			}
			if got := supermicroGeneration(tgt, c.server); got != c.want {
				t.Errorf("supermicroGeneration = %q, want %q", got, c.want)
			}
		})
	}
}

func TestDellGeneration(t *testing.T) {
	cases := []struct {
		name     string
		product  string
		cn       string
		server   string
		engineID string
		want     string
	}{
		{"idrac7 default cert", "", "iDRAC7 default certificate", "", "", "iDRAC7"},
		{"cn with number", "", "iDRAC9-1SL5H03", "", "", "iDRAC9"},
		{"lowercase factory cn", "", "idrac-G39MFF3", "Apache", "", "iDRAC7/8/9"},
		{"uppercase factory cn = newer", "", "iDRAC-1SL5H03", "Apache", "", "iDRAC9/10"},
		{"snmp format-4 engineid = newer", "", "idrac-8ZLSZB3", "Apache", "80001f8804abcdef0011", "iDRAC9/10"},
		{"snmp format-1 engineid stays older", "", "idrac-8ZLSZB3", "Apache", "80001f8880abcdef", "iDRAC7/8/9"},
		{"bare idrac product ignored lowercase cn", "iDRAC", "idrac-2X52333", "Apache", "", "iDRAC7/8/9"},
		{"bare idrac product ignored uppercase cn", "iDRAC", "iDRAC-1SL5H03", "Apache", "", "iDRAC9/10"},
		{"no signals", "", "", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tgt := withTLS(c.product, c.cn)
			id := &engine.Identity{Vendor: "dell", Product: "iDRAC", Attributes: map[string]string{}}
			if c.engineID != "" {
				id.Attributes["snmp.engine_id"] = c.engineID
			}
			if got := dellGeneration(tgt, id, c.server); got != c.want {
				t.Errorf("dellGeneration = %q, want %q", got, c.want)
			}
		})
	}
}

func TestIdracGenFromFW(t *testing.T) {
	cases := map[string]string{
		"1.66.65":    "iDRAC7",
		"2.83.83.83": "iDRAC8",
		"3.30.30.30": "iDRAC9",
		"5.10.50.00": "iDRAC9",
		"7.00.00.00": "iDRAC9",
		"8.10.00.00": "iDRAC10",
		"":           "",
		"garbage":    "",
	}
	for fw, want := range cases {
		if got := idracGenFromFW(fw); got != want {
			t.Errorf("idracGenFromFW(%q) = %q, want %q", fw, got, want)
		}
	}
}

func TestIdracEngineIDNewer(t *testing.T) {
	cases := map[string]bool{
		"80001f8804a1b2c3d4e5": true,  // net-snmp format-4 (MAC) -> newer
		"80001f8880deadbeef":   false, // net-snmp format-1 (text) -> older
		"800000e80123":         false, // HPE iLO PEN, not Dell
		"":                     false,
		"80001f88":             false, // too short for byte-5
	}
	for eid, want := range cases {
		if got := idracEngineIDNewer(eid); got != want {
			t.Errorf("idracEngineIDNewer(%q) = %v, want %v", eid, got, want)
		}
	}
}

func TestHuaweiGeneration(t *testing.T) {
	cases := map[string]string{
		"UPnP/2.0 iBMC/3.01 ProductName/2288H V5 SN/abc": "V3",
		"UPnP/2.0 iBMC/5.10 ProductName/foo V5 SN/abc":   "V5",
		"UPnP/2.0 iBMC/6.22 ProductName/foo V6 SN/abc":   "V5",
		"Apache": "", // no version -> gap
		"":       "",
	}
	for server, want := range cases {
		id := &engine.Identity{Vendor: "huawei", Product: "iBMC", Attributes: map[string]string{"http.server": server}}
		if got := huaweiGeneration(id); got != want {
			t.Errorf("huaweiGeneration(server=%q) = %q, want %q", server, got, want)
		}
	}
}

// TestRefineGenerationNoDowngrade proves an explicit probe-derived generation is
// left untouched (e.g. iLO /xmldata already set "iLO4").
func TestRefineGenerationNoDowngrade(t *testing.T) {
	id := &engine.Identity{Vendor: "hpe", Product: "iLO4", Generation: "iLO4",
		Attributes: map[string]string{"http.server": "HP-iLO-4/2.55"}}
	refineGeneration(&engine.Target{Host: "192.0.2.1"}, id)
	if id.Generation != "iLO4" {
		t.Errorf("generation = %q, want iLO4 (unchanged)", id.Generation)
	}
}

// TestRefineGenerationFillsHPE proves the iLO Server header fills the generation
// when the collectors did not (product == generation, i.e. no explicit gen).
func TestRefineGenerationFillsHPE(t *testing.T) {
	id := &engine.Identity{Vendor: "hpe", Product: "iLO",
		Attributes: map[string]string{"http.server": "HP-iLO-5/2.44"}}
	refineGeneration(&engine.Target{Host: "192.0.2.1"}, id)
	if id.Generation != "iLO5" {
		t.Errorf("generation = %q, want iLO5", id.Generation)
	}
}

// TestRefineGenerationFillsHPEFromRedfishProduct proves the ProLiant Gen name in
// the Redfish system product seeds the iLO generation when neither the SSDP
// HP-iLO-N banner nor /xmldata provided one (e.g. iLO5 2.95 exposing only
// "ProLiant DL380 Gen10" over Redfish).
func TestRefineGenerationFillsHPEFromRedfishProduct(t *testing.T) {
	cases := []struct{ product, want string }{
		{"ProLiant DL380 Gen10", "iLO5"},
		{"ProLiant DL360 Gen9", "iLO4"},
		{"ProLiant ML350 Gen11", "iLO6"},
		{"ProLiant MicroServer Gen8", "iLO4"},
	}
	for _, c := range cases {
		id := &engine.Identity{Vendor: "hpe", Product: "iLO",
			Attributes: map[string]string{"redfish.product": c.product}}
		refineGeneration(&engine.Target{Host: "192.0.2.1"}, id)
		if id.Generation != c.want {
			t.Errorf("product %q => generation %q, want %q", c.product, id.Generation, c.want)
		}
	}
}

func TestXCCGenerationFromTitle(t *testing.T) {
	cases := []struct{ title, server, want string }{
		{"Lenovo XClarity Controller 2", "XCC Web Server", "XCC2"},
		{"Lenovo XClarity Controller 3", "XCC Web Server", "XCC3"},
		{"Lenovo XClarity Controller", "XCC Web Server", "XCC"}, // gen1: no number -> server fallback
		{"", "XCC Web Server", "XCC"},                           // no title -> server
	}
	for _, c := range cases {
		id := &engine.Identity{Vendor: "lenovo", Product: "XCC",
			Attributes: map[string]string{"http.title": c.title, "http.server": c.server}}
		refineGeneration(&engine.Target{Host: "192.0.2.2"}, id)
		if id.Generation != c.want {
			t.Errorf("title %q server %q -> %q, want %q", c.title, c.server, id.Generation, c.want)
		}
	}
}

func TestIRMCGeneration(t *testing.T) {
	cases := []struct{ server, title, want string }{
		{"iRMC S4 Webserver", "", "iRMC S4"},
		{"FUJITSU ServerView iRMC S5 Webserver", "", "iRMC S5"},
		{"iRMC S6 Webserver", "", "iRMC S6"},
		{"", "ServerView Remote Management iRMC S2 Web Server", "iRMC S2"}, // older, title-only
		{"", "", ""},
	}
	for _, c := range cases {
		id := &engine.Identity{Vendor: "fujitsu", Product: "iRMC",
			Attributes: map[string]string{"http.server": c.server, "http.title": c.title}}
		refineGeneration(&engine.Target{Host: "192.0.2.3"}, id)
		if id.Generation != c.want {
			t.Errorf("server %q title %q -> %q, want %q", c.server, c.title, id.Generation, c.want)
		}
	}
}
