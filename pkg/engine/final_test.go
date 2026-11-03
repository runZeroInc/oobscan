package engine

import (
	"testing"
)

// f. builds a Finding with the given check name, risk, and key/value fields.
func fnd(check, risk string, kv ...string) Finding {
	return Finding{Check: check, Risk: risk, Fields: F(kv...)}
}

func TestFinalizeFlags(t *testing.T) {
	tgt := &Target{
		Host:     "192.0.2.10",
		Identity: &Identity{Class: ClassBMC, Vendor: "supermicro", Product: "IPMI", Confidence: ConfHigh},
	}
	// A representative Supermicro finding set.
	tgt.Findings = []Finding{
		fnd("id", "info"),
		fnd("ipmi.v20.rakpHash", "critical", "username", "ADMIN", "hash", "deadbeef"),
		fnd("ipmi.v20.rakpHash", "critical", "username", "root", "hash", "beef"),           // dup -> one flag
		fnd("ipmi.v20.defaultCreds", "critical", "username", "ADMIN", "password", "ADMIN"), // real live cred
		fnd("tls.selfSigned", "low", "vendor", "supermicro"),
		fnd("kvm.ami.vmedia", "info", "vendor", "supermicro"),  // vmedia surface present
		fnd("kvm.vnc", "critical", "defaultUsername", "ADMIN"), // kvm w/ default creds
		fnd("ipmi.versions", "none"),                           // clean probe: no flag
	}
	f := Finalize(tgt)

	if f.Vendor != "supermicro" || f.Class != ClassBMC {
		t.Fatalf("identity = %s/%s, want bmc/supermicro", f.Class, f.Vendor)
	}
	want := map[string]string{
		"rakpHash":     "critical",
		"defaultCreds": "critical",
		"defaultCert":  "low",
		"vmedia":       "info",
		"kvm":          "critical",
	}
	for k, v := range want {
		if f.Flags[k] != v {
			t.Errorf("flag %q = %q, want %q", k, f.Flags[k], v)
		}
	}
	if f.TopRisk != "critical" {
		t.Errorf("top_risk = %q, want critical", f.TopRisk)
	}
	// A "none" probe must not become a finding or a flag.
	if _, ok := f.Flags["versions"]; ok {
		t.Error("clean probe leaked a flag")
	}
	// Actionable count excludes the single "none" finding.
	if f.Findings != 7 {
		t.Errorf("actionable findings = %d, want 7", f.Findings)
	}
}

func TestFinalizeNilIdentity(t *testing.T) {
	f := Finalize(&Target{Host: "192.0.2.11"})
	if f == nil || f.Class != ClassUnknown || f.Confidence != ConfLow {
		t.Fatalf("nil-identity final = %+v, want unknown/low", f)
	}
	if len(f.Flags) != 0 {
		t.Errorf("no findings should yield no flags, got %v", f.Flags)
	}
}

func TestFinalizeVersionFromAttrs(t *testing.T) {
	tgt := &Target{
		Host: "192.0.2.12",
		Identity: &Identity{Class: ClassBMC, Vendor: "hpe", Product: "iLO4", Confidence: ConfHigh,
			Attributes: map[string]string{"ilo.fw": "2.55"}},
	}
	if f := Finalize(tgt); f.Version != "2.55" {
		t.Errorf("version = %q, want 2.55", f.Version)
	}
}

// TestFinalizeSMCModernTar proves the Supermicro Redfish-metadata-tar exposure
// upgrades an IPMI-only X9 baseline to the modern-Redfish band (X13+).
func TestFinalizeSMCModernTar(t *testing.T) {
	tgt := &Target{
		Host:     "192.0.2.10",
		Identity: &Identity{Class: ClassBMC, Vendor: "supermicro", Product: "IPMI", Generation: "X9", Confidence: ConfHigh},
	}
	tgt.Findings = []Finding{
		fnd("http.exposure", "medium", "fingerprint", "xz redfish-metadata tar (42 files, supermicro)"),
	}
	if f := Finalize(tgt); f.Generation != "X13+" {
		t.Errorf("generation = %q, want X13+ (modern-redfish tar)", f.Generation)
	}
}

func TestSmcGenerationFromModel(t *testing.T) {
	cases := []struct{ model, want string }{
		{"X12DPi-N6", "X12"},
		{"X12SDV-4C-SP6F", "X12"},
		{"H13SRD-F", "H13"},
		{"H13DSH", "H13"},
		{"H13SSW", "H13"},
		{"M12SWA-TF", "M12"},
		{"X11DPT-PS", "X11"},
		{"X13DAI-T", "X13"},
		{"X14DBG-AP", "X14"},
		{"x10slm-f", "X10"}, // case-insensitive
		{"X9SCM-F", "X9"},
		{"H11DSU-iN", "H11"},
		// Non-board strings must not yield a generation.
		{"X10 ATEN", ""},       // the shared default-cert label, not a board
		{"SYS-222H-TN", ""},    // system model, not a board SKU
		{"Positron Atlas", ""}, // third-party
		{"", ""},               // empty
		{"X15FOO", ""},         // out of range (no X15 yet)
	}
	for _, c := range cases {
		if got := smcGenerationFromModel(c.model); got != c.want {
			t.Errorf("smcGenerationFromModel(%q) = %q, want %q", c.model, got, c.want)
		}
	}
}

// TestFinalizeSMCGenFromSKU proves a real board SKU leaked over HTTP pins the
// exact generation, overriding the coarse "X10 ATEN" cert baseline.
func TestFinalizeSMCGenFromSKU(t *testing.T) {
	cases := []struct {
		name    string
		baseGen string
		finding Finding
		want    string
	}{
		{"redfish product X12", "X10", fnd("http.endpoint", "info", "product", "X12DPi-N6"), "X12"},
		{"redfish model H13", "X10", fnd("http.redfish.defaultCreds", "critical", "model", "H13SRD-F"), "H13"},
		{"exposure model X14", "X13+", fnd("http.exposure", "low", "model", "X14DBG-AP"), "X14"},
		{"pseudo-model X10 ATEN ignored", "X10", fnd("http.endpoint", "info", "product", "X10 ATEN"), "X10"},
		// Post-auth FRU Board Product is the motherboard SKU -> exact generation.
		{"postauth fru board X13", "X11+", fnd("ipmi.postAuth.fru", "info", "boardProduct", "X13SEED-SF"), "X13"},
		{"postauth fru board H13", "X10", fnd("ipmi.postAuth.fru", "info", "boardProduct", "H13SRD-F"), "H13"},
		{"postauth fru productName fallback X12", "X10", fnd("ipmi.postAuth.fru", "info", "productName", "X12DPi-N6"), "X12"},
		// board=NONE but the real SKU is in the flattened FRU preview (twin/blade).
		{"postauth fru board=NONE, SKU in preview", "X10",
			fnd("ipmi.postAuth.fru", "info", "boardProduct", "NONE",
				"preview", "d0:chassis[0]=CSE-217HQ | d0:board[0]=Supermicro | d0:board[3]=X11DPT-PS | d0:product[0]=Supermicro"), "X11"},
		// GUID board-code prefix pins the generation when no board SKU is exposed.
		{"guid modelPrefix F401MS -> H13", "X10", fnd("ipmi.guid", "info", "modelPrefix", "F401MS"), "H13"},
		{"guid modelPrefix 7001MS -> X10 (no baseline)", "", fnd("ipmi.guid", "info", "modelPrefix", "7001MS"), "X10"},
		{"guid modelPrefix 5201MS -> X12", "", fnd("ipmi.guid", "info", "modelPrefix", "5201MS"), "X12"},
		// Uncatalogued board-code but smc-board-serial family -> X10+ AST floor.
		{"guid board-serial uncatalogued -> X10+ floor", "",
			fnd("ipmi.guid", "info", "family", "smc-board-serial", "modelPrefix", "3101MS"), "X10+"},
		// A real board SKU still wins over the GUID code when both are present is
		// covered by the SKU cases above (SKU is checked first).
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tgt := &Target{
				Host:     "198.51.100.7",
				Identity: &Identity{Class: ClassBMC, Vendor: "supermicro", Product: "IPMI", Generation: c.baseGen, Confidence: ConfHigh},
			}
			tgt.Findings = []Finding{c.finding}
			if f := Finalize(tgt); f.Generation != c.want {
				t.Errorf("generation = %q, want %q", f.Generation, c.want)
			}
		})
	}
}

// TestFinalizeSMCX14OpenBMC proves a Supermicro board running OpenBMC firmware
// (identify labels it vendor "openbmc" from the bmcweb SPA title) is reclaimed to
// supermicro and pinned to generation X14 using the authoritative post-auth
// IPMI/FRU manufacturer - while a genuine non-SMC OpenBMC box is left untouched.
func TestFinalizeSMCX14OpenBMC(t *testing.T) {
	mcSMC := fnd("ipmi.postAuth.mcInfo", "info", "manufacturerId", "10876", "manufacturer", "Super Micro Computer")
	mcATEN := fnd("ipmi.postAuth.mcInfo", "info", "manufacturerId", "21317", "manufacturer", "ATEN International (Supermicro OEM)")
	mcOther := fnd("ipmi.postAuth.mcInfo", "info", "manufacturerId", "42817", "manufacturer", "Ampere Computing")
	cases := []struct {
		name     string
		vendor   string
		baseGen  string
		attrs    map[string]string
		findings []Finding
		wantVend string
		wantGen  string
	}{
		{"openbmc + SMC IPMI mfr -> supermicro/X14", "openbmc", "", nil,
			[]Finding{mcSMC}, "supermicro", "X14"},
		{"openbmc + SMC mfr + X14 board SKU -> supermicro/X14", "openbmc", "", nil,
			[]Finding{mcSMC, fnd("ipmi.postAuth.fru", "info", "boardProduct", "X14DBG-AP", "boardMfg", "Super Micro Computer")}, "supermicro", "X14"},
		{"openbmc + FRU boardMfg only -> supermicro/X14", "openbmc", "", nil,
			[]Finding{fnd("ipmi.postAuth.fru", "info", "boardMfg", "Super Micro Computer", "boardProduct", "Motherboard")}, "supermicro", "X14"},
		{"genuine non-SMC OpenBMC left untouched", "openbmc", "", nil,
			[]Finding{mcOther}, "openbmc", ""},
		{"favicon supermicro + bmcweb + SMC mfr -> X14", "supermicro", "X13+",
			map[string]string{"http.server": "bmcweb"}, []Finding{mcSMC}, "supermicro", "X14"},
		{"ATEN OEM mfr, IPMI-only (no bmcweb) -> ATEN gen not X14", "", "",
			map[string]string{}, []Finding{mcATEN, fnd("ipmi.postAuth.fru", "info", "boardProduct", "X11DPH-T", "boardMfg", "Super Micro Computer")}, "supermicro", "X11"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tgt := &Target{
				Host: "198.51.100.9",
				Identity: &Identity{
					Class: ClassBMC, Vendor: c.vendor, Product: "IPMI",
					Generation: c.baseGen, Confidence: ConfHigh, Attributes: c.attrs,
				},
			}
			tgt.Findings = c.findings
			f := Finalize(tgt)
			if f.Vendor != c.wantVend {
				t.Errorf("vendor = %q, want %q", f.Vendor, c.wantVend)
			}
			if f.Generation != c.wantGen {
				t.Errorf("generation = %q, want %q", f.Generation, c.wantGen)
			}
		})
	}
}

// TestFinalizeSMCCoreUILogin proves the coreui "Supermicro BMC Login" UI upgrades
// the coarse X10 baseline to the X11+ band, and that the precedence between SKU,
// modern-tar (X13+) and coreui (X11+) is respected.
func TestFinalizeSMCCoreUILogin(t *testing.T) {
	cases := []struct {
		name     string
		baseGen  string
		findings []Finding
		want     string
	}{
		{"coreui title upgrades X10", "X10",
			[]Finding{fnd("web.service", "info", "title", "Supermicro BMC Login")}, "X11+"},
		{"coreui body tag upgrades X10", "X10",
			[]Finding{fnd("http.exposure", "info", "fingerprint", "html-meta ATEN International Co Ltd.; smc-ui:coreui")}, "X11+"},
		{"kendo body tag upgrades X10", "X10",
			[]Finding{fnd("http.exposure", "info", "fingerprint", "html-meta ATEN International Co Ltd.; smc-ui:kendo")}, "X11+"},
		{"legacy X10 login leaves X10", "X10",
			[]Finding{fnd("http.exposure", "info", "fingerprint", "html-meta ATEN International Co Ltd.; smc-ui:legacy")}, "X10"},
		{"modern-tar (X13+) beats coreui (X11+)", "X10",
			[]Finding{fnd("web.service", "info", "title", "Supermicro BMC Login"),
				fnd("http.exposure", "medium", "fingerprint", "xz redfish-metadata tar (42 files, supermicro)")}, "X13+"},
		{"SKU beats every band", "X10",
			[]Finding{fnd("web.service", "info", "title", "Supermicro BMC Login"),
				fnd("http.exposure", "medium", "fingerprint", "xz redfish-metadata tar (42 files, supermicro)"),
				fnd("http.endpoint", "info", "product", "X12DPi-N6")}, "X12"},
		{"non-coreui title leaves baseline", "X10",
			[]Finding{fnd("web.service", "info", "title", "500 - Internal Server Error")}, "X10"},
		// Uncatalogued board-serial GUID floors an empty baseline at X10+ ...
		{"board-serial floor from blank baseline", "",
			[]Finding{fnd("ipmi.guid", "info", "family", "smc-board-serial", "modelPrefix", "3101MS")}, "X10+"},
		// ... and coreui then upgrades that floor to X11+.
		{"board-serial floor + coreui -> X11+", "",
			[]Finding{fnd("ipmi.guid", "info", "family", "smc-board-serial", "modelPrefix", "3101MS"),
				fnd("web.service", "info", "title", "Supermicro BMC Login")}, "X11+"},
		// A catalogued code still wins outright over the floor + bands.
		{"catalogued code beats floor+coreui", "",
			[]Finding{fnd("ipmi.guid", "info", "family", "smc-board-serial", "modelPrefix", "5201MS"),
				fnd("web.service", "info", "title", "Supermicro BMC Login")}, "X12"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tgt := &Target{
				Host:     "198.51.100.8",
				Identity: &Identity{Class: ClassBMC, Vendor: "supermicro", Product: "IPMI", Generation: c.baseGen, Confidence: ConfHigh},
			}
			tgt.Findings = c.findings
			if f := Finalize(tgt); f.Generation != c.want {
				t.Errorf("generation = %q, want %q", f.Generation, c.want)
			}
		})
	}
}

func TestFinalizeDellGenFromSSH(t *testing.T) {
	cases := []struct {
		name    string
		baseGen string
		banner  string
		want    string
	}{
		{"sshserver = idrac7", "iDRAC", "SSH-2.0-SSHSERVER", "iDRAC7"},
		{"openssh 7.4 = 8/9", "iDRAC", "SSH-2.0-OpenSSH_7.4", "iDRAC8/9"},
		{"openssh 8.6 = 9", "iDRAC", "SSH-2.0-OpenSSH_8.6", "iDRAC9"},
		{"openssh 9.9 = 9/10", "iDRAC", "SSH-2.0-OpenSSH_9.9", "iDRAC9/10"},
		{"debian openssh is linux, ignored", "iDRAC7/8/9", "SSH-2.0-OpenSSH_10.0p2 Debian-7", "iDRAC7/8/9"},
		{"crisp gen not widened", "iDRAC9", "SSH-2.0-OpenSSH_9.9", "iDRAC9"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tgt := &Target{
				Host:     "192.0.2.13",
				Identity: &Identity{Class: ClassBMC, Vendor: "dell", Product: "iDRAC", Generation: c.baseGen, Confidence: ConfHigh},
			}
			tgt.Findings = []Finding{fnd("ssh.version", "info", "banner", c.banner, "product", c.banner[8:])}
			if f := Finalize(tgt); f.Generation != c.want {
				t.Errorf("generation = %q, want %q", f.Generation, c.want)
			}
		})
	}
}

func TestFinalizeDellGenFromAttrs(t *testing.T) {
	cases := []struct {
		name    string
		baseGen string
		attrs   map[string]string
		want    string
	}{
		{
			name:    "fw maps to idrac9",
			baseGen: "iDRAC7/8/9",
			attrs:   map[string]string{"idrac.fw": "6.10.30.00"},
			want:    "iDRAC9",
		},
		{
			name:    "server generation maps to idrac10",
			baseGen: "iDRAC9/10",
			attrs:   map[string]string{"idrac.serverGen": "17G"},
			want:    "iDRAC10",
		},
		{
			name:    "redfish product token maps to idrac9",
			baseGen: "iDRAC7/8/9",
			attrs:   map[string]string{"redfish.product": "Dell iDRAC9"},
			want:    "iDRAC9",
		},
		{
			name:    "weak token keeps base",
			baseGen: "iDRAC7/8/9",
			attrs:   map[string]string{"redfish.product": "Integrated Dell Remote Access Controller"},
			want:    "iDRAC7/8/9",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tgt := &Target{
				Host: "192.0.2.14",
				Identity: &Identity{Class: ClassBMC, Vendor: "dell", Product: "iDRAC", Generation: c.baseGen, Confidence: ConfHigh,
					Attributes: c.attrs,
				},
			}
			if f := Finalize(tgt); f.Generation != c.want {
				t.Errorf("generation = %q, want %q", f.Generation, c.want)
			}
		})
	}
}

func TestFinalizeDellGenerationZeroIsRefined(t *testing.T) {
	tgt := &Target{
		Host: "192.0.2.15",
		Identity: &Identity{Class: ClassBMC, Vendor: "dell", Product: "iDRAC", Generation: "0", Confidence: ConfHigh,
			Attributes: map[string]string{"idrac.fw": "2.85.85.85"},
		},
	}
	if f := Finalize(tgt); f.Generation != "iDRAC8" {
		t.Errorf("generation = %q, want iDRAC8", f.Generation)
	}
}

func TestFlagsString(t *testing.T) {
	f := &Final{Flags: map[string]string{"rakpHash": "critical", "defaultCert": "low"}}
	if got := f.FlagsString(); got != "defaultCert=low rakpHash=critical" {
		t.Errorf("FlagsString = %q, want sorted pairs", got)
	}
	if (&Final{}).FlagsString() != "" {
		t.Error("empty flags should render empty")
	}
}

// TestFinalizeFaviconVendorUpgrade proves an unattributed host adopts the vendor
// the favicon fingerprint gave (web.service favicon_vendor), and that an already-
// attributed host is never overridden by it.
func TestFinalizeFaviconVendorUpgrade(t *testing.T) {
	// Unknown identity (no vendor) -> upgraded from the favicon match.
	tgt := &Target{Host: "203.0.113.5", Identity: &Identity{Class: ClassUnknown, Confidence: ConfLow}}
	tgt.Findings = []Finding{
		fnd("web.service", "info", "server", "Apache", "favicon", "abc",
			"faviconMmh3", "1428702434", "faviconVendor", "dell", "faviconProduct", "iDRAC"),
	}
	if f := Finalize(tgt); f.Vendor != "dell" || f.Product != "iDRAC" || f.Confidence != ConfMedium || f.Class != ClassBMC {
		t.Errorf("favicon upgrade = %s/%s/%s/%s, want bmc/dell/iDRAC/medium", f.Class, f.Vendor, f.Product, f.Confidence)
	}
	// An explicit identify vendor must not be overridden by a (mismatched) favicon.
	tgt2 := &Target{Host: "203.0.113.6", Identity: &Identity{Class: ClassBMC, Vendor: "hpe", Product: "iLO", Confidence: ConfHigh}}
	tgt2.Findings = []Finding{fnd("web.service", "info", "faviconVendor", "dell", "faviconProduct", "iDRAC")}
	if f := Finalize(tgt2); f.Vendor != "hpe" {
		t.Errorf("explicit vendor overridden by favicon: got %s, want hpe", f.Vendor)
	}
}
