package creds

import "testing"

// TestCredentialTableWellFormed guards the knowledge base: every row needs a
// username (blank passwords are legitimate), and no exact (vendor,class,user,pass)
// row may be duplicated.
func TestCredentialTableWellFormed(t *testing.T) {
	seen := map[[4]string]struct{}{}
	for i, c := range Table {
		if c.Username == "" && c.Vendor != "" {
			t.Errorf("Table[%d] (%s): empty username", i, c.Vendor)
		}
		if c.Source == "" {
			t.Errorf("Table[%d] (%s %s:%s): missing Source", i, c.Vendor, c.Username, c.Password)
		}
		k := [4]string{c.Vendor, string(c.Class), c.Username, c.Password}
		if _, dup := seen[k]; dup {
			t.Errorf("Table[%d]: duplicate row %v", i, k)
		}
		seen[k] = struct{}{}
	}
}

func TestVendorPairsDerived(t *testing.T) {
	if len(VendorPairs) == 0 {
		t.Fatal("VendorPairs not derived from Table")
	}
	for _, vp := range VendorPairs {
		if vp.Vendor == "" {
			t.Errorf("VendorPairs contains a row with no vendor: %+v", vp)
		}
	}
}

func TestNormalizeVendor(t *testing.T) {
	cases := map[string]string{
		"Super Micro Computer": "supermicro",
		"Dell Inc.":            "dell",
		"Hewlett-Packard":      "hpe",
		"American Megatrends":  "ami",
		"Huawei Technologies":  "huawei",
		"unknown vendor xyz":   "",
		"":                     "",
	}
	for in, want := range cases {
		if got := NormalizeVendor(in); got != want {
			t.Errorf("NormalizeVendor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCredsForVendorFirst(t *testing.T) {
	got := CredsFor("dell", ClassIPMI)
	if len(got) == 0 {
		t.Fatal("no creds returned for dell")
	}
	// root:calvin must be attempted before the generic spray.
	if got[0].Username != "root" || got[0].Password != "calvin" {
		t.Errorf("dell first cred = %s:%s, want root:calvin", got[0].Username, got[0].Password)
	}
}

// TestNewVendorCredsPresent guards the AUDIT-4/5 firmware-confirmed defaults so
// CredsFor(vendor) returns them once the bmcfp fingerprint emits the vendor slug.
// A slug typo here (or in the fingerprint) silently drops the vendor's default.
func TestNewVendorCredsPresent(t *testing.T) {
	want := map[string][2]string{ // vendor -> {user, pass} that must be present
		"sierra":    {"user", "12345"},
		"westermo":  {"admin", "westermo"},
		"raritan":   {"admin", "raritan"},
		"avocent":   {"admin", ""},
		"tripplite": {"localadmin", "localadmin"},
		"inspur":    {"sysadmin", "superuser"}, // AMI SP-X OS account (CVE-2022-40242)
		"h3c":       {"admin", "Password@_"},   // HDM documented default
	}
	for vendor, up := range want {
		got := CredsFor(vendor, ClassAny)
		if len(got) == 0 {
			t.Errorf("CredsFor(%q) returned nothing", vendor)
			continue
		}
		found := false
		for _, c := range got {
			if c.Username == up[0] && c.Password == up[1] {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("CredsFor(%q) missing %s:%s", vendor, up[0], up[1])
		}
	}
}

// TestPlatformUsernameParity locks the first 20 usernames to the runZero
// platform IPMI probe's CommonUsernames (same list, same order), so oobscan
// enumerates the same default accounts.
func TestPlatformUsernameParity(t *testing.T) {
	platform := []string{
		"ADMIN", "admin", "Admin", "root", "USERID", "Administrator", "administrator",
		"guest", "default", "anonymous", "sysadmin", "operator", "supervisor", "service",
		"test", "support", "monitor", "user", "avid", "",
	}
	if len(CommonUsernames) < len(platform) {
		t.Fatalf("CommonUsernames has %d entries, need at least %d", len(CommonUsernames), len(platform))
	}
	for i, want := range platform {
		if CommonUsernames[i] != want {
			t.Errorf("CommonUsernames[%d] = %q, want %q (platform parity)", i, CommonUsernames[i], want)
		}
	}
}

func TestPoolsDeduped(t *testing.T) {
	for _, pool := range [][]string{Usernames(), Passwords()} {
		seen := map[string]struct{}{}
		for _, v := range pool {
			if _, dup := seen[v]; dup {
				t.Errorf("duplicate %q in pool", v)
			}
			seen[v] = struct{}{}
		}
	}
}
