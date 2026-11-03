package report

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAdvisoryInventory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte(`
| # | State | Meaning | Count |
|---|---|---|---|
| 1 | Patched by vendor | done | 0 |
| 3 | Reported to vendor | sent | 1 |
| 4 | Confirmed by research | ready | 2 |
`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, vendor := range []string{"hpe", "smc"} {
		if err := os.MkdirAll(filepath.Join(root, vendor), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(root, "hpe", "HPE-0005-CRITICAL-UNAUTH-AUTH-BYPASS-RAKP.md"): "# HPE-0005 - RMCP+ Type Confusion Enables Passwordless Administrator Sessions\n",
		filepath.Join(root, "smc", "SMC-0002-HIGH-UNAUTH-AUTH-BYPASS-RAKP.md"):     "# SMC-0002 - SMCRAKP Fixed Key Allows Authentication as Any IPMI Account\n",
		filepath.Join(root, "smc", "SMC-0005-MEDIUM-ADMIN-CMD-INJ-REDFISH.md"):     "# SMC-0005 - Administrator Can Execute Commands as Root Through SmcDump.Download\n",
	}
	for path, body := range files {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := LoadAdvisoryInventory(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 3 || got.Vendors != 2 {
		t.Fatalf("inventory = total %d, vendors %d; want 3, 2", got.Total, got.Vendors)
	}
	if len(got.States) != 2 || got.States[0].Value != "Reported to vendor" || got.States[0].Count != 1 {
		t.Fatalf("states = %#v", got.States)
	}
	if len(got.Highlights) != 2 || got.Highlights[0].ID != "HPE-0005" {
		t.Fatalf("highlights = %#v", got.Highlights)
	}
}
