package check

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// TestRegistryEmitParity asserts that every registered check.Name has at
// least one matching emit-site (Finding{Check:"..."}) somewhere under
// pkg/check, and that both registered names and emitted IDs already use the
// canonical lower-camel dotted form.
//
// The test walks package sources for Finding{Check:"..."} literals and
// asserts every registered Name maps to at least one literal, and vice-versa.
func TestRegistryEmitParity(t *testing.T) {
	pkgDir, err := findPackageDir(t)
	if err != nil {
		t.Fatalf("find package dir: %v", err)
	}
	emits := scanEmittedCheckIDs(t, pkgDir)
	registered := map[string]bool{}
	for _, c := range All() {
		if got := engine.CanonicalCheckID(c.Name); got != c.Name {
			t.Errorf("registered check name is not canonical: %q -> %q", c.Name, got)
		}
		registered[c.Name] = true
	}
	for id := range emits {
		if got := engine.CanonicalCheckID(id); got != id {
			t.Errorf("emitted check ID is not canonical: %q -> %q", id, got)
		}
	}

	// Rule: for every registered Name, some emit ID must exist under the same
	// base namespace (before the first dot). This is deliberately loose because
	// one registered check (e.g. ipmi.defaultCreds) legitimately emits several
	// sub-check IDs (ipmi.v20.cipherZero, ipmi.v20.rakpHash,
	// ipmi.v15.defaultCreds, ...), and one registration (e.g. ssh.exposure) may
	// emit ssh.version / ssh.defaultCreds / ssh.weakCrypto etc.
	// dynamicEmitAllowlist covers registrations whose runner builds the emit
	// check ID at runtime via string concatenation (e.g. `Check: kind +
	// ".fingerprint"`); the static regex scanner cannot see these, so the
	// corresponding _test.go files exercise the runners directly.
	dynamicEmitAllowlist := map[string]bool{
		"pdu.exposure":           true, // pdu_check.go builds Check dynamically
		"pdu.confirm":            true, // pdu_confirm.go builds Check dynamically via apc/other family
		"serialconsole.exposure": true, // serialconsole_check.go: kind + ".fingerprint" / ".defaultCreds"
	}
	var missing []string
	for name := range registered {
		if dynamicEmitAllowlist[name] {
			continue
		}
		if !hasEmitForRegisteredName(name, emits) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("registered check names with no matching emit site: %v", missing)
	}

	// Reverse direction: every emit ID should trace back to some registered
	// check via prefix or base-namespace match. If not, we have an orphaned
	// emit that no CLI --checks flag can select.
	var orphans []string
	for id := range emits {
		if hasRegisteredForEmit(id, registered) {
			continue
		}
		orphans = append(orphans, id)
	}
	if len(orphans) > 0 {
		t.Errorf("emit IDs with no registered check.Name: %v", orphans)
	}
}

// hasEmitForRegisteredName looks for an emit ID that plausibly maps back
// to the registered check.Name. It accepts an exact match, and for names whose
// runner emits a family of
// sub-IDs -- any emit ID sharing the base namespace before the first dot.
func hasEmitForRegisteredName(name string, emits map[string]bool) bool {
	name = engine.CanonicalCheckID(name)
	if emits[name] {
		return true
	}
	base := name
	if i := strings.Index(name, "."); i > 0 {
		base = name[:i]
	}
	for id := range emits {
		if strings.HasPrefix(id, base+".") {
			return true
		}
	}
	// Single-word registrations (no dot): `id` and `snmp` are common. Accept
	// any emit that equals or starts with the name.
	for id := range emits {
		if id == name || strings.HasPrefix(id, name+".") {
			return true
		}
	}
	return false
}

// hasRegisteredForEmit does the reverse mapping: for an emitted ID, see if
// any registered check.Name (either the same string or a prefix of the emit
// ID) maps to it.
func hasRegisteredForEmit(id string, registered map[string]bool) bool {
	id = engine.CanonicalCheckID(id)
	if registered[id] {
		return true
	}
	// Prefix match: emit `kvm.vnc.unauth` is owned by registered `kvm.vnc`.
	parts := strings.Split(id, ".")
	for i := len(parts) - 1; i > 0; i-- {
		prefix := strings.Join(parts[:i], ".")
		if registered[prefix] {
			return true
		}
	}
	// Suffix/base-namespace match: emit `ipmi.v20.cipherZero` is owned by a
	// registered check whose base namespace is `ipmi`. This
	// covers `ipmi.defaultCreds` -> `ipmi.v20.cipherZero`.
	base := parts[0]
	for r := range registered {
		rp := strings.Split(r, ".")
		if len(rp) >= 2 && rp[0] == base {
			return true
		}
	}
	return false
}

// scanEmittedCheckIDs walks every .go source file in pkgDir and extracts
// the string literal after `Check:` in a Finding{...} composite. It uses a
// simple regex rather than go/parser to keep the test cheap.
func scanEmittedCheckIDs(t *testing.T, pkgDir string) map[string]bool {
	t.Helper()
	re := regexp.MustCompile(`Check:\s*"([a-zA-Z0-9._-]+)"`)
	out := map[string]bool{}
	err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range re.FindAllSubmatch(b, -1) {
			out[string(m[1])] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", pkgDir, err)
	}
	return out
}

// findPackageDir locates the oobscan/pkg root using the test's working
// directory as the anchor. The registry test scans the whole pkg tree
// because Finding emitters live in vendor-specific packages (pkg/ssh,
// pkg/snmp, pkg/tlscert, pkg/pdu, ...) as well as pkg/check.
func findPackageDir(t *testing.T) (string, error) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// The test runs inside oobscan/pkg/check; walk two levels up to
	// oobscan/pkg so scanEmittedCheckIDs picks up sibling packages.
	pkgRoot := filepath.Clean(filepath.Join(cwd, ".."))
	return pkgRoot, nil
}
