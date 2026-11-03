// Package check is the unified security-check registry. A Check declares which
// device identities it applies to (Applicability) and a Run function; the
// per-target pipeline asks ForIdentity for the ordered set of checks to run
// (device-specific first, then cross-vendor). New checks register themselves
// from init(), so adding one is a localized change with no pipeline edits.
package check

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/runZeroInc/oobscan/pkg/creds"
	"github.com/runZeroInc/oobscan/pkg/engine"
)

// Applicability declares which identities a check targets. A check is
// device-specific when it names Classes or Vendors and is not CrossVendor;
// CrossVendor (or a fully empty Applicability) marks a general check.
type Applicability struct {
	Classes     []engine.DeviceClass // empty = any class
	Vendors     []string             // lowercase slugs; empty = any vendor
	CrossVendor bool                 // runs regardless of vendor/class
}

func (ap Applicability) matches(id *engine.Identity) bool {
	if ap.CrossVendor || (len(ap.Classes) == 0 && len(ap.Vendors) == 0) {
		return true
	}
	if id == nil {
		return false
	}
	if slices.Contains(ap.Classes, id.Class) {
		return true
	}
	for _, v := range ap.Vendors {
		if strings.EqualFold(id.Vendor, v) {
			return true
		}
	}
	return false
}

func (ap Applicability) deviceSpecific() bool {
	return !ap.CrossVendor && (len(ap.Classes) > 0 || len(ap.Vendors) > 0)
}

func proofKV(kv ...string) string {
	return engine.F(kv...).String()
}

// vendorSlugField normalizes a free-form manufacturer / certificate-organization
// string ("Super Micro Computer", "Dell Inc.") to a vendor slug, returning the field
// to append or nothing when no alias matches. Normalizing here rather than in
// engine.Finalize keeps engine free of the creds dependency and makes the attribution
// visible in the output.
func vendorSlugField(manufacturer string) engine.Fields {
	slug := creds.NormalizeVendor(manufacturer)
	if slug == "" {
		return nil
	}
	return engine.Fields{engine.Field{Key: "vendor", Val: slug}}
}

// Check is one registered security check.
type Check struct {
	Name          string // stable unique id, protocol-first, e.g. "http.idrac.defaultCreds"
	Description   string
	Category      string
	Applies       Applicability
	Authenticated bool // needs a credential to fire
	Destructive   bool // may crash/reset the target
	Enabled       bool // in the default set
	Run           func(ctx context.Context, t *engine.Target) []engine.Finding
}

var (
	mu       sync.RWMutex
	registry = map[string]Check{}

	explainMu       sync.RWMutex
	explainRegistry = map[string]func(host string, f engine.Finding) string{}
)

// Register adds a check, panicking on a duplicate Name (a programming error).
func Register(c Check) {
	canonical := engine.CanonicalCheckID(c.Name)
	if canonical == "" {
		panic("check: empty registration name")
	}
	if canonical != c.Name {
		panic(fmt.Sprintf("check: non-canonical registration %q (want %q)", c.Name, canonical))
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[c.Name]; dup {
		panic(fmt.Sprintf("check: duplicate registration %q", c.Name))
	}
	registry[c.Name] = c
}

// RegisterExplain registers a markdown explainer for a specific finding name.
// Called from init() in each check file, directly next to the Register call
// that emits that finding. Panics on duplicate registration (programming error).
// The finding name is the Check field on engine.Finding -- it often differs from
// the registered check name because one check can emit several finding types
// (e.g. "ipmi.defaultCreds" emits "ipmi.v20.cipherZero", "ipmi.v20.rakpHash",
// "ipmi.v20.defaultCreds", etc.).
func RegisterExplain(findingName string, fn func(host string, f engine.Finding) string) {
	canonical := engine.CanonicalCheckID(findingName)
	if canonical == "" {
		panic("check: empty explain registration name")
	}
	if canonical != findingName {
		panic(fmt.Sprintf("check: non-canonical explain registration %q (want %q)", findingName, canonical))
	}
	explainMu.Lock()
	defer explainMu.Unlock()
	if _, dup := explainRegistry[findingName]; dup {
		panic(fmt.Sprintf("check: duplicate explain registration %q", findingName))
	}
	explainRegistry[findingName] = fn
}

// GetExplainer returns the explainer registered for a finding name, if any.
// The confirmed web default-cred family emits per-vendor names
// (http.<vendor>.defaultCreds) that render from the vendor field, so an exact
// miss on that pattern falls back to the shared http.web.defaultCreds explainer.
func GetExplainer(findingName string) (func(host string, f engine.Finding) string, bool) {
	findingName = engine.CanonicalCheckID(findingName)
	explainMu.RLock()
	defer explainMu.RUnlock()
	if fn, ok := explainRegistry[findingName]; ok {
		return fn, true
	}
	if strings.HasPrefix(findingName, "http.") && strings.HasSuffix(findingName, ".defaultCreds") {
		if fn, ok := explainRegistry["http.web.defaultCreds"]; ok {
			return fn, true
		}
	}
	return nil, false
}

// All returns every registered check, sorted by category then name.
func All() []Check {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Check, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Categories returns the sorted set of distinct categories.
func Categories() []string {
	seen := map[string]struct{}{}
	for _, c := range All() {
		seen[c.Category] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Selector folds the CLI knobs that decide whether a check runs.
type Selector struct {
	Checks      []string // --checks allow-list (name, category, or dotted prefix)
	Categories  []string // --categories allow-list
	Destructive bool     // --destructive
	HasCreds    bool     // a credential was supplied
}

var selectionAliases = map[string][]string{
	// These are emitted by the IPMI default-credential/auth pipeline rather than
	// standalone registered checks. Let --checks on the leaf finding IDs select
	// the producer that gathers the required RAKP/auth/setup evidence.
	"ipmi.defaultCreds": {
		"ipmi.openBmc.rakp1SetupCommands",
		"ipmi.rakp.state.setupLocalPreRakp3",
		"ipmi.rakp.state.activeRelabelLowToAdmin",
	},
}

// checkIDTokenMatch reports exact check/finding-name or dotted-prefix matches.
func checkIDTokenMatch(c Check, tokens []string) bool {
	name := engine.CanonicalCheckID(c.Name)
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		canonical := engine.CanonicalCheckID(t)
		prefix := strings.TrimSuffix(canonical, ".") + "."
		if name == canonical || strings.HasPrefix(name, prefix) {
			return true
		}
		for _, alias := range selectionAliases[name] {
			alias = engine.CanonicalCheckID(alias)
			if alias == canonical || strings.HasPrefix(alias, prefix) {
				return true
			}
		}
	}
	return false
}

// tokenMatch mirrors audit.Select: exact name, exact category, or dotted prefix.
func tokenMatch(c Check, tokens []string) bool {
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if c.Category == t {
			return true
		}
	}
	return checkIDTokenMatch(c, tokens)
}

func (s Selector) explicitCheckRequest(c Check) bool {
	return len(s.Checks) > 0 && checkIDTokenMatch(c, s.Checks)
}

func (s Selector) explicitTokenMatch(c Check) bool {
	if tokenMatch(c, s.Checks) {
		return true
	}
	return tokenMatch(c, s.Categories)
}

func (s Selector) hasExplicitTokens() bool {
	return len(s.Checks) > 0 || len(s.Categories) > 0
}

// allow decides whether a check is eligible under the selector, independent of
// the target identity.
func (s Selector) allow(c Check) bool {
	if c.Destructive && !s.Destructive {
		return false
	}
	if c.Authenticated && !s.HasCreds && !s.explicitCheckRequest(c) {
		return false
	}
	// An explicit --checks/--categories list overrides the default Enabled set.
	if s.hasExplicitTokens() {
		return s.explicitTokenMatch(c)
	}
	return c.Enabled
}

// ForIdentity returns the checks to run against a target, device-specific first
// (vendor/class matches) then cross-vendor, filtered by the selector.
func ForIdentity(id *engine.Identity, sel Selector) []Check {
	// A host identify flagged as a honeypot/deception node runs only the identity
	// reporter, which records the honeypot verdict; the whole credential/exposure
	// battery is skipped. Exercising checks against a decoy wastes scan budget and
	// manufactures bogus findings from its emulated services.
	if id != nil && id.Class == engine.ClassHoneypot {
		var only []Check
		for _, c := range All() {
			if c.Name == "id" && sel.allow(c) {
				only = append(only, c)
			}
		}
		return only
	}
	var specific, cross []Check
	for _, c := range All() {
		if !sel.allow(c) || !c.Applies.matches(id) {
			continue
		}
		if c.Applies.deviceSpecific() {
			specific = append(specific, c)
		} else {
			cross = append(cross, c)
		}
	}
	return append(specific, cross...)
}
