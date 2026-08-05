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

type Applicability struct {
	Classes     []engine.DeviceClass
	Vendors     []string
	CrossVendor bool
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

func vendorSlugField(manufacturer string) engine.Fields {
	slug := creds.NormalizeVendor(manufacturer)
	if slug == "" {
		return nil
	}
	return engine.Fields{engine.Field{Key: "vendor", Val: slug}}
}

type Check struct {
	Name          string
	Description   string
	Category      string
	Applies       Applicability
	Authenticated bool
	Destructive   bool
	Enabled       bool
	Run           func(ctx context.Context, t *engine.Target) []engine.Finding
}

var (
	mu       sync.RWMutex
	registry = map[string]Check{}

	explainMu       sync.RWMutex
	explainRegistry = map[string]func(host string, f engine.Finding) string{}
)

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

type Selector struct {
	Checks      []string
	Categories  []string
	Destructive bool
	HasCreds    bool
}

var selectionAliases = map[string][]string{

	"ipmi.defaultCreds": {
		"ipmi.openBmc.rakp1SetupCommands",
		"ipmi.rakp.state.setupLocalPreRakp3",
		"ipmi.rakp.state.setupIdentity",
	},
}

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

func (s Selector) allow(c Check) bool {
	if c.Destructive && !s.Destructive {
		return false
	}
	if c.Authenticated && !s.HasCreds && !s.explicitCheckRequest(c) {
		return false
	}

	if s.hasExplicitTokens() {
		return s.explicitTokenMatch(c)
	}
	return c.Enabled
}

func ForIdentity(id *engine.Identity, sel Selector) []Check {

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
