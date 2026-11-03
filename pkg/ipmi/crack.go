package ipmi

import "github.com/runZeroInc/oobscan/pkg/creds"

type passwordCandidate struct {
	Password string
	Kind     string
}

func offlineCrackPasswordCandidates(vendor string, extra []string, permute bool) []passwordCandidate {
	out := make([]passwordCandidate, 0, 256)
	seen := map[string]struct{}{}
	add := func(pw, kind string) {
		if pw == "" {
			return
		}
		if _, ok := seen[pw]; ok {
			return
		}
		seen[pw] = struct{}{}
		out = append(out, passwordCandidate{Password: pw, Kind: kind})
	}

	for _, c := range creds.CredsFor(vendor, creds.ClassIPMI) {
		kind := "default"
		if c.Source == "spray" {
			kind = "common"
		}
		add(c.Password, kind)
	}
	for _, pw := range extra {
		add(pw, "custom")
	}
	if permute {
		for _, seed := range creds.CommonPasswordSeeds {
			creds.Permute(seed, true, func(v string) bool {
				add(v, "permutation")
				return false
			})
		}
	}
	return out
}

// CrackResult records a recovered BMC password and how it was found.
type CrackResult struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	PasswordType   string `json:"passwordType"`     // "default" | "common" | "custom" | "permutation" | "online" | "smcrakp-fixed-key"
	Vendor         string `json:"vendor,omitempty"` // vendor slug whose default list produced the hit
	Attempts       int    `json:"attempts"`
	Verified       bool   `json:"verified"`                 // an actual RAKP-3/4 login with this credential completed
	LoginTested    bool   `json:"loginTested"`              // a login was attempted, so !Verified means it failed rather than untested
	AcceptsAny     bool   `json:"acceptsAny,omitempty"`     // BMC returns a RAKP-2 for any username (crack username is unreliable)
	CommandCapable bool   `json:"commandCapable,omitempty"` // SMCRAKP: a forged session executed an unprotected (no-integrity/no-encrypt) command - the H3 bypass is exploitable, not just forgeable
	Proof          string `json:"proof,omitempty"`          // server-derived proof that the credential worked
}

// CrackOptions tunes offline RAKP cracking.
type CrackOptions struct {
	Vendor         string   // vendor slug to prioritize (e.g. "dell" tries root:calvin first)
	ExtraPasswords []string // caller-supplied candidates tried before permutation
	Permute        bool     // enable the CPU-intensive permutation pass
}

// CrackRAKP recovers the account password offline by recomputing the RAKP-2 HMAC
// for candidate passwords against the leaked hash in r, so it does no network I/O
// and cannot trigger account lockout (CVE-2013-4786). Candidates are tried in
// order: vendor defaults, the generic default/common spray (both via
// creds.CredsFor), caller extras, then permutation seeds. Returns nil on no match.
func CrackRAKP(r *RAKPResult, opts CrackOptions) *CrackResult {
	if r == nil || len(r.RAKPHash) == 0 {
		return nil
	}
	if r.UsesSMCRAKPFixedKey() {
		return &CrackResult{
			Username:     r.Username,
			Password:     "<smcrakp-fixed-key>",
			PasswordType: "smcrakp-fixed-key",
			Vendor:       opts.Vendor,
			Attempts:     1,
		}
	}
	attempts := 0
	seen := map[string]struct{}{}
	try := func(pw, kind string) *CrackResult {
		if _, dup := seen[pw]; dup {
			return nil
		}
		seen[pw] = struct{}{}
		attempts++
		if r.VerifyRAKPPassword(pw) {
			return &CrackResult{Username: r.Username, Password: pw, PasswordType: kind, Vendor: opts.Vendor, Attempts: attempts}
		}
		return nil
	}

	for _, cand := range offlineCrackPasswordCandidates(opts.Vendor, opts.ExtraPasswords, false) {
		if hit := try(cand.Password, cand.Kind); hit != nil {
			return hit
		}
	}
	// 2. Caller-supplied extras are already included in the candidate stream.
	// 3. Permutation of common seeds (case/leet/affix variants).
	if opts.Permute {
		for _, cand := range offlineCrackPasswordCandidates(opts.Vendor, opts.ExtraPasswords, true) {
			if cand.Kind != "permutation" {
				continue
			}
			if hit := try(cand.Password, cand.Kind); hit != nil {
				return hit
			}
		}
	}
	return nil
}
