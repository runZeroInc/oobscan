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

type CrackResult struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	PasswordType   string `json:"passwordType"`
	Vendor         string `json:"vendor,omitempty"`
	Attempts       int    `json:"attempts"`
	Verified       bool   `json:"verified"`
	LoginTested    bool   `json:"loginTested"`
	AcceptsAny     bool   `json:"acceptsAny,omitempty"`
	CommandCapable bool   `json:"commandCapable,omitempty"`
	Proof          string `json:"proof,omitempty"`
}

type CrackOptions struct {
	Vendor         string
	ExtraPasswords []string
	Permute        bool
}

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
