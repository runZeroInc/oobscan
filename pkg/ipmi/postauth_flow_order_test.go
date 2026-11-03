package ipmi

import "testing"

func flowLabels(flows []AuthFlow) []string {
	out := make([]string, 0, len(flows))
	for _, f := range flows {
		out = append(out, f.Version+"/"+f.Mode+":"+userOrNullTest(f.Username))
	}
	return out
}

func userOrNullTest(u string) string {
	if u == "" {
		return "(null)"
	}
	return u
}

// Returning cipherZero or 1.5 authNone ahead of a real credential ignores the most
// privileged credential available. A no-auth session sits at whatever privilege the BMC
// gives an unauthenticated caller, so Get Device ID / chassis / user-list / FRU come
// back cc=0xd4 while only the lower-privilege LAN reads succeed.
func TestPostAuthFlowsPutNoAuthLast(t *testing.T) {
	auth := &AuthReport{
		CipherZero: true,
		Suite:      &CipherAlgos{Suite: 3, Auth: RAKPHMACSHA1},
		Cracked: []CrackResult{
			{Username: "ADMIN", Password: "secret", Verified: true},
		},
	}
	v15 := &V15Report{AuthNoneOK: true}

	flows := SelectPostAuthFlows(auth, v15)
	if len(flows) < 3 {
		t.Fatalf("want at least cred + cipherZero + authNone, got %v", flowLabels(flows))
	}
	if flows[0].Mode != "cred" || flows[0].Username != "ADMIN" {
		t.Errorf("first flow = %s/%s user=%q, want the real ADMIN credential (got order %v)",
			flows[0].Version, flows[0].Mode, flows[0].Username, flowLabels(flows))
	}
	// Both no-auth modes must sit behind every real credential.
	firstNoAuth := len(flows)
	lastCred := -1
	for i, f := range flows {
		switch f.Mode {
		case "cipherZero", "authNone":
			if i < firstNoAuth {
				firstNoAuth = i
			}
		case "cred":
			lastCred = i
		}
	}
	if firstNoAuth < lastCred {
		t.Errorf("a no-auth flow (index %d) precedes a real credential (index %d): %v",
			firstNoAuth, lastCred, flowLabels(flows))
	}
}

// Admin-looking accounts are tried before other accounts, because the privilege the
// BMC grants is what decides whether mcInfo/chassis/users/FRU can be read at all.
func TestPostAuthFlowsRankAdminUsernamesFirst(t *testing.T) {
	auth := &AuthReport{
		Suite: &CipherAlgos{Suite: 3},
		Cracked: []CrackResult{
			{Username: "guest", Password: "g", Verified: true},
			{Username: "monitor", Password: "m", Verified: true},
			{Username: "ADMIN", Password: "a", Verified: true},
		},
	}
	flows := SelectPostAuthFlows(auth, nil)
	if len(flows) == 0 || flows[0].Username != "ADMIN" {
		t.Fatalf("want ADMIN first, got %v", flowLabels(flows))
	}
}

// A low-privilege credential plus the name of an Administrator account yields an SMC
// reserved-role escalation candidate: RAKP-1 needs no password to name the admin, and
// RAKP-3 is still signed with our own password.
func TestPostAuthFlowsOfferReservedRoleEscalation(t *testing.T) {
	auth := &AuthReport{
		Suite: &CipherAlgos{Suite: 3},
		// ADMIN was seen in RAKP but never cracked; only the low-priv account cracked.
		Results: []RAKPResult{{Username: "ADMIN"}, {Username: "monitor"}},
		Cracked: []CrackResult{{Username: "monitor", Password: "m", Verified: true}},
	}
	flows := SelectPostAuthFlows(auth, nil)
	var esc *AuthFlow
	for i := range flows {
		if flows[i].Mode == "smcReservedRole" {
			esc = &flows[i]
			break
		}
	}
	if esc == nil {
		t.Fatalf("no reserved-role escalation candidate offered: %v", flowLabels(flows))
	}
	if esc.Username != "monitor" || esc.Password != "m" {
		t.Errorf("escalation must use the credential we hold, got user=%q", esc.Username)
	}
	if esc.RelabelUser != "ADMIN" {
		t.Errorf("escalation must name the admin account to inherit privilege from, got %q", esc.RelabelUser)
	}
	// It is an escalation, not a preference: the plain credential is tried first.
	if flows[0].Mode != "cred" {
		t.Errorf("first flow = %s, want the plain credential before the escalation", flows[0].Mode)
	}
}

// Escalating to the account we already hold would be pointless.
func TestPostAuthFlowsSkipsSelfEscalation(t *testing.T) {
	auth := &AuthReport{
		Suite:   &CipherAlgos{Suite: 3},
		Results: []RAKPResult{{Username: "ADMIN"}},
		Cracked: []CrackResult{{Username: "ADMIN", Password: "a", Verified: true}},
	}
	for _, f := range SelectPostAuthFlows(auth, nil) {
		if f.Mode == "smcReservedRole" {
			t.Errorf("offered an escalation from ADMIN to ADMIN: %+v", f)
		}
	}
}

// A forged SMCRAKP session is only useful when unprotected commands actually
// execute; otherwise the session opens and nothing can be read.
func TestPostAuthFlowsSkipNonCommandCapableForgery(t *testing.T) {
	auth := &AuthReport{
		Suite: &CipherAlgos{Suite: 3},
		Cracked: []CrackResult{
			{Username: "ADMIN", PasswordType: "smcrakp-fixed-key", Verified: true, CommandCapable: false},
		},
	}
	for _, f := range SelectPostAuthFlows(auth, nil) {
		if f.Mode == "smcrakpFixedKey" {
			t.Errorf("offered a forged session that cannot run commands: %+v", f)
		}
	}
}

// Unverified cracks are not credentials.
func TestPostAuthFlowsIgnoreUnverifiedCracks(t *testing.T) {
	auth := &AuthReport{
		Suite:   &CipherAlgos{Suite: 3},
		Cracked: []CrackResult{{Username: "ADMIN", Password: "a", Verified: false}},
	}
	if flows := SelectPostAuthFlows(auth, nil); len(flows) != 0 {
		t.Errorf("unverified crack produced flows: %v", flowLabels(flows))
	}
}

// The single-flow wrapper must agree with the head of the list.
func TestSelectPostAuthFlowMatchesListHead(t *testing.T) {
	auth := &AuthReport{
		CipherZero: true,
		Suite:      &CipherAlgos{Suite: 3},
		Cracked:    []CrackResult{{Username: "root", Password: "r", Verified: true}},
	}
	flows := SelectPostAuthFlows(auth, nil)
	one, ok := SelectPostAuthFlow(auth, nil)
	if !ok || len(flows) == 0 || one.Mode != flows[0].Mode || one.Username != flows[0].Username {
		t.Fatalf("wrapper returned %+v, want head of %v", one, flowLabels(flows))
	}
}

func TestUsernamePrivRankOrdersAdminsFirst(t *testing.T) {
	if UsernamePrivRank("ADMIN") >= UsernamePrivRank("someuser") {
		t.Error("ADMIN should rank above an unknown account")
	}
	if UsernamePrivRank("someuser") >= UsernamePrivRank("") {
		t.Error("a named account should rank above the null/anonymous account")
	}
}
