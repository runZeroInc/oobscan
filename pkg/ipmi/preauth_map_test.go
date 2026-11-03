package ipmi

import "testing"

// Regression guard for PreAuthMapResult.tally() categorisation. A RAKP-2 HMAC
// disclosure (CVE-2013-4786) and a username-enumeration oracle are information
// leaks, not auth bypasses.
func TestPreAuthMapTally(t *testing.T) {
	res := &PreAuthMapResult{
		Requests: []PreAuthRequestResult{
			{ResponseSeen: true, ParsedCC: true, CompletionCode: 0x00}, // 0x38 answered
			{ResponseSeen: true, ParsedCC: true, CompletionCode: 0x00}, // 0x54 answered
			{ResponseSeen: false},                           // device-id timeout
			{ResponseSeen: true, PotentialAuthBypass: true}, // a genuine bypass
			{ResponseSeen: true, PotentialMemoryLeak: true}, // a genuine memory leak
		},
		RAKP: []RAKPPreAuthResult{
			{Username: "admin", Error: "short RAKP2 payload"},
			{Username: "ADMIN", HashLen: 20, PotentialHashLeak: true}, // the CVE-2013-4786 leak
			{Username: "guest", PotentialUserOracle: true},            // user-enum oracle
		},
	}
	res.tally()

	if res.ResponseCount != 4 {
		t.Errorf("ResponseCount=%d want 4", res.ResponseCount)
	}
	if res.AcceptedCount != 2 {
		t.Errorf("AcceptedCount=%d want 2", res.AcceptedCount)
	}
	// leaks = 1 request-level memory leak + 2 RAKP (hash leak + oracle) = 3
	if res.PotentialLeakCount != 3 {
		t.Errorf("PotentialLeakCount=%d want 3 (RAKP hash leak + user oracle must count as LEAKS)", res.PotentialLeakCount)
	}
	// bypass = only the request-level PotentialAuthBypass = 1
	if res.PotentialBypassCount != 1 {
		t.Errorf("PotentialBypassCount=%d want 1 (RAKP hash leak must NOT be counted as a bypass)", res.PotentialBypassCount)
	}

	// Idempotent: re-tally must not accumulate.
	res.tally()
	if res.PotentialLeakCount != 3 || res.PotentialBypassCount != 1 {
		t.Errorf("tally not idempotent: leaks=%d bypass=%d", res.PotentialLeakCount, res.PotentialBypassCount)
	}
}
