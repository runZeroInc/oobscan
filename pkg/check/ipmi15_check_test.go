package check

import (
	"testing"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func TestV15UsernameOracleFindingsWildcardSuppressesUserList(t *testing.T) {
	var valid []ipmi.V15OracleEntry
	for _, user := range ipmi.V15OracleUserList()[1:] {
		valid = append(valid, ipmi.V15OracleEntry{Username: user, CC: 0x00})
	}
	rep := &ipmi.V15Report{ValidUsernames: valid, OracleInvalidUser: "", OracleInvalidCC: 0x82}

	got := v15UsernameOracleFindings(rep)
	if len(got) != 1 {
		t.Fatalf("len(got)=%d, want 1", len(got))
	}
	if got[0].Check != "ipmi.v15.oracleBlind" || got[0].Risk != "info" {
		t.Fatalf("finding=%+v, want info ipmi.v15.oracleBlind", got[0])
	}
	if explainField(got[0], "wildcard") != "true" {
		t.Fatalf("wildcard field=%q, want true", explainField(got[0], "wildcard"))
	}
}

func TestV15UsernameOracleFindingsPartialKeepsUserList(t *testing.T) {
	rep := &ipmi.V15Report{
		ValidUsernames:    []ipmi.V15OracleEntry{{Username: "ADMIN", CC: 0x00}, {Username: "root", CC: 0x00}},
		OracleInvalidUser: "guest",
		OracleInvalidCC:   0x81,
	}

	got := v15UsernameOracleFindings(rep)
	if len(got) != 1 {
		t.Fatalf("len(got)=%d, want 1", len(got))
	}
	if got[0].Check != "ipmi.v15.usernameOracle" || got[0].Risk != "low" {
		t.Fatalf("finding=%+v, want low ipmi.v15.usernameOracle", got[0])
	}
	if users := explainField(got[0], "users"); users != "ADMIN,root" {
		t.Fatalf("users=%q, want ADMIN,root", users)
	}
}
